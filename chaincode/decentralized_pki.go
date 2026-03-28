// decentralized_pki.go implements the Fabric chaincode runtime for distributed CA governance, TSS-backed CSR signing, and certificate lifecycle state.
// Runtime flow: Fabric invoke/query entrypoints call contract methods, which coordinate ledger state transitions, threshold policies, and verification helpers.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const DefaultCAID = "root-ca-001"
const merkleConfigKeyPrefix = "CONFIG:MERKLE:"

// ===================== SECURITY CONSTANTS =====================

// MinOrgsForApproval requires votes from at least this many different orgs
// This ensures cross-org consensus (set to 1 to disable)
const MinOrgsForApproval = 2
const EnableSecurityLimits = true

type DecentralizedPKIContract struct {
	contractapi.Contract
}

// ===================== STRUCTS =====================

type DistributedCA struct {
	CAID             string               `json:"caId"`
	Name             string               `json:"name"`
	ThresholdParams  ThresholdParameters  `json:"thresholdParams"`
	Members          []string             `json:"members"` // This stores the members
	Epoch            int                  `json:"epoch"`
	PublicKey        string               `json:"publicKey"`
	PartySalt        string               `json:"partySalt"`
	CreatedAt        time.Time            `json:"createdAt"`
	IsActive         bool                 `json:"isActive"`
	GovernanceParams GovernanceParameters `json:"governanceParams"`
}

type ThresholdParameters struct {
	Threshold  int    `json:"threshold"`
	TotalNodes int    `json:"totalNodes"`
	Scheme     string `json:"scheme"`
}

type GovernanceParameters struct {
	VotingPeriodDays  int `json:"votingPeriodDays"`
	QuorumPercentage  int `json:"quorumPercentage"`
	ApprovalThreshold int `json:"approvalThreshold"`
}

type CSRProposal struct {
	ProposalID    string    `json:"proposalId"`
	SubmitterID   string    `json:"submitterId"`
	CSRData       string    `json:"csrData"`
	SubmitterRole string    `json:"submitterRole"`
	SubmitterCert string    `json:"submitterCertPem"`
	SubmittedAt   time.Time `json:"submittedAt"`
	VotingEndsAt  time.Time `json:"votingEndsAt"`
	Status        string    `json:"status"`
	VotesFor      int       `json:"votesFor"`
	VotesAgainst  int       `json:"votesAgainst"`
	VotersList    []string  `json:"votersList"`
}

type Vote struct {
	VoterID   string    `json:"voterId"`
	Decision  string    `json:"decision"` // approve, reject
	Timestamp time.Time `json:"timestamp"`
	Rationale string    `json:"rationale,omitempty,optional"`
}

type PartialSignature struct {
	SignerID       string    `json:"signerId"`
	PartialSig     string    `json:"partialSig"`  // Hex-encoded combined signature "R:S"
	SignerIndex    int       `json:"signerIndex"` // TSS party index
	SubmittedAt    time.Time `json:"submittedAt"`
	PublicKeyShare string    `json:"publicKeyShare"` // For verification
}

type SigningSession struct {
	ProposalID        string             `json:"proposalId"`
	CSRHash           string             `json:"csrHash"`
	RequiredSigners   int                `json:"requiredSigners"`
	PartialSignatures []PartialSignature `json:"partialSignatures"`
	Status            string             `json:"status"` // active, completed
	CreatedAt         time.Time          `json:"createdAt"`
}

type Certificate struct {
	CertID           string    `json:"certId"`
	MemberID         string    `json:"memberId"`
	CertificatePEM   string    `json:"certificatePem"`
	CertificateHash  string    `json:"certificateHash"`
	Subject          string    `json:"subject"`
	PublicKey        string    `json:"publicKey"`
	SerialNumber     string    `json:"serialNumber"`
	IssuedAt         time.Time `json:"issuedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
	Status           string    `json:"status"` // active, revoked
	IsRevoked        bool      `json:"isRevoked"`
	RevokedAt        string    `json:"revokedAt"`
	RevocationReason string    `json:"revocationReason"`
	ProposalID       string    `json:"proposalId"`
	Epoch            int       `json:"epoch"`
	SignatureR       string    `json:"signatureR,omitempty,optional"`
	SignatureS       string    `json:"signatureS,omitempty,optional"`
}

// CertificateMerkleState stores the Merkle tree of active certificates
// Updated after every certificate registration or revocation.
type CertificateMerkleState struct {
	MerkleRoot      string   `json:"merkleRoot"`
	ActiveCertCount int      `json:"activeCertCount"`
	LeafHashes      []string `json:"leafHashes"`
	UpdatedAt       string   `json:"updatedAt"`
	TriggerAction   string   `json:"triggerAction"` // "certificate_registered" or "certificate_revoked"
	TriggerCertID   string   `json:"triggerCertId"`
}

// Whether the Merkle tree is updated
type MerkleConfig struct {
	Enabled   bool   `json:"enabled"`
	UpdatedAt string `json:"updatedAt,omitempty,optional"`
	UpdatedBy string `json:"updatedBy,omitempty,optional"`
}

type RevocationProposal struct {
	ProposalID   string    `json:"proposalId"`
	TargetNodeID string    `json:"targetNodeId"`
	Reason       string    `json:"reason"`
	SubmittedBy  string    `json:"submittedBy"`
	SubmittedAt  time.Time `json:"submittedAt"`
	VotingEndsAt time.Time `json:"votingEndsAt"`
	Status       string    `json:"status"`
	VotesFor     int       `json:"votesFor"`
	VotesAgainst int       `json:"votesAgainst"`
	VotersList   []string  `json:"votersList"`
}

type MemberRemovalProposal struct {
	ProposalID     string    `json:"proposalId"`
	TargetMemberID string    `json:"targetMemberId"`
	Reason         string    `json:"reason"`
	SubmittedBy    string    `json:"submittedBy"`
	CAID           string    `json:"caId"`
	SubmittedAt    time.Time `json:"submittedAt"`
	VotingEndsAt   time.Time `json:"votingEndsAt"`
	Status         string    `json:"status"`
	VotesFor       int       `json:"votesFor"`
	VotesAgainst   int       `json:"votesAgainst"`
	VotersList     []string  `json:"votersList"`
}

type JoinRequestProposal struct {
	ProposalID    string    `json:"proposalId"`
	CandidateID   string    `json:"candidateId"`
	CandidateRole string    `json:"candidateRole"`
	CandidateCert string    `json:"candidateCertPem"`
	Reason        string    `json:"reason"`
	SubmittedBy   string    `json:"submittedBy"`
	CAID          string    `json:"caId"`
	SubmittedAt   time.Time `json:"submittedAt"`
	VotingEndsAt  time.Time `json:"votingEndsAt"`
	Status        string    `json:"status"`
	VotesFor      int       `json:"votesFor"`
	VotesAgainst  int       `json:"votesAgainst"`
	VotersList    []string  `json:"votersList"`
}

type ReshareSession struct {
	Epoch              int      `json:"epoch"`
	TriggerReason      string   `json:"triggerReason"`
	OldNodeSet         []string `json:"oldNodeSet"`
	OldThreshold       int      `json:"oldThreshold"`
	NewNodeSet         []string `json:"newNodeSet"`
	NewThreshold       int      `json:"newThreshold"`
	Status             string   `json:"status"`
	AckCount           int      `json:"ackCount"`
	AcknowledgedBy     []string `json:"acknowledgedBy"`
	CompletionAckedBy  []string `json:"completionAckedBy"`
	CompletionAckCount int      `json:"completionAckCount"`
	InitiatedAt        string   `json:"initiatedAt"`
	CompletedAt        string   `json:"completedAt"`
	NewCAPublicKey     string   `json:"newCaPublicKey"`
	OldPartySalt       string   `json:"oldPartySalt"`
	NewPartySalt       string   `json:"newPartySalt"`
	SupersededBy       int      `json:"supersededBy,omitempty,optional"`
	SupersededAt       string   `json:"supersededAt,omitempty,optional"`
}

type storageAttributionTracker struct {
	workflow                string
	action                  string
	proposalID              string
	epoch                   string
	logicalWriteBytesTotal  int
	logicalDeleteBytesTotal int
	logicalWriteByCategory  map[string]int
	logicalDeleteByCategory map[string]int
}

// ===================== Helpers for storage attribution during benchmarking, emitted by tracker events =====================

// derives normalized storage category values for downstream governance and signing logic
// Called by: (*storageAttributionTracker).trackDelete, (*storageAttributionTracker).trackWrite.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func normalizeStorageCategory(category string) string {
	switch strings.TrimSpace(strings.ToLower(category)) {
	case "proposal":
		return "proposal"
	case "vote":
		return "vote"
	case "certificate":
		return "certificate"
	case "active_index":
		return "active_index"
	case "ca_state":
		return "ca_state"
	case "reshare_state":
		return "reshare_state"
	case "merkle_state":
		return "merkle_state"
	case "signing_state":
		return "signing_state"
	default:
		return "other"
	}
}

// manages storage attribution within chaincode state
// Called by: (*DecentralizedPKIContract).ProposeRemoveMember, (*DecentralizedPKIContract).ProposeRevocation, (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SubmitCSR, (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).VoteOnRevocation, (*DecentralizedPKIContract).executeJoinApproval, (*DecentralizedPKIContract).executeMemberRemoval, (*DecentralizedPKIContract).executeRevocation.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func newStorageAttributionTracker(workflow string, action string, proposalID string, epoch string) *storageAttributionTracker {
	return &storageAttributionTracker{
		workflow:                strings.TrimSpace(workflow),
		action:                  strings.TrimSpace(action),
		proposalID:              strings.TrimSpace(proposalID),
		epoch:                   strings.TrimSpace(epoch),
		logicalWriteByCategory:  map[string]int{},
		logicalDeleteByCategory: map[string]int{},
	}
}

// manages write within chaincode state
// Called by: internal helper paths (none in current static call graph).
// Triggered: internal storage-attribution bookkeeping during state writes/deletes.
func (t *storageAttributionTracker) trackWrite(category string, payload []byte) {
	if t == nil {
		return
	}
	if len(payload) <= 0 {
		return
	}
	cat := normalizeStorageCategory(category)
	t.logicalWriteBytesTotal += len(payload)
	t.logicalWriteByCategory[cat] = t.logicalWriteByCategory[cat] + len(payload)
}

// manages delete within chaincode state
// Called by: internal helper paths (none in current static call graph).
// Triggered: internal storage-attribution bookkeeping during state writes/deletes.
func (t *storageAttributionTracker) trackDelete(category string, previousValue []byte) {
	if t == nil {
		return
	}
	if len(previousValue) <= 0 {
		return
	}
	cat := normalizeStorageCategory(category)
	t.logicalDeleteBytesTotal += len(previousValue)
	t.logicalDeleteByCategory[cat] = t.logicalDeleteByCategory[cat] + len(previousValue)
}

// manages event payload within chaincode state
// Called by: internal helper paths (none in current static call graph).
// Triggered: internal storage-attribution bookkeeping during state writes/deletes.
func (t *storageAttributionTracker) applyToEventPayload(ctx contractapi.TransactionContextInterface, payload map[string]interface{}) {
	if t == nil || payload == nil {
		return
	}
	payload["eventVersion"] = 2
	if t.workflow != "" {
		payload["workflow"] = t.workflow
	}
	if t.action != "" {
		payload["action"] = t.action
	}
	if t.proposalID != "" {
		payload["proposalId"] = t.proposalID
	}
	if t.epoch != "" {
		payload["epoch"] = t.epoch
	}
	if ctx != nil {
		payload["txId"] = ctx.GetStub().GetTxID()
	}
	payload["logicalWriteBytesTotal"] = t.logicalWriteBytesTotal
	payload["logicalDeleteBytesTotal"] = t.logicalDeleteBytesTotal
	payload["logicalWriteByCategory"] = t.logicalWriteByCategory
	payload["logicalDeleteByCategory"] = t.logicalDeleteByCategory
}

// ===================== CA JOIN Procedure =====================

// records a join proposal with identity, role, and policy checks
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) RequestJoinCA(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposalID string,
	reason string,
) error {
	candidateID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	cert, certPEM, err := getClientCert(ctx)
	if err != nil {
		return err
	}
	role, err := getClientRole(ctx, cert)
	if err != nil {
		return err
	}
	if role != "member" {
		return fmt.Errorf("certificate role not eligible for member join request")
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}
	if contains(ca.Members, candidateID) {
		return fmt.Errorf("already a full member of this CA")
	}
	if err := c.assertNoActiveKeySession(ctx, "submit join request"); err != nil {
		return err
	}
	if err := c.assertNoPendingMembershipGovernance(ctx, caId, "submit join request"); err != nil {
		return err
	}

	if err := validateMemberOrgLimit(ca.Members, candidateID); err != nil {
		return err
	}

	key := fmt.Sprintf("JOINREQ:%s:%s", caId, proposalID)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("join request %s already exists", proposalID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	submittedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	votingEndsAt := submittedAt.AddDate(0, 0, ca.GovernanceParams.VotingPeriodDays)

	if err := validateCertAtTime(cert, submittedAt); err != nil {
		return err
	}

	proposal := JoinRequestProposal{
		ProposalID:    proposalID,
		CandidateID:   candidateID,
		CandidateRole: role,
		CandidateCert: certPEM,
		Reason:        reason,
		SubmittedBy:   candidateID,
		CAID:          caId,
		SubmittedAt:   submittedAt,
		VotingEndsAt:  votingEndsAt,
		Status:        "pending",
		VotesFor:      0,
		VotesAgainst:  0,
		VotersList:    []string{},
	}

	proposalJSON, _ := json.Marshal(proposal)
	tracker := newStorageAttributionTracker("join", "member_join_requested", proposalID, strconv.Itoa(ca.Epoch))
	tracker.trackWrite("proposal", proposalJSON)

	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "join",
		"action":       "member_join_requested",
		"proposalId":   proposalID,
		"candidate":    candidateID,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	ev, _ := json.Marshal(eventPayload)
	_ = ctx.GetStub().SetEvent("MemberJoinRequested", ev)

	return ctx.GetStub().PutState(key, proposalJSON)
}

// records and evaluates join votes so candidate admission only proceeds after quorum and approval constraints are satisfied.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) VoteOnJoinRequest(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposalID string,
	decision string,
	rationale string,
) error {
	voterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("invalid decision")
	}

	proposalJSON, err := ctx.GetStub().GetState(fmt.Sprintf("JOINREQ:%s:%s", caId, proposalID))
	if err != nil {
		return err
	}
	if proposalJSON == nil {
		return fmt.Errorf("join request not found")
	}

	var proposal JoinRequestProposal
	if err := json.Unmarshal(proposalJSON, &proposal); err != nil {
		return err
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	if currentTime.After(proposal.VotingEndsAt) {
		return fmt.Errorf("voting period ended")
	}

	if contains(proposal.VotersList, voterID) {
		return fmt.Errorf("already voted")
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return err
	}
	if err := c.assertNoActiveKeySession(ctx, "vote on join request"); err != nil {
		return err
	}
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}
	tracker := newStorageAttributionTracker("join", "member_join_voted", proposalID, strconv.Itoa(ca.Epoch))
	if !contains(ca.Members, voterID) {
		return fmt.Errorf("voter not authorized")
	}

	if decision == "approve" {
		candidateCert, err := parseCertFromPEM(proposal.CandidateCert)
		if err != nil {
			return fmt.Errorf("join request missing valid candidate certificate: %v", err)
		}
		if err := validateCertAtTime(candidateCert, currentTime); err != nil {
			return err
		}
		role := strings.ToLower(strings.TrimSpace(proposal.CandidateRole))
		if role == "" {
			role = roleFromCert(candidateCert)
		}
		if role != "member" {
			return fmt.Errorf("candidate role not eligible for membership")
		}
	}

	vote := Vote{
		VoterID:   voterID,
		Decision:  decision,
		Timestamp: currentTime,
		Rationale: rationale,
	}
	voteJSON, _ := json.Marshal(vote)
	tracker.trackWrite("vote", voteJSON)
	voteKey := fmt.Sprintf("JOINVOTE:%s:%s:%s", caId, proposalID, voterID)
	if err := ctx.GetStub().PutState(voteKey, voteJSON); err != nil {
		return err
	}

	proposal.VotersList = append(proposal.VotersList, voterID)
	if decision == "approve" {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}
	voteEvent := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "join",
		"action":       "member_join_voted",
		"proposalId":   proposalID,
		"candidateId":  proposal.CandidateID,
		"voterId":      voterID,
		"decision":     decision,
		"votesFor":     proposal.VotesFor,
		"votesAgainst": proposal.VotesAgainst,
	}
	proposalBytesForStorage, _ := json.Marshal(proposal)
	tracker.trackWrite("proposal", proposalBytesForStorage)
	tracker.applyToEventPayload(ctx, voteEvent)
	if eventBytes, err := json.Marshal(voteEvent); err == nil {
		_ = ctx.GetStub().SetEvent("MemberJoinVoted", eventBytes)
	}

	votesReceived := len(proposal.VotersList)
	quorumReached := hasNetworkWideApproval(votesReceived, totalAuthorized, ca.GovernanceParams.QuorumPercentage)

	if quorumReached {
		if err := validateMultiOrgVotes(proposal.VotersList); err != nil {
			proposalJSON, _ = json.Marshal(proposal)
			return ctx.GetStub().PutState(fmt.Sprintf("JOINREQ:%s:%s", caId, proposalID), proposalJSON)
		}

		if hasNetworkWideApproval(proposal.VotesFor, totalAuthorized, ca.GovernanceParams.ApprovalThreshold) {
			proposal.Status = "approved"
			if err := c.executeJoinApproval(ctx, caId, &proposal); err != nil {
				return err
			}
			proposal.Status = "executed"
		} else if !canStillReachNetworkWideApproval(
			proposal.VotesFor,
			votesReceived,
			totalAuthorized,
			ca.GovernanceParams.ApprovalThreshold,
		) {
			proposal.Status = "rejected"
		}
	}

	proposalJSON, _ = json.Marshal(proposal)
	return ctx.GetStub().PutState(fmt.Sprintf("JOINREQ:%s:%s", caId, proposalID), proposalJSON)
}

// finalizes an approved join proposal and updates CA membership on-chain
// Called by: (*DecentralizedPKIContract).VoteOnJoinRequest.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) executeJoinApproval(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposal *JoinRequestProposal,
) error {
	if err := c.assertNoActiveKeySession(ctx, "execute join approval"); err != nil {
		return err
	}
	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return err
	}

	if contains(ca.Members, proposal.CandidateID) {
		return nil
	}

	if err := validateMemberOrgLimit(ca.Members, proposal.CandidateID); err != nil {
		return err
	}

	oldMembers := append([]string(nil), ca.Members...)
	oldThreshold := ca.ThresholdParams.Threshold
	tracker := newStorageAttributionTracker("join", "member_join_approved", proposal.ProposalID, "")

	ca.Members = append(ca.Members, proposal.CandidateID)
	ca.Epoch++
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(
		len(ca.Members),
		ca.GovernanceParams.QuorumPercentage,
	)

	caJSON, _ := json.Marshal(ca)
	tracker.epoch = strconv.Itoa(ca.Epoch)
	tracker.trackWrite("ca_state", caJSON)
	if err := ctx.GetStub().PutState("CA:"+caId, caJSON); err != nil {
		return err
	}

	// Initiate reshare for the new member set
	if err := c.initiateReshare(ctx, ca.Epoch, "member_join_requested", proposal.CandidateID, oldMembers, oldThreshold, ca.Members, ca.ThresholdParams.Threshold); err != nil {
		return err
	}
	reshareState, _ := ctx.GetStub().GetState("RESHARE:" + strconv.Itoa(ca.Epoch))
	tracker.trackWrite("reshare_state", reshareState)

	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "join",
		"action":       "member_join_approved",
		"caId":         caId,
		"proposalId":   proposal.ProposalID,
		"candidate":    proposal.CandidateID,
		"epoch":        ca.Epoch,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("MemberJoinApproved", eventBytes)

	return nil
}

// lists Pending join requests from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ListPendingJoinRequests(
	ctx contractapi.TransactionContextInterface,
	caId string,
) (string, error) {
	startKey := fmt.Sprintf("JOINREQ:%s:", caId)
	endKey := fmt.Sprintf("JOINREQ:%s;", caId)
	iterator, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return "", err
	}
	defer iterator.Close()

	requests := make([]JoinRequestProposal, 0)
	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			continue
		}
		var r JoinRequestProposal
		if err := json.Unmarshal(result.Value, &r); err != nil {
			continue
		}
		if r.Status == "pending" {
			requests = append(requests, r)
		}
	}

	result, _ := json.Marshal(requests)
	return string(result), nil
}

// retrieves Node Role from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetNodeRole(
	ctx contractapi.TransactionContextInterface,
	caId string,
	nodeID string,
) (string, error) {
	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return "", fmt.Errorf("CA not found: %w", err)
	}

	if contains(ca.Members, nodeID) {
		return "full", nil
	}
	return "none", nil
}

// ===================== MEMBER REMOVAL =====================

// opens governance to remove a CA member
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ProposeRemoveMember(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposalID string,
	targetMemberID string,
	reason string,
) error {
	if targetMemberID == "" {
		return fmt.Errorf("target member ID cannot be empty")
	}
	submitterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return err
	}
	if err := c.assertNoActiveKeySession(ctx, "submit member removal proposal"); err != nil {
		return err
	}
	if err := c.assertNoPendingMembershipGovernance(ctx, caId, "submit member removal proposal"); err != nil {
		return err
	}
	if !contains(ca.Members, submitterID) {
		return fmt.Errorf("submitter not authorized")
	}
	if !contains(ca.Members, targetMemberID) {
		return fmt.Errorf("target is not a member of this CA")
	}
	if len(ca.Members) <= 2 {
		return fmt.Errorf("cannot remove member: would leave fewer than 2 members")
	}

	key := fmt.Sprintf("REMOVE:%s:%s", caId, proposalID)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("removal proposal %s already exists", proposalID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	submittedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	votingEndsAt := submittedAt.AddDate(0, 0, ca.GovernanceParams.VotingPeriodDays)

	proposal := MemberRemovalProposal{
		ProposalID:     proposalID,
		TargetMemberID: targetMemberID,
		Reason:         reason,
		SubmittedBy:    submitterID,
		CAID:           caId,
		SubmittedAt:    submittedAt,
		VotingEndsAt:   votingEndsAt,
		Status:         "pending",
		VotesFor:       0,
		VotesAgainst:   0,
		VotersList:     []string{},
	}

	proposalJSON, _ := json.Marshal(proposal)
	tracker := newStorageAttributionTracker("removal", "member_removal_proposed", proposalID, strconv.Itoa(ca.Epoch))
	tracker.trackWrite("proposal", proposalJSON)

	eventPayload := map[string]interface{}{
		"eventVersion":   2,
		"workflow":       "removal",
		"action":         "member_removal_proposed",
		"proposalId":     proposalID,
		"caId":           caId,
		"targetMemberId": targetMemberID,
		"submitterId":    submitterID,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	ev, _ := json.Marshal(eventPayload)
	_ = ctx.GetStub().SetEvent("MemberRemovalProposed", ev)

	return ctx.GetStub().PutState(key, proposalJSON)
}

// records member-removal votes so disruptive membership changes require explicit cross-member approval.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) VoteOnRemoveMember(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposalID string,
	decision string,
	rationale string,
) error {
	voterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}
	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("invalid decision")
	}

	key := fmt.Sprintf("REMOVE:%s:%s", caId, proposalID)
	proposalJSON, err := ctx.GetStub().GetState(key)
	if err != nil {
		return err
	}
	if proposalJSON == nil {
		return fmt.Errorf("removal proposal not found")
	}

	var proposal MemberRemovalProposal
	if err := json.Unmarshal(proposalJSON, &proposal); err != nil {
		return err
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	if currentTime.After(proposal.VotingEndsAt) {
		return fmt.Errorf("voting period ended")
	}
	if contains(proposal.VotersList, voterID) {
		return fmt.Errorf("already voted")
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return err
	}
	if err := c.assertNoActiveKeySession(ctx, "vote on member removal proposal"); err != nil {
		return err
	}
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}
	tracker := newStorageAttributionTracker("removal", "member_removal_voted", proposalID, strconv.Itoa(ca.Epoch))
	if !contains(ca.Members, voterID) {
		return fmt.Errorf("voter not authorized")
	}

	vote := Vote{
		VoterID:   voterID,
		Decision:  decision,
		Timestamp: currentTime,
		Rationale: rationale,
	}
	voteJSON, _ := json.Marshal(vote)
	tracker.trackWrite("vote", voteJSON)
	voteKey := fmt.Sprintf("REMOVEVOTE:%s:%s:%s", caId, proposalID, voterID)
	if err := ctx.GetStub().PutState(voteKey, voteJSON); err != nil {
		return err
	}

	proposal.VotersList = append(proposal.VotersList, voterID)
	if decision == "approve" {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}
	voteEvent := map[string]interface{}{
		"eventVersion":   2,
		"workflow":       "removal",
		"action":         "member_removal_voted",
		"proposalId":     proposalID,
		"caId":           caId,
		"targetMemberId": proposal.TargetMemberID,
		"voterId":        voterID,
		"decision":       decision,
		"votesFor":       proposal.VotesFor,
		"votesAgainst":   proposal.VotesAgainst,
	}
	proposalBytesForStorage, _ := json.Marshal(proposal)
	tracker.trackWrite("proposal", proposalBytesForStorage)
	tracker.applyToEventPayload(ctx, voteEvent)
	if eventBytes, err := json.Marshal(voteEvent); err == nil {
		_ = ctx.GetStub().SetEvent("MemberRemovalVoted", eventBytes)
	}

	votesReceived := len(proposal.VotersList)
	quorumReached := hasNetworkWideApproval(votesReceived, totalAuthorized, ca.GovernanceParams.QuorumPercentage)

	if quorumReached {
		if err := validateMultiOrgVotes(proposal.VotersList); err != nil {
			proposalJSON, _ = json.Marshal(proposal)
			return ctx.GetStub().PutState(key, proposalJSON)
		}

		if hasNetworkWideApproval(proposal.VotesFor, totalAuthorized, ca.GovernanceParams.ApprovalThreshold) {
			proposal.Status = "approved"
			if err := c.executeMemberRemoval(ctx, caId, &proposal); err != nil {
				return err
			}
			proposal.Status = "executed"
		} else if !canStillReachNetworkWideApproval(
			proposal.VotesFor,
			votesReceived,
			totalAuthorized,
			ca.GovernanceParams.ApprovalThreshold,
		) {
			proposal.Status = "rejected"
		}
	}

	proposalJSON, _ = json.Marshal(proposal)
	return ctx.GetStub().PutState(key, proposalJSON)
}

// applies an approved member removal and triggers reshare prerequisites so threshold remains valid after membership change.
// Called by: (*DecentralizedPKIContract).VoteOnRemoveMember.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) executeMemberRemoval(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposal *MemberRemovalProposal,
) error {
	tracker := newStorageAttributionTracker("removal", "member_removed", proposal.ProposalID, "")
	if err := c.assertNoActiveKeySession(ctx, "execute member removal"); err != nil {
		return err
	}
	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return err
	}
	if !contains(ca.Members, proposal.TargetMemberID) {
		return fmt.Errorf("target is not a member of this CA")
	}
	if len(ca.Members) <= 2 {
		return fmt.Errorf("cannot remove member: would leave fewer than 2 members")
	}

	oldMembers := append([]string(nil), ca.Members...)
	oldThreshold := ca.ThresholdParams.Threshold

	// Exclude the removed member from the old committee
	// cannot block reshare if t+1 is still achievable.
	oldReshareMembers := make([]string, 0, len(oldMembers)-1)
	for _, member := range oldMembers {
		if member != proposal.TargetMemberID {
			oldReshareMembers = append(oldReshareMembers, member)
		}
	}
	if len(oldReshareMembers) <= oldThreshold {
		return fmt.Errorf("cannot reshare after removal: remaining old committee (%d) cannot satisfy threshold %d; consider ForceFreshDKG", len(oldReshareMembers), oldThreshold)
	}

	newMembers := make([]string, 0, len(ca.Members)-1)
	for _, m := range ca.Members {
		if m != proposal.TargetMemberID {
			newMembers = append(newMembers, m)
		}
	}
	ca.Members = newMembers

	ca.Epoch++
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(
		len(ca.Members),
		ca.GovernanceParams.QuorumPercentage,
	)

	caJSON, _ := json.Marshal(ca)
	tracker.epoch = strconv.Itoa(ca.Epoch)
	tracker.trackWrite("ca_state", caJSON)
	if err := ctx.GetStub().PutState("CA:"+caId, caJSON); err != nil {
		return err
	}

	if err := c.initiateReshare(ctx, ca.Epoch, "member_removed", proposal.TargetMemberID, oldReshareMembers, oldThreshold, ca.Members, ca.ThresholdParams.Threshold); err != nil {
		return err
	}
	reshareState, _ := ctx.GetStub().GetState("RESHARE:" + strconv.Itoa(ca.Epoch))
	tracker.trackWrite("reshare_state", reshareState)

	eventPayload := map[string]interface{}{
		"eventVersion":   2,
		"workflow":       "removal",
		"action":         "member_removed",
		"proposalId":     proposal.ProposalID,
		"caId":           caId,
		"targetMemberId": proposal.TargetMemberID,
		"epoch":          ca.Epoch,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("MemberRemoved", eventBytes)

	return nil
}

// lists Pending Remove Member Proposals from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ListPendingRemoveMemberProposals(
	ctx contractapi.TransactionContextInterface,
	caId string,
) (string, error) {
	startKey := fmt.Sprintf("REMOVE:%s:", caId)
	endKey := fmt.Sprintf("REMOVE:%s;", caId)
	iterator, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return "", err
	}
	defer iterator.Close()

	proposals := make([]MemberRemovalProposal, 0)
	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			continue
		}
		var p MemberRemovalProposal
		if err := json.Unmarshal(result.Value, &p); err != nil {
			continue
		}
		if p.Status == "pending" {
			proposals = append(proposals, p)
		}
	}

	result, _ := json.Marshal(proposals)
	return string(result), nil
}

// ===================== CSR SUBMISSION & VOTING =====================

// validates and stores a CSR proposal so certificate issuance starts from an authenticated request with proof-of-possession.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) SubmitCSR(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	csrPEM string,
) error {
	memberID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	cert, certPEM, err := getClientCert(ctx)
	if err != nil {
		return err
	}
	role, err := getClientRole(ctx, cert)
	if err != nil {
		return err
	}

	exists, err := c.ProposalExists(ctx, proposalID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("proposal %s already exists", proposalID)
	}

	if len(csrPEM) < 100 {
		return fmt.Errorf("invalid CSR format")
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		return fmt.Errorf("invalid CSR PEM encoding")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("invalid CSR parse: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("invalid CSR signature: %w", err)
	}

	// prevent duplicate active certificate per identity
	activeCertKey, _ := ctx.GetStub().GetState("ACTIVECERT:" + memberID)
	if activeCertKey != nil {
		certJSON, _ := ctx.GetStub().GetState("CERT:" + string(activeCertKey))
		if certJSON != nil {
			var existingCert Certificate
			if err := json.Unmarshal(certJSON, &existingCert); err == nil {
				if !existingCert.IsRevoked {
					return fmt.Errorf("identity already has an active certificate (revoke it first)")
				}
			}
		}
	}

	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	submittedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	votingEndsAt := submittedAt.AddDate(0, 0, ca.GovernanceParams.VotingPeriodDays)

	if err := validateCertAtTime(cert, submittedAt); err != nil {
		return err
	}
	// Actual proposal
	proposal := CSRProposal{
		ProposalID:    proposalID,
		SubmitterID:   memberID,
		CSRData:       csrPEM,
		SubmitterRole: role,
		SubmitterCert: certPEM,
		SubmittedAt:   submittedAt,
		VotingEndsAt:  votingEndsAt,
		Status:        "pending",
		VotesFor:      0,
		VotesAgainst:  0,
		VotersList:    []string{},
	}

	proposalJSON, _ := json.Marshal(proposal)
	tracker := newStorageAttributionTracker("csr", "csr_submitted", proposalID, strconv.Itoa(ca.Epoch))
	tracker.trackWrite("proposal", proposalJSON)

	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "csr",
		"action":       "csr_submitted",
		"proposalId":   proposalID,
		"submitterId":  memberID,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	ev, _ := json.Marshal(eventPayload)
	_ = ctx.GetStub().SetEvent("CSRSubmitted", ev)

	return ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON)
}

// records governance votes for CSR proposals so certificate signing only starts after policy-compliant approval.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) VoteOnCSR(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	decision string, // "approve"/"reject"
	rationale string,
) error {

	// Get voter identity
	voterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get voter identity: %v", err)
	}
	// Validate decision
	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("invalid decision: must be 'approve' or 'reject'")
	}

	// Get proposal
	proposal, err := c.GetCSRProposal(ctx, proposalID)
	if err != nil {
		return err
	}
	if proposal.Status != "pending" {
		return fmt.Errorf("CSR proposal %s is not pending (status=%s)", proposalID, proposal.Status)
	}

	// Check if voting period ended
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	if currentTime.After(proposal.VotingEndsAt) {
		return fmt.Errorf("voting period has ended")
	}

	// Check if already voted
	if contains(proposal.VotersList, voterID) {
		return fmt.Errorf("voter %s has already voted", voterID)
	}

	// Verify voter is authorized (CA-Member)
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}
	tracker := newStorageAttributionTracker("csr", "csr_voted", proposalID, strconv.Itoa(ca.Epoch))

	if !contains(ca.Members, voterID) {
		return fmt.Errorf("voter %s is not authorized", voterID)
	}

	if decision == "approve" {
		submitterCert, err := parseCertFromPEM(proposal.SubmitterCert)
		if err != nil {
			return fmt.Errorf("proposal missing valid submitter certificate: %v", err)
		}
		if err := validateCertAtTime(submitterCert, currentTime); err != nil {
			return err
		}
		role := strings.ToLower(strings.TrimSpace(proposal.SubmitterRole))
		if role == "" {
			role = roleFromCert(submitterCert)
		}
		if role != "observer" && role != "member" {
			return fmt.Errorf("submitter role not authorized for CSR approval")
		}
	}

	// Record vote
	vote := Vote{
		VoterID:   voterID,
		Decision:  decision,
		Timestamp: currentTime,
		Rationale: rationale,
	}

	voteJSON, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	tracker.trackWrite("vote", voteJSON)

	// Store vote
	voteKey := fmt.Sprintf("VOTE:%s:%s", proposalID, voterID)
	if err := ctx.GetStub().PutState(voteKey, voteJSON); err != nil {
		return err
	}

	// Update proposal vote counts
	proposal.VotersList = append(proposal.VotersList, voterID)
	if decision == "approve" {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}
	voteEvent := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "csr",
		"action":       "csr_voted",
		"proposalId":   proposalID,
		"submitterId":  proposal.SubmitterID,
		"voterId":      voterID,
		"decision":     decision,
		"votesFor":     proposal.VotesFor,
		"votesAgainst": proposal.VotesAgainst,
	}
	proposalBytesForStorage, _ := json.Marshal(proposal)
	tracker.trackWrite("proposal", proposalBytesForStorage)
	tracker.applyToEventPayload(ctx, voteEvent)
	if eventBytes, err := json.Marshal(voteEvent); err == nil {
		_ = ctx.GetStub().SetEvent("CSRVoted", eventBytes)
	}

	// Check if quorum reached
	votesReceived := len(proposal.VotersList)
	quorumReached := hasNetworkWideApproval(votesReceived, totalAuthorized, ca.GovernanceParams.QuorumPercentage)

	if quorumReached {
		// SECURITY: Check multi-org voting requirement before execution
		if err := validateMultiOrgVotes(proposal.VotersList); err != nil {
			// Not enough org diversity yet, save vote and wait for more
			proposalJSON, _ := json.Marshal(proposal)
			return ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON)
		}

		// Approval is evaluated against all authorized members
		if hasNetworkWideApproval(proposal.VotesFor, totalAuthorized, ca.GovernanceParams.ApprovalThreshold) {
			proposal.Status = "approved"

			// Automatically initiate signing session
			if err := c.initiateSigningSession(ctx, proposal); err != nil {
				return err
			}
			signingState, _ := ctx.GetStub().GetState("SIGNING:" + proposalID)
			tracker.trackWrite("signing_state", signingState)
		} else if !canStillReachNetworkWideApproval(
			proposal.VotesFor,
			votesReceived,
			totalAuthorized,
			ca.GovernanceParams.ApprovalThreshold,
		) {
			proposal.Status = "rejected"
		}
	}

	// Save updated proposal
	proposalJSON, err := json.Marshal(proposal)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON)
}

// ===================== REVOCATION =====================

// creates a revocation proposal for an active certificate
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ProposeRevocation(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	targetNodeID string,
	reason string,
) error {
	if err := ensureCanonicalID(targetNodeID); err != nil {
		return err
	}
	submitterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	cert, _, err := getClientCert(ctx)
	if err != nil {
		return err
	}
	role, err := getClientRole(ctx, cert)
	if err != nil {
		return err
	}
	if role != "observer" && role != "member" {
		return fmt.Errorf("certificate role not authorized to propose revocation")
	}

	// Look up active cert
	activeCertKey, err := ctx.GetStub().GetState("ACTIVECERT:" + targetNodeID)
	if err != nil {
		return err
	}
	if activeCertKey == nil {
		return fmt.Errorf("target has no certificate")
	}
	certJSON, err := ctx.GetStub().GetState("CERT:" + string(activeCertKey))
	if err != nil {
		return err
	}
	if certJSON == nil {
		return fmt.Errorf("target has no certificate")
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	submittedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	votingEndsAt := submittedAt.AddDate(0, 0, ca.GovernanceParams.VotingPeriodDays)

	if err := validateCertAtTime(cert, submittedAt); err != nil {
		return err
	}

	revocation := RevocationProposal{
		ProposalID:   proposalID,
		TargetNodeID: targetNodeID,
		Reason:       reason,
		SubmittedBy:  submitterID,
		SubmittedAt:  submittedAt,
		VotingEndsAt: votingEndsAt,
		Status:       "pending",
		VotesFor:     0,
		VotesAgainst: 0,
		VotersList:   []string{},
	}

	revocationJSON, err := json.Marshal(revocation)
	if err != nil {
		return err
	}
	tracker := newStorageAttributionTracker("revocation", "revocation_proposed", proposalID, strconv.Itoa(ca.Epoch))
	tracker.trackWrite("proposal", revocationJSON)

	// Emit event
	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "revocation",
		"action":       "revocation_proposed",
		"proposalId":   proposalID,
		"nodeId":       targetNodeID,
		"reason":       reason,
		"epoch":        ca.Epoch,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RevocationProposed", eventBytes)

	return ctx.GetStub().PutState("REVOKE:"+proposalID, revocationJSON)
}

// records revocation decisions so certificate invalidation requires quorum-backed approval.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) VoteOnRevocation(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	decision string,
	rationale string,
) error {
	voterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("invalid decision")
	}

	// Get revocation proposal
	revocationJSON, err := ctx.GetStub().GetState("REVOKE:" + proposalID)
	if err != nil {
		return err
	}
	if revocationJSON == nil {
		return fmt.Errorf("revocation proposal not found")
	}

	var revocation RevocationProposal
	if err := json.Unmarshal(revocationJSON, &revocation); err != nil {
		return err
	}

	// Check voting period
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	currentTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	if currentTime.After(revocation.VotingEndsAt) {
		return fmt.Errorf("voting period ended")
	}

	// Check if already voted
	if contains(revocation.VotersList, voterID) {
		return fmt.Errorf("already voted")
	}

	// Verify voter is authorized
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}
	tracker := newStorageAttributionTracker("revocation", "revocation_voted", proposalID, strconv.Itoa(ca.Epoch))
	if !contains(ca.Members, voterID) {
		return fmt.Errorf("voter not authorized")
	}

	// Record vote
	vote := Vote{
		VoterID:   voterID,
		Decision:  decision,
		Timestamp: currentTime,
		Rationale: rationale,
	}

	voteJSON, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	tracker.trackWrite("vote", voteJSON)

	voteKey := fmt.Sprintf("REVOKEVOTE:%s:%s", proposalID, voterID)
	if err := ctx.GetStub().PutState(voteKey, voteJSON); err != nil {
		return err
	}

	// Update counts
	revocation.VotersList = append(revocation.VotersList, voterID)
	if decision == "approve" {
		revocation.VotesFor++
	} else {
		revocation.VotesAgainst++
	}
	voteEvent := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "revocation",
		"action":       "revocation_voted",
		"proposalId":   proposalID,
		"nodeId":       revocation.TargetNodeID,
		"voterId":      voterID,
		"decision":     decision,
		"votesFor":     revocation.VotesFor,
		"votesAgainst": revocation.VotesAgainst,
	}
	revocationBytesForStorage, _ := json.Marshal(revocation)
	tracker.trackWrite("proposal", revocationBytesForStorage)
	tracker.applyToEventPayload(ctx, voteEvent)
	if eventBytes, err := json.Marshal(voteEvent); err == nil {
		_ = ctx.GetStub().SetEvent("RevocationVoted", eventBytes)
	}

	// Check quorum
	votesReceived := len(revocation.VotersList)
	quorumReached := hasNetworkWideApproval(votesReceived, totalAuthorized, ca.GovernanceParams.QuorumPercentage)

	if quorumReached {
		if hasNetworkWideApproval(revocation.VotesFor, totalAuthorized, ca.GovernanceParams.ApprovalThreshold) {
			revocation.Status = "approved"

			// Execute revocation immediately
			if err := c.executeRevocation(ctx, &revocation); err != nil {
				return err
			}
		} else if !canStillReachNetworkWideApproval(
			revocation.VotesFor,
			votesReceived,
			totalAuthorized,
			ca.GovernanceParams.ApprovalThreshold,
		) {
			revocation.Status = "rejected"
		}
	}

	revocationJSON, err = json.Marshal(revocation)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("REVOKE:"+proposalID, revocationJSON)
}

// marks a certificate revoked and updates related indexes so revocation state is enforceable across queries and checks.
// Called by: (*DecentralizedPKIContract).VoteOnRevocation.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) executeRevocation(
	ctx contractapi.TransactionContextInterface,
	revocation *RevocationProposal,
) error {
	tracker := newStorageAttributionTracker("revocation", "certificate_revoked", revocation.ProposalID, "")
	// Look up active cert
	activeCertKey, err := ctx.GetStub().GetState("ACTIVECERT:" + revocation.TargetNodeID)
	if err != nil {
		return err
	}
	if activeCertKey == nil {
		return fmt.Errorf("no active certificate for member")
	}

	certJSON, err := ctx.GetStub().GetState("CERT:" + string(activeCertKey))
	if err != nil {
		return err
	}

	var cert Certificate
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return err
	}

	// Mark as revoked
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	revokedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	cert.IsRevoked = true
	cert.Status = "revoked"
	cert.RevokedAt = revokedAt

	reason := revocation.Reason
	cert.RevocationReason = reason

	certJSON, err = json.Marshal(cert)
	if err != nil {
		return err
	}
	tracker.trackWrite("certificate", certJSON)
	// Store revoked cert at its original key (CERT:<proposalID>)
	if err := ctx.GetStub().PutState("CERT:"+string(activeCertKey), certJSON); err != nil {
		return err
	}

	// Clear active cert index â€” allows member to request a new certificate
	tracker.trackDelete("active_index", activeCertKey)
	if err := ctx.GetStub().DelState("ACTIVECERT:" + revocation.TargetNodeID); err != nil {
		return err
	}

	// Update Merkle tree of active certificates (revoked cert removed)
	if err := c.updateCertificateMerkleTree(ctx, "certificate_revoked", cert.CertID, cert.CertificateHash, true); err != nil {
		fmt.Printf("Warning: failed to update Merkle tree after revocation: %v\n", err)
	} else {
		merkleState, _ := ctx.GetStub().GetState("MERKLE:CERTS")
		tracker.trackWrite("merkle_state", merkleState)
	}

	// Update revocation status
	revocation.Status = "executed"

	// Emit event
	ca, _ := c.GetDistributedCA(ctx, DefaultCAID)
	epochStr := "0"
	if ca != nil {
		epochStr = strconv.Itoa(ca.Epoch)
	}
	tracker.epoch = epochStr
	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "revocation",
		"action":       "certificate_revoked",
		"proposalId":   revocation.ProposalID,
		"nodeId":       revocation.TargetNodeID,
		"reason":       revocation.Reason,
		"epoch":        epochStr,
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("NodeRevoked", eventBytes)

	return nil
}

// ===================== CA INITIALIZATION =====================

// creates the root distributed CA state so all later governance and certificate operations share a baseline.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) InitializeDistributedCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
	name string,
	threshold int,
	initialPublicKey string,
) error {
	exists, err := c.CAExists(ctx, caID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("CA %s already exists", caID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	createdAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	ca := DistributedCA{
		CAID:      caID,
		Name:      name,
		PublicKey: initialPublicKey,
		PartySalt: "",
		ThresholdParams: ThresholdParameters{
			Threshold:  threshold,
			TotalNodes: 0,
			Scheme:     "ECDSA-TSS",
		},
		CreatedAt: createdAt,
		IsActive:  true,
		Members:   []string{},
		GovernanceParams: GovernanceParameters{
			VotingPeriodDays:  7,
			QuorumPercentage:  51,
			ApprovalThreshold: 51,
		},
	}

	caJSON, err := json.Marshal(ca)
	if err != nil {
		return fmt.Errorf("failed to marshal CA: %v", err)
	}

	return ctx.GetStub().PutState("CA:"+caID, caJSON)
}

// retrieves trusted CA from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetTrustedCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
) (*DistributedCA, error) {
	return c.GetDistributedCA(ctx, caID)
}

// adds an initial trusted member and starts key-session orchestration so the CA can become operational
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) BootstrapJoinCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
	bootstrapLimit int,
) error {
	memberID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}
	cert, _, err := getClientCert(ctx)
	if err != nil {
		return err
	}
	role, err := getClientRole(ctx, cert)
	if err != nil {
		return err
	}
	if role != "member" {
		return fmt.Errorf("certificate role not eligible for bootstrap join")
	}

	ca, err := c.GetDistributedCA(ctx, caID)
	if err != nil {
		return err
	}

	if contains(ca.Members, memberID) {
		return nil
	}

	if len(ca.Members) >= bootstrapLimit {
		return fmt.Errorf("bootstrap closed: %d members already joined", len(ca.Members))
	}

	oldMembers := append([]string(nil), ca.Members...)
	oldThreshold := ca.ThresholdParams.Threshold

	ca.Members = append(ca.Members, memberID)
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(
		len(ca.Members),
		ca.GovernanceParams.QuorumPercentage,
	)
	ca.Epoch++

	b, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caID, b); err != nil {
		return err
	}

	// existing DKG if present
	existingDKG, _ := ctx.GetStub().GetState("DKG:0")
	createdDKG := false

	// Start DKG (when not public key set yet and at least two members)
	if len(ca.Members) >= 2 && ca.PublicKey == "" {
		// Check existing DKG (to prevent conflicts with multiple sessions)
		if existingDKG == nil {

			txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
			initiatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

			dkgSession := map[string]interface{}{
				"epoch":       0,
				"reason":      "initial_dkg",
				"members":     ca.Members,
				"threshold":   ca.ThresholdParams.Threshold,
				"status":      "initiated",
				"ackCount":    0,
				"ackedBy":     []string{},
				"initiatedAt": initiatedAt,
			}

			sessionJSON, _ := json.Marshal(dkgSession)
			ctx.GetStub().PutState("DKG:0", sessionJSON)

			// Event with full payload
			eventPayload := map[string]interface{}{
				"eventVersion": 2,
				"workflow":     "dkg",
				"action":       "dkg_initiated",
				"epoch":        0,
				"members":      ca.Members,
				"threshold":    ca.ThresholdParams.Threshold,
			}
			eventBytes, _ := json.Marshal(eventPayload)
			ctx.GetStub().SetEvent("DKGInitiated", eventBytes)
			createdDKG = true
		}
	}

	// If a session or pub-key exists trigger reshare instead of fresh DKG
	if !createdDKG && (existingDKG != nil || ca.PublicKey != "") {
		// Avoid duplicating a reshare for the same epoch
		reshareKey := "RESHARE:" + strconv.Itoa(ca.Epoch)
		if existingReshare, _ := ctx.GetStub().GetState(reshareKey); existingReshare == nil {
			_ = c.initiateReshare(ctx, ca.Epoch, "member_join_bootstrap", memberID, oldMembers, oldThreshold, ca.Members, ca.ThresholdParams.Threshold)
		}
	}

	return nil
}

// ===================== DKG & RESHARE MANAGEMENT =====================

// starts a distributed key-generation session
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) InitiateDKG(
	ctx contractapi.TransactionContextInterface,
	caID string,
) error {
	memberID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caID)
	if err != nil {
		return err
	}

	// CA member?
	if !contains(ca.Members, memberID) {
		return fmt.Errorf("only CA members can initiate DKG")
	}

	// DKG already present or completed?
	if ca.PublicKey != "" {
		return fmt.Errorf("DKG already completed; public key is set")
	}
	if dkgStatus, err := c.getActiveDKGStatus(ctx); err != nil {
		return err
	} else if dkgStatus != "" {
		return fmt.Errorf("DKG already in progress with status %s", dkgStatus)
	}
	if reshare, err := c.getLatestActiveReshareSession(ctx); err != nil {
		return err
	} else if reshare != nil {
		return fmt.Errorf("cannot initiate DKG while reshare epoch %d is %s", reshare.Epoch, reshare.Status)
	}

	// Create DKG session (epoch 0 for initial DKG)
	completionRequiredAcks := len(ca.Members)
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	initiatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	dkgSession := map[string]interface{}{
		"epoch":                  0,
		"reason":                 "initial_dkg",
		"members":                ca.Members,
		"threshold":              ca.ThresholdParams.Threshold,
		"completionRequiredAcks": completionRequiredAcks,
		"status":                 "initiated",
		"initiatedAt":            initiatedAt,
	}

	sessionJSON, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}

	// Store session
	if err := ctx.GetStub().PutState("DKG:0", sessionJSON); err != nil {
		return err
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "dkg",
		"action":       "dkg_initiated",
		"epoch":        0,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("DKGInitiated", eventBytes)

	return nil
}

// rotates into a fresh DKG epoch so the network can recover safely from stale or blocked key-management sessions
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ForceFreshDKG(
	ctx contractapi.TransactionContextInterface,
	caID string,
	reason string,
) error {
	memberID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caID)
	if err != nil {
		return err
	}

	if !contains(ca.Members, memberID) {
		return fmt.Errorf("only CA members can force a fresh DKG")
	}
	if dkgStatus, err := c.getActiveDKGStatus(ctx); err != nil {
		return err
	} else if dkgStatus != "" {
		return fmt.Errorf("cannot force fresh DKG while DKG session is %s", dkgStatus)
	}
	if err := c.assertNoPendingMembershipGovernance(ctx, caID, "force fresh DKG"); err != nil {
		return err
	}

	if reason == "" {
		reason = "fresh_dkg"
	}

	// Override current stuck session
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	supersedeAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	iter, err := ctx.GetStub().GetStateByRange("RESHARE:", "RESHARE;")
	if err == nil {
		defer iter.Close()
		for iter.HasNext() {
			kv, err := iter.Next()
			if err != nil {
				return err
			}
			var sess ReshareSession
			if err := json.Unmarshal(kv.Value, &sess); err != nil {
				continue
			}
			if sess.Status == "completed" || sess.Status == "superseded" {
				continue
			}
			sess.Status = "superseded"
			sess.CompletedAt = supersedeAt
			sess.SupersededAt = supersedeAt
			sess.SupersededBy = ca.Epoch + 1
			kvBytes, err := json.Marshal(sess)
			if err == nil {
				_ = ctx.GetStub().PutState(kv.Key, kvBytes)
			}
		}
	}

	// Reset CA
	ca.PublicKey = ""
	ca.PartySalt = ""
	ca.Epoch++
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(len(ca.Members), ca.GovernanceParams.QuorumPercentage)

	caJSON, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caID, caJSON); err != nil {
		return err
	}

	initiatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	dkgSession := map[string]interface{}{
		"epoch":                  0,
		"reason":                 reason,
		"members":                ca.Members,
		"threshold":              ca.ThresholdParams.Threshold,
		"completionRequiredAcks": len(ca.Members),
		"status":                 "initiated",
		"ackCount":               0,
		"ackedBy":                []string{},
		"initiatedAt":            initiatedAt,
	}

	sessionJSON, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("DKG:0", sessionJSON); err != nil {
		return err
	}

	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "dkg",
		"action":       "fresh_dkg_initiated",
		"epoch":        0,
		"members":      ca.Members,
		"threshold":    ca.ThresholdParams.Threshold,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("DKGInitiated", eventBytes)

	return nil
}

// retrieves DKG Session from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetDKGSession(
	ctx contractapi.TransactionContextInterface,
	epochStr string,
) (string, error) {
	dkgKey := "DKG:" + epochStr
	dkgBytes, err := ctx.GetStub().GetState(dkgKey)
	if err != nil {
		return "", fmt.Errorf("failed to read DKG session: %v", err)
	}
	if dkgBytes == nil {
		return "", fmt.Errorf("DKG session not found for epoch %s", epochStr)
	}
	return string(dkgBytes), nil
}

// records a member acknowledgement for the active DKG session
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) AcknowledgeDKG(
	ctx contractapi.TransactionContextInterface,
	epochStr string,
) error {
	nodeID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	// Get DKG session
	dkgKey := "DKG:" + epochStr
	dkgBytes, err := ctx.GetStub().GetState(dkgKey)
	if err != nil {
		return err
	}
	if dkgBytes == nil {
		return fmt.Errorf("DKG session not found for epoch %s", epochStr)
	}

	var dkgSession map[string]interface{}
	if err := json.Unmarshal(dkgBytes, &dkgSession); err != nil {
		return err
	}

	membersRaw, _ := dkgSession["members"].([]interface{})
	members := make([]string, 0, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}

	// Is member?
	if !contains(members, nodeID) {
		return fmt.Errorf("node %s is not a member of this DKG session", nodeID)
	}
	if len(members) == 0 {
		return fmt.Errorf("DKG session has no members")
	}

	// Ack list
	ackedByRaw, _ := dkgSession["ackedBy"].([]interface{})
	ackedBy := make([]string, 0, len(ackedByRaw))
	for _, a := range ackedByRaw {
		if s, ok := a.(string); ok {
			ackedBy = append(ackedBy, s)
		}
	}

	// Guard double acking
	if contains(ackedBy, nodeID) {
		return nil
	}

	status, _ := dkgSession["status"].(string)
	// Check for already completed ack stages
	if status == "ready" || status == "proposed" || status == "completed" {
		return nil
	}
	if status != "initiated" {
		return fmt.Errorf("DKG session not in initiated state, current status: %s", status)
	}

	// Add ack
	ackedBy = append(ackedBy, nodeID)
	dkgSession["ackedBy"] = ackedBy
	dkgSession["ackCount"] = len(ackedBy)

	// All acknowledged?
	required := len(members)
	if len(ackedBy) >= required {
		dkgSession["status"] = "ready"

		// Emit event
		epoch, _ := strconv.Atoi(epochStr)
		eventPayload := map[string]interface{}{
			"eventVersion": 2,
			"workflow":     "dkg",
			"action":       "dkg_ready",
			"epoch":        epoch,
			"members":      members,
		}
		eventBytes, _ := json.Marshal(eventPayload)
		ctx.GetStub().SetEvent("DKGReady", eventBytes)
	}

	// Save update
	updatedBytes, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(dkgKey, updatedBytes)
}

// commits the agreed CA public key for an epoch so threshold signing can later proceed against a single authoritative key.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) CompleteDKG(
	ctx contractapi.TransactionContextInterface,
	epochStr string,
	publicKey string,
) error {
	nodeID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	// Get session
	dkgKey := "DKG:" + epochStr
	dkgBytes, err := ctx.GetStub().GetState(dkgKey)
	if err != nil {
		return err
	}
	if dkgBytes == nil {
		return fmt.Errorf("DKG session not found for epoch %s", epochStr)
	}

	var dkgSession map[string]interface{}
	if err := json.Unmarshal(dkgBytes, &dkgSession); err != nil {
		return err
	}

	status, _ := dkgSession["status"].(string)

	// Member?
	membersRaw, _ := dkgSession["members"].([]interface{})
	members := make([]string, 0, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}

	if !contains(members, nodeID) {
		return fmt.Errorf("node %s is not a member of this DKG session", nodeID)
	}
	if len(members) == 0 {
		return fmt.Errorf("DKG session has no members")
	}

	existingPubKey, _ := dkgSession["publicKey"].(string)
	// Already finalized?
	if status == "completed" {
		// Wrong public key? To prevent a malicous issuance of a wrong key
		if existingPubKey != "" && existingPubKey != publicKey {
			return fmt.Errorf("public key mismatch for completed DKG")
		}
		return nil
	}
	if status != "ready" && status != "proposed" {
		return fmt.Errorf("DKG session not in ready/proposed state, current status: %s", status)
	}

	// Record and verify public key
	if existingPubKey == "" {
		dkgSession["publicKey"] = publicKey
	} else if existingPubKey != publicKey {
		return fmt.Errorf("public key mismatch for DKG completion proposal")
	}

	// Track acknowledgements
	completionAckedRaw, _ := dkgSession["completionAckedBy"].([]interface{})
	completionAckedBy := make([]string, 0, len(completionAckedRaw))
	for _, a := range completionAckedRaw {
		if s, ok := a.(string); ok {
			completionAckedBy = append(completionAckedBy, s)
		}
	}
	if !contains(completionAckedBy, nodeID) {
		completionAckedBy = append(completionAckedBy, nodeID)
	}
	dkgSession["completionAckedBy"] = completionAckedBy
	dkgSession["completionAckCount"] = len(completionAckedBy)

	requiredAcks := len(members)
	dkgSession["completionRequiredAcks"] = requiredAcks

	if len(completionAckedBy) < requiredAcks {
		if status == "ready" {
			dkgSession["status"] = "proposed"
		}
		updatedBytes, err := json.Marshal(dkgSession)
		if err != nil {
			return err
		}
		if err := ctx.GetStub().PutState(dkgKey, updatedBytes); err != nil {
			return err
		}
		// Emit event
		eventPayload := map[string]interface{}{
			"eventVersion": 2,
			"workflow":     "dkg",
			"action":       "dkg_completion_proposed",
			"epoch":        epochStr,
			"publicKey":    dkgSession["publicKey"],
			"ackCount":     len(completionAckedBy),
			"requiredAcks": requiredAcks,
		}
		if eventBytes, err := json.Marshal(eventPayload); err == nil {
			ctx.GetStub().SetEvent("DKGCompletionProposed", eventBytes)
		}
		return nil
	}

	// Required acknowledgements received
	dkgSession["status"] = "completed"
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	completedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	dkgSession["completedAt"] = completedAt

	// Save updates
	updatedBytes, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(dkgKey, updatedBytes); err != nil {
		return err
	}

	// Update the CA
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}
	ca.PublicKey = publicKey
	ca.PartySalt = ""
	caBytes, err := json.Marshal(ca)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("CA:"+DefaultCAID, caBytes); err != nil {
		return err
	}

	// Emit completion event
	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "dkg",
		"action":       "dkg_completed",
		"epoch":        epochStr,
		"publicKey":    publicKey,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("DKGCompleted", eventBytes)

	return nil
}

// ===================== Helpers for DKG =====================

// derives normalized reshare session values
// Called by: (*DecentralizedPKIContract).GetReshareSession, (*DecentralizedPKIContract).getLatestActiveReshareSession.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func normalizeReshareSession(reshare *ReshareSession) {
	if reshare == nil {
		return
	}
	if len(reshare.OldNodeSet) == 0 && len(reshare.NewNodeSet) > 0 {
		reshare.OldNodeSet = append([]string(nil), reshare.NewNodeSet...)
	}
	if reshare.OldThreshold == 0 && reshare.NewThreshold > 0 {
		reshare.OldThreshold = reshare.NewThreshold
	}
	if reshare.CompletionAckedBy == nil {
		reshare.CompletionAckedBy = []string{}
	}
	if reshare.CompletionAckCount == 0 && len(reshare.CompletionAckedBy) > 0 {
		reshare.CompletionAckCount = len(reshare.CompletionAckedBy)
	}
	// Ensure fields are present even for legacy sessions where they were omitted.
	if reshare.SupersededBy == 0 {
		reshare.SupersededBy = -1
	}
	if strings.TrimSpace(reshare.SupersededAt) == "" {
		reshare.SupersededAt = "n/a"
	}
}

// derives salt values
// Called by: (*DecentralizedPKIContract).initiateReshare.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func nextPartySalt(current string) string {
	cur := strings.TrimSpace(current)
	if cur == "" {
		return "new"
	}
	if cur == "new" {
		return ""
	}
	return "new"
}

// evaluates whether a dkg is running
// Called by: (*DecentralizedPKIContract).getActiveDKGStatus.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func isActiveDKGStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "initiated", "ready", "proposed":
		return true
	default:
		return false
	}
}

// evaluates whether a reshare is running
// Called by: (*DecentralizedPKIContract).getLatestActiveReshareSession.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func isActiveReshareStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "initiated", "acknowledged", "proposed":
		return true
	default:
		return false
	}
}

// retrieves the active DKG from world state
// Called by: (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).InitiateDKG, (*DecentralizedPKIContract).assertNoActiveKeySession.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) getActiveDKGStatus(ctx contractapi.TransactionContextInterface) (string, error) {
	raw, err := ctx.GetStub().GetState("DKG:0")
	if err != nil {
		return "", err
	}
	if raw == nil {
		return "", nil
	}
	var session map[string]interface{}
	if err := json.Unmarshal(raw, &session); err != nil {
		return "", nil
	}
	status, _ := session["status"].(string)
	if isActiveDKGStatus(status) {
		return status, nil
	}
	return "", nil
}

// retrieves the latest active reshare session from world state
// Called by: (*DecentralizedPKIContract).InitiateDKG, (*DecentralizedPKIContract).assertNoActiveKeySession.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) getLatestActiveReshareSession(ctx contractapi.TransactionContextInterface) (*ReshareSession, error) {
	iter, err := ctx.GetStub().GetStateByRange("RESHARE:", "RESHARE;")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var latest *ReshareSession
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var sess ReshareSession
		if err := json.Unmarshal(kv.Value, &sess); err != nil {
			continue
		}
		normalizeReshareSession(&sess)
		if !isActiveReshareStatus(sess.Status) {
			continue
		}
		if latest == nil || sess.Epoch > latest.Epoch {
			copySess := sess
			latest = &copySess
		}
	}
	return latest, nil
}

// validates that there are no active key generation or resharing sessions before allowing critical operations to proceed
// Called by: (*DecentralizedPKIContract).ProposeRemoveMember, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).executeJoinApproval, (*DecentralizedPKIContract).executeMemberRemoval.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) assertNoActiveKeySession(ctx contractapi.TransactionContextInterface, action string) error {
	dkgStatus, err := c.getActiveDKGStatus(ctx)
	if err != nil {
		return err
	}
	if dkgStatus != "" {
		return fmt.Errorf("cannot %s while DKG session is %s", action, dkgStatus)
	}
	reshare, err := c.getLatestActiveReshareSession(ctx)
	if err != nil {
		return err
	}
	if reshare != nil {
		return fmt.Errorf("cannot %s while reshare epoch %d is %s", action, reshare.Epoch, reshare.Status)
	}
	return nil
}

// derives join proposals
// Called by: (*DecentralizedPKIContract).assertNoPendingMembershipGovernance.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) pendingJoinRequestCount(ctx contractapi.TransactionContextInterface, caID string) (int, error) {
	startKey := fmt.Sprintf("JOINREQ:%s:", caID)
	endKey := fmt.Sprintf("JOINREQ:%s;", caID)
	iter, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	count := 0
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return 0, err
		}
		var req JoinRequestProposal
		if err := json.Unmarshal(kv.Value, &req); err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(req.Status), "pending") {
			count++
		}
	}
	return count, nil
}

// derives removal proposals
// Called by: (*DecentralizedPKIContract).assertNoPendingMembershipGovernance.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) pendingRemovalProposalCount(ctx contractapi.TransactionContextInterface, caID string) (int, error) {
	startKey := fmt.Sprintf("REMOVE:%s:", caID)
	endKey := fmt.Sprintf("REMOVE:%s;", caID)
	iter, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	count := 0
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return 0, err
		}
		var proposal MemberRemovalProposal
		if err := json.Unmarshal(kv.Value, &proposal); err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(proposal.Status), "pending") {
			count++
		}
	}
	return count, nil
}

// validates there are no pending membership governance actions
// Called by: (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).ProposeRemoveMember, (*DecentralizedPKIContract).RequestJoinCA.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) assertNoPendingMembershipGovernance(ctx contractapi.TransactionContextInterface, caID string, action string) error {
	pendingJoin, err := c.pendingJoinRequestCount(ctx, caID)
	if err != nil {
		return err
	}
	pendingRemoval, err := c.pendingRemovalProposalCount(ctx, caID)
	if err != nil {
		return err
	}
	if pendingJoin > 0 || pendingRemoval > 0 {
		return fmt.Errorf(
			"cannot %s while membership governance is pending (join=%d, removal=%d)",
			action, pendingJoin, pendingRemoval,
		)
	}
	return nil
}

// ===================== TSS KEY RESHARING =====================

// creates a reshare session for old/new committees
// Called by: (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).ForceReshare, (*DecentralizedPKIContract).executeJoinApproval, (*DecentralizedPKIContract).executeMemberRemoval.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) initiateReshare(
	ctx contractapi.TransactionContextInterface,
	epoch int,
	reason string,
	affectedNode string,
	oldNodeSet []string,
	oldThreshold int,
	newNodeSet []string,
	newThreshold int,
) error {
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}

	initiatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	reshare := ReshareSession{
		Epoch:              epoch,
		TriggerReason:      reason + ":" + affectedNode,
		OldNodeSet:         oldNodeSet,
		OldThreshold:       oldThreshold,
		NewNodeSet:         newNodeSet,
		NewThreshold:       newThreshold,
		Status:             "initiated",
		AckCount:           0,
		AcknowledgedBy:     []string{},
		CompletionAckedBy:  []string{},
		CompletionAckCount: 0,
		InitiatedAt:        initiatedAt,
		CompletedAt:        "",
		NewCAPublicKey:     "",
		OldPartySalt:       ca.PartySalt,
		NewPartySalt:       nextPartySalt(ca.PartySalt),
	}

	reshareJSON, err := json.Marshal(reshare)
	if err != nil {
		return err
	}

	if err := ctx.GetStub().PutState("RESHARE:"+strconv.Itoa(epoch), reshareJSON); err != nil {
		return err
	}

	// Emit event
	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "reshare",
		"action":       "reshare_initiated",
		"epoch":        epoch,
		"reason":       reason,
		"nodeSet":      ca.Members,
		"threshold":    ca.ThresholdParams.Threshold,
		"newThreshold": newThreshold,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("ReshareInitiated", eventBytes)
	ctx.GetStub().SetEvent("ReshareRequired", eventBytes)

	return nil
}

// starts an administrative reshare path so operators can recover from stalled membership-key transitions.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ForceReshare(
	ctx contractapi.TransactionContextInterface,
	caID string,
	reason string,
) error {
	nodeID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(ca.PublicKey) == "" {
		return fmt.Errorf("cannot reshare: CA public key not set (complete DKG first)")
	}

	if !contains(ca.Members, nodeID) {
		return fmt.Errorf("only CA members can force reshare")
	}

	if reason == "" {
		reason = "manual_reshare"
	}

	oldMembers := append([]string(nil), ca.Members...)
	oldThreshold := ca.ThresholdParams.Threshold

	// Determine next available epoch for a fresh reshare
	newEpoch := ca.Epoch + 1
	for {
		reshareKey := "RESHARE:" + strconv.Itoa(newEpoch)
		existing, _ := ctx.GetStub().GetState(reshareKey)
		if existing == nil {
			break
		}
		newEpoch++
	}

	// Ovverride any existing reshares
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	supersedeAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	iter, err := ctx.GetStub().GetStateByRange("RESHARE:", "RESHARE;")
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return err
		}
		var sess ReshareSession
		if err := json.Unmarshal(kv.Value, &sess); err != nil {
			continue
		}
		if sess.Status == "completed" || sess.Status == "superseded" {
			continue
		}
		sess.Status = "superseded"
		sess.CompletedAt = supersedeAt
		sess.SupersededAt = supersedeAt
		sess.SupersededBy = newEpoch
		kvBytes, err := json.Marshal(sess)
		if err == nil {
			_ = ctx.GetStub().PutState(kv.Key, kvBytes)
		}
	}

	// Bump epoch
	ca.Epoch = newEpoch

	// Recalculate threshold based on current governance ratio
	newThreshold := calculateDynamicThreshold(len(ca.Members), ca.GovernanceParams.QuorumPercentage)
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = newThreshold

	caJSON, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caID, caJSON); err != nil {
		return err
	}

	return c.initiateReshare(ctx, ca.Epoch, reason, nodeID, oldMembers, oldThreshold, ca.Members, newThreshold)
}

// records committee readiness for reshare so completion eligibility reflects actual participant acknowledgement.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) AcknowledgeReshare(
	ctx contractapi.TransactionContextInterface,
	epoch int,
) error {
	nodeID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	// Get reshare session
	reshareJSON, err := ctx.GetStub().GetState("RESHARE:" + strconv.Itoa(epoch))
	if err != nil {
		return err
	}
	if reshareJSON == nil {
		return fmt.Errorf("reshare session not found")
	}

	var reshare ReshareSession
	if err := json.Unmarshal(reshareJSON, &reshare); err != nil {
		return err
	}

	if reshare.Status != "initiated" && reshare.Status != "acknowledged" {
		if reshare.Status == "completed" {
			return fmt.Errorf("reshare already completed")
		}
		return fmt.Errorf("reshare not in a state that accepts acknowledgements")
	}

	// Check if already acknowledged
	if contains(reshare.AcknowledgedBy, nodeID) {
		return fmt.Errorf("already acknowledged")
	}

	// Verify node is in new node set
	if !contains(reshare.NewNodeSet, nodeID) {
		return fmt.Errorf("node not in new node set")
	}

	reshare.AcknowledgedBy = append(reshare.AcknowledgedBy, nodeID)
	reshare.AckCount++

	// Require full new-committee acknowledgement before starting reshare keygen (possible point for a DoS but can't be circumvented in this library to provide a proper reshare)
	required := len(reshare.NewNodeSet)
	if len(reshare.NewNodeSet) == 0 {
		return fmt.Errorf("reshare has empty node set")
	}
	if reshare.AckCount >= required {
		reshare.Status = "acknowledged"

		// Emit event for off-chain DKG
		eventPayload := map[string]interface{}{
			"eventVersion": 2,
			"workflow":     "reshare",
			"action":       "all_nodes_ready_for_dkg",
			"epoch":        epoch,
		}
		eventBytes, _ := json.Marshal(eventPayload)
		ctx.GetStub().SetEvent("DKGReady", eventBytes)
	} else {
		// Keep status as initiated until everyone has acknowledged
		reshare.Status = "initiated"
	}

	reshareJSON, err = json.Marshal(reshare)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("RESHARE:"+strconv.Itoa(epoch), reshareJSON)
}

// finalizes a reshare epoch and public-key continuity checks so post-membership signing remains coherent and auditable.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) CompleteReshare(
	ctx contractapi.TransactionContextInterface,
	epoch int,
	newCAPublicKey string,
) error {
	caller, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	reshareJSON, err := ctx.GetStub().GetState("RESHARE:" + strconv.Itoa(epoch))
	if err != nil {
		return err
	}
	if reshareJSON == nil {
		return fmt.Errorf("reshare session not found")
	}

	var reshare ReshareSession
	if err := json.Unmarshal(reshareJSON, &reshare); err != nil {
		return err
	}

	if !contains(reshare.NewNodeSet, caller) {
		return fmt.Errorf("caller not in reshare node set")
	}

	if reshare.Status != "acknowledged" && reshare.Status != "proposed" {
		return fmt.Errorf("reshare not acknowledged (threshold not reached)")
	}

	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	if strings.TrimSpace(newCAPublicKey) == "" {
		return fmt.Errorf("public key required")
	}
	if ca.PublicKey != "" && ca.PublicKey != newCAPublicKey {
		return fmt.Errorf("reshare public key mismatch")
	}

	if reshare.NewCAPublicKey == "" {
		reshare.NewCAPublicKey = newCAPublicKey
	} else if reshare.NewCAPublicKey != newCAPublicKey {
		return fmt.Errorf("reshare public key mismatch")
	}

	if reshare.CompletionAckedBy == nil {
		reshare.CompletionAckedBy = []string{}
	}
	if !contains(reshare.CompletionAckedBy, caller) {
		reshare.CompletionAckedBy = append(reshare.CompletionAckedBy, caller)
	}
	reshare.CompletionAckCount = len(reshare.CompletionAckedBy)

	// Require full new-committee completion acknowledgements before marking the eshare completed on-chain. This prevents next governance actions from tarting while some peers are still finishing local reshare processing.
	// DoS possible but due to library limitations
	requiredAcks := len(reshare.NewNodeSet)
	if requiredAcks == 0 {
		return fmt.Errorf("reshare has empty node set")
	}

	if len(reshare.CompletionAckedBy) < requiredAcks {
		if reshare.Status == "acknowledged" {
			reshare.Status = "proposed"
		}
		reshareJSON, err = json.Marshal(reshare)
		if err != nil {
			return err
		}
		if err := ctx.GetStub().PutState("RESHARE:"+strconv.Itoa(epoch), reshareJSON); err != nil {
			return err
		}
		eventPayload := map[string]interface{}{
			"eventVersion": 2,
			"workflow":     "reshare",
			"action":       "reshare_completion_proposed",
			"epoch":        strconv.Itoa(epoch),
			"publicKey":    reshare.NewCAPublicKey,
			"ackCount":     len(reshare.CompletionAckedBy),
			"requiredAcks": requiredAcks,
		}
		if eventBytes, err := json.Marshal(eventPayload); err == nil {
			ctx.GetStub().SetEvent("ReshareCompletionProposed", eventBytes)
		}
		return nil
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	completedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	reshare.Status = "completed"
	reshare.CompletedAt = completedAt

	reshareJSON, err = json.Marshal(reshare)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("RESHARE:"+strconv.Itoa(epoch), reshareJSON); err != nil {
		return err
	}

	// Update CA public key (should be unchanged during reshar, could also integrate a check here)
	ca.PublicKey = newCAPublicKey
	ca.PartySalt = reshare.NewPartySalt

	caJSON, err := json.Marshal(ca)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("CA:"+DefaultCAID, caJSON); err != nil {
		return err
	}

	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "reshare",
		"action":       "reshare_completed",
		"epoch":        strconv.Itoa(epoch),
		"newPublicKey": newCAPublicKey,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("ReshareCompleted", eventBytes)

	return nil
}

// ===================== QUERY FUNCTIONS =====================

// loads and validates the canonical CA record so all flows read a single authoritative governance and key-management state.
// Called by: (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).CompleteDKG, (*DecentralizedPKIContract).CompleteReshare, (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).ForceReshare, (*DecentralizedPKIContract).GetCAPublicKey, (*DecentralizedPKIContract).GetNodeRole, (*DecentralizedPKIContract).GetOrgMembershipStats, (*DecentralizedPKIContract).GetTrustedCA, (*DecentralizedPKIContract).InitiateDKG, (*DecentralizedPKIContract).ProposeRemoveMember, (*DecentralizedPKIContract).ProposeRevocation, (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SetMerkleEnabled, (*DecentralizedPKIContract).SubmitCSR, (*DecentralizedPKIContract).SubmitPartialSignature, (*DecentralizedPKIContract).ValidateMemberCandidate, (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).VoteOnRevocation, (*DecentralizedPKIContract).executeJoinApproval, (*DecentralizedPKIContract).executeMemberRemoval, (*DecentralizedPKIContract).executeRevocation, (*DecentralizedPKIContract).initiateReshare, (*DecentralizedPKIContract).initiateSigningSession, (*DecentralizedPKIContract).verifyTSSSignature.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetDistributedCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
) (*DistributedCA, error) {
	caJSON, err := ctx.GetStub().GetState("CA:" + caID)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA: %v", err)
	}
	if caJSON == nil {
		return nil, fmt.Errorf("CA not found")
	}

	var ca DistributedCA
	json.Unmarshal(caJSON, &ca)
	return &ca, nil
}

// returns the caller canonical identity and role context so clients can debug authorization and membership
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) WhoAmI(ctx contractapi.TransactionContextInterface) (string, error) {
	return c.canonicalMemberID(ctx)
}

// retrieves All Certificates from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetAllCertificates(
	ctx contractapi.TransactionContextInterface,
) ([]Certificate, error) {
	// Query for all keys that start with "CERT:"
	iter, err := ctx.GetStub().GetStateByRange("CERT:", "CERTz")
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates: %v", err)
	}
	defer iter.Close()

	var certificates []Certificate

	// Iterate over the results and unmarshal the JSON data into Certificate struct
	for iter.HasNext() {
		queryResponse, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read next certificate: %v", err)
		}

		var cert Certificate
		err = json.Unmarshal(queryResponse.Value, &cert)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal certificate data: %v", err)
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// retrieves State By Range from world state (generic query)
// Called by: (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).ForceReshare, (*DecentralizedPKIContract).GetAllCertificates, (*DecentralizedPKIContract).GetAllPeerAddresses, (*DecentralizedPKIContract).GetPendingCSRProposals, (*DecentralizedPKIContract).GetPendingRevocations, (*DecentralizedPKIContract).GetPendingSigningSessions, (*DecentralizedPKIContract).GetStateByRange, (*DecentralizedPKIContract).IsNodeRevoked, (*DecentralizedPKIContract).ListPendingJoinRequests, (*DecentralizedPKIContract).ListPendingRemoveMemberProposals, (*DecentralizedPKIContract).getLatestActiveReshareSession, (*DecentralizedPKIContract).pendingJoinRequestCount, (*DecentralizedPKIContract).pendingRemovalProposalCount, (*DecentralizedPKIContract).updateCertificateMerkleTree.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetStateByRange(
	ctx contractapi.TransactionContextInterface,
	startKey string,
	endKey string,
) ([]string, error) {
	// Query for all keys in the given range
	iter, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get state by range: %v", err)
	}
	defer iter.Close()

	var results []string

	// Iterate over the results and add the key-value pairs to the results
	for iter.HasNext() {
		queryResponse, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read next state: %v", err)
		}
		results = append(results, fmt.Sprintf("Key: %s, Value: %s", queryResponse.Key, string(queryResponse.Value)))
	}

	return results, nil
}

// retrieves pending CSR Proposals from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetPendingCSRProposals(
	ctx contractapi.TransactionContextInterface,
) ([]*CSRProposal, error) {
	// Query for all proposals
	iter, err := ctx.GetStub().GetStateByRange("PROPOSAL:", "PROPOSAL:~")
	if err != nil {
		return nil, fmt.Errorf("failed to get proposals: %v", err)
	}
	defer iter.Close()

	var pendingProposals []*CSRProposal

	for iter.HasNext() {
		queryResponse, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read next proposal: %v", err)
		}

		var proposal CSRProposal
		if err := json.Unmarshal(queryResponse.Value, &proposal); err != nil {
			continue // Skip malformed entries
		}

		if proposal.Status == "pending" {
			pendingProposals = append(pendingProposals, &proposal)
		}
	}

	return pendingProposals, nil
}

// retrieves CSR Proposal from world state
// Called by: (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature, (*DecentralizedPKIContract).VoteOnCSR.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetCSRProposal(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
) (*CSRProposal, error) {
	proposalJSON, err := ctx.GetStub().GetState("PROPOSAL:" + proposalID)
	if err != nil {
		return nil, err
	}
	if proposalJSON == nil {
		return nil, fmt.Errorf("proposal not found")
	}

	var proposal CSRProposal
	json.Unmarshal(proposalJSON, &proposal)
	return &proposal, nil
}

// retrieves Signing Session from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetSigningSession(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
) (*SigningSession, error) {
	sessionJSON, err := ctx.GetStub().GetState("SIGNING:" + proposalID)
	if err != nil {
		return nil, err
	}
	if sessionJSON == nil {
		return nil, fmt.Errorf("signing session not found")
	}

	var session SigningSession
	json.Unmarshal(sessionJSON, &session)
	return &session, nil
}

// retrieves Pending Signing Sessions from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetPendingSigningSessions(
	ctx contractapi.TransactionContextInterface,
) ([]SigningSession, error) {
	// Query all keys starting with "SIGNING:"
	// Use GetStateByRange with startKey="SIGNING:" and endKey="SIGNING:~" to get all SIGNING:* keys
	iterator, err := ctx.GetStub().GetStateByRange("SIGNING:", "SIGNING:~")
	if err != nil {
		return nil, fmt.Errorf("failed to get state: %w", err)
	}
	defer iterator.Close()

	var sessions []SigningSession

	for iterator.HasNext() {
		queryResponse, err := iterator.Next()
		if err != nil {
			return nil, err
		}

		var session SigningSession
		err = json.Unmarshal(queryResponse.Value, &session)
		if err != nil {
			// Skip malformed entries
			continue
		}

		// Only return active sessions
		if session.Status == "active" {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// retrieves Certificate from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetCertificate(
	ctx contractapi.TransactionContextInterface,
	id string,
) (*Certificate, error) {
	// Try direct lookup by proposalID
	certJSON, err := ctx.GetStub().GetState("CERT:" + id)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %v", err)
	}

	if certJSON == nil {
		// Fallback: try as memberID via ACTIVECERT index
		activeCertKey, err := ctx.GetStub().GetState("ACTIVECERT:" + id)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate: %v", err)
		}
		if activeCertKey != nil {
			certJSON, err = ctx.GetStub().GetState("CERT:" + string(activeCertKey))
			if err != nil {
				return nil, fmt.Errorf("failed to get certificate: %v", err)
			}
		}
	}

	if certJSON == nil {
		return nil, fmt.Errorf("certificate not found")
	}

	var cert Certificate
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate data: %v", err)
	}

	return &cert, nil
}

// retrieves Pending Revocations from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetPendingRevocations(
	ctx contractapi.TransactionContextInterface,
) ([]RevocationProposal, error) {
	iterator, err := ctx.GetStub().GetStateByRange("REVOKE:", "REVOKE:~")
	if err != nil {
		return nil, fmt.Errorf("failed to query revocations: %v", err)
	}
	defer iterator.Close()

	var proposals []RevocationProposal
	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			continue
		}
		var proposal RevocationProposal
		if err := json.Unmarshal(result.Value, &proposal); err != nil {
			continue
		}
		if proposal.Status == "pending" {
			proposals = append(proposals, proposal)
		}
	}
	return proposals, nil
}

// retrieves Reshare Session from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetReshareSession(
	ctx contractapi.TransactionContextInterface,
	epoch int,
) (*ReshareSession, error) {
	reshareJSON, err := ctx.GetStub().GetState("RESHARE:" + strconv.Itoa(epoch))
	if err != nil {
		return nil, err
	}
	if reshareJSON == nil {
		return nil, fmt.Errorf("reshare session not found")
	}

	var reshare ReshareSession
	if err := json.Unmarshal(reshareJSON, &reshare); err != nil {
		return nil, err
	}
	normalizeReshareSession(&reshare)
	return &reshare, nil
}

// ===================== PEER DISCOVERY =====================
// This is the part where the peers register their TSS p2p adress

type PeerInfo struct {
	NodeID    string `json:"nodeId"`
	Address   string `json:"address"`
	P2PPort   int    `json:"p2pPort"`
	GRPCPort  int    `json:"grpcPort"`
	UpdatedAt string `json:"updatedAt"`
}

// applies controlled state transitions for Peer Address
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) RegisterPeerAddress(
	ctx contractapi.TransactionContextInterface,
	address string,
	p2pPortStr string,
	grpcPortStr string,
) error {
	nodeID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	p2pPort, err := strconv.Atoi(p2pPortStr)
	if err != nil {
		return fmt.Errorf("invalid p2pPort: %v", err)
	}
	grpcPort, err := strconv.Atoi(grpcPortStr)
	if err != nil {
		return fmt.Errorf("invalid grpcPort: %v", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	updatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	peerInfo := PeerInfo{
		NodeID:    nodeID,
		Address:   address,
		P2PPort:   p2pPort,
		GRPCPort:  grpcPort,
		UpdatedAt: updatedAt,
	}

	peerJSON, err := json.Marshal(peerInfo)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("PEER:"+nodeID, peerJSON)
}

// retrieves Peer Address from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetPeerAddress(
	ctx contractapi.TransactionContextInterface,
	nodeID string,
) (*PeerInfo, error) {
	peerJSON, err := ctx.GetStub().GetState("PEER:" + nodeID)
	if err != nil {
		return nil, err
	}
	if peerJSON == nil {
		return nil, fmt.Errorf("peer address not found for %s", nodeID)
	}

	var peerInfo PeerInfo
	if err := json.Unmarshal(peerJSON, &peerInfo); err != nil {
		return nil, err
	}
	return &peerInfo, nil
}

// retrieves All Peer Addresses from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetAllPeerAddresses(
	ctx contractapi.TransactionContextInterface,
) ([]PeerInfo, error) {
	iter, err := ctx.GetStub().GetStateByRange("PEER:", "PEERz")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var peers []PeerInfo
	for iter.HasNext() {
		queryResponse, err := iter.Next()
		if err != nil {
			return nil, err
		}

		var peer PeerInfo
		if err := json.Unmarshal(queryResponse.Value, &peer); err != nil {
			continue
		}
		peers = append(peers, peer)
	}

	return peers, nil
}

// reports whether the distributed CA record already exists so setup clients can avoid duplicate initialization attempts.
// Called by: (*DecentralizedPKIContract).InitializeDistributedCA.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) CAExists(
	ctx contractapi.TransactionContextInterface,
	caID string,
) (bool, error) {
	caJSON, err := ctx.GetStub().GetState("CA:" + caID)
	if err != nil {
		return false, err
	}
	return caJSON != nil, nil
}

// reports whether a proposal key exists so clients can guard follow-up governance calls against missing state.
// Called by: (*DecentralizedPKIContract).SubmitCSR.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ProposalExists(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
) (bool, error) {
	proposalJSON, err := ctx.GetStub().GetState("PROPOSAL:" + proposalID)
	if err != nil {
		return false, err
	}
	return proposalJSON != nil, nil
}

// ===================== TSS SIGNING COORDINATION =====================

type deterministicSigningCertificateMaterial struct {
	CSR               *x509.CertificateRequest
	SerialNumber      *big.Int
	SerialNumberStr   string
	ValidityDays      int
	NotBefore         time.Time
	NotAfter          time.Time
	Subject           string
	PublicKeyHex      string
	RawTBSCertificate []byte
	TBSHash           []byte
	TBSHashHex        string
}

// derives normalized signing validity From Created At values
// Called by: buildDeterministicSigningCertificateMaterial.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func deterministicSigningValidityFromCreatedAt(createdAt time.Time) (time.Time, time.Time, int) {
	notBefore := createdAt.UTC().Truncate(time.Second)
	validityDays := 365
	notAfter := notBefore.AddDate(0, 0, validityDays)
	return notBefore, notAfter, validityDays
}

// derives normalized signing serial values
// Called by: buildDeterministicSigningCertificateMaterial.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func deterministicSigningSerial(proposalID, submitterID string, notBefore time.Time) *big.Int {
	seed := strings.TrimSpace(proposalID) + "|" +
		strings.TrimSpace(submitterID) + "|" +
		notBefore.UTC().Format(time.RFC3339)
	sum := sha256.Sum256([]byte(seed))
	serialBytes := append([]byte(nil), sum[:20]...)
	serialBytes[0] &= 0x7f
	zero := true
	for _, b := range serialBytes {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		serialBytes[len(serialBytes)-1] = 1
	}
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() <= 0 {
		return big.NewInt(1)
	}
	return serial
}

// constructs provisional raw TBS (to be signed) deterministically
// Called by: buildDeterministicSigningCertificateMaterial.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func buildProvisionalRawTBS(template, issuer *x509.Certificate, subjectPublicKey interface{}) ([]byte, error) {
	throwawayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate throwaway key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, subjectPublicKey, throwawayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create provisional certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provisional certificate: %w", err)
	}
	if len(parsed.RawTBSCertificate) == 0 {
		return nil, fmt.Errorf("provisional certificate missing RawTBSCertificate")
	}
	return append([]byte(nil), parsed.RawTBSCertificate...), nil
}

// derives deterministic certificate fields and TBS (to be signed) bytes so all parties sign the same certificate message and prevent hash drift.
// Called by: (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature, (*DecentralizedPKIContract).initiateSigningSession.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func buildDeterministicSigningCertificateMaterial(
	proposalID string,
	proposal *CSRProposal,
	sessionCreatedAt time.Time,
) (*deterministicSigningCertificateMaterial, error) {
	if proposal == nil {
		return nil, fmt.Errorf("missing CSR proposal")
	}
	if strings.TrimSpace(proposal.CSRData) == "" {
		return nil, fmt.Errorf("CSR proposal missing CSRData")
	}

	csrBlock, _ := pem.Decode([]byte(proposal.CSRData))
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	notBefore, notAfter, validityDays := deterministicSigningValidityFromCreatedAt(sessionCreatedAt)
	serial := deterministicSigningSerial(proposalID, proposal.SubmitterID, notBefore)

	certTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		Issuer: pkix.Name{
			CommonName:   "Decentralized PKI CA",
			Organization: []string{"BPKI"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Decentralized PKI CA",
			Organization: []string{"BPKI"},
		},
		NotBefore:             notBefore.Add(-24 * time.Hour),
		NotAfter:              notBefore.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	rawTBS, err := buildProvisionalRawTBS(certTemplate, issuerTemplate, csr.PublicKey)
	if err != nil {
		return nil, err
	}
	tbsHash := sha256.Sum256(rawTBS)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR public key: %w", err)
	}

	return &deterministicSigningCertificateMaterial{
		CSR:               csr,
		SerialNumber:      serial,
		SerialNumberStr:   serial.String(),
		ValidityDays:      validityDays,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		Subject:           csr.Subject.String(),
		PublicKeyHex:      hex.EncodeToString(pubKeyBytes),
		RawTBSCertificate: rawTBS,
		TBSHash:           append([]byte(nil), tbsHash[:]...),
		TBSHashHex:        hex.EncodeToString(tbsHash[:]),
	}, nil
}

// derives normalized String Slices
// Called by: validateCertificateAgainstCSR.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// derives normalized IP Slices
// Called by: validateCertificateAgainstCSR.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func equalIPSlices(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// derives normalized URI Slices
// Called by: validateCertificateAgainstCSR.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func equalURISlices(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		switch {
		case a[i] == nil && b[i] == nil:
			continue
		case a[i] == nil || b[i] == nil:
			return false
		case a[i].String() != b[i].String():
			return false
		}
	}
	return true
}

// validates certificate against CSR so invalid identities, signatures, and state transitions are rejected before commit.
// Called by: (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func validateCertificateAgainstCSR(cert *x509.Certificate, csr *x509.CertificateRequest) error {
	if cert == nil {
		return fmt.Errorf("parsed certificate is nil")
	}
	if csr == nil {
		return fmt.Errorf("parsed CSR is nil")
	}
	if cert.Subject.String() != csr.Subject.String() {
		return fmt.Errorf("certificate subject does not match CSR subject")
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("certificate public key does not match CSR public key")
	}
	if !equalStringSlices(cert.DNSNames, csr.DNSNames) {
		return fmt.Errorf("certificate DNS SANs do not match CSR")
	}
	if !equalStringSlices(cert.EmailAddresses, csr.EmailAddresses) {
		return fmt.Errorf("certificate email SANs do not match CSR")
	}
	if !equalIPSlices(cert.IPAddresses, csr.IPAddresses) {
		return fmt.Errorf("certificate IP SANs do not match CSR")
	}
	if !equalURISlices(cert.URIs, csr.URIs) {
		return fmt.Errorf("certificate URI SANs do not match CSR")
	}
	return nil
}

// creates deterministic signing-session material so all signers hash and sign the exact same certificate payload.
// Called by: (*DecentralizedPKIContract).VoteOnCSR.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) initiateSigningSession(
	ctx contractapi.TransactionContextInterface,
	proposal *CSRProposal,
) error {
	if proposal == nil {
		return fmt.Errorf("missing CSR proposal")
	}
	if strings.TrimSpace(proposal.ProposalID) == "" {
		return fmt.Errorf("missing CSR proposal ID")
	}

	// Idempotency guard: once a signing session exists and is active/completed,
	// never overwrite it. This prevents csrHash/createdAt drift mid-signing.
	sessionKey := "SIGNING:" + proposal.ProposalID
	existingJSON, err := ctx.GetStub().GetState(sessionKey)
	if err != nil {
		return err
	}
	if existingJSON != nil {
		var existing SigningSession
		if err := json.Unmarshal(existingJSON, &existing); err != nil {
			return fmt.Errorf("failed to decode existing signing session: %w", err)
		}
		switch existing.Status {
		case "active", "completed":
			return nil
		}
	}

	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	createdAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	certMaterial, err := buildDeterministicSigningCertificateMaterial(proposal.ProposalID, proposal, createdAt)
	if err != nil {
		return err
	}

	session := SigningSession{
		ProposalID:        proposal.ProposalID,
		CSRHash:           certMaterial.TBSHashHex,
		RequiredSigners:   ca.ThresholdParams.Threshold + 1,
		PartialSignatures: []PartialSignature{},
		Status:            "active",
		CreatedAt:         createdAt,
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := ctx.GetStub().PutState(sessionKey, sessionJSON); err != nil {
		return err
	}

	// Emit event for nodes to start TSS
	eventPayload := map[string]interface{}{
		"eventVersion": 2,
		"workflow":     "csr",
		"action":       "signing_initiated",
		"proposalId":   proposal.ProposalID,
		"csrHash":      certMaterial.TBSHashHex,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("SigningInitiated", eventBytes)

	return nil
}

// verifies and records partial threshold signatures so only valid signer contributions count toward issuance.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) SubmitPartialSignature(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	partialSig string,
	signerIndex int,
	publicKeyShare string,
) error {

	// Get signer identity
	signerID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get signer identity: %v", err)
	}

	// Check CA membership

	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	if !contains(ca.Members, signerID) {
		return fmt.Errorf("signer %s is not authorized", signerID)
	}

	// Get signing session
	sessionJSON, err := ctx.GetStub().GetState("SIGNING:" + proposalID)
	if err != nil {
		return err
	}
	if sessionJSON == nil {
		return fmt.Errorf("signing session not found for proposal %s", proposalID)
	}

	var session SigningSession
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return err
	}

	if session.Status != "active" {
		return fmt.Errorf("signing session is not active")
	}
	if strings.TrimSpace(session.CSRHash) == "" {
		return fmt.Errorf("signing session has empty signing hash")
	}

	// Check if already submitted
	for _, sig := range session.PartialSignatures {
		if sig.SignerID == signerID {
			return fmt.Errorf("signer %s already submitted signature", signerID)
		}
	}

	// Validate submitted signature before counting it toward threshold.
	partialSig = strings.TrimSpace(partialSig)
	parts := strings.Split(partialSig, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid partial signature format: expected hexR:hexS")
	}
	sigR := strings.TrimSpace(parts[0])
	sigS := strings.TrimSpace(parts[1])
	if sigR == "" || sigS == "" {
		return fmt.Errorf("invalid partial signature format: empty R/S component")
	}
	valid, err := c.verifyTSSSignature(ctx, session.CSRHash, sigR, sigS)
	if err != nil {
		return fmt.Errorf("invalid partial signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid partial signature")
	}
	// Normalize stored format so all entries are consistent.
	partialSig = strings.ToLower(sigR) + ":" + strings.ToLower(sigS)

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	submittedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	// Add partial signature
	partialSignature := PartialSignature{
		SignerID:       signerID,
		PartialSig:     partialSig,
		SignerIndex:    signerIndex,
		SubmittedAt:    submittedAt,
		PublicKeyShare: publicKeyShare,
	}

	session.PartialSignatures = append(session.PartialSignatures, partialSignature)

	// Check if threshold reached
	if len(session.PartialSignatures) >= session.RequiredSigners {
		session.Status = "completed"

		// Emit event for signature combination
		eventPayload := map[string]interface{}{
			"eventVersion":    2,
			"workflow":        "csr",
			"action":          "threshold_reached",
			"proposalId":      proposalID,
			"signaturesCount": len(session.PartialSignatures),
		}
		eventBytes, _ := json.Marshal(eventPayload)
		ctx.GetStub().SetEvent("ThresholdReached", eventBytes)
	}

	// Save updated session
	sessionJSON, err = json.Marshal(session)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("SIGNING:"+proposalID, sessionJSON)
}

// verifies strict certificate/signature binding and writes the issued certificate so ledger state reflects only valid threshold-issued certs.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) RegisterCombinedCertificateWithSignature(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	certificatePEM string,
	certificateHash string,
	subject string,
	publicKey string,
	serialNumber string,
	validityDays int,
	signatureR string,
	signatureS string,
) error {

	// Certificate already combined?
	existingCertJSON, err := ctx.GetStub().GetState("CERT:" + proposalID)
	if err != nil {
		return err
	}
	if existingCertJSON != nil {
		return nil
	}

	// Get signing session
	sessionJSON, err := ctx.GetStub().GetState("SIGNING:" + proposalID)
	if err != nil {
		return err
	}
	if sessionJSON == nil {
		return fmt.Errorf("signing session not found")
	}

	var session SigningSession
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return err
	}

	if session.Status != "completed" {
		return fmt.Errorf("signing session not completed yet")
	}

	// Get proposal
	proposal, err := c.GetCSRProposal(ctx, proposalID)
	if err != nil {
		return err
	}

	certificateHash = strings.ToLower(strings.TrimSpace(certificateHash))
	subject = strings.TrimSpace(subject)
	publicKey = strings.TrimSpace(publicKey)
	serialNumber = strings.TrimSpace(serialNumber)
	signatureR = strings.TrimSpace(signatureR)
	signatureS = strings.TrimSpace(signatureS)

	// Validate certificate hash format
	if len(certificateHash) != 64 {
		return fmt.Errorf("invalid certificate hash")
	}
	if signatureR == "" || signatureS == "" {
		return fmt.Errorf("missing TSS signature components")
	}

	certMaterial, err := buildDeterministicSigningCertificateMaterial(proposalID, proposal, session.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to derive deterministic certificate material: %w", err)
	}
	if !strings.EqualFold(session.CSRHash, certMaterial.TBSHashHex) {
		return fmt.Errorf("session signing hash mismatch with deterministic certificate material")
	}

	certBlock, _ := pem.Decode([]byte(certificatePEM))
	if certBlock == nil {
		return fmt.Errorf("invalid certificate PEM")
	}
	certDER := certBlock.Bytes
	computedCertHash := sha256.Sum256(certDER)
	if hex.EncodeToString(computedCertHash[:]) != certificateHash {
		return fmt.Errorf("certificate hash does not match certificate PEM")
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate PEM: %w", err)
	}
	if parsedCert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fmt.Errorf("unsupported certificate signature algorithm: %s", parsedCert.SignatureAlgorithm.String())
	}
	if err := validateCertificateAgainstCSR(parsedCert, certMaterial.CSR); err != nil {
		return err
	}
	if parsedCert.SerialNumber == nil || parsedCert.SerialNumber.Cmp(certMaterial.SerialNumber) != 0 {
		return fmt.Errorf("certificate serial number does not match deterministic value")
	}
	if !parsedCert.NotBefore.Equal(certMaterial.NotBefore) || !parsedCert.NotAfter.Equal(certMaterial.NotAfter) {
		return fmt.Errorf("certificate validity window does not match deterministic session window")
	}
	if !bytes.Equal(parsedCert.RawTBSCertificate, certMaterial.RawTBSCertificate) {
		return fmt.Errorf("certificate TBS does not match deterministic certificate material")
	}

	certPublicKeyBytes, err := x509.MarshalPKIXPublicKey(parsedCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %w", err)
	}
	certPublicKeyHex := strings.ToLower(hex.EncodeToString(certPublicKeyBytes))
	if subject != certMaterial.Subject || subject != parsedCert.Subject.String() {
		return fmt.Errorf("subject field mismatch with certificate/CSR")
	}
	if !strings.EqualFold(publicKey, certMaterial.PublicKeyHex) || !strings.EqualFold(publicKey, certPublicKeyHex) {
		return fmt.Errorf("public key field mismatch with certificate/CSR")
	}
	if serialNumber != certMaterial.SerialNumberStr {
		return fmt.Errorf("serial number field mismatch with deterministic value")
	}
	if validityDays != certMaterial.ValidityDays {
		return fmt.Errorf("validityDays mismatch with deterministic policy")
	}

	rBytes, err := hex.DecodeString(signatureR)
	if err != nil {
		return fmt.Errorf("invalid signatureR hex: %w", err)
	}
	sBytes, err := hex.DecodeString(signatureS)
	if err != nil {
		return fmt.Errorf("invalid signatureS hex: %w", err)
	}
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return fmt.Errorf("invalid zero-valued signature components")
	}
	type ecdsaSig struct {
		R, S *big.Int
	}
	sigASN1, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	if err != nil {
		return fmt.Errorf("failed to marshal signature components: %w", err)
	}
	if !bytes.Equal(parsedCert.Signature, sigASN1) {
		return fmt.Errorf("submitted signature components do not match certificate signature")
	}

	// Get CA
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(ca.PublicKey) == "" {
		return fmt.Errorf("CA public key is not initialized")
	}
	caPubKey, err := reconstructPublicKeyFromHex(ca.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to reconstruct CA public key: %w", err)
	}
	tbsHash := sha256.Sum256(parsedCert.RawTBSCertificate)
	tbsHashHex := hex.EncodeToString(tbsHash[:])
	if !strings.EqualFold(tbsHashHex, certMaterial.TBSHashHex) || !strings.EqualFold(tbsHashHex, session.CSRHash) {
		return fmt.Errorf("certificate TBS hash mismatch with session")
	}
	if !ecdsa.Verify(caPubKey, tbsHash[:], r, s) {
		return fmt.Errorf("certificate signature verification failed against CA public key")
	}

	tracker := newStorageAttributionTracker("csr", "certificate_registered", proposalID, strconv.Itoa(ca.Epoch))

	issuedAt := certMaterial.NotBefore
	expiresAt := certMaterial.NotAfter
	normalizedCertificatePEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// Create certificate record
	// At the moment the pem and hash are stored making it also possible to view the certificate directly
	// Could be changed to verify the signature and then only store the hash and reference to the certificate data if we want to save space and not store the full certificate on-chain
	cert := Certificate{
		CertID:           "CERT:" + proposalID,
		MemberID:         proposal.SubmitterID,
		CertificatePEM:   normalizedCertificatePEM,
		CertificateHash:  certificateHash,
		Subject:          certMaterial.Subject,
		PublicKey:        certMaterial.PublicKeyHex,
		SerialNumber:     certMaterial.SerialNumberStr,
		IssuedAt:         issuedAt,
		ExpiresAt:        expiresAt,
		Status:           "active",
		IsRevoked:        false,
		RevokedAt:        "",
		RevocationReason: "NOT_REVOKED",
		ProposalID:       proposalID,
		Epoch:            ca.Epoch,
		SignatureR:       signatureR,
		SignatureS:       signatureS,
	}

	certJSON, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	tracker.trackWrite("certificate", certJSON)

	// Store certificate by proposalID
	if err := ctx.GetStub().PutState("CERT:"+proposalID, certJSON); err != nil {
		return err
	}

	// Update active cert index for this member
	activeIndexValue := []byte(proposalID)
	tracker.trackWrite("active_index", activeIndexValue)
	if err := ctx.GetStub().PutState("ACTIVECERT:"+proposal.SubmitterID, []byte(proposalID)); err != nil {
		return err
	}

	// Update proposal status
	proposal.Status = "completed"
	proposalJSON, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	tracker.trackWrite("proposal", proposalJSON)
	if err := ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON); err != nil {
		return err
	}

	// Update Merkle tree of active certificates
	if err := c.updateCertificateMerkleTree(ctx, "certificate_registered", cert.CertID, certificateHash, false); err != nil {
		// Log if update fails but do not fail the whole transaction since the certificate is validly registered and the Merkle tree can be updated in a later transaction
		fmt.Printf("Warning: failed to update Merkle tree: %v\n", err)
	} else {
		merkleState, _ := ctx.GetStub().GetState("MERKLE:CERTS")
		tracker.trackWrite("merkle_state", merkleState)
	}

	// Emit certificate registered event
	eventPayload := map[string]interface{}{
		"eventVersion":    2,
		"workflow":        "csr",
		"action":          "certificate_registered",
		"proposalId":      proposalID,
		"nodeId":          proposal.SubmitterID,
		"certificateHash": certificateHash,
		"epoch":           strconv.Itoa(ca.Epoch),
	}
	tracker.applyToEventPayload(ctx, eventPayload)
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRegistered", eventBytes)

	return nil
}

// ===================== HELPER FUNCTIONS =====================

// manages chaincode state
// Called by: (*DecentralizedPKIContract).AcknowledgeDKG, (*DecentralizedPKIContract).AcknowledgeReshare, (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).CompleteDKG, (*DecentralizedPKIContract).CompleteReshare, (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).ForceReshare, (*DecentralizedPKIContract).GetNodeRole, (*DecentralizedPKIContract).InitiateDKG, (*DecentralizedPKIContract).ProposeRemoveMember, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SetMerkleEnabled, (*DecentralizedPKIContract).SubmitPartialSignature, (*DecentralizedPKIContract).ValidateMemberCandidate, (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).VoteOnRevocation, (*DecentralizedPKIContract).executeJoinApproval, (*DecentralizedPKIContract).executeMemberRemoval.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// derives normalized Org From Member ID
// Called by: (*DecentralizedPKIContract).GetOrgMembershipStats, (*DecentralizedPKIContract).ValidateMemberCandidate, countVotingOrgs.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func extractOrgFromMemberID(memberID string) string {
	memberID = strings.TrimSpace(memberID)
	if memberID == "" {
		return "unknown"
	}

	for _, candidate := range orgExtractionCandidates(memberID) {
		if mspid := normalizeMSPIDCandidate(candidate); mspid != "" {
			return mspid
		}
	}

	return "unknown"
}

// derives normalized Candidates
// Called by: extractOrgFromMemberID.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func orgExtractionCandidates(memberID string) []string {
	parts := strings.Split(memberID, "::")
	var out []string
	if len(parts) >= 3 {
		out = append(out, splitDNValues(parts[2])...)
	}
	if len(parts) >= 2 {
		out = append(out, splitDNValues(parts[1])...)
	}
	return out
}

// derives normalized DN Values
// Called by: orgExtractionCandidates.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func splitDNValues(dn string) []string {
	var out []string
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if eq := strings.Index(part, "="); eq >= 0 {
			value := strings.TrimSpace(part[eq+1:])
			if value != "" {
				out = append(out, value)
			}
			continue
		}
		out = append(out, part)
	}
	return out
}

// derives normalized MSPID Candidate
// Called by: extractOrgFromMemberID.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func normalizeMSPIDCandidate(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}

	// First pass: explicit MSP token (e.g. IRS1MSP).
	for _, token := range candidateTokens(value) {
		if strings.HasSuffix(token, "msp") && len(token) > len("msp") {
			prefix := token[:len(token)-len("msp")]
			if isOrgToken(prefix) {
				return strings.ToUpper(prefix) + "MSP"
			}
		}
	}

	// Second pass: domain or org token (e.g. irs1 from ca.irs1.kit.edu).
	for _, token := range candidateTokens(value) {
		if isOrgToken(token) {
			return strings.ToUpper(token) + "MSP"
		}
	}

	return ""
}

// derives normalized Tokens
// Called by: normalizeMSPIDCandidate.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func candidateTokens(value string) []string {
	var out []string
	parts := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', ':', '/', '\\', '@':
			return true
		default:
			return false
		}
	})
	for _, part := range parts {
		part = strings.Trim(part, "\"'()[]{}")
		if part == "" {
			continue
		}
		for _, dot := range strings.Split(part, ".") {
			dot = strings.Trim(dot, "\"'()[]{}")
			if dot != "" {
				out = append(out, dot)
			}
		}
	}
	return out
}

// evaluates org token structure (e.g. "irs1") so normalized MSPID derivation can identify org tokens and avoid false positives from non-org parts of the identity string.
// Called by: normalizeMSPIDCandidate.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func isOrgToken(token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return false
	}
	i := 0
	for i < len(token) && token[i] >= 'a' && token[i] <= 'z' {
		i++
	}
	if i < 3 || i >= len(token) {
		return false
	}
	for j := i; j < len(token); j++ {
		if token[j] < '0' || token[j] > '9' {
			return false
		}
	}
	return true
}

// derives normalized Voting Orgs
// Called by: validateMultiOrgVotes.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func countVotingOrgs(voters []string) int {
	orgs := make(map[string]bool)
	for _, voter := range voters {
		org := extractOrgFromMemberID(voter)
		if org != "unknown" {
			orgs[org] = true
		}
	}
	return len(orgs)
}

// validates Member Org Limit
// Called by: (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).ValidateMemberCandidate, (*DecentralizedPKIContract).executeJoinApproval.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func validateMemberOrgLimit(members []string, newMemberID string) error {
	// Per-org member limits removed - always allow
	return nil
}

// validates Multi Org Votes
// Called by: (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func validateMultiOrgVotes(voters []string) error {
	if !EnableSecurityLimits {
		return nil
	}

	orgCount := countVotingOrgs(voters)
	if orgCount < MinOrgsForApproval {
		return fmt.Errorf("requires votes from at least %d different organizations (currently have %d)",
			MinOrgsForApproval, orgCount)
	}

	return nil
}

// returns raw state for a key so operators can troubleshoot ledger data during testing and incident analysis.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) DebugGetState(
	ctx contractapi.TransactionContextInterface,
	key string,
) (string, error) {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", err
	}
	if b == nil {
		return "", fmt.Errorf("state not found for key %s", key)
	}
	return string(b), nil
}

// derives a stable Fabric-member identifier from client identity so vote, membership, and signer checks cannot drift across certificate encodings.
// Called by: (*DecentralizedPKIContract).AcknowledgeDKG, (*DecentralizedPKIContract).AcknowledgeReshare, (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).CompleteDKG, (*DecentralizedPKIContract).CompleteReshare, (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).ForceReshare, (*DecentralizedPKIContract).InitiateDKG, (*DecentralizedPKIContract).ProposeRemoveMember, (*DecentralizedPKIContract).ProposeRevocation, (*DecentralizedPKIContract).RegisterPeerAddress, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SetMerkleEnabled, (*DecentralizedPKIContract).SubmitCSR, (*DecentralizedPKIContract).SubmitPartialSignature, (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).VoteOnRevocation, (*DecentralizedPKIContract).WhoAmI.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) canonicalMemberID(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("failed to get client identity: %v", err)
	}

	// Already canonical
	if strings.HasPrefix(id, "x509::") {
		return id, nil
	}

	// Some environments return base64-encoded ID (e.g., "eDUwOTo6...")
	if decoded, derr := base64.StdEncoding.DecodeString(id); derr == nil {
		s := string(decoded)
		if strings.HasPrefix(s, "x509::") {
			return s, nil
		}
		// If it's decodable but different format, still return decoded (optional)
		return s, nil
	}

	// Last resort: return raw ID (or error if you want strictness)
	return id, nil
}

// validates Canonical ID so invalid identities, signatures, and state transitions are rejected before commit.
// Called by: (*DecentralizedPKIContract).ProposeRevocation.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func ensureCanonicalID(id string) error {
	if strings.HasPrefix(id, "x509::") {
		return nil
	}
	// allow base64-encoded x509::...
	if decoded, err := base64.StdEncoding.DecodeString(id); err == nil {
		if strings.HasPrefix(string(decoded), "x509::") {
			return nil
		}
	}
	return fmt.Errorf("id must be canonical member id (x509::...) or base64(x509::...), got: %s", id)
}

// retrieves Client Cert from world state
// Called by: (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).ProposeRevocation, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SubmitCSR.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func getClientCert(ctx contractapi.TransactionContextInterface) (*x509.Certificate, string, error) {
	cidClient, err := cid.New(ctx.GetStub())
	if err != nil {
		return nil, "", fmt.Errorf("failed to read client identity: %w", err)
	}
	cert, err := cidClient.GetX509Certificate()
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse client certificate: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return cert, string(pemBytes), nil
}

// derives normalized Cert From PEM
// Called by: (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func parseCertFromPEM(pemStr string) (*x509.Certificate, error) {
	if strings.TrimSpace(pemStr) == "" {
		return nil, fmt.Errorf("empty certificate")
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// enforces certificate validity bounds at transaction time
// Called by: (*DecentralizedPKIContract).ProposeRevocation, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SubmitCSR, (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func validateCertAtTime(cert *x509.Certificate, at time.Time) error {
	if at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
		return fmt.Errorf("certificate not valid at %s", at.UTC().Format(time.RFC3339))
	}
	return nil
}

// derives role From Cert values
// Called by: (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, getClientRole.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func roleFromCert(cert *x509.Certificate) string {
	for _, ou := range cert.Subject.OrganizationalUnit {
		role := strings.ToLower(strings.TrimSpace(ou))
		if role == "admin" {
			return "member"
		}
		if role == "member" || role == "observer" {
			return role
		}
	}
	return ""
}

// retrieves Client Role from world state
// Called by: (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).ProposeRevocation, (*DecentralizedPKIContract).RequestJoinCA, (*DecentralizedPKIContract).SubmitCSR.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func getClientRole(ctx contractapi.TransactionContextInterface, cert *x509.Certificate) (string, error) {
	role := roleFromCert(cert)
	if role == "" {
		if attr, found, err := cid.GetAttributeValue(ctx.GetStub(), "role"); err == nil && found {
			role = strings.ToLower(strings.TrimSpace(attr))
		}
	}
	if role == "admin" {
		role = "member"
	}
	if role != "member" && role != "observer" {
		return "", fmt.Errorf("certificate role must be member or observer")
	}
	return role, nil
}

// Dynamic Threshold values
// Called by: (*DecentralizedPKIContract).BootstrapJoinCA, (*DecentralizedPKIContract).ForceFreshDKG, (*DecentralizedPKIContract).ForceReshare, (*DecentralizedPKIContract).executeJoinApproval, (*DecentralizedPKIContract).executeMemberRemoval.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func calculateDynamicThreshold(memberCount int, percentageRequired int) int {
	exactSigners := float64(memberCount) * float64(percentageRequired) / 100.0
	requiredSigners := int(math.Ceil(exactSigners))

	if requiredSigners < 2 {
		requiredSigners = 2
	}

	return requiredSigners - 1 // TSS threshold (tss-lib uses t as the maximum number of corruped nodes (So the number of nodes that can be corrupted before malicious certificates can be issued not before the malicious nodes can do DoS!))
}

// evaluates whether Network Wide Approval is reached
// Called by: (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).VoteOnRevocation, canStillReachNetworkWideApproval.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func hasNetworkWideApproval(votesFor, totalAuthorized, approvalThreshold int) bool {
	if totalAuthorized <= 0 {
		return false
	}
	return (votesFor * 100 / totalAuthorized) >= approvalThreshold
}

// evaluates whether Network Wide Approval is reachable
// Called by: (*DecentralizedPKIContract).VoteOnCSR, (*DecentralizedPKIContract).VoteOnJoinRequest, (*DecentralizedPKIContract).VoteOnRemoveMember, (*DecentralizedPKIContract).VoteOnRevocation.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func canStillReachNetworkWideApproval(votesFor, votesReceived, totalAuthorized, approvalThreshold int) bool {
	if totalAuthorized <= 0 {
		return false
	}
	remaining := totalAuthorized - votesReceived
	if remaining < 0 {
		remaining = 0
	}
	maxPossibleVotesFor := votesFor + remaining
	return hasNetworkWideApproval(maxPossibleVotesFor, totalAuthorized, approvalThreshold)
}

// Called by: internal helper paths (none in current static call graph).
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func hash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// ===================== TSS SIGNATURE VERIFICATION =====================

// constructs Public Key From Hex
// Called by: (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature, (*DecentralizedPKIContract).verifyTSSSignature.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func reconstructPublicKeyFromHex(pubKeyHex string) (*ecdsa.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	// Handle both compressed and uncompressed formats
	curve := elliptic.P256() // secp256k1 equivalent for Fabric chaincode

	// Check format
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("empty public key")
	}

	var x, y *big.Int

	switch pubKeyBytes[0] {
	case 0x04: // Uncompressed: 04 || X || Y
		if len(pubKeyBytes) != 65 {
			return nil, fmt.Errorf("invalid uncompressed public key length: %d", len(pubKeyBytes))
		}
		x = new(big.Int).SetBytes(pubKeyBytes[1:33])
		y = new(big.Int).SetBytes(pubKeyBytes[33:65])

	case 0x02, 0x03: // Compressed: 02/03 || X (decompress Y)
		if len(pubKeyBytes) != 33 {
			return nil, fmt.Errorf("invalid compressed public key length: %d", len(pubKeyBytes))
		}
		x, y = elliptic.UnmarshalCompressed(curve, pubKeyBytes)
		if x == nil {
			return nil, fmt.Errorf("failed to decompress public key")
		}

	default:
		// Try raw X||Y format (64 bytes)
		if len(pubKeyBytes) == 64 {
			x = new(big.Int).SetBytes(pubKeyBytes[0:32])
			y = new(big.Int).SetBytes(pubKeyBytes[32:64])
		} else {
			return nil, fmt.Errorf("unknown public key format, first byte: 0x%02x, length: %d", pubKeyBytes[0], len(pubKeyBytes))
		}
	}

	// Verify point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// validates threshold-signature material against the active CA public key so only cryptographically valid signature fragments are accepted.
// Called by: (*DecentralizedPKIContract).VerifySignature.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) verifyTSSSignature(
	ctx contractapi.TransactionContextInterface,
	csrHash string,
	signatureR string,
	signatureS string,
) (bool, error) {
	// Get CA public key
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return false, fmt.Errorf("failed to get CA: %w", err)
	}

	if ca.PublicKey == "" {
		return false, fmt.Errorf("CA public key is not initialized")
	}

	// Validate signature format (hex-encoded, minimum length for ECDSA)
	if len(signatureR) < 32 || len(signatureS) < 32 {
		return false, fmt.Errorf("signature components too short: R=%d, S=%d", len(signatureR), len(signatureS))
	}

	// Decode signature R component
	rBytes, err := hex.DecodeString(signatureR)
	if err != nil {
		return false, fmt.Errorf("invalid signatureR hex: %w", err)
	}

	// Decode signature S component
	sBytes, err := hex.DecodeString(signatureS)
	if err != nil {
		return false, fmt.Errorf("invalid signatureS hex: %w", err)
	}

	// Verify CSR hash is present
	if csrHash == "" {
		return false, fmt.Errorf("empty CSR hash")
	}

	// Decode the message hash
	hashBytes, err := hex.DecodeString(csrHash)
	if err != nil {
		return false, fmt.Errorf("invalid CSR hash hex: %w", err)
	}
	if len(hashBytes) != sha256.Size {
		return false, fmt.Errorf("invalid CSR hash length: got %d, expected %d", len(hashBytes), sha256.Size)
	}

	// Reconstruct the CA's public key from hex
	pubKey, err := reconstructPublicKeyFromHex(ca.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to reconstruct CA public key: %w", err)
	}

	// Convert R and S bytes to big.Int for ECDSA verification
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	// Perform ECDSA signature verification
	valid := ecdsa.Verify(pubKey, hashBytes, r, s)

	if !valid {
		return false, fmt.Errorf("ECDSA signature verification failed")
	}

	return true, nil
}

// evaluates whether Node Revoked
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) IsNodeRevoked(
	ctx contractapi.TransactionContextInterface,
	nodeID string,
) (bool, error) {
	// Check for an active cert via index
	activeCertKey, err := ctx.GetStub().GetState("ACTIVECERT:" + nodeID)
	if err != nil {
		return false, err
	}

	if activeCertKey == nil {
		// No active cert index â€” either never had one or it was revoked
		// Check if there are any certs at all for this member by iterating
		iter, err := ctx.GetStub().GetStateByRange("CERT:", "CERTz")
		if err != nil {
			return false, err
		}
		defer iter.Close()
		for iter.HasNext() {
			kv, err := iter.Next()
			if err != nil {
				continue
			}
			var cert Certificate
			if err := json.Unmarshal(kv.Value, &cert); err != nil {
				continue
			}
			if cert.MemberID == nodeID && cert.IsRevoked {
				return true, nil
			}
		}
		return false, nil
	}

	// Has an active cert index â€” check if that cert is actually active
	certJSON, err := ctx.GetStub().GetState("CERT:" + string(activeCertKey))
	if err != nil {
		return false, err
	}
	if certJSON == nil {
		return false, nil
	}

	var cert Certificate
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return false, err
	}

	return cert.IsRevoked, nil
}

// validates Signature so invalid identities, signatures, and state transitions are rejected before commit.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) VerifySignature(
	ctx contractapi.TransactionContextInterface,
	messageHash string,
	signatureR string,
	signatureS string,
) (bool, error) {
	return c.verifyTSSSignature(ctx, messageHash, signatureR, signatureS)
}

// retrieves CA Public Key from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetCAPublicKey(
	ctx contractapi.TransactionContextInterface,
) (string, error) {
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return "", err
	}
	return ca.PublicKey, nil
}

// ===================== SECURITY QUERY FUNCTIONS =====================

// represents membership statistics per organization
type OrgMembershipStats struct {
	OrgID          string   `json:"orgId"`
	MemberCount    int      `json:"memberCount"`
	MaxMembers     int      `json:"maxMembers"`
	RemainingSlots int      `json:"remainingSlots"`
	Members        []string `json:"members"`
}

// retrieves Org Membership Stats from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetOrgMembershipStats(
	ctx contractapi.TransactionContextInterface,
) ([]OrgMembershipStats, error) {
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return nil, err
	}

	// Group members by org
	orgMembers := make(map[string][]string)
	for _, member := range ca.Members {
		org := extractOrgFromMemberID(member)
		orgMembers[org] = append(orgMembers[org], member)
	}

	var stats []OrgMembershipStats
	var orgIDs []string
	for orgID := range orgMembers {
		if orgID == "unknown" {
			continue
		}
		orgIDs = append(orgIDs, orgID)
	}
	sort.Strings(orgIDs)

	for _, orgID := range orgIDs {
		members := orgMembers[orgID]
		stats = append(stats, OrgMembershipStats{
			OrgID:          orgID,
			MemberCount:    len(members),
			MaxMembers:     -1, // No limit
			RemainingSlots: -1, // No limit
			Members:        members,
		})
	}

	// Add unknown org if any
	if unknownMembers, ok := orgMembers["unknown"]; ok && len(unknownMembers) > 0 {
		stats = append(stats, OrgMembershipStats{
			OrgID:          "unknown",
			MemberCount:    len(unknownMembers),
			MaxMembers:     -1, // No limit for unknown
			RemainingSlots: -1,
			Members:        unknownMembers,
		})
	}

	return stats, nil
}

// represents the current security configuration
type SecurityConfig struct {
	MaxMembersPerOrg      int  `json:"maxMembersPerOrg"`
	MinOrgsForApproval    int  `json:"minOrgsForApproval"`
	SecurityLimitsEnabled bool `json:"securityLimitsEnabled"`
}

// retrieves Security Config from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetSecurityConfig(
	ctx contractapi.TransactionContextInterface,
) (SecurityConfig, error) {
	return SecurityConfig{
		MaxMembersPerOrg:      0, // No limit
		MinOrgsForApproval:    MinOrgsForApproval,
		SecurityLimitsEnabled: EnableSecurityLimits,
	}, nil
}

// contains the result of a validation check
type ValidationResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// validates Member Candidate so invalid identities, signatures, and state transitions are rejected before commit.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) ValidateMemberCandidate(
	ctx contractapi.TransactionContextInterface,
	candidateID string,
) (ValidationResult, error) {
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return ValidationResult{}, err
	}

	// Check if already a member
	if contains(ca.Members, candidateID) {
		return ValidationResult{Valid: false, Message: "candidate is already a member"}, nil
	}

	// Check org limit
	if err := validateMemberOrgLimit(ca.Members, candidateID); err != nil {
		return ValidationResult{Valid: false, Message: err.Error()}, nil
	}

	candidateOrg := extractOrgFromMemberID(candidateID)
	return ValidationResult{Valid: true, Message: fmt.Sprintf("candidate can be added (org: %s)", candidateOrg)}, nil
}

// ===================== CERTIFICATE MERKLE TREE =====================

// derives config key for Merkle tree settings
// Called by: (*DecentralizedPKIContract).GetMerkleEnabled, (*DecentralizedPKIContract).SetMerkleEnabled.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func merkleConfigKey(caID string) string {
	return merkleConfigKeyPrefix + caID
}

// retrieves Merkle Enabled from world state
// Called by: (*DecentralizedPKIContract).GetCertificateMerkleProof, (*DecentralizedPKIContract).GetCertificateMerkleRoot, (*DecentralizedPKIContract).updateCertificateMerkleTree.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetMerkleEnabled(
	ctx contractapi.TransactionContextInterface,
	caID string,
) (bool, error) {
	stateJSON, err := ctx.GetStub().GetState(merkleConfigKey(caID))
	if err != nil {
		return true, err
	}
	if stateJSON == nil {
		return true, nil
	}

	var cfg MerkleConfig
	if err := json.Unmarshal(stateJSON, &cfg); err != nil {
		return true, err
	}
	return cfg.Enabled, nil
}

// applies controlled state transitions for Merkle Enabled
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) SetMerkleEnabled(
	ctx contractapi.TransactionContextInterface,
	caID string,
	enabled bool,
) error {
	caller, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caID)
	if err != nil {
		return err
	}
	if !contains(ca.Members, caller) {
		return fmt.Errorf("only CA members can change Merkle config")
	}

	key := merkleConfigKey(caID)
	if existing, _ := ctx.GetStub().GetState(key); existing != nil {
		var cfg MerkleConfig
		if err := json.Unmarshal(existing, &cfg); err == nil && cfg.Enabled == enabled {
			return nil
		}
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	updatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	cfg := MerkleConfig{
		Enabled:   enabled,
		UpdatedAt: updatedAt,
		UpdatedBy: caller,
	}
	stateJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, stateJSON)
}

// recomputes and persists Merkle tree artifacts after certificate state changes
// Called by: (*DecentralizedPKIContract).RegisterCombinedCertificateWithSignature, (*DecentralizedPKIContract).executeRevocation.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func (c *DecentralizedPKIContract) updateCertificateMerkleTree(
	ctx contractapi.TransactionContextInterface,
	action string,
	triggerCertID string,
	currentCertHash string, // the hash of the cert being registered/revoked
	isRevocation bool, // true = remove currentCertHash, false = add it
) error {
	enabled, err := c.GetMerkleEnabled(ctx, DefaultCAID)
	if err != nil {
		return fmt.Errorf("failed to read Merkle config: %w", err)
	}
	if !enabled {
		return nil
	}

	// Try to reuse existing Merkle state to preserve leaf ordering.
	var leafHashes []string
	stateJSON, err := ctx.GetStub().GetState("MERKLE:CERTS")
	if err == nil && stateJSON != nil {
		var state CertificateMerkleState
		if err := json.Unmarshal(stateJSON, &state); err == nil && len(state.LeafHashes) > 0 {
			leafHashes = append([]string(nil), state.LeafHashes...)
		}
	}

	if len(leafHashes) == 0 {
		// No prior state - build from active certificates in deterministic order.
		type certEntry struct {
			hash     string
			issuedAt time.Time
			certID   string
		}
		entries := make([]certEntry, 0)
		iter, err := ctx.GetStub().GetStateByRange("CERT:", "CERTz")
		if err != nil {
			return fmt.Errorf("failed to iterate certificates: %w", err)
		}
		defer iter.Close()

		for iter.HasNext() {
			kv, err := iter.Next()
			if err != nil {
				return fmt.Errorf("failed to read certificate: %w", err)
			}

			var cert Certificate
			if err := json.Unmarshal(kv.Value, &cert); err != nil {
				continue
			}
			// Only include active (non-revoked) certificates
			if cert.IsRevoked || cert.CertificateHash == "" {
				continue
			}
			entries = append(entries, certEntry{
				hash:     cert.CertificateHash,
				issuedAt: cert.IssuedAt,
				certID:   cert.CertID,
			})
		}

		sort.Slice(entries, func(i, j int) bool {
			if entries[i].issuedAt.Equal(entries[j].issuedAt) {
				return entries[i].certID < entries[j].certID
			}
			return entries[i].issuedAt.Before(entries[j].issuedAt)
		})

		for _, entry := range entries {
			leafHashes = append(leafHashes, entry.hash)
		}
	}

	if currentCertHash != "" {
		if isRevocation {
			for i, h := range leafHashes {
				if h == currentCertHash {
					leafHashes = append(leafHashes[:i], leafHashes[i+1:]...)
					break
				}
			}
		} else {
			exists := false
			for _, h := range leafHashes {
				if h == currentCertHash {
					exists = true
					break
				}
			}
			if !exists {
				leafHashes = append(leafHashes, currentCertHash)
			}
		}
	}

	// Compute Merkle root
	merkleRoot := computeMerkleRoot(leafHashes)

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	updatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	state := CertificateMerkleState{
		MerkleRoot:      merkleRoot,
		ActiveCertCount: len(leafHashes),
		LeafHashes:      leafHashes,
		UpdatedAt:       updatedAt,
		TriggerAction:   action,
		TriggerCertID:   triggerCertID,
	}

	stateJSON, err = json.Marshal(state)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("MERKLE:CERTS", stateJSON)
}

// constructs Merkle Root
// Called by: (*DecentralizedPKIContract).updateCertificateMerkleTree.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func computeMerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Convert hex leaves to byte hashes
	level := make([][]byte, len(leaves))
	for i, h := range leaves {
		b, err := hex.DecodeString(h)
		if err != nil {
			// If we can't decode, hash the string representation
			hash := sha256.Sum256([]byte(h))
			b = hash[:]
		}
		level[i] = b
	}

	// Build tree bottom-up
	for len(level) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				// Hash pair
				combined := append(level[i], level[i+1]...)
				hash := sha256.Sum256(combined)
				nextLevel = append(nextLevel, hash[:])
			} else {
				// Odd element: promote (duplicate)
				combined := append(level[i], level[i]...)
				hash := sha256.Sum256(combined)
				nextLevel = append(nextLevel, hash[:])
			}
		}
		level = nextLevel
	}

	return hex.EncodeToString(level[0])
}

// retrieves Certificate Merkle Root from world state
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetCertificateMerkleRoot(
	ctx contractapi.TransactionContextInterface,
) (*CertificateMerkleState, error) {
	enabled, err := c.GetMerkleEnabled(ctx, DefaultCAID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fmt.Errorf("merkle tree disabled")
	}

	stateJSON, err := ctx.GetStub().GetState("MERKLE:CERTS")
	if err != nil {
		return nil, err
	}
	if stateJSON == nil {
		return &CertificateMerkleState{MerkleRoot: "", ActiveCertCount: 0}, nil
	}

	var state CertificateMerkleState
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// returns an inclusion proof for a certificate hash so clients can independently verify membership in the on-ledger Merkle root.
// Called by: external Fabric client transaction invocation.
// Triggered: Fabric chaincode invoke/query request for this transaction function.
func (c *DecentralizedPKIContract) GetCertificateMerkleProof(
	ctx contractapi.TransactionContextInterface,
	certHash string,
) (string, error) {
	enabled, err := c.GetMerkleEnabled(ctx, DefaultCAID)
	if err != nil {
		return "", err
	}
	if !enabled {
		return "", fmt.Errorf("merkle tree disabled")
	}

	stateJSON, err := ctx.GetStub().GetState("MERKLE:CERTS")
	if err != nil {
		return "", err
	}
	if stateJSON == nil {
		return "", fmt.Errorf("no Merkle state found")
	}

	var state CertificateMerkleState
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		return "", err
	}

	// Find the leaf index
	leafIndex := -1
	for i, h := range state.LeafHashes {
		if h == certHash {
			leafIndex = i
			break
		}
	}
	if leafIndex < 0 {
		return "", fmt.Errorf("certificate hash not found in Merkle tree (may be revoked)")
	}

	// Build the proof
	proof := buildMerkleProof(state.LeafHashes, leafIndex)

	proofJSON, err := json.Marshal(map[string]interface{}{
		"certHash":    certHash,
		"merkleRoot":  state.MerkleRoot,
		"leafIndex":   leafIndex,
		"totalLeaves": len(state.LeafHashes),
		"proof":       proof,
	})
	if err != nil {
		return "", err
	}

	return string(proofJSON), nil
}

// represents one step in a Merkle inclusion proof.
type MerkleProofNode struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// constructs Merkle Proof
// Called by: (*DecentralizedPKIContract).GetCertificateMerkleProof.
// Triggered: internal chaincode helper during governance, DKG/reshare, CSR signing, or query processing.
func buildMerkleProof(leaves []string, targetIndex int) []MerkleProofNode {
	if len(leaves) <= 1 {
		return nil
	}

	// Convert to byte arrays
	level := make([][]byte, len(leaves))
	for i, h := range leaves {
		b, err := hex.DecodeString(h)
		if err != nil {
			hash := sha256.Sum256([]byte(h))
			b = hash[:]
		}
		level[i] = b
	}

	var proof []MerkleProofNode
	idx := targetIndex

	for len(level) > 1 {
		var nextLevel [][]byte

		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				combined := append(level[i], level[i+1]...)
				hash := sha256.Sum256(combined)
				nextLevel = append(nextLevel, hash[:])
			} else {
				combined := append(level[i], level[i]...)
				hash := sha256.Sum256(combined)
				nextLevel = append(nextLevel, hash[:])
			}
		}

		// Record sibling for the proof
		if idx%2 == 0 {
			// Our node is on the left, sibling is on the right
			siblingIdx := idx + 1
			if siblingIdx < len(level) {
				proof = append(proof, MerkleProofNode{
					Hash:     hex.EncodeToString(level[siblingIdx]),
					Position: "right",
				})
			} else {
				// Odd element, sibling is itself (duplicate)
				proof = append(proof, MerkleProofNode{
					Hash:     hex.EncodeToString(level[idx]),
					Position: "right",
				})
			}
		} else {
			// Our node is on the right, sibling is on the left
			proof = append(proof, MerkleProofNode{
				Hash:     hex.EncodeToString(level[idx-1]),
				Position: "left",
			})
		}

		idx = idx / 2
		level = nextLevel
	}

	return proof
}

// starts the chaincode contract runtime so Fabric peers can route invoke/query requests into the decentralized PKI contract methods.
// Called by: entrypoint.
// Triggered: chaincode process startup and contract registration.
func main() {
	chaincode, err := contractapi.NewChaincode(&DecentralizedPKIContract{})
	if err != nil {
		fmt.Printf("Error creating decentralized PKI chaincode: %v\n", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting decentralized PKI chaincode: %v\n", err)
	}
}
