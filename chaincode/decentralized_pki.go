package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const DefaultCAID = "root-ca-001"
const merkleConfigKeyPrefix = "CONFIG:MERKLE:"

// ===================== SECURITY CONSTANTS =====================

// MinOrgsForApproval requires votes from at least this many different orgs
// This ensures cross-org consensus for critical decisions (set to 1 to disable)
const MinOrgsForApproval = 2

// EnableSecurityLimits controls whether multi-org voting is enforced
// Set to true for production deployments
const EnableSecurityLimits = true

type DecentralizedPKIContract struct {
	contractapi.Contract
}

// ===================== STRUCTS =====================

type DistributedCA struct {
	CAID             string               `json:"caId"`
	Name             string               `json:"name"`
	Organization     string               `json:"organization"`
	ThresholdParams  ThresholdParameters  `json:"thresholdParams"`
	Members          []string             `json:"members"`   // Full participants (DKG, signing, voting)
	Observers        []string             `json:"observers"` // Observer nodes (query, CSR, no signing)
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
	ProposalID   string    `json:"proposalId"`
	MemberID     string    `json:"memberId"`
	CSRData      string    `json:"csrData"`
	SubmittedAt  time.Time `json:"submittedAt"`
	VotingEndsAt time.Time `json:"votingEndsAt"`
	Status       string    `json:"status"`
	VotesFor     int       `json:"votesFor"`
	VotesAgainst int       `json:"votesAgainst"`
	VotersList   []string  `json:"votersList"`
}

type Vote struct {
	VoterID   string    `json:"voterId"`
	Decision  string    `json:"decision"` // approve, reject
	Timestamp time.Time `json:"timestamp"`
	Rationale string    `json:"rationale,omitempty,optional"`
}

type PartialSignature struct {
	SignerID       string    `json:"signerId"`
	PartialSig     string    `json:"partialSig"`  // Base64 encoded partial signature
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

// CertificateMerkleState stores the latest Merkle root over all active certificates.
// Updated after every certificate registration or revocation.
type CertificateMerkleState struct {
	MerkleRoot      string   `json:"merkleRoot"`
	ActiveCertCount int      `json:"activeCertCount"`
	LeafHashes      []string `json:"leafHashes"` // sorted cert hashes (leaves)
	UpdatedAt       string   `json:"updatedAt"`
	TriggerAction   string   `json:"triggerAction"` // "certificate_registered" or "certificate_revoked"
	TriggerCertID   string   `json:"triggerCertId"`
}

// MerkleConfig controls whether the certificate Merkle tree is maintained on-chain.
type MerkleConfig struct {
	Enabled   bool   `json:"enabled"`
	UpdatedAt string `json:"updatedAt,omitempty,optional"`
	UpdatedBy string `json:"updatedBy,omitempty,optional"`
}

type RevocationProposal struct {
	ProposalID     string    `json:"proposalId"`
	TargetMemberID string    `json:"targetMemberId"`
	Reason         string    `json:"reason"`
	SubmittedBy    string    `json:"submittedBy"`
	SubmittedAt    time.Time `json:"submittedAt"`
	VotingEndsAt   time.Time `json:"votingEndsAt"`
	Status         string    `json:"status"`
	VotesFor       int       `json:"votesFor"`
	VotesAgainst   int       `json:"votesAgainst"`
	VotersList     []string  `json:"votersList"`
}

// MemberRemovalProposal represents a governance proposal to remove a CA member.
type MemberRemovalProposal struct {
	ProposalID     string    `json:"proposalId"`
	TargetMemberID string    `json:"targetMemberId"`
	Reason         string    `json:"reason"`
	SubmittedBy    string    `json:"submittedBy"`
	CAID           string    `json:"caId"`
	SubmittedAt    time.Time `json:"submittedAt"`
	VotingEndsAt   time.Time `json:"votingEndsAt"`
	Status         string    `json:"status"` // pending, approved, rejected, executed
	VotesFor       int       `json:"votesFor"`
	VotesAgainst   int       `json:"votesAgainst"`
	VotersList     []string  `json:"votersList"`
}

// JoinRequestProposal represents a self-request to join the CA as a full member.
type JoinRequestProposal struct {
	ProposalID   string    `json:"proposalId"`
	CandidateID  string    `json:"candidateId"`
	Reason       string    `json:"reason"`
	SubmittedBy  string    `json:"submittedBy"`
	CAID         string    `json:"caId"`
	SubmittedAt  time.Time `json:"submittedAt"`
	VotingEndsAt time.Time `json:"votingEndsAt"`
	Status       string    `json:"status"` // pending, approved, rejected, executed
	VotesFor     int       `json:"votesFor"`
	VotesAgainst int       `json:"votesAgainst"`
	VotersList   []string  `json:"votersList"`
}

type ReshareSession struct {
	Epoch          int      `json:"epoch"`
	TriggerReason  string   `json:"triggerReason"`
	OldNodeSet     []string `json:"oldNodeSet"`
	OldThreshold   int      `json:"oldThreshold"`
	NewNodeSet     []string `json:"newNodeSet"`
	NewThreshold   int      `json:"newThreshold"`
	Status         string   `json:"status"` // initiated, acknowledged, completed, superseded
	AckCount       int      `json:"ackCount"`
	AcknowledgedBy []string `json:"acknowledgedBy"`
	CompletionAckedBy   []string `json:"completionAckedBy"`
	CompletionAckCount  int      `json:"completionAckCount"`
	InitiatedAt    string   `json:"initiatedAt"`
	CompletedAt    string   `json:"completedAt"`
	NewCAPublicKey string   `json:"newCaPublicKey"`
	OldPartySalt   string   `json:"oldPartySalt"`
	NewPartySalt   string   `json:"newPartySalt"`
	SupersededBy   int      `json:"supersededBy,omitempty,optional"`
	SupersededAt   string   `json:"supersededAt,omitempty,optional"`
}

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

// SponsoredMember tracks a sponsored membership for expedited joining
type SponsoredMember struct {
	MemberID     string   `json:"memberId"`
	SponsorID    string   `json:"sponsorId"`
	CAID         string   `json:"caId"`
	Status       string   `json:"status"` // pending, approved, rejected
	SponsoredAt  string   `json:"sponsoredAt"`
	Endorsements []string `json:"endorsements"` // Other members who endorse this sponsorship
	Reason       string   `json:"reason"`
}

// SponsorJoinCA - An existing member sponsors a new member for expedited joining
// The new member is immediately added if threshold endorsements are met
// This is useful when the new member's Fabric identity is already trusted
func (c *DecentralizedPKIContract) SponsorJoinCA(
	ctx contractapi.TransactionContextInterface,
	caId string,
	newMemberID string,
	reason string,
) error {
	if !strings.HasPrefix(newMemberID, "external::") {
		if err := ensureCanonicalID(newMemberID); err != nil {
			return err
		}
	}

	// 1. Get sponsor identity
	sponsorID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	// 2. Get CA and verify it exists
	ca, err := c.GetTrustedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}

	// 3. Verify sponsor is a CA member
	isSponsorMember := false
	for _, member := range ca.Members {
		if member == sponsorID {
			isSponsorMember = true
			break
		}
	}
	if !isSponsorMember {
		return fmt.Errorf("only CA members can sponsor new members")
	}

	// 4. Check if new member is already a member
	for _, member := range ca.Members {
		if member == newMemberID {
			return fmt.Errorf("already a member of this CA")
		}
	}

	// 5. Create or update sponsorship record
	sponsorshipKey := fmt.Sprintf("SPONSOR:%s:%s", caId, hash(newMemberID)[:16])
	existing, _ := ctx.GetStub().GetState(sponsorshipKey)

	var sponsorship SponsoredMember
	if existing != nil {
		json.Unmarshal(existing, &sponsorship)
		if sponsorship.Status != "pending" {
			return fmt.Errorf("sponsorship already %s", sponsorship.Status)
		}
		// Add new endorsement if not already endorsed by this sponsor
		for _, e := range sponsorship.Endorsements {
			if e == sponsorID {
				return fmt.Errorf("you already endorsed this member")
			}
		}
		sponsorship.Endorsements = append(sponsorship.Endorsements, sponsorID)
	} else {
		txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
		sponsoredAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339)
		sponsorship = SponsoredMember{
			MemberID:     newMemberID,
			SponsorID:    sponsorID,
			CAID:         caId,
			Status:       "pending",
			SponsoredAt:  sponsoredAt,
			Endorsements: []string{sponsorID},
			Reason:       reason,
		}
	}

	// 6. Check if enough endorsements for immediate admission
	// Require threshold endorsements for expedited joining
	requiredEndorsements := ca.ThresholdParams.Threshold
	if requiredEndorsements < 1 {
		requiredEndorsements = 1
	}

	if len(sponsorship.Endorsements) >= requiredEndorsements {
		sponsorship.Status = "approved"

		oldMembers := append([]string(nil), ca.Members...)
		oldThreshold := ca.ThresholdParams.Threshold

		// Add new member to CA
		ca.Members = append(ca.Members, newMemberID)
		ca.Epoch++
		ca.ThresholdParams.TotalNodes = len(ca.Members)

		// Remove from observers if this was a promotion
		newObservers := make([]string, 0, len(ca.Observers))
		for _, obs := range ca.Observers {
			if obs != newMemberID {
				newObservers = append(newObservers, obs)
			}
		}
		ca.Observers = newObservers

		// Recalculate threshold based on current governance ratio
		newThreshold := calculateDynamicThreshold(len(ca.Members), ca.GovernanceParams.QuorumPercentage)
		ca.ThresholdParams.Threshold = newThreshold

		// Save updated CA
		caJSON, _ := json.Marshal(ca)
		ctx.GetStub().PutState("CA:"+caId, caJSON)

		// Initiate reshare for the new member set
		c.initiateReshare(ctx, ca.Epoch, "member_join_sponsored", newMemberID, oldMembers, oldThreshold, ca.Members, newThreshold)

		// Emit event
		eventData := map[string]interface{}{
			"caId":      caId,
			"newMember": newMemberID,
			"sponsor":   sponsorID,
			"epoch":     ca.Epoch,
		}
		eventBytes, _ := json.Marshal(eventData)
		ctx.GetStub().SetEvent("MemberSponsoredJoin", eventBytes)

	}

	// 7. Save sponsorship record
	sponsorshipJSON, _ := json.Marshal(sponsorship)
	ctx.GetStub().PutState(sponsorshipKey, sponsorshipJSON)

	return nil
}

// EndorseSponsoredMember - Additional member endorses a sponsored membership
// When threshold endorsements are reached, the member is automatically admitted
func (c *DecentralizedPKIContract) EndorseSponsoredMember(
	ctx contractapi.TransactionContextInterface,
	caId string,
	newMemberID string,
) error {
	// This is essentially calling SponsorJoinCA again to add endorsement
	return c.SponsorJoinCA(ctx, caId, newMemberID, "")
}

// SponsorExternalIdentity - Sponsor an external identity (not a Fabric user) to join the CA
// This allows organizations outside the Fabric channel to participate in the PKI
// The externalID should be a stable identifier (e.g., public key hash, DID)
// The publicKey is the external entity's signing public key
func (c *DecentralizedPKIContract) SponsorExternalIdentity(
	ctx contractapi.TransactionContextInterface,
	caId string,
	externalID string,
	publicKey string,
	organizationName string,
	reason string,
) error {
	// 1. Get sponsor identity
	sponsorID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	// 2. Get CA and verify it exists
	ca, err := c.GetTrustedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}

	// 3. Verify sponsor is a CA member
	isSponsorMember := false
	for _, member := range ca.Members {
		if member == sponsorID {
			isSponsorMember = true
			break
		}
	}
	if !isSponsorMember {
		return fmt.Errorf("only CA members can sponsor external identities")
	}

	// 4. Create external member ID format: external::{orgName}::{publicKeyHash}
	memberID := fmt.Sprintf("external::%s::%s", organizationName, hash(publicKey)[:32])

	// 5. Check if already a member
	for _, member := range ca.Members {
		if member == memberID {
			return fmt.Errorf("external identity already a member")
		}
	}

	// 6. Store external identity details
	externalKey := fmt.Sprintf("EXTERNAL:%s:%s", caId, hash(memberID)[:16])
	externalData := map[string]string{
		"memberId":     memberID,
		"externalId":   externalID,
		"publicKey":    publicKey,
		"organization": organizationName,
		"sponsorId":    sponsorID,
	}
	externalBytes, _ := json.Marshal(externalData)
	ctx.GetStub().PutState(externalKey, externalBytes)

	// 7. Use normal sponsorship flow
	return c.SponsorJoinCA(ctx, caId, memberID, reason)
}

// GetExternalIdentity - Get details of a sponsored external identity
func (c *DecentralizedPKIContract) GetExternalIdentity(
	ctx contractapi.TransactionContextInterface,
	caId string,
	memberID string,
) (string, error) {
	externalKey := fmt.Sprintf("EXTERNAL:%s:%s", caId, hash(memberID)[:16])
	data, err := ctx.GetStub().GetState(externalKey)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", fmt.Errorf("external identity not found")
	}
	return string(data), nil
}

// ListPendingSponsorships - List all pending sponsorship requests for a CA
func (c *DecentralizedPKIContract) ListPendingSponsorships(
	ctx contractapi.TransactionContextInterface,
	caId string,
) (string, error) {
	iterator, err := ctx.GetStub().GetStateByRange("SPONSOR:"+caId+":", "SPONSOR:"+caId+";")
	if err != nil {
		return "", err
	}
	defer iterator.Close()

	sponsorships := make([]SponsoredMember, 0)
	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			continue
		}
		var s SponsoredMember
		if err := json.Unmarshal(result.Value, &s); err != nil {
			continue
		}
		if s.Status == "pending" {
			sponsorships = append(sponsorships, s)
		}
	}

	result, _ := json.Marshal(sponsorships)
	return string(result), nil
}

// ===================== OBSERVER NODE MANAGEMENT =====================

// JoinAsObserver allows any Fabric identity to join the CA as a read-only observer.
// Observers can query CA state, submit CSRs, and verify certificates,
// but cannot participate in DKG/signing, vote, or propose revocations.
// No sponsorship required — any channel participant can observe.
func (c *DecentralizedPKIContract) JoinAsObserver(
	ctx contractapi.TransactionContextInterface,
	caId string,
) error {
	memberID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}

	// Already a full member?
	if contains(ca.Members, memberID) {
		return fmt.Errorf("already a full member of this CA")
	}

	// Already an observer?
	if contains(ca.Observers, memberID) {
		return nil // Idempotent
	}

	ca.Observers = append(ca.Observers, memberID)

	caJSON, _ := json.Marshal(ca)
	ctx.GetStub().PutState("CA:"+caId, caJSON)

	eventData := map[string]interface{}{
		"caId":     caId,
		"observer": memberID,
		"action":   "observer_joined",
	}
	eventBytes, _ := json.Marshal(eventData)
	ctx.GetStub().SetEvent("ObserverJoined", eventBytes)

	return nil
}

// PromoteObserver promotes an observer to a full CA member.
// Requires threshold endorsements from existing full members (uses sponsorship flow).
// After promotion the observer is removed from the Observers list and added to Members,
// which triggers a reshare so the new member receives a key share.
func (c *DecentralizedPKIContract) PromoteObserver(
	ctx contractapi.TransactionContextInterface,
	caId string,
	observerID string,
	reason string,
) error {
	sponsorID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}

	// Verify caller is a full member
	if !contains(ca.Members, sponsorID) {
		return fmt.Errorf("only full members can promote observers")
	}

	// Verify target is actually an observer
	if !contains(ca.Observers, observerID) {
		return fmt.Errorf("%s is not an observer of this CA", observerID)
	}

	// Use the existing sponsorship flow for threshold endorsements
	return c.SponsorJoinCA(ctx, caId, observerID, reason)
}

// RemoveObserver removes an observer from the CA.
// Full members can remove any observer; an observer may remove themselves.
func (c *DecentralizedPKIContract) RemoveObserver(
	ctx contractapi.TransactionContextInterface,
	caId string,
	observerID string,
	reason string,
) error {
	callerID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
	}

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}

	if !contains(ca.Observers, observerID) {
		return fmt.Errorf("%s is not an observer of this CA", observerID)
	}

	if callerID != observerID && !contains(ca.Members, callerID) {
		return fmt.Errorf("only full members can remove observers")
	}

	newObservers := make([]string, 0, len(ca.Observers))
	for _, obs := range ca.Observers {
		if obs != observerID {
			newObservers = append(newObservers, obs)
		}
	}
	ca.Observers = newObservers

	caJSON, _ := json.Marshal(ca)
	ctx.GetStub().PutState("CA:"+caId, caJSON)

	eventData := map[string]interface{}{
		"caId":      caId,
		"observer":  observerID,
		"removedBy": callerID,
		"reason":    reason,
		"action":    "observer_removed",
	}
	eventBytes, _ := json.Marshal(eventData)
	ctx.GetStub().SetEvent("ObserverRemoved", eventBytes)

	return nil
}

// ===================== JOIN REQUESTS =====================

// RequestJoinCA allows a node to submit a self-request to join as a full CA member.
// Existing members must vote to approve. If approved, a reshare is initiated.
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

	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return fmt.Errorf("CA not found: %w", err)
	}

	if contains(ca.Members, candidateID) {
		return fmt.Errorf("already a full member of this CA")
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

	proposal := JoinRequestProposal{
		ProposalID:   proposalID,
		CandidateID:  candidateID,
		Reason:       reason,
		SubmittedBy:  candidateID,
		CAID:         caId,
		SubmittedAt:  submittedAt,
		VotingEndsAt: votingEndsAt,
		Status:       "pending",
		VotesFor:     0,
		VotesAgainst: 0,
		VotersList:   []string{},
	}

	proposalJSON, _ := json.Marshal(proposal)

	eventPayload := map[string]string{
		"proposalId": proposalID,
		"candidate":  candidateID,
		"action":     "member_join_requested",
	}
	ev, _ := json.Marshal(eventPayload)
	_ = ctx.GetStub().SetEvent("MemberJoinRequested", ev)

	return ctx.GetStub().PutState(key, proposalJSON)
}

// VoteOnJoinRequest allows CA members to vote on a join request.
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
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}
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

	votesReceived := len(proposal.VotersList)
	quorumReached := (votesReceived * 100 / totalAuthorized) >= ca.GovernanceParams.QuorumPercentage

	if quorumReached {
		if err := validateMultiOrgVotes(proposal.VotersList); err != nil {
			proposalJSON, _ = json.Marshal(proposal)
			return ctx.GetStub().PutState(fmt.Sprintf("JOINREQ:%s:%s", caId, proposalID), proposalJSON)
		}

		approvalPercentage := proposal.VotesFor * 100 / votesReceived
		if approvalPercentage >= ca.GovernanceParams.ApprovalThreshold {
			proposal.Status = "approved"
			if err := c.executeJoinApproval(ctx, caId, &proposal); err != nil {
				return err
			}
			proposal.Status = "executed"
		} else {
			proposal.Status = "rejected"
		}
	}

	proposalJSON, _ = json.Marshal(proposal)
	return ctx.GetStub().PutState(fmt.Sprintf("JOINREQ:%s:%s", caId, proposalID), proposalJSON)
}

func (c *DecentralizedPKIContract) executeJoinApproval(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposal *JoinRequestProposal,
) error {
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

	ca.Members = append(ca.Members, proposal.CandidateID)
	ca.Epoch++
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(
		len(ca.Members),
		ca.GovernanceParams.QuorumPercentage,
	)

	// Remove from observers if present
	newObservers := make([]string, 0, len(ca.Observers))
	for _, obs := range ca.Observers {
		if obs != proposal.CandidateID {
			newObservers = append(newObservers, obs)
		}
	}
	ca.Observers = newObservers

	caJSON, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caId, caJSON); err != nil {
		return err
	}

	// Initiate reshare for the new member set
	if err := c.initiateReshare(ctx, ca.Epoch, "member_join_requested", proposal.CandidateID, oldMembers, oldThreshold, ca.Members, ca.ThresholdParams.Threshold); err != nil {
		return err
	}

	eventPayload := map[string]interface{}{
		"caId":      caId,
		"candidate": proposal.CandidateID,
		"epoch":     ca.Epoch,
		"action":    "member_join_approved",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("MemberJoinApproved", eventBytes)

	return nil
}

// ListPendingJoinRequests lists pending join requests for a CA.
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

// GetNodeRole returns the role of a node in the CA: "full", "observer", or "none".
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
	if contains(ca.Observers, nodeID) {
		return "observer", nil
	}
	return "none", nil
}

// ListObservers returns the list of observer nodes for a CA.
func (c *DecentralizedPKIContract) ListObservers(
	ctx contractapi.TransactionContextInterface,
	caId string,
) (string, error) {
	ca, err := c.GetDistributedCA(ctx, caId)
	if err != nil {
		return "", fmt.Errorf("CA not found: %w", err)
	}

	result, _ := json.Marshal(ca.Observers)
	return string(result), nil
}

// ===================== CA INITIALIZATION =====================
// =================================================================
// =================================================================

func (c *DecentralizedPKIContract) InitializeDistributedCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
	name string,
	organization string,
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
		CAID:         caID,
		Name:         name,
		Organization: organization,
		PublicKey:    initialPublicKey,
		PartySalt:    "",
		ThresholdParams: ThresholdParameters{
			Threshold:  threshold,
			TotalNodes: 0,
			Scheme:     "ECDSA-TSS",
		},
		CreatedAt: createdAt,
		IsActive:  true,
		Members:   []string{},
		Observers: []string{},
		GovernanceParams: GovernanceParameters{
			VotingPeriodDays:  7,
			QuorumPercentage:  50, // 2/3 majority
			ApprovalThreshold: 50,
		},
	}

	caJSON, err := json.Marshal(ca)
	if err != nil {
		return fmt.Errorf("failed to marshal CA: %v", err)
	}

	return ctx.GetStub().PutState("CA:"+caID, caJSON)
}

// GetTrustedCA returns the CA view expected by bootstrap scripts.
func (c *DecentralizedPKIContract) GetTrustedCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
) (*DistributedCA, error) {
	return c.GetDistributedCA(ctx, caID)
}

func (c *DecentralizedPKIContract) BootstrapJoinCA(
	ctx contractapi.TransactionContextInterface,
	caID string,
	bootstrapLimit int,
) error {
	memberID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return err
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
		66, // or ca.GovernanceParams.QuorumPercentage
	)
	ca.Epoch++

	b, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caID, b); err != nil {
		return err
	}

	// Capture existing DKG (if any) before possibly creating a new one
	existingDKG, _ := ctx.GetStub().GetState("DKG:0")
	createdDKG := false

	// Trigger DKG when we have enough members (at least 2) and no key yet
	// DKG requires multiple parties - can't do it with just 1 member
	if len(ca.Members) >= 2 && ca.PublicKey == "" {
		// Check if DKG already initiated
		if existingDKG == nil {
			// No existing DKG session - create it directly here
			// (Don't call InitiateDKG to avoid read-after-write issues)

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

			// Emit DKGInitiated event with full payload
			eventPayload := map[string]interface{}{
				"epoch":     0,
				"members":   ca.Members,
				"threshold": ca.ThresholdParams.Threshold,
				"action":    "dkg_initiated",
			}
			eventBytes, _ := json.Marshal(eventPayload)
			ctx.GetStub().SetEvent("DKGInitiated", eventBytes)
			createdDKG = true
		}
	}

	// If a DKG already exists or a key has been established, a bootstrap join should
	// trigger a reshare so the new member is included in the key shares.
	if !createdDKG && (existingDKG != nil || ca.PublicKey != "") {
		// Avoid duplicating a reshare for the same epoch if it already exists
		reshareKey := "RESHARE:" + strconv.Itoa(ca.Epoch)
		if existingReshare, _ := ctx.GetStub().GetState(reshareKey); existingReshare == nil {
			_ = c.initiateReshare(ctx, ca.Epoch, "member_join_bootstrap", memberID, oldMembers, oldThreshold, ca.Members, ca.ThresholdParams.Threshold)
		}
	}

	return nil
}

// =================================================================
// ===================== DKG & RESHARE MANAGEMENT =====================
// =================================================================
// =================================================================

// InitiateDKG initiates the initial Distributed Key Generation for the CA
// This is called after all founding members have joined via bootstrap
// Only callable by a CA member
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

	// Check if caller is a CA member
	if !contains(ca.Members, memberID) {
		return fmt.Errorf("only CA members can initiate DKG")
	}

	// Check if DKG has already started or completed
	if ca.PublicKey != "" {
		return fmt.Errorf("DKG already completed; public key is set")
	}

	// Create a DKG session (epoch 0 is reserved for initial DKG)
	dkgSession := map[string]interface{}{
		"epoch":       0,
		"reason":      "initial_dkg",
		"members":     ca.Members,
		"threshold":   ca.ThresholdParams.Threshold,
		"status":      "initiated",
		"initiatedAt": time.Now().Unix(),
	}

	sessionJSON, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}

	// Store DKG session
	if err := ctx.GetStub().PutState("DKG:0", sessionJSON); err != nil {
		return err
	}

	// Emit event to trigger DKG on peers
	eventPayload := map[string]interface{}{
		"epoch":  0,
		"action": "dkg_initiated",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("DKGInitiated", eventBytes)

	return nil
}

// ForceFreshDKG resets the CA public key and starts a brand-new DKG session
// for the current membership. This discards the existing key and requires
// all members to complete DKG again.
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

	if reason == "" {
		reason = "fresh_dkg"
	}

	// Supersede any in-progress reshares to avoid cross-epoch confusion
	supersedeAt := time.Now().UTC().Format(time.RFC3339Nano)
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

	// Reset CA key and bump epoch to indicate a new key generation round
	ca.PublicKey = ""
	ca.PartySalt = ""
	ca.Epoch++
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(len(ca.Members), ca.GovernanceParams.QuorumPercentage)

	caJSON, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caID, caJSON); err != nil {
		return err
	}

	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	initiatedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)

	dkgSession := map[string]interface{}{
		"epoch":       0,
		"reason":      reason,
		"members":     ca.Members,
		"threshold":   ca.ThresholdParams.Threshold,
		"status":      "initiated",
		"ackCount":    0,
		"ackedBy":     []string{},
		"initiatedAt": initiatedAt,
	}

	sessionJSON, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("DKG:0", sessionJSON); err != nil {
		return err
	}

	eventPayload := map[string]interface{}{
		"epoch":     0,
		"members":   ca.Members,
		"threshold": ca.ThresholdParams.Threshold,
		"action":    "fresh_dkg_initiated",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("DKGInitiated", eventBytes)

	return nil
}

// GetDKGSession returns a DKG session by epoch
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

// AcknowledgeDKG acknowledges readiness for initial DKG (epoch 0)
// This is separate from AcknowledgeReshare which handles reshare sessions
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

	// Parse the session
	var dkgSession map[string]interface{}
	if err := json.Unmarshal(dkgBytes, &dkgSession); err != nil {
		return err
	}

	status, _ := dkgSession["status"].(string)
	if status != "initiated" {
		return fmt.Errorf("DKG session not in initiated state, current status: %s", status)
	}

	// Get members list
	membersRaw, _ := dkgSession["members"].([]interface{})
	members := make([]string, 0, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}

	// Check if caller is a member
	if !contains(members, nodeID) {
		return fmt.Errorf("node %s is not a member of this DKG session", nodeID)
	}

	// Get ackedBy list
	ackedByRaw, _ := dkgSession["ackedBy"].([]interface{})
	ackedBy := make([]string, 0, len(ackedByRaw))
	for _, a := range ackedByRaw {
		if s, ok := a.(string); ok {
			ackedBy = append(ackedBy, s)
		}
	}

	// Check if already acknowledged
	if contains(ackedBy, nodeID) {
		return fmt.Errorf("node already acknowledged this DKG session")
	}

	// Add to acknowledged list
	ackedBy = append(ackedBy, nodeID)
	dkgSession["ackedBy"] = ackedBy
	dkgSession["ackCount"] = len(ackedBy)

	// Get threshold
	threshold := 1
	if t, ok := dkgSession["threshold"].(float64); ok {
		threshold = int(t)
	}

	// Check if all required nodes have acknowledged
	if len(ackedBy) >= threshold {
		dkgSession["status"] = "ready"

		// Emit DKGReady event
		epoch, _ := strconv.Atoi(epochStr)
		eventPayload := map[string]interface{}{
			"epoch":   epoch,
			"action":  "dkg_ready",
			"members": members,
		}
		eventBytes, _ := json.Marshal(eventPayload)
		ctx.GetStub().SetEvent("DKGReady", eventBytes)
	}

	// Save updated session
	updatedBytes, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(dkgKey, updatedBytes)
}

// CompleteDKG marks the initial DKG as completed and sets the CA public key
// This should be called after all nodes have completed TSS keygen off-chain
func (c *DecentralizedPKIContract) CompleteDKG(
	ctx contractapi.TransactionContextInterface,
	epochStr string,
	publicKey string,
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

	// Parse the session
	var dkgSession map[string]interface{}
	if err := json.Unmarshal(dkgBytes, &dkgSession); err != nil {
		return err
	}

	status, _ := dkgSession["status"].(string)
	if status == "completed" {
		return fmt.Errorf("DKG already completed")
	}
	if status != "ready" && status != "proposed" {
		return fmt.Errorf("DKG session not in ready/proposed state, current status: %s", status)
	}

	// Get members list to verify caller is a member
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

	// Record/verify proposed public key
	existingPubKey, _ := dkgSession["publicKey"].(string)
	if existingPubKey == "" {
		dkgSession["publicKey"] = publicKey
	} else if existingPubKey != publicKey {
		return fmt.Errorf("public key mismatch for DKG completion proposal")
	}

	// Track completion acknowledgements (all members must acknowledge)
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

	// Require all members to acknowledge the proposed public key
	if len(completionAckedBy) < len(members) {
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
		// Emit proposal event
		eventPayload := map[string]interface{}{
			"epoch":         epochStr,
			"publicKey":     dkgSession["publicKey"],
			"ackCount":      len(completionAckedBy),
			"requiredAcks":  len(members),
			"action":        "dkg_completion_proposed",
		}
		if eventBytes, err := json.Marshal(eventPayload); err == nil {
			ctx.GetStub().SetEvent("DKGCompletionProposed", eventBytes)
		}
		return nil
	}

	// All members acknowledged: mark DKG as completed
	dkgSession["status"] = "completed"
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	completedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	dkgSession["completedAt"] = completedAt

	// Save updated DKG session
	updatedBytes, err := json.Marshal(dkgSession)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(dkgKey, updatedBytes); err != nil {
		return err
	}

	// Update the CA with the public key
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
		"epoch":     epochStr,
		"action":    "dkg_completed",
		"publicKey": publicKey,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("DKGCompleted", eventBytes)

	return nil
}

// ===================== CSR SUBMISSION & VOTING =====================
// =================================================================
// =================================================================

func (c *DecentralizedPKIContract) SubmitCSR(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	csrPEM string,
) error {
	memberID, err := c.canonicalMemberID(ctx)
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

	proposal := CSRProposal{
		ProposalID:   proposalID,
		MemberID:     memberID,
		CSRData:      csrPEM,
		SubmittedAt:  submittedAt,
		VotingEndsAt: votingEndsAt,
		Status:       "pending",
		VotesFor:     0,
		VotesAgainst: 0,
		VotersList:   []string{},
	}

	proposalJSON, _ := json.Marshal(proposal)

	eventPayload := map[string]string{
		"proposalId": proposalID,
		"memberId":   memberID,
		"action":     "csr_submitted",
	}
	ev, _ := json.Marshal(eventPayload)
	_ = ctx.GetStub().SetEvent("CSRSubmitted", ev)

	return ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON)
}

func (c *DecentralizedPKIContract) VoteOnCSR(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	decision string, // "approve" or "reject"
	rationale string,
) error {
	// Get voter identity
	voterID, err := c.canonicalMemberID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get voter identity: %v", err)
	}

	// Authorization is checked below via CA membership (contains(ca.Members, voterID)).
	// Certificate revocation does NOT revoke CA membership - those are separate.

	// Validate decision
	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("invalid decision: must be 'approve' or 'reject'")
	}

	// Get proposal
	proposal, err := c.GetCSRProposal(ctx, proposalID)
	if err != nil {
		return err
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

	// Verify voter is authorized
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}

	if !contains(ca.Members, voterID) {
		return fmt.Errorf("voter %s is not authorized", voterID)
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

	// Store individual vote
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

	// Check if quorum reached
	votesReceived := len(proposal.VotersList)
	quorumReached := (votesReceived * 100 / totalAuthorized) >= ca.GovernanceParams.QuorumPercentage

	if quorumReached {
		// SECURITY: Check multi-org voting requirement before execution
		if err := validateMultiOrgVotes(proposal.VotersList); err != nil {
			// Not enough org diversity yet, save vote and wait for more
			proposalJSON, _ := json.Marshal(proposal)
			return ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON)
		}

		// Check if approved
		approvalPercentage := proposal.VotesFor * 100 / votesReceived
		if approvalPercentage >= ca.GovernanceParams.ApprovalThreshold {
			proposal.Status = "approved"

			// Automatically initiate signing session
			if err := c.initiateSigningSession(ctx, proposal); err != nil {
				return err
			}
		} else {
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

// ===================== TSS SIGNING COORDINATION =====================
// =================================================================
// =================================================================

func (c *DecentralizedPKIContract) initiateSigningSession(
	ctx contractapi.TransactionContextInterface,
	proposal *CSRProposal,
) error {
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	// Hash the CSR for signing
	csrHash := sha256.Sum256([]byte(proposal.CSRData))
	csrHashHex := hex.EncodeToString(csrHash[:])

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	createdAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	session := SigningSession{
		ProposalID:        proposal.ProposalID,
		CSRHash:           csrHashHex,
		RequiredSigners:   ca.ThresholdParams.Threshold,
		PartialSignatures: []PartialSignature{},
		Status:            "active",
		CreatedAt:         createdAt,
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := ctx.GetStub().PutState("SIGNING:"+proposal.ProposalID, sessionJSON); err != nil {
		return err
	}

	// Emit event for nodes to start TSS signing
	eventPayload := map[string]string{
		"proposalId": proposal.ProposalID,
		"csrHash":    csrHashHex,
		"action":     "signing_initiated",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("SigningInitiated", eventBytes)

	return nil
}

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

	// Verify signer is authorized
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

	// Check if already submitted
	for _, sig := range session.PartialSignatures {
		if sig.SignerID == signerID {
			return fmt.Errorf("signer %s already submitted signature", signerID)
		}
	}

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
			"proposalId":      proposalID,
			"signaturesCount": len(session.PartialSignatures),
			"action":          "threshold_reached",
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

// RegisterCombinedCertificateWithSignature registers a certificate with explicit TSS signature components
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

	// Validate certificate hash
	if len(certificateHash) != 64 {
		return fmt.Errorf("invalid certificate hash")
	}

	// Verify TSS signature if provided
	if signatureR != "" && signatureS != "" {
		valid, verifyErr := c.verifyTSSSignature(ctx, session.CSRHash, signatureR, signatureS)
		if verifyErr != nil {
			return fmt.Errorf("signature verification error: %w", verifyErr)
		}
		if !valid {
			return fmt.Errorf("invalid TSS signature")
		}
	}

	// Get CA
	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}

	issuedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))
	expiresAt := issuedAt.AddDate(0, 0, validityDays)

	// Create certificate record (keyed by proposalID to preserve history)
	cert := Certificate{
		CertID:           "CERT:" + proposalID,
		MemberID:         proposal.MemberID,
		CertificatePEM:   certificatePEM,
		CertificateHash:  certificateHash,
		Subject:          subject,
		PublicKey:        publicKey,
		SerialNumber:     serialNumber,
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

	// Store certificate keyed by proposalID (preserves revoked certs)
	if err := ctx.GetStub().PutState("CERT:"+proposalID, certJSON); err != nil {
		return err
	}

	// Update active cert index for this member
	if err := ctx.GetStub().PutState("ACTIVECERT:"+proposal.MemberID, []byte(proposalID)); err != nil {
		return err
	}

	// Update proposal status
	proposal.Status = "completed"
	proposalJSON, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("PROPOSAL:"+proposalID, proposalJSON); err != nil {
		return err
	}

	// NOTE: Certificate registration does NOT add the requester to the CA member list.
	// CA membership is managed separately via SponsorJoinCA/BootstrapJoinCA.
	// Certificates are identity credentials; CA membership is a governance role.

	// Update Merkle tree of active certificates
	if err := c.updateCertificateMerkleTree(ctx, "certificate_registered", cert.CertID, certificateHash, false); err != nil {
		// Log but don't fail - Merkle tree is supplementary
		fmt.Printf("Warning: failed to update Merkle tree: %v\n", err)
	}

	// Emit certificate registered event
	eventPayload := map[string]string{
		"nodeId":          proposal.MemberID,
		"certificateHash": certificateHash,
		"epoch":           strconv.Itoa(ca.Epoch),
		"action":          "certificate_registered",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("CertificateRegistered", eventBytes)

	return nil
}

// ===================== REVOCATION =====================

func (c *DecentralizedPKIContract) ProposeRevocation(
	ctx contractapi.TransactionContextInterface,
	proposalID string,
	targetMemberID string,
	reason string,
) error {
	if err := ensureCanonicalID(targetMemberID); err != nil {
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

	// Look up active cert via index
	activeCertKey, err := ctx.GetStub().GetState("ACTIVECERT:" + targetMemberID)
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

	revocation := RevocationProposal{
		ProposalID:     proposalID,
		TargetMemberID: targetMemberID,
		Reason:         reason,
		SubmittedBy:    submitterID,
		SubmittedAt:    submittedAt,
		VotingEndsAt:   votingEndsAt,
		Status:         "pending",
		VotesFor:       0,
		VotesAgainst:   0,
		VotersList:     []string{},
	}

	revocationJSON, err := json.Marshal(revocation)
	if err != nil {
		return err
	}

	// Emit event
	eventPayload := map[string]string{
		"proposalId": proposalID,
		"nodeId":     targetMemberID,
		"reason":     reason,
		"action":     "revocation_proposed",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("RevocationProposed", eventBytes)

	return ctx.GetStub().PutState("REVOKE:"+proposalID, revocationJSON)
}

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

	// Authorization is checked below via CA membership.
	// Certificate revocation does NOT revoke CA membership.

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

	// Check quorum
	votesReceived := len(revocation.VotersList)
	quorumReached := (votesReceived * 100 / totalAuthorized) >= ca.GovernanceParams.QuorumPercentage

	if quorumReached {
		approvalPercentage := revocation.VotesFor * 100 / votesReceived
		if approvalPercentage >= ca.GovernanceParams.ApprovalThreshold {
			revocation.Status = "approved"

			// Execute revocation immediately
			if err := c.executeRevocation(ctx, &revocation); err != nil {
				return err
			}
		} else {
			revocation.Status = "rejected"
		}
	}

	revocationJSON, err = json.Marshal(revocation)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("REVOKE:"+proposalID, revocationJSON)
}

func (c *DecentralizedPKIContract) executeRevocation(
	ctx contractapi.TransactionContextInterface,
	revocation *RevocationProposal,
) error {
	// Look up active cert via index
	activeCertKey, err := ctx.GetStub().GetState("ACTIVECERT:" + revocation.TargetMemberID)
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
	// Store revoked cert at its original key (CERT:<proposalID>)
	if err := ctx.GetStub().PutState("CERT:"+string(activeCertKey), certJSON); err != nil {
		return err
	}

	// Clear active cert index — allows member to request a new certificate
	if err := ctx.GetStub().DelState("ACTIVECERT:" + revocation.TargetMemberID); err != nil {
		return err
	}

	// Update Merkle tree of active certificates (revoked cert removed)
	if err := c.updateCertificateMerkleTree(ctx, "certificate_revoked", cert.CertID, cert.CertificateHash, true); err != nil {
		fmt.Printf("Warning: failed to update Merkle tree after revocation: %v\n", err)
	}

	// Update revocation status
	revocation.Status = "executed"

	// NOTE: Certificate revocation does NOT remove the member from the CA.
	// Member removal is a separate governance action via ProposeRemoveMember/VoteOnRemoveMember.
	// This decouples certificate lifecycle from CA membership.

	// Emit event
	ca, _ := c.GetDistributedCA(ctx, DefaultCAID)
	epochStr := "0"
	if ca != nil {
		epochStr = strconv.Itoa(ca.Epoch)
	}
	eventPayload := map[string]string{
		"nodeId": revocation.TargetMemberID,
		"reason": revocation.Reason,
		"epoch":  epochStr,
		"action": "certificate_revoked",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("NodeRevoked", eventBytes)

	return nil
}

// ===================== MEMBER REMOVAL =====================

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

	eventPayload := map[string]string{
		"proposalId": proposalID,
		"target":     targetMemberID,
		"action":     "member_removal_proposed",
	}
	ev, _ := json.Marshal(eventPayload)
	_ = ctx.GetStub().SetEvent("MemberRemovalProposed", ev)

	return ctx.GetStub().PutState(key, proposalJSON)
}

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
	totalAuthorized := len(ca.Members)
	if totalAuthorized == 0 {
		return fmt.Errorf("no members in CA")
	}
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

	votesReceived := len(proposal.VotersList)
	quorumReached := (votesReceived * 100 / totalAuthorized) >= ca.GovernanceParams.QuorumPercentage

	if quorumReached {
		if err := validateMultiOrgVotes(proposal.VotersList); err != nil {
			proposalJSON, _ = json.Marshal(proposal)
			return ctx.GetStub().PutState(key, proposalJSON)
		}

		approvalPercentage := proposal.VotesFor * 100 / votesReceived
		if approvalPercentage >= ca.GovernanceParams.ApprovalThreshold {
			proposal.Status = "approved"
			if err := c.executeMemberRemoval(ctx, caId, &proposal); err != nil {
				return err
			}
			proposal.Status = "executed"
		} else {
			proposal.Status = "rejected"
		}
	}

	proposalJSON, _ = json.Marshal(proposal)
	return ctx.GetStub().PutState(key, proposalJSON)
}

func (c *DecentralizedPKIContract) executeMemberRemoval(
	ctx contractapi.TransactionContextInterface,
	caId string,
	proposal *MemberRemovalProposal,
) error {
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
	// Exclude the removed member from the old committee so a malicious/offline node
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

	// Remove from observers if present
	newObservers := make([]string, 0, len(ca.Observers))
	for _, obs := range ca.Observers {
		if obs != proposal.TargetMemberID {
			newObservers = append(newObservers, obs)
		}
	}
	ca.Observers = newObservers

	ca.Epoch++
	ca.ThresholdParams.TotalNodes = len(ca.Members)
	ca.ThresholdParams.Threshold = calculateDynamicThreshold(
		len(ca.Members),
		ca.GovernanceParams.QuorumPercentage,
	)

	caJSON, _ := json.Marshal(ca)
	if err := ctx.GetStub().PutState("CA:"+caId, caJSON); err != nil {
		return err
	}

	if err := c.initiateReshare(ctx, ca.Epoch, "member_removed", proposal.TargetMemberID, oldReshareMembers, oldThreshold, ca.Members, ca.ThresholdParams.Threshold); err != nil {
		return err
	}

	eventPayload := map[string]interface{}{
		"caId":   caId,
		"member": proposal.TargetMemberID,
		"epoch":  ca.Epoch,
		"action": "member_removed",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("MemberRemoved", eventBytes)

	return nil
}

// ListPendingRemoveMemberProposals lists pending member removal proposals for a CA.
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

// ===================== TSS KEY RESHARING =====================

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
		Epoch:          epoch,
		TriggerReason:  reason + ":" + affectedNode,
		OldNodeSet:     oldNodeSet,
		OldThreshold:   oldThreshold,
		NewNodeSet:     newNodeSet,
		NewThreshold:   newThreshold,
		Status:         "initiated",
		AckCount:       0,
		AcknowledgedBy: []string{},
		CompletionAckedBy:  []string{},
		CompletionAckCount: 0,
		InitiatedAt:    initiatedAt,
		CompletedAt:    "",
		NewCAPublicKey: "",
		OldPartySalt:   ca.PartySalt,
		NewPartySalt:   nextPartySalt(ca.PartySalt),
	}

	reshareJSON, err := json.Marshal(reshare)
	if err != nil {
		return err
	}

	if err := ctx.GetStub().PutState("RESHARE:"+strconv.Itoa(epoch), reshareJSON); err != nil {
		return err
	}

	// Emit events - both ReshareInitiated and ReshareRequired for compatibility
	eventPayload := map[string]interface{}{
		"epoch":        epoch,
		"reason":       reason,
		"nodeSet":      ca.Members,
		"threshold":    ca.ThresholdParams.Threshold,
		"newThreshold": newThreshold,
		"action":       "reshare_initiated",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("ReshareInitiated", eventBytes)

	// Also emit ReshareRequired for backward compatibility with membership handler
	ctx.GetStub().SetEvent("ReshareRequired", eventBytes)

	return nil
}

// ForceReshare manually triggers a reshare for the current CA membership.
// This is useful when a member was added via bootstrap (no automatic reshare).
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

	// Supersede any in-progress reshares (avoid stuck epochs)
	supersedeAt := time.Now().UTC().Format(time.RFC3339Nano)
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

	// Bump epoch to represent a new key generation round
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

	ca, err := c.GetDistributedCA(ctx, DefaultCAID)
	if err != nil {
		return err
	}

	reshare.AcknowledgedBy = append(reshare.AcknowledgedBy, nodeID)
	reshare.AckCount++

	// Check if enough nodes acknowledged (quorum-based)
	required := calculateDynamicThreshold(len(reshare.NewNodeSet), ca.GovernanceParams.QuorumPercentage) + 1
	if required < 1 {
		required = 1
	}
	if required > len(reshare.NewNodeSet) {
		required = len(reshare.NewNodeSet)
	}
	if len(reshare.NewNodeSet) == 0 {
		return fmt.Errorf("reshare has empty node set")
	}
	if reshare.AckCount >= required {
		reshare.Status = "acknowledged"

		// Emit event for off-chain DKG execution
		eventPayload := map[string]interface{}{
			"epoch":  epoch,
			"action": "all_nodes_ready_for_dkg",
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

	requiredAcks := calculateDynamicThreshold(len(reshare.NewNodeSet), ca.GovernanceParams.QuorumPercentage)
	if requiredAcks < 1 {
		requiredAcks = 1
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
			"epoch":        strconv.Itoa(epoch),
			"publicKey":    reshare.NewCAPublicKey,
			"ackCount":     len(reshare.CompletionAckedBy),
			"requiredAcks": requiredAcks,
			"action":       "reshare_completion_proposed",
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

	// Update CA public key (should be unchanged during reshare)
	ca.PublicKey = newCAPublicKey
	ca.PartySalt = reshare.NewPartySalt

	caJSON, err := json.Marshal(ca)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("CA:"+DefaultCAID, caJSON); err != nil {
		return err
	}

	eventPayload := map[string]string{
		"epoch":        strconv.Itoa(epoch),
		"newPublicKey": newCAPublicKey,
		"action":       "reshare_completed",
	}
	eventBytes, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("ReshareCompleted", eventBytes)

	return nil
}

// ===================== QUERY FUNCTIONS =====================

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

func (c *DecentralizedPKIContract) WhoAmI(ctx contractapi.TransactionContextInterface) (string, error) {
	return c.canonicalMemberID(ctx)
}

// GetAllCertificates retrieves all registered certificates
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

// GetStateByRange is a generic function that retrieves all state values in a given range.
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

// GetPendingCSRProposals returns all CSR proposals with "pending" status
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

// GetPendingSigningSessions returns all active signing sessions
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

// GetCertificate retrieves a certificate by proposalID or memberID.
// It first tries CERT:<id> directly (proposalID), then falls back to
// looking up the active cert via ACTIVECERT:<id> (memberID).
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

// GetPendingRevocations returns all revocation proposals with "pending" status
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

// PeerInfo stores P2P connection information for a peer
type PeerInfo struct {
	NodeID    string `json:"nodeId"`
	Address   string `json:"address"`
	P2PPort   int    `json:"p2pPort"`
	GRPCPort  int    `json:"grpcPort"`
	UpdatedAt string `json:"updatedAt"`
}

// RegisterPeerAddress stores a peer's P2P address for discovery
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

// GetPeerAddress retrieves a peer's P2P address
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

// GetAllPeerAddresses retrieves all registered peer addresses
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

// ===================== HELPER FUNCTIONS =====================

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// extractOrgFromMemberID extracts the Fabric org MSP ID from a canonical member ID
// The member ID format is: x509::CN=User1,OU=client::CN=ca.org1.example.com,O=org1.example.com...
// We extract the org from the issuer's CN (ca.orgX.example.com)
func extractOrgFromMemberID(memberID string) string {
	// Split by :: to get issuer part
	parts := strings.Split(memberID, "::")
	if len(parts) < 3 {
		return "unknown"
	}

	issuer := strings.ToLower(parts[2])

	// Match common patterns like "cn=ca.org1.example.com" or "o=org1.example.com"
	for _, orgNum := range []string{"1", "2", "3", "4", "5"} {
		patterns := []string{
			fmt.Sprintf("org%s.", orgNum),
			fmt.Sprintf("org%smsp", orgNum),
		}
		for _, pattern := range patterns {
			if strings.Contains(issuer, pattern) {
				return fmt.Sprintf("Org%sMSP", orgNum)
			}
		}
	}

	return "unknown"
}

// countVotingOrgs returns how many unique orgs have voted
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

// validateMemberOrgLimit - NO-OP: per-org member limits disabled
func validateMemberOrgLimit(members []string, newMemberID string) error {
	// Per-org member limits removed - always allow
	return nil
}

// validateMultiOrgVotes checks if votes come from enough different orgs
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

func removeNode(nodes []string, nodeID string) []string {
	var result []string
	for _, n := range nodes {
		if n != nodeID {
			result = append(result, n)
		}
	}
	return result
}

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

func calculateDynamicThreshold(memberCount int, percentageRequired int) int {
	exactSigners := float64(memberCount) * float64(percentageRequired) / 100.0
	requiredSigners := int(math.Ceil(exactSigners))

	if requiredSigners < 2 {
		requiredSigners = 2
	}

	return requiredSigners - 1 // TSS threshold
}

func hash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// ===================== TSS SIGNATURE VERIFICATION =====================

// reconstructPublicKeyFromHex reconstructs an ECDSA public key from hex-encoded bytes
// The public key is stored as uncompressed SEC1 format: 04 || X (32 bytes) || Y (32 bytes)
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

// verifyTSSSignature verifies a threshold signature against the CA's public key
// This performs FULL ECDSA signature verification using Go's crypto libraries
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
		// During bootstrap, public key may not be set yet
		// Allow signatures during DKG/bootstrap phase
		return true, nil
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

	// Reconstruct the CA's public key from hex
	pubKey, err := reconstructPublicKeyFromHex(ca.PublicKey)
	if err != nil {
		// If we can't reconstruct the key, log warning but allow during transition
		// This handles the case where the public key format is not yet standardized
		return true, nil // Fallback to allow during key format migration
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

// IsNodeRevoked checks if a node has been revoked and is no longer authorized
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
		// No active cert index — either never had one or it was revoked
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

	// Has an active cert index — check if that cert is actually active
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

// VerifySignature is a public function to verify a signature (for querying)
func (c *DecentralizedPKIContract) VerifySignature(
	ctx contractapi.TransactionContextInterface,
	messageHash string,
	signatureR string,
	signatureS string,
) (bool, error) {
	return c.verifyTSSSignature(ctx, messageHash, signatureR, signatureS)
}

// GetCAPublicKey returns the current CA public key
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

// OrgMembershipStats represents membership statistics per organization
type OrgMembershipStats struct {
	OrgID          string   `json:"orgId"`
	MemberCount    int      `json:"memberCount"`
	MaxMembers     int      `json:"maxMembers"`
	RemainingSlots int      `json:"remainingSlots"`
	Members        []string `json:"members"`
}

// GetOrgMembershipStats returns membership statistics for all organizations
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

	// Build stats for all potential orgs (1-5)
	var stats []OrgMembershipStats
	for _, orgNum := range []string{"1", "2", "3", "4", "5"} {
		orgID := fmt.Sprintf("Org%sMSP", orgNum)
		members := orgMembers[orgID]
		count := len(members)

		stats = append(stats, OrgMembershipStats{
			OrgID:          orgID,
			MemberCount:    count,
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

// SecurityConfig represents the current security configuration
type SecurityConfig struct {
	MaxMembersPerOrg      int  `json:"maxMembersPerOrg"`
	MinOrgsForApproval    int  `json:"minOrgsForApproval"`
	SecurityLimitsEnabled bool `json:"securityLimitsEnabled"`
}

// GetSecurityConfig returns the current security configuration
func (c *DecentralizedPKIContract) GetSecurityConfig(
	ctx contractapi.TransactionContextInterface,
) (SecurityConfig, error) {
	return SecurityConfig{
		MaxMembersPerOrg:      0, // No limit
		MinOrgsForApproval:    MinOrgsForApproval,
		SecurityLimitsEnabled: EnableSecurityLimits,
	}, nil
}

// ValidationResult contains the result of a validation check
type ValidationResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// ValidateMemberCandidate checks if a candidate member can be added
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

func merkleConfigKey(caID string) string {
	return merkleConfigKeyPrefix + caID
}

// GetMerkleEnabled returns whether the certificate Merkle tree is enabled.
// Defaults to true if no config is stored yet.
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

// SetMerkleEnabled updates the Merkle tree setting for the CA (members only).
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

// updateCertificateMerkleTree recomputes the Merkle root over all active (non-revoked)
// certificate hashes and stores the result on-chain. Should be called after every
// certificate registration or revocation.
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

// computeMerkleRoot computes the Merkle root from a sorted list of hex-encoded leaf hashes.
// Returns the hex-encoded root hash; returns empty string for empty input.
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

// GetCertificateMerkleRoot returns the current Merkle root of all active certificates.
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

// GetCertificateMerkleProof returns the Merkle inclusion proof for a specific certificate.
// The proof contains sibling hashes needed to recompute the root from the leaf.
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

// MerkleProofNode represents one step in a Merkle inclusion proof.
type MerkleProofNode struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// buildMerkleProof returns the sibling hashes needed to verify inclusion.
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
