// operations_csr_signing.go bundles CSR submission, signing-session processing, and certificate registration workflows.
// Runtime flow: menu/API/polling paths invoke these operations as proposals move from submit to threshold completion.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

// ===================== CSR POLLING & AUTO-VOTING =====================

// scans pending CSR proposals and auto-votes when this node is eligible.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in CSR/signing automation.
func (p *TSSPeer) checkPendingCSRs() {
	// Get pending CSR proposals
	result, err := p.Query("GetPendingCSRProposals")
	if err != nil {
		// No pending proposals or function doesn't exist - that's fine
		return
	}

	// Handle empty or null response
	if len(result) == 0 || string(result) == "null" {
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		return
	}

	for _, proposal := range proposals {
		proposalID, ok := proposal["proposalId"].(string)
		if !ok {
			continue
		}
		p.mutex.Lock()
		if !p.observedCSRSubmits[proposalID] {
			p.observedCSRSubmits[proposalID] = true
			p.mutex.Unlock()
			p.emitMetric("csr_submitted_observed", map[string]interface{}{
				"proposal_id": proposalID,
			})
		} else {
			p.mutex.Unlock()
		}

		status, _ := proposal["status"].(string)
		if status != "pending" {
			continue
		}

		// Check if we already voted
		votersList, _ := proposal["votersList"].([]interface{})
		alreadyVoted := false
		for _, voter := range votersList {
			if voterStr, ok := voter.(string); ok && voterStr == p.MemberID {
				alreadyVoted = true
				break
			}
		}

		if alreadyVoted {
			continue
		}

		if !p.isCAMember() {
			p.logAutoVoteSkip("csr", proposalID, "not a CA member")
			continue
		}
		if inProgress, epoch := p.localKeySessionState(); inProgress {
			p.logAutoVoteSkip("csr", proposalID, fmt.Sprintf("local key session in progress (epoch=%d)", epoch))
			continue
		}

		// Auto-vote approve (in production, you'd validate the CSR)
		log.Printf("[%s] Auto-voting on CSR proposal %s", p.NodeID, proposalID)
		p.applyAutoVoteJitter("csr", proposalID)
		_, err := p.Execute("VoteOnCSR", proposalID, "approve", "Autonomous approval")
		if err != nil {
			errMsg := err.Error()
			// Stop retrying permanently on non-transient errors
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "revoked") ||
				containsIgnoreCase(errMsg, "role") ||
				containsIgnoreCase(errMsg, "certificate") {
				log.Printf("[%s] Cannot vote on CSR %s (permanent): %v", p.NodeID, proposalID, err)
				continue
			}
			log.Printf("[%s] Failed to vote on CSR %s: %v", p.NodeID, proposalID, err)
		} else {
			log.Printf("[%s] OK Voted approve on CSR proposal %s", p.NodeID, proposalID)
			p.emitMetric("csr_voted", map[string]interface{}{
				"proposal_id": proposalID,
				"vote":        "approve",
			})
		}
	}
}

// ===================== SIGNING SESSION POLLING =====================

// detects active signing sessions and starts local signing when needed.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).StartPollingLoop, (*TSSPeer).handleP2PConnection.
// Triggered: polling tick in CSR/signing automation.
func (p *TSSPeer) checkSigningSessions() {
	// Skip if no key share or already signing
	p.mutex.RLock()
	hasKeyShare := p.TSSKeyShare != nil
	isSigning := p.signingInProgress
	isKeygen := p.keygenInProgress
	p.mutex.RUnlock()

	if !hasKeyShare || isSigning {
		return
	}
	if isKeygen {
		return
	}
	if blocked, _ := p.signingBlockedByKeySession(); blocked {
		return
	}

	// Get active signing sessions
	result, err := p.Query("GetPendingSigningSessions")
	if err != nil {
		return
	}

	// Handle empty or null response
	if len(result) == 0 || string(result) == "null" {
		return
	}

	var sessions []map[string]interface{}
	if err := json.Unmarshal(result, &sessions); err != nil {
		return
	}

	for _, session := range sessions {
		proposalID, ok := session["proposalId"].(string)
		if !ok {
			continue
		}

		status, _ := session["status"].(string)
		if status != "active" {
			continue
		}

		// Skip proposals we already completed signing for
		p.mutex.RLock()
		alreadyDone := p.completedProposals[proposalID]
		p.mutex.RUnlock()
		if alreadyDone {
			continue
		}

		// Check if we already submitted a partial signature on-chain
		partialSigs, _ := session["partialSignatures"].([]interface{})
		alreadySubmitted := false
		for _, sig := range partialSigs {
			if sigMap, ok := sig.(map[string]interface{}); ok {
				if signerID, ok := sigMap["signerId"].(string); ok && signerID == p.MemberID {
					alreadySubmitted = true
					break
				}
			}
		}

		if alreadySubmitted {
			// Mark as completed locally so we stop checking
			p.mutex.Lock()
			p.completedProposals[proposalID] = true
			p.mutex.Unlock()
			continue
		}

		csrHash, _ := session["csrHash"].(string)
		if csrHash == "" {
			continue
		}

		// Set signingInProgress BEFORE launching goroutine to prevent race condition
		p.mutex.Lock()
		if p.signingInProgress {
			p.mutex.Unlock()
			return // Another goroutine beat us
		}
		p.signingInProgress = true
		p.mutex.Unlock()

		if stale, reason := p.isKeyShareStale(); stale {
			log.Printf("[%s] Key share stale (%s); skipping signing for proposal %s", p.NodeID, reason, proposalID)
			p.mutex.Lock()
			p.signingInProgress = false
			p.mutex.Unlock()
			p.autoForceReshareMissingShare()
			return
		}

		log.Printf("[%s] Found active signing session for proposal %s", p.NodeID, proposalID)
		p.emitMetric("signing_session_active", map[string]interface{}{
			"proposal_id": proposalID,
		})
		go p.executeTSSSigning(proposalID, csrHash)
		break // Only handle one at a time
	}
}

// ===================== TSS SIGNING =====================

type deterministicSigningCertMaterial struct {
	submitterID        string
	csr                *x509.CertificateRequest
	certTemplate       *x509.Certificate
	issuerTemplate     *x509.Certificate
	serialNumber       *big.Int
	validityDays       int
	notBefore          time.Time
	notAfter           time.Time
	rawTBSCertificate  []byte
	tbsHash            []byte
	tbsHashHex         string
	subject            string
	publicKeyHex       string
	sessionMessageHash string
}

// derives deterministic validity bounds from a signing-session timestamp.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: deterministicSigningCertMaterialFromSession.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func deterministicCertValidityFromSession(createdAt time.Time) (time.Time, time.Time, int) {
	notBefore := createdAt.UTC().Truncate(time.Second)
	validityDays := 365
	notAfter := notBefore.AddDate(0, 0, validityDays)
	return notBefore, notAfter, validityDays
}

// derives a deterministic positive non-zero certificate serial number.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: deterministicSigningCertMaterialFromSession.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func deterministicCertificateSerial(proposalID, submitterID string, notBefore time.Time) *big.Int {
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

// parses a signing-session createdAt value from chaincode JSON.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: deterministicSigningCertMaterialFromSession.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func parseSigningSessionCreatedAt(raw interface{}) (time.Time, error) {
	switch v := raw.(type) {
	case string:
		token := strings.TrimSpace(v)
		if token == "" {
			return time.Time{}, fmt.Errorf("empty createdAt")
		}
		if t, err := time.Parse(time.RFC3339Nano, token); err == nil {
			return t, nil
		}
		if t, err := time.Parse(time.RFC3339, token); err == nil {
			return t, nil
		}
		return time.Time{}, fmt.Errorf("invalid createdAt timestamp: %q", token)
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported createdAt type %T", raw)
	}
}

// derives deterministic certificate material and TBS hash from proposal + session state.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).executeTSSSigning, (*TSSPeer).tryRegisterCertificate.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) deterministicSigningCertMaterialFromSession(
	proposalID string,
	session map[string]interface{},
	proposal map[string]interface{},
) (*deterministicSigningCertMaterial, error) {
	if session == nil {
		return nil, fmt.Errorf("missing signing session")
	}
	if proposal == nil {
		return nil, fmt.Errorf("missing CSR proposal")
	}

	createdAt, err := parseSigningSessionCreatedAt(session["createdAt"])
	if err != nil {
		return nil, err
	}
	notBefore, notAfter, validityDays := deterministicCertValidityFromSession(createdAt)

	csrData, _ := proposal["csrData"].(string)
	if strings.TrimSpace(csrData) == "" {
		return nil, fmt.Errorf("proposal missing csrData")
	}
	submitterID, _ := proposal["submitterId"].(string)
	if strings.TrimSpace(submitterID) == "" {
		return nil, fmt.Errorf("proposal missing submitterId")
	}

	csrBlock, _ := pem.Decode([]byte(csrData))
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	serialNumber := deterministicCertificateSerial(proposalID, submitterID, notBefore)
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
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

	throwawayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate throwaway key: %w", err)
	}
	provisionalDER, err := x509.CreateCertificate(rand.Reader, certTemplate, issuerTemplate, csr.PublicKey, throwawayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create provisional certificate: %w", err)
	}
	provisionalCert, err := x509.ParseCertificate(provisionalDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provisional certificate: %w", err)
	}
	if len(provisionalCert.RawTBSCertificate) == 0 {
		return nil, fmt.Errorf("provisional certificate missing RawTBSCertificate")
	}
	rawTBS := append([]byte(nil), provisionalCert.RawTBSCertificate...)
	tbsHash := sha256.Sum256(rawTBS)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR public key: %w", err)
	}

	sessionMessageHash, _ := session["csrHash"].(string)

	return &deterministicSigningCertMaterial{
		submitterID:        submitterID,
		csr:                csr,
		certTemplate:       certTemplate,
		issuerTemplate:     issuerTemplate,
		serialNumber:       serialNumber,
		validityDays:       validityDays,
		notBefore:          notBefore,
		notAfter:           notAfter,
		rawTBSCertificate:  rawTBS,
		tbsHash:            append([]byte(nil), tbsHash[:]...),
		tbsHashHex:         hex.EncodeToString(tbsHash[:]),
		subject:            csr.Subject.String(),
		publicKeyHex:       hex.EncodeToString(pubKeyBytes),
		sessionMessageHash: strings.TrimSpace(sessionMessageHash),
	}, nil
}

//	onfigures and starts a TSS signing round for one CSR proposal.
//
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).checkSigningSessions.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) executeTSSSigning(proposalID, expectedMessageHash string) {
	// signingInProgress is already set to true by checkSigningSessions before launching this goroutine
	p.mutex.RLock()
	keyShare := p.TSSKeyShare
	cachedPartyIDs := p.cachedPartyIDs
	cachedMembers := p.cachedMembers
	myIndex := p.myPartyIndex
	threshold := p.Threshold
	p.mutex.RUnlock()

	defer func() {
		p.mutex.Lock()
		p.signingInProgress = false
		p.mutex.Unlock()
	}()

	if keyShare == nil {
		log.Printf("[%s] Cannot sign: no key share available", p.NodeID)
		return
	}

	// Wait for keygen handler to fully exit so the tssMessages channel is free
	p.mutex.RLock()
	keygenRunning := p.keygenInProgress
	p.mutex.RUnlock()
	if keygenRunning {
		select {
		case <-p.keygenDone:
			// keygen handler has exited
		case <-time.After(30 * time.Second):
			log.Printf("[%s] Timeout waiting for keygen handler to exit", p.NodeID)
			return
		}
	}

	// Load peer addresses if not loaded
	if err := p.LoadPeerAddresses(); err != nil {
		log.Printf("[%s] Failed to load peer addresses: %v", p.NodeID, err)
		return
	}

	sessionResult, err := p.Query("GetSigningSession", proposalID)
	if err != nil {
		log.Printf("[%s] Failed to get signing session for %s: %v", p.NodeID, proposalID, err)
		return
	}
	var session map[string]interface{}
	if err := json.Unmarshal(sessionResult, &session); err != nil {
		log.Printf("[%s] Failed to decode signing session for %s: %v", p.NodeID, proposalID, err)
		return
	}

	proposalResult, err := p.Query("GetCSRProposal", proposalID)
	if err != nil {
		log.Printf("[%s] Failed to get CSR proposal for %s: %v", p.NodeID, proposalID, err)
		return
	}
	var proposal map[string]interface{}
	if err := json.Unmarshal(proposalResult, &proposal); err != nil {
		log.Printf("[%s] Failed to decode CSR proposal for %s: %v", p.NodeID, proposalID, err)
		return
	}

	certMaterial, err := p.deterministicSigningCertMaterialFromSession(proposalID, session, proposal)
	if err != nil {
		log.Printf("[%s] Failed to derive deterministic signing material for %s: %v", p.NodeID, proposalID, err)
		return
	}
	if strings.TrimSpace(expectedMessageHash) != "" && !strings.EqualFold(strings.TrimSpace(expectedMessageHash), certMaterial.tbsHashHex) {
		log.Printf("[%s] Refusing to sign proposal %s: session hash mismatch (expected %s..., local %s...)",
			p.NodeID, proposalID, strings.TrimSpace(expectedMessageHash)[:min(12, len(strings.TrimSpace(expectedMessageHash)))], certMaterial.tbsHashHex[:12])
		return
	}
	if certMaterial.sessionMessageHash != "" && !strings.EqualFold(certMaterial.sessionMessageHash, certMaterial.tbsHashHex) {
		log.Printf("[%s] Refusing to sign proposal %s: on-chain session message hash does not match deterministic certificate TBS hash", p.NodeID, proposalID)
		return
	}

	message := new(big.Int).SetBytes(certMaterial.tbsHash)
	log.Printf("[%s] Starting TSS signing for proposal %s, message: %s...",
		p.NodeID, proposalID, message.Text(16)[:20])

	// Always rebuild party IDs from current CA members to avoid stale mappings
	ca, err := p.GetCA()
	if err != nil {
		log.Printf("[%s] Failed to get CA for signing: %v", p.NodeID, err)
		return
	}

	membersRaw, _ := ca["members"].([]interface{})
	members := make([]string, 0, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}
	sort.Strings(members)
	if len(members) == 0 {
		log.Printf("[%s] Cannot sign: CA member set is empty", p.NodeID)
		return
	}

	// Wait only for members that are part of the active signing committee.
	if !p.waitForPeersSubset(members, 30*time.Second) {
		log.Printf("[%s] Not all signing members reachable", p.NodeID)
		return
	}

	caThreshold := threshold
	if t, ok := ca["thresholdParams"].(map[string]interface{}); ok {
		if th, ok := t["threshold"].(float64); ok {
			caThreshold = int(th)
		}
	}
	if caThreshold != threshold {
		log.Printf("[%s] Key share threshold (%d) does not match CA threshold (%d) - wait for reshare", p.NodeID, threshold, caThreshold)
		return
	}

	if len(cachedMembers) > 0 && !equalStringSlices(cachedMembers, members) {
		log.Printf("[%s] Key share member set mismatch (cached %d, CA %d) - wait for reshare", p.NodeID, len(cachedMembers), len(members))
		return
	}
	if len(cachedMembers) == 0 && len(cachedPartyIDs) > 0 && len(cachedPartyIDs) != len(members) {
		log.Printf("[%s] Key share party count (%d) does not match CA member count (%d) - wait for reshare", p.NodeID, len(cachedPartyIDs), len(members))
		return
	}

	// Build party IDs; prefer the derivation that matches the current key share
	committee := p.buildReshareCommittee(members, "sign", "")
	selected := committee
	if !keyShareMatchesPartyIDs(keyShare, committee.partyIDs) {
		salted := p.buildReshareCommittee(members, "new", "new")
		if keyShareMatchesPartyIDs(keyShare, salted.partyIDs) {
			selected = salted
		} else {
			log.Printf("[%s] Cannot sign: key share party IDs do not match current CA member set; wait for reshare", p.NodeID)
			return
		}
	}

	myPartyID := selected.memberToParty[p.MemberID]
	if myPartyID == nil {
		log.Printf("[%s] Cannot sign: current member ID not in CA member set", p.NodeID)
		return
	}
	myIndex = myPartyID.Index

	p.mutex.Lock()
	p.TSSPartyID = myPartyID
	p.myPartyIndex = myIndex
	p.partyIndexMap = make(map[int]string)
	for nodeID, pid := range selected.nodeIDToParty {
		p.partyIndexMap[pid.Index] = nodeID
	}
	p.mutex.Unlock()

	sortedPartyIDs := selected.partyIDs
	n := len(sortedPartyIDs)

	// Create TSS signing context
	peerCtx := tss.NewPeerContext(sortedPartyIDs)

	params := tss.NewParameters(
		elliptic.P256(), // NIST P-256 curve (secp256r1)
		peerCtx,
		p.TSSPartyID,
		n,
		threshold,
	)

	log.Printf("[%s] TSS Signing: N=%d, T=%d, myIndex=%d", p.NodeID, n, threshold, myIndex)
	p.emitMetric("tss_signing_start", map[string]interface{}{
		"proposal_id": proposalID,
		"n":           n,
		"threshold":   threshold,
	})

	outCh := make(chan tss.Message, n*20)
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	// signing.NewLocalParty expects a value channel for SignatureData.
	// We bridge it to a pointer channel used by the local handler.
	valueEndCh := make(chan common.SignatureData, 1)
	go forwardSignatureData(valueEndCh, endCh, p.ctx.Done())
	party := signing.NewLocalParty(message, params, *keyShare, outCh, valueEndCh)

	// Done channel - signing handler will close this when finished
	signingDone := make(chan struct{})

	// Start message handler (blocks until signing completes, errors, or times out)
	p.wg.Add(1)
	go p.handleTSSSigningMessages(party, sortedPartyIDs, outCh, endCh, errCh, proposalID, myIndex, signingDone)

	// Start signing
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		log.Printf("[%s] Starting signing party...", p.NodeID)
		if err := party.Start(); err != nil {
			log.Printf("[%s] TSS signing start error: %v", p.NodeID, err)
			errCh <- err
		}
	}()

	// Block until signing handler finishes
	<-signingDone
}

// bridges SignatureData value-channel output into pointer-channel handling.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).executeTSSSigning.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func forwardSignatureData(src <-chan common.SignatureData, dst chan<- *common.SignatureData, done <-chan struct{}) {
	// common.SignatureData carries protobuf internals with a lock.
	// Use reflection-based receive and copy only exported byte fields into a new object.
	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(src)},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(done)},
	}

	chosen, recv, ok := reflect.Select(cases)
	if chosen == 1 || !ok {
		return
	}

	copyField := func(name string) []byte {
		f := recv.FieldByName(name)
		if !f.IsValid() || f.Kind() != reflect.Slice {
			return nil
		}
		srcBytes, ok := f.Interface().([]byte)
		if !ok || len(srcBytes) == 0 {
			return nil
		}
		dstBytes := make([]byte, len(srcBytes))
		copy(dstBytes, srcBytes)
		return dstBytes
	}

	sig := &common.SignatureData{
		Signature:         copyField("Signature"),
		SignatureRecovery: copyField("SignatureRecovery"),
		R:                 copyField("R"),
		S:                 copyField("S"),
		M:                 copyField("M"),
	}

	select {
	case dst <- sig:
	case <-done:
	}
}

// runs the signing protocol message loop and submits partial signatures on completion.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).executeTSSSigning.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) handleTSSSigningMessages(
	party tss.Party,
	partyIDs []*tss.PartyID,
	outCh <-chan tss.Message,
	endCh <-chan *common.SignatureData,
	errCh <-chan *tss.Error,
	proposalID string,
	myIndex int,
	signingDone chan struct{},
) {
	defer p.wg.Done()
	defer close(signingDone) // Signal to executeTSSSigning that we're done

	timeout := time.After(5 * time.Minute)
	messagesSent := 0
	messagesReceived := 0

	log.Printf("[%s] Signing message handler started for proposal %s", p.NodeID, proposalID)

	for {
		select {
		case <-p.ctx.Done():
			return

		case <-timeout:
			log.Printf("[%s] TSS signing timeout for %s (sent=%d, recv=%d)",
				p.NodeID, proposalID, messagesSent, messagesReceived)
			return

		case err := <-errCh:
			if err != nil {
				log.Printf("[%s] TSS signing error: %v", p.NodeID, err.Error())
			}
			return

		case msg := <-outCh:
			if msg == nil {
				continue
			}

			wireBytes, routing, err := msg.WireBytes()
			if err != nil {
				log.Printf("[%s] Failed to get wire bytes: %v", p.NodeID, err)
				continue
			}

			messagesSent++

			if routing.IsBroadcast {
				log.Printf("[%s] [SIGN SEND #%d] Broadcasting", p.NodeID, messagesSent)
				for i := range partyIDs {
					if i == myIndex {
						continue
					}
					targetNodeID := p.getNodeIDForPartyIndex(i)
					tssMsg := &TSSMessage{
						From:        p.NodeID,
						FromIndex:   myIndex,
						To:          targetNodeID,
						ToIndex:     i,
						SessionID:   "sign-" + proposalID,
						MsgType:     "signing",
						Payload:     wireBytes,
						IsBroadcast: true,
						Round:       messagesSent,
					}
					p.SendTSSMessageWithRetry(targetNodeID, tssMsg, 5)
				}
			} else {
				for _, to := range routing.To {
					targetNodeID := p.getNodeIDForPartyIndex(to.Index)
					log.Printf("[%s] [SIGN SEND #%d] P2P to %s", p.NodeID, messagesSent, targetNodeID)
					tssMsg := &TSSMessage{
						From:        p.NodeID,
						FromIndex:   myIndex,
						To:          targetNodeID,
						ToIndex:     to.Index,
						SessionID:   "sign-" + proposalID,
						MsgType:     "signing",
						Payload:     wireBytes,
						IsBroadcast: false,
						Round:       messagesSent,
					}
					p.SendTSSMessageWithRetry(targetNodeID, tssMsg, 5)
				}
			}

		case incoming := <-p.signingMessages:
			if incoming == nil {
				continue
			}

			// Priority check: if endCh is ready, handle signing completion first
			select {
			case sig := <-endCh:
				log.Printf("[%s] TSS SIGNING COMPLETED for %s (priority check)!", p.NodeID, proposalID)
				p.emitMetric("tss_signing_complete", map[string]interface{}{
					"proposal_id": proposalID,
				})
				log.Printf("[%s] Signature R: %s...", p.NodeID, hex.EncodeToString(sig.R)[:20])
				log.Printf("[%s] Signature S: %s...", p.NodeID, hex.EncodeToString(sig.S)[:20])
				p.submitPartialSignature(proposalID, sig)
				return
			default:
			}

			// Filter by session ID to prevent cross-contamination
			expectedSessionID := "sign-" + proposalID
			if incoming.SessionID != "" && incoming.SessionID != expectedSessionID {
				log.Printf("[%s] Ignoring signing message for wrong session: got %s, want %s",
					p.NodeID, incoming.SessionID, expectedSessionID)
				continue
			}

			messagesReceived++
			log.Printf("[%s] [SIGN RECV #%d] From %s", p.NodeID, messagesReceived, incoming.From)

			var fromParty *tss.PartyID
			if incoming.FromIndex >= 0 && incoming.FromIndex < len(partyIDs) {
				fromParty = partyIDs[incoming.FromIndex]
			}

			if fromParty == nil {
				log.Printf("[%s] Unknown sender in signing: %s", p.NodeID, incoming.From)
				continue
			}

			ok, err := party.UpdateFromBytes(incoming.Payload, fromParty, incoming.IsBroadcast)
			if err != nil {
				log.Printf("[%s] Signing update error: %v", p.NodeID, err)
				continue
			}
			if ok {
				log.Printf("[%s] [SIGN RECV #%d] Processed OK", p.NodeID, messagesReceived)
			}

		case sig := <-endCh:
			log.Printf("[%s] TSS SIGNING COMPLETED for %s!", p.NodeID, proposalID)
			p.emitMetric("tss_signing_complete", map[string]interface{}{
				"proposal_id": proposalID,
			})
			log.Printf("[%s] Signature R: %s...", p.NodeID, hex.EncodeToString(sig.R)[:20])
			log.Printf("[%s] Signature S: %s...", p.NodeID, hex.EncodeToString(sig.S)[:20])

			// Submit partial signature to blockchain
			p.submitPartialSignature(proposalID, sig)
			return
		}
	}
}

// validates a locally produced combined TSS signature against the active signing session hash and CA public key.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).submitPartialSignature.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) verifyLocalSignatureBeforeSubmit(proposalID, sigR, sigS string, sig *common.SignatureData) error {
	sessionResult, err := p.Query("GetSigningSession", proposalID)
	if err != nil {
		return fmt.Errorf("failed to query signing session: %w", err)
	}
	var session map[string]interface{}
	if err := json.Unmarshal(sessionResult, &session); err != nil {
		return fmt.Errorf("failed to decode signing session: %w", err)
	}

	proposalResult, err := p.Query("GetCSRProposal", proposalID)
	if err != nil {
		return fmt.Errorf("failed to query CSR proposal: %w", err)
	}
	var proposal map[string]interface{}
	if err := json.Unmarshal(proposalResult, &proposal); err != nil {
		return fmt.Errorf("failed to decode CSR proposal: %w", err)
	}

	certMaterial, err := p.deterministicSigningCertMaterialFromSession(proposalID, session, proposal)
	if err != nil {
		return fmt.Errorf("failed to derive deterministic signing material: %w", err)
	}

	if certMaterial.sessionMessageHash == "" {
		return fmt.Errorf("signing session has empty message hash")
	}
	if !strings.EqualFold(certMaterial.sessionMessageHash, certMaterial.tbsHashHex) {
		return fmt.Errorf("signing session hash mismatch with deterministic TBS hash")
	}

	if sig != nil && len(sig.M) > 0 {
		localMHex := hex.EncodeToString(sig.M)
		if !strings.EqualFold(localMHex, certMaterial.tbsHashHex) {
			return fmt.Errorf(
				"local signature payload hash mismatch (local=%s..., expected=%s...)",
				localMHex[:min(12, len(localMHex))],
				certMaterial.tbsHashHex[:12],
			)
		}
	}

	ca, err := p.GetCA()
	if err != nil {
		return fmt.Errorf("failed to read CA state: %w", err)
	}
	caPublicKeyHex, _ := ca["caPublicKey"].(string)
	if strings.TrimSpace(caPublicKeyHex) == "" {
		caPublicKeyHex, _ = ca["publicKey"].(string)
	}
	caPublicKeyHex = strings.TrimSpace(caPublicKeyHex)
	if caPublicKeyHex == "" {
		return fmt.Errorf("CA public key is not set")
	}

	caPoint := parseCAPublicKeyPoint(caPublicKeyHex)
	if caPoint == nil {
		return fmt.Errorf("failed to parse CA public key")
	}
	caPubKey := caPoint.ToECDSAPubKey()
	if caPubKey == nil {
		return fmt.Errorf("failed to construct ECDSA CA public key")
	}

	rBytes, err := hex.DecodeString(strings.TrimSpace(sigR))
	if err != nil {
		return fmt.Errorf("invalid signature R hex: %w", err)
	}
	sBytes, err := hex.DecodeString(strings.TrimSpace(sigS))
	if err != nil {
		return fmt.Errorf("invalid signature S hex: %w", err)
	}
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return fmt.Errorf("invalid zero-valued signature components")
	}

	if !ecdsa.Verify(caPubKey, certMaterial.tbsHash, r, s) {
		return fmt.Errorf("signature does not verify against CA public key and signing-session hash")
	}
	return nil
}

// submits the local signature contribution and triggers certificate registration attempts.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).handleTSSSigningMessages.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) submitPartialSignature(proposalID string, sig *common.SignatureData) {
	// For threshold signatures, we submit the combined signature
	// In a real implementation, each party would submit their partial signature
	// and the chaincode would combine them

	sigR := hex.EncodeToString(sig.R)
	sigS := hex.EncodeToString(sig.S)

	// Get public key share from key share
	pubKeyShare := ""
	if p.TSSKeyShare != nil && p.TSSKeyShare.ECDSAPub != nil {
		pubBytes := elliptic.Marshal(
			p.TSSKeyShare.ECDSAPub.Curve(),
			p.TSSKeyShare.ECDSAPub.X(),
			p.TSSKeyShare.ECDSAPub.Y(),
		)
		pubKeyShare = hex.EncodeToString(pubBytes)
	}

	p.mutex.RLock()
	myIndex := p.myPartyIndex
	p.mutex.RUnlock()

	if err := p.verifyLocalSignatureBeforeSubmit(proposalID, sigR, sigS, sig); err != nil {
		errMsg := err.Error()
		log.Printf("[%s] Local pre-submit signature verification FAILED for %s: %v", p.NodeID, proposalID, err)
		p.emitMetric("partial_signature_local_verify_failed", map[string]interface{}{
			"proposal_id": proposalID,
			"error":       errMsg,
		})
		if containsIgnoreCase(errMsg, "payload hash mismatch") || containsIgnoreCase(errMsg, "session hash mismatch") {
			log.Printf("[%s] Signing session hash drift detected for %s; skipping this stale signature and waiting for latest session", p.NodeID, proposalID)
			p.setRecoveryStatus("signing_session_hash_drift")
			return
		}
		log.Printf("[%s] This node's key share appears invalid/out-of-sync; skipping SubmitPartialSignature for %s", p.NodeID, proposalID)
		p.setRecoveryStatus("local_signature_invalid_share")
		return
	}

	log.Printf("[%s] Submitting partial signature for %s...", p.NodeID, proposalID)

	_, err := p.Execute("SubmitPartialSignature",
		proposalID,
		sigR+":"+sigS, // Combined signature
		fmt.Sprintf("%d", myIndex),
		pubKeyShare,
	)

	if err != nil {
		errMsg := err.Error()
		if containsIgnoreCase(errMsg, "signing session is not active") ||
			containsIgnoreCase(errMsg, "already completed") ||
			containsIgnoreCase(errMsg, "already registered") {
			log.Printf("[%s] Partial signature not accepted (session already finalized)", p.NodeID)
			p.mutex.Lock()
			p.completedProposals[proposalID] = true
			p.mutex.Unlock()
			// Another peer likely completed registration. If we are the owner,
			// sync the cert from chaincode so it is saved locally.
			go p.syncOwnedCertificateWithRetry(5, 2*time.Second)
			return
		}
		log.Printf("[%s] Failed to submit partial signature: %v", p.NodeID, err)
		return
	}

	log.Printf("[%s] OK Partial signature submitted for %s", p.NodeID, proposalID)
	p.mutex.Lock()
	p.completedProposals[proposalID] = true
	p.mutex.Unlock()
	p.emitMetric("partial_signature_submitted", map[string]interface{}{
		"proposal_id": proposalID,
	})

	// Every peer tries to register the certificate after submitting their partial sig.
	// The first to succeed wins; others get a harmless "already registered" error.
	go p.tryRegisterCertificate(proposalID, sigR, sigS)
}

// waits for signing completion and attempts final certificate registration on-chain.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).submitPartialSignature.
// Triggered: CSR/signing operation workflow.
func (p *TSSPeer) tryRegisterCertificate(proposalID, sigR, sigS string) {
	// Wait for signing session completion with bounded polling.
	// In practice, endorsements can briefly observe a pre-commit snapshot.
	const sessionWaitAttempts = 10
	status := ""
	var session map[string]interface{}
	for attempt := 1; attempt <= sessionWaitAttempts; attempt++ {
		result, err := p.Query("GetSigningSession", proposalID)
		if err != nil {
			backoff := computeExecuteBackoff(500*time.Millisecond, 4*time.Second, p.executeBackoffJitterPct, attempt)
			log.Printf("[%s] Failed to get signing session for %s (attempt %d/%d): %v",
				p.NodeID, proposalID, attempt, sessionWaitAttempts, err)
			time.Sleep(backoff)
			continue
		}

		var currentSession map[string]interface{}
		if err := json.Unmarshal(result, &currentSession); err != nil {
			backoff := computeExecuteBackoff(500*time.Millisecond, 4*time.Second, p.executeBackoffJitterPct, attempt)
			log.Printf("[%s] Failed to decode signing session for %s (attempt %d/%d): %v",
				p.NodeID, proposalID, attempt, sessionWaitAttempts, err)
			time.Sleep(backoff)
			continue
		}

		status, _ = currentSession["status"].(string)
		if status == "completed" {
			session = currentSession
			break
		}
		backoff := computeExecuteBackoff(500*time.Millisecond, 4*time.Second, p.executeBackoffJitterPct, attempt)
		log.Printf("[%s] Signing session for %s status=%s (attempt %d/%d), waiting %v",
			p.NodeID, proposalID, status, attempt, sessionWaitAttempts, backoff)
		time.Sleep(backoff)
	}
	if status != "completed" {
		log.Printf("[%s] Signing session not completed yet for %s (final status=%s), aborting this register attempt",
			p.NodeID, proposalID, status)
		return
	}

	proposalResult, err := p.Query("GetCSRProposal", proposalID)
	if err != nil {
		log.Printf("[%s] Failed to get CSR proposal: %v", p.NodeID, err)
		return
	}

	var proposal map[string]interface{}
	if err := json.Unmarshal(proposalResult, &proposal); err != nil {
		log.Printf("[%s] Failed to decode CSR proposal for %s: %v", p.NodeID, proposalID, err)
		return
	}

	if session == nil {
		log.Printf("[%s] Missing completed signing session for %s", p.NodeID, proposalID)
		return
	}

	certMaterial, err := p.deterministicSigningCertMaterialFromSession(proposalID, session, proposal)
	if err != nil {
		log.Printf("[%s] Failed to derive deterministic cert material for %s: %v", p.NodeID, proposalID, err)
		return
	}
	if certMaterial.sessionMessageHash != "" && !strings.EqualFold(certMaterial.sessionMessageHash, certMaterial.tbsHashHex) {
		log.Printf("[%s] Signing session hash mismatch for %s (session=%s..., local=%s...), aborting registration",
			p.NodeID, proposalID,
			certMaterial.sessionMessageHash[:min(12, len(certMaterial.sessionMessageHash))],
			certMaterial.tbsHashHex[:12],
		)
		return
	}
	submitterID := certMaterial.submitterID

	// Get CA public key for the issuer
	ca, err := p.GetCA()
	if err != nil {
		log.Printf("[%s] Failed to get CA: %v", p.NodeID, err)
		return
	}
	caPublicKeyHex, _ := ca["caPublicKey"].(string)
	if caPublicKeyHex == "" {
		caPublicKeyHex, _ = ca["publicKey"].(string)
	}

	isOwner := submitterID != "" && submitterID == p.MemberID
	if !isOwner {
		// Give the owner a small head start to avoid unnecessary races.
		time.Sleep(2 * time.Second)
	}

	// Decode TSS signature R and S
	rBytes, err := hex.DecodeString(sigR)
	if err != nil {
		log.Printf("[%s] Failed to decode sigR: %v", p.NodeID, err)
		return
	}
	sBytes, err := hex.DecodeString(sigS)
	if err != nil {
		log.Printf("[%s] Failed to decode sigS: %v", p.NodeID, err)
		return
	}

	// Build the real X.509 DER certificate with the TSS ECDSA signature
	certDER, err := buildX509WithTSSSignature(certMaterial.certTemplate, certMaterial.issuerTemplate, certMaterial.csr.PublicKey, rBytes, sBytes)
	if err != nil {
		log.Printf("[%s] Failed to build X.509 certificate: %v", p.NodeID, err)
		return
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Compute certificate hash
	certHash := sha256.Sum256(certDER)
	certHashHex := hex.EncodeToString(certHash[:])

	subject := certMaterial.subject
	publicKeyHex := certMaterial.publicKeyHex
	serialNumberStr := certMaterial.serialNumber.String()
	validityDays := certMaterial.validityDays

	log.Printf("[%s] Registering X.509 certificate for %s...", p.NodeID, submitterID)

	const registerAttempts = 6
	var registerErr error
	for attempt := 1; attempt <= registerAttempts; attempt++ {
		_, registerErr = p.Execute("RegisterCombinedCertificateWithSignature",
			proposalID,
			string(certPEM),
			certHashHex,
			subject,
			publicKeyHex,
			serialNumberStr,
			fmt.Sprintf("%d", validityDays),
			sigR,
			sigS,
		)
		if registerErr == nil {
			break
		}

		// Handle race: another peer may have already registered.
		if containsIgnoreCase(registerErr.Error(), "already") || containsIgnoreCase(registerErr.Error(), "MVCC_READ_CONFLICT") {
			log.Printf("[%s] Certificate already registered for %s (another peer beat us)", p.NodeID, submitterID)
			registerErr = nil
			break
		}

		// Transient state-lag during cross-peer endorsement; keep trying.
		if isTransientSigningSessionLagError(registerErr) && attempt < registerAttempts {
			backoff := computeExecuteBackoff(500*time.Millisecond, 4*time.Second, p.executeBackoffJitterPct, attempt)
			log.Printf("[%s] RegisterCombinedCertificateWithSignature not ready for %s, retry %d/%d in %v",
				p.NodeID, proposalID, attempt+1, registerAttempts, backoff)
			time.Sleep(backoff)
			continue
		}
		break
	}
	if registerErr != nil {
		log.Printf("[%s] Failed to register certificate: %v", p.NodeID, registerErr)
		// If we're the owner, try to sync the cert from chaincode.
		if isOwner {
			p.syncOwnedCertificateWithRetry(5, 2*time.Second)
		}
		if caPublicKeyHex != "" {
			p.persistCAPublicKeyHex(caPublicKeyHex)
		}
		return
	}

	log.Printf("[%s] OK X.509 certificate registered for %s!", p.NodeID, submitterID)
	p.emitMetric("cert_registered", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   submitterID,
	})

	if isOwner {
		// Save certificate to local file (only for the owning org)
		certsDir := filepath.Join("certs", p.Organization)
		os.MkdirAll(certsDir, 0700)
		certPath := filepath.Join(certsDir, proposalID+".cert.pem")
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			log.Printf("[%s] Warning: failed to save certificate: %v", p.NodeID, err)
		} else {
			log.Printf("[%s] Certificate saved to %s", p.NodeID, certPath)
		}
	} else {
		log.Printf("[%s] Skipping certificate save for %s (owned by %s)", p.NodeID, proposalID, submitterID)
	}

	// Also save CA public key for verification
	if caPublicKeyHex != "" {
		p.persistCAPublicKeyHex(caPublicKeyHex)
	}
}

// constructs a DER certificate by embedding the TSS-produced ECDSA signature.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).tryRegisterCertificate.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func buildX509WithTSSSignature(
	template, issuer *x509.Certificate,
	subjectPubKey interface{},
	sigR, sigS []byte,
) ([]byte, error) {
	// Step 1: Create a self-signed cert using a throwaway key, just to get the
	// properly-encoded TBSCertificate ASN.1 structure from Go's x509 library.
	throwawayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate throwaway key: %w", err)
	}

	dummyCertDER, err := x509.CreateCertificate(rand.Reader, template, issuer, subjectPubKey, throwawayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create template cert: %w", err)
	}

	// Step 2: Parse the ASN.1 structure to extract the TBSCertificate portion
	// X.509 Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	var certASN1 struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}
	if _, err := asn1.Unmarshal(dummyCertDER, &certASN1); err != nil {
		return nil, fmt.Errorf("failed to parse dummy cert ASN.1: %w", err)
	}

	// Step 3: Construct the ECDSA signature from TSS R, S values
	// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
	type ecdsaSig struct {
		R, S *big.Int
	}
	sigBytes, err := asn1.Marshal(ecdsaSig{
		R: new(big.Int).SetBytes(sigR),
		S: new(big.Int).SetBytes(sigS),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA signature: %w", err)
	}

	// Step 4: Replace the signature in the certificate with the TSS signature
	certASN1.SignatureValue = asn1.BitString{
		Bytes:     sigBytes,
		BitLength: len(sigBytes) * 8,
	}

	// Step 5: Re-marshal the complete certificate
	finalDER, err := asn1.Marshal(certASN1)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal final cert: %w", err)
	}

	return finalDER, nil
}

// ===================== CSR SUBMISSION =====================

// creates and submits a CSR proposal using an auto-generated proposal ID.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).submitCSRMenu.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) SubmitCSR(cn, org, locality, province, country string) (string, error) {
	return p.SubmitCSRWithID(cn, org, locality, province, country, "")
}

// creates keys/CSR material, submits the proposal, and persists local artifacts.
// Lifecycle: CSR and threshold-signing workflow progression.
// Called by: (*TSSPeer).SubmitCSR, (*TSSPeer).apiSubmitCSR.
// Triggered: CSR/signing workflow initiated from menu, API, or poll-driven progression.
func (p *TSSPeer) SubmitCSRWithID(cn, org, locality, province, country, proposalID string) (string, error) {
	// Generate a proper ECDSA key pair for the CSR
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	subjectName := pkix.Name{
		CommonName:   cn,
		Organization: []string{org},
	}
	if locality != "" {
		subjectName.Locality = []string{locality}
	}
	if province != "" {
		subjectName.Province = []string{province}
	}
	if country != "" {
		subjectName.Country = []string{country}
	}

	template := &x509.CertificateRequest{
		Subject:            subjectName,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	if strings.TrimSpace(proposalID) == "" {
		proposalID = fmt.Sprintf("csr-%s-%d", p.Organization, time.Now().Unix())
	}

	log.Printf("[%s] Submitting CSR for %s (proposal: %s)", p.NodeID, cn, proposalID)

	_, err = p.Execute("SubmitCSR", proposalID, string(csrPEM))
	if err != nil {
		return "", fmt.Errorf("failed to submit CSR: %w", err)
	}

	// Store private key for later use when certificate is issued
	p.mutex.Lock()
	p.csrPrivateKeys[proposalID] = privateKey
	p.mutex.Unlock()

	// Also save the private key to disk immediately
	certsDir := filepath.Join("certs", p.Organization)
	os.MkdirAll(certsDir, 0700)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY",
		Bytes: func() []byte {
			b, _ := x509.MarshalECPrivateKey(privateKey)
			return b
		}(),
	})
	keyPath := filepath.Join(certsDir, proposalID+".key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Printf("[%s] Warning: failed to save private key: %v", p.NodeID, err)
	} else {
		log.Printf("[%s] Private key saved to %s", p.NodeID, keyPath)
	}

	// Save CSR to disk too
	csrPath := filepath.Join(certsDir, proposalID+".csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		log.Printf("[%s] Warning: failed to save CSR: %v", p.NodeID, err)
	}

	log.Printf("[%s] OK CSR submitted: %s", p.NodeID, proposalID)
	p.emitMetric("csr_submitted", map[string]interface{}{
		"proposal_id": proposalID,
	})
	return proposalID, nil
}
