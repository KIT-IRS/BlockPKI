// operations_governance.go bundles governance workflows including join/removal/revocation and reshare control operations.
// Runtime flow: polling/menu/API triggers drive proposal lifecycle actions and membership-related state transitions.

// Handles different reshare sessions and states

package main

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

type governanceMetricEvent struct {
	name   string
	fields map[string]interface{}
}

// ===================== RESHARE SESSION POLLING =====================

// checks active reshare sessions and advances local reshare progress.
// Lifecycle: Governance workflow progression (join/removal/revocation/reshare).
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in governance automation.
func (p *TSSPeer) checkReshareSessions() {
	// Get CA to check epoch
	ca, err := p.GetCA()
	if err != nil {
		return
	}

	// Check if still a CA member - if not, skip reshare entirely
	members, _ := ca["members"].([]interface{})
	isMember := false
	for _, m := range members {
		if mStr, ok := m.(string); ok && mStr == p.MemberID {
			isMember = true
			break
		}
	}
	if !isMember {
		return // Not a CA member, no reshare to process
	}

	epoch, ok := ca["epoch"].(float64)
	if !ok {
		return
	}

	if pub, ok := ca["publicKey"].(string); ok && strings.TrimSpace(pub) == "" {
		// Reshare requires a completed DKG with a CA public key.
		return
	}

	// Skip if this epoch is already completed
	p.mutex.RLock()
	epochDone := p.completedEpochs[int(epoch)]
	epochMissingShare := p.missingShareReshares[int(epoch)]
	isKeygen := p.keygenInProgress
	p.mutex.RUnlock()
	if epochDone || epochMissingShare {
		p.clearKeySessionProgress(fmt.Sprintf("reshare:%d", int(epoch)))
		return
	}

	// Check for reshare at current epoch
	result, err := p.Query("GetReshareSession", fmt.Sprintf("%d", int(epoch)))
	if err != nil {
		// "not found" is expected when no reshare is active; avoid log spam.
		if containsIgnoreCase(err.Error(), "reshare session not found") {
			p.clearKeySessionProgress(fmt.Sprintf("reshare:%d", int(epoch)))
			return
		}
		log.Printf("[%s] GetReshareSession(%d) failed: %v", p.NodeID, int(epoch), err)
		return
	}

	var reshare map[string]interface{}
	if err := json.Unmarshal(result, &reshare); err != nil {
		return
	}

	status, _ := reshare["status"].(string)
	ackCount := intFromAny(reshare["ackCount"])
	completionAckCount := intFromAny(reshare["completionAckCount"])
	reshareSessionKey := fmt.Sprintf("reshare:%d", int(epoch))
	if status == "initiated" || status == "acknowledged" || status == "proposed" {
		if shouldEscalate, stalledFor := p.checkKeySessionStall(reshareSessionKey, status, ackCount, completionAckCount); shouldEscalate {
			reason := fmt.Sprintf("stuck_reshare_status_%s_epoch_%d_%ds", status, int(epoch), int(stalledFor.Seconds()))
			log.Printf("[%s] Reshare session appears stalled (epoch=%d, status=%s, ack=%d, complete=%d, stalled=%s); evaluating fresh DKG recovery", p.NodeID, int(epoch), status, ackCount, completionAckCount, stalledFor.Round(time.Second))
			p.tryAutoForceFreshDKG(int(epoch), reason, true, true)
		}
	} else {
		p.clearKeySessionProgress(reshareSessionKey)
	}

	switch status {
	case "initiated":
		// Check if already acknowledged
		ackedBy, _ := reshare["acknowledgedBy"].([]interface{})
		alreadyAcked := false
		for _, acked := range ackedBy {
			if ackedStr, ok := acked.(string); ok && ackedStr == p.MemberID {
				alreadyAcked = true
				break
			}
		}

		if alreadyAcked {
			return
		}

		// Check if we're even in the new node set before trying
		newNodeSet := toStringSlice(reshare["newNodeSet"])
		isMemberOfReshare := false
		for _, n := range newNodeSet {
			if n == p.MemberID {
				isMemberOfReshare = true
				break
			}
		}
		if !isMemberOfReshare {
			// removed from the CA - mark this epoch done so we stop retrying
			log.Printf("[%s] Not in reshare node set for epoch %d (we may have been removed)", p.NodeID, int(epoch))
			p.mutex.Lock()
			p.completedEpochs[int(epoch)] = true
			p.mutex.Unlock()
			return
		}

		log.Printf("[%s] Found pending reshare for epoch %d, acknowledging...", p.NodeID, int(epoch))
		_, err = p.Execute("AcknowledgeReshare", fmt.Sprintf("%d", int(epoch)))
		if err != nil {
			log.Printf("[%s] Failed to acknowledge reshare: %v", p.NodeID, err)
			// If not in the node set, stop retrying
			if containsIgnoreCase(err.Error(), "not in new node set") {
				p.mutex.Lock()
				p.completedEpochs[int(epoch)] = true
				p.mutex.Unlock()
			}
		} else {
			log.Printf("[%s] Acknowledged reshare for epoch %d", p.NodeID, int(epoch))
			reason, _ := reshare["triggerReason"].(string)
			p.emitMetric("reshare_acknowledged", map[string]interface{}{
				"epoch":     int(epoch),
				"threshold": reshare["newThreshold"],
				"reason":    reason,
			})
		}

	case "acknowledged":
		// All nodes have acknowledged, ready to execute reshare
		// Skip if keygen is already in progress or this epoch was already completed
		if isKeygen {
			return
		}

		// Verify in the new node set
		newNodeSet := toStringSlice(reshare["newNodeSet"])
		isMemberOfReshare := false
		for _, n := range newNodeSet {
			if n == p.MemberID {
				isMemberOfReshare = true
				break
			}
		}
		if !isMemberOfReshare {
			log.Printf("[%s] Not in reshare node set for epoch %d, skipping", p.NodeID, int(epoch))
			p.mutex.Lock()
			p.completedEpochs[int(epoch)] = true
			p.mutex.Unlock()
			return
		}

		// Edge case: single-node reshare (N=1) - no threshold crypto possible
		if len(newNodeSet) <= 1 {
			log.Printf("[%s] Single-node reshare for epoch %d - completing directly (no TSS needed)", p.NodeID, int(epoch))
			// With only 1 node, there's no threshold to distribute. Just complete the reshare.
			existingPubKey := ""
			if caPub, ok := ca["publicKey"].(string); ok && strings.TrimSpace(caPub) != "" {
				existingPubKey = caPub
			}
			if existingPubKey == "" && p.TSSKeyShare != nil && p.TSSKeyShare.ECDSAPub != nil {
				pubBytes := elliptic.Marshal(
					p.TSSKeyShare.ECDSAPub.Curve(),
					p.TSSKeyShare.ECDSAPub.X(),
					p.TSSKeyShare.ECDSAPub.Y(),
				)
				existingPubKey = hex.EncodeToString(pubBytes)
			}
			if existingPubKey == "" {
				log.Printf("[%s] Cannot complete single-node reshare: no public key available", p.NodeID)
				return
			}
			p.completeReshare(int(epoch), existingPubKey)
			return
		}

		// Load peer addresses and execute reshare
		if err := p.LoadPeerAddresses(); err != nil {
			log.Printf("[%s] Failed to load peer addresses for reshare: %v", p.NodeID, err)
			return
		}

		if !p.waitForPeersSubset(newNodeSet, 30*time.Second) {
			log.Printf("[%s] Not all peers reachable for reshare", p.NodeID)
			return
		}

		log.Printf("[%s] Reshare acknowledged - starting TSS reshare keygen...", p.NodeID)
		reason, _ := reshare["triggerReason"].(string)
		p.emitMetric("reshare_keygen_start", map[string]interface{}{
			"epoch":     int(epoch),
			"threshold": reshare["newThreshold"],
			"reason":    reason,
		})

		p.executeTSSReshare(int(epoch), reshare)

	case "proposed":
		// Reshare completion proposed; acknowledge if key share present.
		// If key share is missing, re-enter local reshare execution to avoid stalls.
		newNodeSet := toStringSlice(reshare["newNodeSet"])
		isMemberOfReshare := false
		for _, n := range newNodeSet {
			if n == p.MemberID {
				isMemberOfReshare = true
				break
			}
		}
		if !isMemberOfReshare {
			return
		}
		ackedBy, _ := reshare["completionAckedBy"].([]interface{})
		for _, acked := range ackedBy {
			if ackedStr, ok := acked.(string); ok && ackedStr == p.MemberID {
				return
			}
		}
		completionAckCount := intFromAny(reshare["completionAckCount"])
		requiredCompletionAcks := intFromAny(reshare["completionRequiredAcks"])
		if requiredCompletionAcks <= 0 {
			newThreshold := intFromAny(reshare["newThreshold"])
			requiredCompletionAcks = newThreshold + 1
		}
		if requiredCompletionAcks < 1 {
			requiredCompletionAcks = 1
		}
		if len(newNodeSet) > 0 && requiredCompletionAcks > len(newNodeSet) {
			requiredCompletionAcks = len(newNodeSet)
		}
		p.mutex.RLock()
		keyShare := p.TSSKeyShare
		keySessionInProgress := p.keygenInProgress
		keySessionEpoch := p.keygenEpoch
		p.mutex.RUnlock()

		keyShareUsableForCompletion := keyShare != nil && keyShare.ECDSAPub != nil
		if keyShareUsableForCompletion {
			oldSalt := ""
			if v, ok := reshare["oldPartySalt"].(string); ok {
				oldSalt = strings.TrimSpace(v)
			}
			newSalt := ""
			if v, ok := reshare["newPartySalt"].(string); ok {
				newSalt = strings.TrimSpace(v)
			}
			explicitSalts := oldSalt != "" || newSalt != ""
			shareMatchesNewCommittee := false
			if explicitSalts {
				// When chaincode specifies reshare salts, completion must only use a
				// key share that matches the exact on-chain new committee salt (including "").
				expectedNew := p.buildReshareCommittee(newNodeSet, "new", newSalt)
				shareMatchesNewCommittee = keyShareContainsPartyIDs(keyShare, expectedNew.partyIDs)
			} else if newSalt != "" {
				expectedNew := p.buildReshareCommittee(newNodeSet, "new", newSalt)
				shareMatchesNewCommittee = keyShareContainsPartyIDs(keyShare, expectedNew.partyIDs)
			} else {
				expectedUnsalted := p.buildReshareCommittee(newNodeSet, "new", "")
				expectedSalted := p.buildReshareCommittee(newNodeSet, "new", "new")
				shareMatchesNewCommittee = keyShareContainsPartyIDs(keyShare, expectedUnsalted.partyIDs) ||
					keyShareContainsPartyIDs(keyShare, expectedSalted.partyIDs)
			}
			if !shareMatchesNewCommittee {
				keyShareUsableForCompletion = false
				log.Printf("[%s] Proposed reshare for epoch %d has stale local key share; waiting for local reshare before completion ack", p.NodeID, int(epoch))
			}
		}

		if !keyShareUsableForCompletion {
			// Retry local reshare execution at a controlled cadence while waiting for completion.
			// If the last missing ack and local reshare appears stuck for this same
			// epoch, may acknowledge completion with the on-chain reshare public key to unblock quorum.
			// IMPORTANT: avoid this shortcut for 2-member committees; it can finalize on-chain while local
			// share remains stale and trigger repeated follow-up reshare loops.
			const completionFallbackMinStall = 60 * time.Second
			sessionStalledFor := time.Duration(0)
			p.mutex.RLock()
			if rec, ok := p.sessionProgress[fmt.Sprintf("reshare:%d", int(epoch))]; ok {
				if rec.Status == "proposed" && !rec.LastProgressAt.IsZero() {
					sessionStalledFor = time.Since(rec.LastProgressAt)
				}
			}
			p.mutex.RUnlock()
			if requiredCompletionAcks > 0 &&
				len(newNodeSet) > 2 &&
				completionAckCount >= requiredCompletionAcks-1 &&
				keySessionInProgress &&
				keySessionEpoch == int(epoch) &&
				sessionStalledFor >= completionFallbackMinStall {
				pubKeyHex := getResharePublicKeyHex(reshare)
				if pubKeyHex == "" {
					if caPub, ok := ca["publicKey"].(string); ok {
						pubKeyHex = strings.TrimSpace(caPub)
					}
				}
				if pubKeyHex != "" {
					log.Printf("[%s] Proposed reshare for epoch %d appears blocked on local stale session; submitting completion ack with on-chain public key to unblock quorum", p.NodeID, int(epoch))
					p.completeReshare(int(epoch), pubKeyHex)
					return
				}
			}

			p.mutex.Lock()
			lastAttempt := p.lastReshareResumeAttempt[int(epoch)]
			if !lastAttempt.IsZero() && time.Since(lastAttempt) < 20*time.Second {
				p.mutex.Unlock()
				return
			}
			p.lastReshareResumeAttempt[int(epoch)] = time.Now()
			p.mutex.Unlock()

			if err := p.LoadPeerAddresses(); err != nil {
				log.Printf("[%s] Proposed reshare for epoch %d but key share is missing; failed to load peers for resume: %v", p.NodeID, int(epoch), err)
				return
			}
			if !p.waitForPeersSubset(newNodeSet, 30*time.Second) {
				log.Printf("[%s] Proposed reshare for epoch %d but key share is missing; peers not reachable for resume", p.NodeID, int(epoch))
				return
			}
			if keySessionInProgress {
				log.Printf("[%s] Proposed reshare for epoch %d waiting for local key session to finish (epoch=%d)", p.NodeID, int(epoch), keySessionEpoch)
				return
			}
			log.Printf("[%s] Proposed reshare for epoch %d but key share is missing; re-running local reshare", p.NodeID, int(epoch))
			p.emitMetric("reshare_resume_from_proposed", map[string]interface{}{
				"epoch": int(epoch),
			})
			p.executeTSSReshare(int(epoch), reshare)
			return
		}
		p.mutex.Lock()
		delete(p.lastReshareResumeAttempt, int(epoch))
		p.mutex.Unlock()
		pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
		pubKeyHex := hex.EncodeToString(pubBytes)
		log.Printf("[%s] Reshare completion proposed; acknowledging with local public key", p.NodeID)
		p.completeReshare(int(epoch), pubKeyHex)

	case "completed":
		p.clearKeySessionProgress(reshareSessionKey)
		shouldEmit := false
		clearLocalKeySession := false
		p.mutex.Lock()
		if !p.completedEpochs[int(epoch)] {
			p.completedEpochs[int(epoch)] = true
		}
		if !p.observedReshares[int(epoch)] {
			p.observedReshares[int(epoch)] = true
			shouldEmit = true
		}
		if p.keygenInProgress && p.keygenEpoch == int(epoch) {
			p.keygenInProgress = false
			p.keygenEpoch = -1
			clearLocalKeySession = true
		}
		p.mutex.Unlock()
		if clearLocalKeySession {
			select {
			case <-p.keygenDone:
			default:
				close(p.keygenDone)
			}
		}
		if shouldEmit {
			log.Printf("[%s] Reshare completion observed on-chain for epoch %d", p.NodeID, int(epoch))
			reason, _ := reshare["triggerReason"].(string)
			p.emitMetric("reshare_complete_observed", map[string]interface{}{
				"epoch":  int(epoch),
				"reason": reason,
			})
		}
		if stale, staleReason := p.isKeyShareStale(); stale {
			log.Printf("[%s] Local key share still stale after reshare completion (%s); forcing follow-up reshare", p.NodeID, staleReason)
			p.autoForceReshareMissingShare()
		}
	case "superseded":
		p.clearKeySessionProgress(reshareSessionKey)
		clearLocalKeySession := false
		p.mutex.Lock()
		p.completedEpochs[int(epoch)] = true
		if p.keygenInProgress && p.keygenEpoch == int(epoch) {
			p.keygenInProgress = false
			p.keygenEpoch = -1
			clearLocalKeySession = true
		}
		p.mutex.Unlock()
		if clearLocalKeySession {
			select {
			case <-p.keygenDone:
			default:
				close(p.keygenDone)
			}
		}
		return
	}
}

// ===================== REVOCATION AUTO-VOTING =====================

// scans pending revocation proposals and submits auto-votes when eligible.
// Lifecycle: Governance workflow progression (join/removal/revocation/reshare).
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in governance automation.
func (p *TSSPeer) checkPendingRevocations() {
	result, err := p.Query("GetPendingRevocations")
	if err != nil {
		return
	}

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
		if targetID, ok := proposal["targetNodeId"].(string); ok && targetID != "" {
			p.mutex.Lock()
			p.pendingRevocations[proposalID] = targetID
			p.mutex.Unlock()
		}
		p.mutex.Lock()
		if !p.observedRevocationSubmits[proposalID] {
			p.observedRevocationSubmits[proposalID] = true
			p.mutex.Unlock()
			p.emitMetric("revocation_proposed_observed", map[string]interface{}{
				"proposal_id": proposalID,
			})
		} else {
			p.mutex.Unlock()
		}

		// Check if already voted
		votersList, _ := proposal["votersList"].([]interface{})
		alreadyVoted := false
		for _, v := range votersList {
			if voterStr, ok := v.(string); ok && voterStr == p.MemberID {
				alreadyVoted = true
				break
			}
		}
		if alreadyVoted {
			continue
		}

		if !p.isCAMember() {
			p.logAutoVoteSkip("revocation", proposalID, "not a CA member")
			continue
		}
		if inProgress, epoch := p.localKeySessionState(); inProgress {
			p.logAutoVoteSkip("revocation", proposalID, fmt.Sprintf("local key session in progress (epoch=%d)", epoch))
			continue
		}

		// Auto-vote approve on revocations
		log.Printf("[%s] Auto-voting approve on revocation proposal %s", p.NodeID, proposalID)
		p.applyAutoVoteJitter("revocation", proposalID)
		_, err := p.Execute("VoteOnRevocation", proposalID, "approve", "auto-approved by peer")
		if err != nil {
			errMsg := err.Error()
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "revoked") ||
				containsIgnoreCase(errMsg, "not a member") {
				// Permanent failure - stop retrying
				continue
			}
			if isSessionSerializationError(err) {
				// Temporary chaincode serialization guard; retry later.
				continue
			}
			log.Printf("[%s] Failed to vote on revocation %s: %v", p.NodeID, proposalID, err)
		} else {
			log.Printf("[%s] OK Voted approve on revocation %s", p.NodeID, proposalID)
			p.emitMetric("revocation_voted", map[string]interface{}{
				"proposal_id": proposalID,
				"vote":        "approve",
			})
		}
	}
}

// ===================== OBSERVED ON-CHAIN COMPLETIONS =====================

// maps observed certificate ledger state into local benchmark/event markers.
// Lifecycle: Governance workflow progression (join/removal/revocation/reshare).
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in governance automation.
func (p *TSSPeer) checkObservedCertificates() {
	result, err := p.Query("GetAllCertificates")
	if err != nil {
		return
	}
	if len(result) == 0 || string(result) == "null" {
		return
	}

	var certs []map[string]interface{}
	if err := json.Unmarshal(result, &certs); err != nil {
		return
	}

	events := make([]governanceMetricEvent, 0)
	needSync := false

	p.mutex.Lock()
	for _, c := range certs {
		proposalID := ""
		if v, ok := c["certId"].(string); ok && strings.HasPrefix(v, "CERT:") {
			proposalID = strings.TrimPrefix(v, "CERT:")
		} else if v, ok := c["proposalId"].(string); ok && v != "" {
			proposalID = v
		}

		if proposalID != "" && !p.observedCerts[proposalID] {
			p.observedCerts[proposalID] = true
			memberID, _ := c["memberId"].(string)
			events = append(events, governanceMetricEvent{
				name: "cert_registered_observed",
				fields: map[string]interface{}{
					"proposal_id": proposalID,
					"member_id":   memberID,
				},
			})
			if memberID != "" && memberID == p.MemberID {
				needSync = true
			}
		}

		if revoked, _ := c["isRevoked"].(bool); revoked {
			memberID, _ := c["memberId"].(string)
			for proposalID, target := range p.pendingRevocations {
				if target == memberID && !p.observedRevocations[proposalID] {
					p.observedRevocations[proposalID] = true
					delete(p.pendingRevocations, proposalID)
					events = append(events, governanceMetricEvent{
						name: "revocation_executed_observed",
						fields: map[string]interface{}{
							"proposal_id": proposalID,
							"member_id":   memberID,
						},
					})
				}
			}
		}
	}
	p.mutex.Unlock()

	for _, ev := range events {
		p.emitMetric(ev.name, ev.fields)
	}
	if needSync {
		go p.syncOwnedCertificateWithRetry(5, 2*time.Second)
	}
}

// maps membership set changes to pending join/removal proposal outcomes.
// Lifecycle: Governance workflow progression (join/removal/revocation/reshare).
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in governance automation.
func (p *TSSPeer) checkObservedMembershipChanges() {
	ca, err := p.GetCA()
	if err != nil {
		return
	}

	membersRaw, _ := ca["members"].([]interface{})
	memberSet := make(map[string]bool, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			memberSet[s] = true
		}
	}
	p.setMemberStatus(memberSet[p.MemberID])

	events := make([]governanceMetricEvent, 0)

	p.mutex.Lock()
	for proposalID, candidate := range p.pendingJoinRequests {
		if candidate != "" && memberSet[candidate] && !p.observedJoinApprovals[proposalID] {
			p.observedJoinApprovals[proposalID] = true
			delete(p.pendingJoinRequests, proposalID)
			events = append(events, governanceMetricEvent{
				name: "join_request_approved_observed",
				fields: map[string]interface{}{
					"proposal_id": proposalID,
					"member_id":   candidate,
				},
			})
		}
	}
	for proposalID, target := range p.pendingRemovals {
		if target != "" && !memberSet[target] && !p.observedRemovals[proposalID] {
			p.observedRemovals[proposalID] = true
			delete(p.pendingRemovals, proposalID)
			events = append(events, governanceMetricEvent{
				name: "member_removal_executed_observed",
				fields: map[string]interface{}{
					"proposal_id": proposalID,
					"member_id":   target,
				},
			})
		}
	}
	p.mutex.Unlock()

	for _, ev := range events {
		p.emitMetric(ev.name, ev.fields)
	}
}

// ===================== JOIN REQUEST AUTO-VOTING =====================

// scans pending join requests and auto-votes with recovery-aware guards.
// Lifecycle: Governance workflow progression (join/removal/revocation/reshare).
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in governance automation.
func (p *TSSPeer) checkPendingJoinRequests() {
	result, err := p.Query("ListPendingJoinRequests", DefaultCAID)
	if err != nil {
		return
	}

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
		if candidateID, ok := proposal["candidateId"].(string); ok && candidateID != "" {
			p.mutex.Lock()
			p.pendingJoinRequests[proposalID] = candidateID
			p.mutex.Unlock()
		}
		p.mutex.Lock()
		if !p.observedJoinSubmits[proposalID] {
			p.observedJoinSubmits[proposalID] = true
			p.mutex.Unlock()
			p.emitMetric("join_request_submitted_observed", map[string]interface{}{
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
		for _, v := range votersList {
			if voterStr, ok := v.(string); ok && voterStr == p.MemberID {
				alreadyVoted = true
				break
			}
		}
		if alreadyVoted {
			continue
		}

		if !p.isCAMember() {
			p.logAutoVoteSkip("join_request", proposalID, "not a CA member")
			continue
		}
		if inProgress, epoch := p.localKeySessionState(); inProgress {
			p.mutex.RLock()
			recoveryStatus := p.recoveryStatus
			p.mutex.RUnlock()
			allowDuringRecovery := strings.Contains(recoveryStatus, "reshare_degraded_new_only") ||
				strings.Contains(recoveryStatus, "auto_fresh_dkg_waiting_governance")
			if !allowDuringRecovery {
				p.logAutoVoteSkip("join_request", proposalID, fmt.Sprintf("local key session in progress (epoch=%d)", epoch))
				continue
			}
			log.Printf("[%s] Auto-voting join request %s despite local key session in progress (epoch=%d, recovery=%s)", p.NodeID, proposalID, epoch, recoveryStatus)
		}

		candidateRole := "unknown"
		if roleRaw, ok := proposal["candidateRole"].(string); ok {
			roleNorm := strings.ToLower(strings.TrimSpace(roleRaw))
			if roleNorm != "" {
				candidateRole = roleNorm
			}
		}

		// Auto-vote approve (placeholder; replace with policy validation as needed)
		log.Printf("[%s] Auto-voting on join request %s (candidateRole=%s, voterRole=ca-member)", p.NodeID, proposalID, candidateRole)
		p.applyAutoVoteJitter("join_request", proposalID)
		_, err := p.Execute("VoteOnJoinRequest", DefaultCAID, proposalID, "approve", "Autonomous approval")
		if err != nil {
			errMsg := err.Error()
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "not a member") ||
				containsIgnoreCase(errMsg, "revoked") ||
				containsIgnoreCase(errMsg, "role") ||
				containsIgnoreCase(errMsg, "certificate") {
				continue
			}
			if isSessionSerializationError(err) {
				// Temporary chaincode serialization guard; retry later.
				continue
			}
			log.Printf("[%s] Failed to vote on join request %s: %v", p.NodeID, proposalID, err)
		} else {
			log.Printf("[%s] Voted approve on join request %s", p.NodeID, proposalID)
			p.emitMetric("join_request_voted", map[string]interface{}{
				"proposal_id": proposalID,
				"vote":        "approve",
			})
		}
	}
}

// ===================== MEMBER REMOVAL AUTO-VOTING =====================

// scans pending member removals and auto-votes when allowed.
// Lifecycle: Governance workflow progression (join/removal/revocation/reshare).
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick in governance automation.
func (p *TSSPeer) checkPendingRemoveMemberProposals() {
	result, err := p.Query("ListPendingRemoveMemberProposals", DefaultCAID)
	if err != nil {
		return
	}

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
		if targetID, ok := proposal["targetMemberId"].(string); ok && targetID != "" {
			p.mutex.Lock()
			p.pendingRemovals[proposalID] = targetID
			p.mutex.Unlock()
		}
		p.mutex.Lock()
		if !p.observedRemovalSubmits[proposalID] {
			p.observedRemovalSubmits[proposalID] = true
			p.mutex.Unlock()
			p.emitMetric("member_removal_proposed_observed", map[string]interface{}{
				"proposal_id": proposalID,
			})
		} else {
			p.mutex.Unlock()
		}

		status, _ := proposal["status"].(string)
		if status != "pending" {
			continue
		}

		// Check if already voted
		votersList, _ := proposal["votersList"].([]interface{})
		alreadyVoted := false
		for _, v := range votersList {
			if voterStr, ok := v.(string); ok && voterStr == p.MemberID {
				alreadyVoted = true
				break
			}
		}
		if alreadyVoted {
			continue
		}

		if !p.isCAMember() {
			p.logAutoVoteSkip("member_removal", proposalID, "not a CA member")
			continue
		}
		if inProgress, epoch := p.localKeySessionState(); inProgress {
			p.logAutoVoteSkip("member_removal", proposalID, fmt.Sprintf("local key session in progress (epoch=%d)", epoch))
			continue
		}

		// Auto-vote approve (placeholder; replace with policy validation as needed)
		log.Printf("[%s] Auto-voting approve on member removal %s", p.NodeID, proposalID)
		p.applyAutoVoteJitter("member_removal", proposalID)
		_, err := p.Execute("VoteOnRemoveMember", DefaultCAID, proposalID, "approve", "auto-approved by peer")
		if err != nil {
			errMsg := err.Error()
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "not a member") ||
				containsIgnoreCase(errMsg, "revoked") {
				continue
			}
			if isSessionSerializationError(err) {
				// Temporary chaincode serialization guard; retry later.
				continue
			}
			log.Printf("[%s] Failed to vote on member removal %s: %v", p.NodeID, proposalID, err)
		} else {
			log.Printf("[%s] Voted approve on member removal %s", p.NodeID, proposalID)
			p.emitMetric("member_removal_voted", map[string]interface{}{
				"proposal_id": proposalID,
				"vote":        "approve",
			})
		}
	}
}
