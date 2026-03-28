// runtime_dkg_polling.go coordinates CA bootstrap/join logic, periodic polling, and DKG/reshare recovery automation.
// Runtime flow: startup launches StartPollingLoop, which drives session checks, auto-voting, and stall recovery.

// handles functions that poll for dkg and administers membership state

package main

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// keySessionProgress tracks stall detection state for DKG/reshare sessions.
type keySessionProgress struct {
	Status             string
	AckCount           int
	CompletionAckCount int
	LastProgressAt     time.Time
	LastEscalationAt   time.Time
}

// returns the on-chain DKG session document for the requested epoch.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: polling/runtime control flow for DKG and membership.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) GetDKGSession(epoch int) (map[string]interface{}, error) {
	payload, err := p.Query("GetDKGSession", fmt.Sprintf("%d", epoch))
	if err != nil {
		return nil, err
	}

	var dkg map[string]interface{}
	if err := json.Unmarshal(payload, &dkg); err != nil {
		return nil, err
	}
	return dkg, nil
}

// Checks whether the ca is initialized and applies join-mode bootstrap behavior.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: main.
// Triggered: polling/runtime control flow for DKG and membership.
func (p *TSSPeer) EnsureCAInitialized() error {
	log.Printf("[%s] Checking if CA exists...", p.NodeID)

	// Try to initialize CA with MVCC retry
	for attempt := 0; attempt < 3; attempt++ {
		_, err := p.GetCA()
		if err != nil {
			// CA doesn't exist, try to initialize
			log.Printf("[%s] Initializing CA...", p.NodeID)
			_, err = p.Execute("InitializeDistributedCA", DefaultCAID, "Decentralized PKI CA", "2", "")
			if err != nil {
				if containsIgnoreCase(err.Error(), "already exists") {
					log.Printf("[%s] CA already initialized by another node", p.NodeID)
					break
				} else if containsIgnoreCase(err.Error(), "MVCC_READ_CONFLICT") {
					log.Printf("[%s] MVCC conflict during init, retrying... (attempt %d/3)", p.NodeID, attempt+1)
					time.Sleep(time.Duration(attempt+1) * time.Second)
					continue // Retry - check if CA exists now
				} else {
					return fmt.Errorf("failed to initialize CA: %v", err)
				}
			} else {
				log.Printf("[%s] CA initialized successfully", p.NodeID)
				break
			}
		} else {
			log.Printf("[%s] CA already exists", p.NodeID)
			break
		}
	}

	switch normalizeJoinMode(p.joinMode) {
	case "none":
		log.Printf("[%s] Join mode=none; skipping CA join", p.NodeID)
		return nil
	case "request":
		// Avoid noisy self-join attempts during recovery when this node is already
		// part of the CA membership.
		if ca, err := p.GetCA(); err == nil {
			for _, m := range toStringSlice(ca["members"]) {
				if m == p.MemberID {
					log.Printf("[%s] Join mode=request but node is already a CA member; skipping RequestJoinCA", p.NodeID)
					return nil
				}
			}
		}
		proposalID := fmt.Sprintf("join-%s-%d", p.Organization, time.Now().Unix())
		log.Printf("[%s] Submitting join request (%s)...", p.NodeID, proposalID)
		if err := p.RequestJoinCA(proposalID, "auto_join_request"); err != nil {
			if containsIgnoreCase(err.Error(), "already") {
				log.Printf("[%s] Join request already exists or member already joined", p.NodeID)
			} else {
				log.Printf("[%s] Join request warning: %v", p.NodeID, err)
			}
		} else {
			log.Printf("[%s] Join request submitted (%s)", p.NodeID, proposalID)
		}
		return nil
	default:
		// Try to join via bootstrap with retry for MVCC conflicts
		log.Printf("[%s] Attempting bootstrap join...", p.NodeID)
		for attempt := 0; attempt < 3; attempt++ {
			_, err := p.Execute("BootstrapJoinCA", DefaultCAID, "3")
			if err != nil {
				if containsIgnoreCase(err.Error(), "already") {
					log.Printf("[%s] Already a CA member", p.NodeID)
					break
				} else if containsIgnoreCase(err.Error(), "bootstrap") {
					log.Printf("[%s] Bootstrap period ended - submit a join request to become a member", p.NodeID)
					break
				} else if containsIgnoreCase(err.Error(), "MVCC_READ_CONFLICT") {
					log.Printf("[%s] MVCC conflict, retrying... (attempt %d/3)", p.NodeID, attempt+1)
					time.Sleep(time.Duration(attempt+1) * time.Second)
					continue
				} else {
					log.Printf("[%s] Bootstrap join warning: %v", p.NodeID, err)
					break
				}
			} else {
				log.Printf("[%s] Successfully joined CA", p.NodeID)
				break
			}
		}

		// Check if a member, if not, advise join request
		p.checkMembershipStatus()
	}

	return nil
}

// whether this peer is currently in the CA member set (with appended dkg).
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).EnsureCAInitialized.
// Triggered: polling tick while reconciling DKG, governance, and session state.
func (p *TSSPeer) checkMembershipStatus() {
	ca, err := p.GetCA()
	if err != nil {
		return
	}

	membersRaw, _ := ca["members"].([]interface{})
	isMember := false
	for _, m := range membersRaw {
		if mStr, ok := m.(string); ok && mStr == p.MemberID {
			isMember = true
			break
		}
	}
	p.setMemberStatus(isMember)

	if !isMember {
		log.Printf("[%s] WARNING: Not a CA member. Submit a join request to be considered.", p.NodeID)
		log.Printf("[%s] Join request ID format: join-%s-<unix_ts>", p.NodeID, p.Organization)
		log.Printf("[%s] Member ID: %s", p.NodeID, p.MemberID)
	} else {
		log.Printf("[%s] Confirmed as CA member", p.NodeID)

		// Check if DKG needs to be initiated
		p.checkAndInitiateDKG()
	}
}

// initiates DKG when membership and key-state preconditions are met.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).checkMembershipStatus.
// Triggered: polling tick while reconciling DKG, governance, and session state.
func (p *TSSPeer) checkAndInitiateDKG() {
	ca, err := p.GetCA()
	if err != nil {
		return
	}

	membersRaw, _ := ca["members"].([]interface{})
	threshold := 1
	if t, ok := ca["thresholdParams"].(map[string]interface{}); ok {
		if th, ok := t["threshold"].(float64); ok {
			threshold = int(th)
		}
	}
	caPublicKey := ""
	if pk, ok := ca["publicKey"].(string); ok {
		caPublicKey = strings.TrimSpace(pk)
	}

	p.mutex.RLock()
	hasShare := p.TSSKeyShare != nil
	p.mutex.RUnlock()

	// If a key already exists on-chain and no local share, trigger reshare.
	if caPublicKey != "" && !hasShare {
		log.Printf("[%s] Joined CA with existing public key; requesting reshare", p.NodeID)
		p.autoForceReshareMissingShare()
		return
	}

	// Check if DKG already exists
	_, err = p.GetDKGSession(0)
	if err == nil {
		log.Printf("[%s] DKG session already exists", p.NodeID)
		return
	}

	// Auto-initiate DKG once at least 2 members and no key exists yet.
	if len(membersRaw) < 2 {
		log.Printf("[%s] Need at least 2 members for DKG, currently have %d", p.NodeID, len(membersRaw))
		return
	}

	log.Printf("[%s] Auto-initiating DKG after join (members=%d, threshold=%d)", p.NodeID, len(membersRaw), threshold)
	if _, err := p.Execute("InitiateDKG", DefaultCAID); err != nil {
		log.Printf("[%s] InitiateDKG failed: %v", p.NodeID, err)
		return
	}
	log.Printf("[%s] DKG initiated successfully", p.NodeID)
}

// updates cached membership state and clears skipped auto-votes after joining.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).checkMembershipStatus, (*TSSPeer).checkObservedMembershipChanges.
// Triggered: polling/runtime control flow for DKG and membership.
func (p *TSSPeer) setMemberStatus(isMember bool) {
	p.mutex.Lock()
	prev := p.isMember
	p.isMember = isMember
	if isMember && !prev {
		// Clear any skipped auto-votes once a member.
		p.autoVoteSkipped = make(map[string]bool)
	}
	p.mutex.Unlock()
}

// reports whether this node is currently a CA member.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: polling/runtime control flow for DKG and membership.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) isCAMember() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.isMember
}

// returns local key-session in-progress state and active epoch
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: polling/runtime control flow for DKG and membership.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) localKeySessionState() (inProgress bool, epoch int) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.keygenInProgress, p.keygenEpoch
}

// reports whether signing should be blocked by active DKG/reshare state to not sign while in progress
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).checkSigningSessions.
// Triggered: polling/runtime control flow for DKG and membership.
func (p *TSSPeer) signingBlockedByKeySession() (bool, string) {
	if inProgress, epoch := p.localKeySessionState(); inProgress {
		return true, fmt.Sprintf("local key session in progress (epoch=%d)", epoch)
	}

	if dkg, err := p.GetDKGSession(0); err == nil {
		if status, _ := dkg["status"].(string); status == "initiated" || status == "ready" || status == "proposed" {
			return true, fmt.Sprintf("dkg status %s", status)
		}
	}

	ca, err := p.GetCA()
	if err != nil {
		return false, ""
	}
	if pub, ok := ca["publicKey"].(string); !ok || strings.TrimSpace(pub) == "" {
		return false, ""
	}
	epochRaw, ok := ca["epoch"].(float64)
	if !ok {
		return false, ""
	}
	epoch := int(epochRaw)
	reshareRaw, err := p.Query("GetReshareSession", fmt.Sprintf("%d", epoch))
	if err != nil {
		if containsIgnoreCase(err.Error(), "reshare session not found") {
			return false, ""
		}
		return false, ""
	}
	if len(reshareRaw) == 0 || string(reshareRaw) == "null" {
		return false, ""
	}

	var reshare map[string]interface{}
	if err := json.Unmarshal(reshareRaw, &reshare); err != nil {
		return false, ""
	}
	status, _ := reshare["status"].(string)
	if status == "initiated" || status == "acknowledged" || status == "proposed" {
		return true, fmt.Sprintf("reshare epoch %d status %s", epoch, status)
	}
	return false, ""
}

// records and logs a one-time auto-vote skip reason for a proposal (primarily if not a member and no voting rights anyway)
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: recovery path when stalled sessions or missing key shares are detected.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) logAutoVoteSkip(kind, proposalID, reason string) {
	key := kind + ":" + proposalID
	p.mutex.Lock()
	if p.autoVoteSkipped[key] {
		p.mutex.Unlock()
		return
	}
	p.autoVoteSkipped[key] = true
	p.mutex.Unlock()
	log.Printf("[%s] Skipping auto-vote on %s %s: %s", p.NodeID, kind, proposalID, reason)
}

// computes deterministic per-proposal jitter to reduce vote contention on mvcc
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).applyAutoVoteJitter.
// Triggered: recovery path when stalled sessions or missing key shares are detected.
func (p *TSSPeer) autoVoteJitterDelay(proposalID string) time.Duration {
	if strings.TrimSpace(proposalID) == "" || strings.TrimSpace(p.MemberID) == "" {
		return 0
	}
	maxJitter := p.autoVoteJitterMax
	if maxJitter <= 0 {
		return 0
	}
	maxMs := uint64(maxJitter / time.Millisecond)
	if maxMs == 0 {
		return 0
	}

	seed := sha256.Sum256([]byte(proposalID + "|" + p.MemberID))
	var n uint64
	for i := 0; i < 8; i++ {
		n = (n << 8) | uint64(seed[i])
	}
	delayMs := n % (maxMs + 1)
	return time.Duration(delayMs) * time.Millisecond
}

//	applies deterministic vote jitter before submitting an auto-vote (ideally to prevent mvcc conflicts but in this case not really capable of that)
//
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: recovery path when stalled sessions or missing key shares are detected.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) applyAutoVoteJitter(kind, proposalID string) {
	delay := p.autoVoteJitterDelay(proposalID)
	if delay <= 0 {
		return
	}
	log.Printf("[%s] Auto-vote jitter for %s %s: %v", p.NodeID, kind, proposalID, delay)
	time.Sleep(delay)
}

// Acknowledges readyness for a dkg session
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).checkPendingDKG.
// Triggered: polling/runtime control flow for DKG and membership.
func (p *TSSPeer) AcknowledgeDKG(epoch int) error {
	log.Printf("[%s] Acknowledging DKG for epoch %d...", p.NodeID, epoch)
	_, err := p.Execute("AcknowledgeDKG", fmt.Sprintf("%d", epoch))
	if err != nil {
		return fmt.Errorf("failed to acknowledge DKG: %v", err)
	}
	log.Printf("[%s] DKG acknowledged for epoch %d", p.NodeID, epoch)
	return nil
}

// ===================== POLLING LOOP =====================

// runs the periodic loop for DKG, governance, and session health.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: main.
// Triggered: startup goroutine with periodic polling ticks.
func (p *TSSPeer) StartPollingLoop() {
	interval := p.pollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	heavyEvery := p.heavyPollEvery
	if heavyEvery <= 0 {
		heavyEvery = 2
	}
	certScanEvery := p.certFullScanEvery
	if certScanEvery <= 0 {
		certScanEvery = 6
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("[%s] Starting polling loop (%s interval)...", p.NodeID, interval)
	log.Printf("[%s] Poll cadence configured: heavyEvery=%d, certFullScanEvery=%d", p.NodeID, heavyEvery, certScanEvery)

	tickCount := 0
	lastMode := ""

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.checkObservedMembershipChanges()

			tickCount++
			runtimeMode := "observer-lite"
			if p.isCAMember() {
				runtimeMode = "member-active"
			}
			if runtimeMode != lastMode {
				log.Printf("[%s] Poll runtime mode: %s", p.NodeID, runtimeMode)
				lastMode = runtimeMode
			}

			shouldCertScan := tickCount%certScanEvery == 0
			if runtimeMode == "observer-lite" {
				// Lightweight observer profile: startup sync plus low-frequency fallback.
				// Ongoing updates are primarily event-driven via CertificateRegistered events.
				if shouldCertScan || tickCount == 1 {
					_ = p.syncOwnedCertificateOnce()
				}
				continue
			}

			if tickCount%heavyEvery == 0 || tickCount == 1 {
				p.checkPendingDKG()
				p.checkPendingCSRs()
				p.checkPendingJoinRequests()
				p.checkPendingRemoveMemberProposals()
				p.checkReshareSessions()
				p.checkSigningSessions()
				p.checkPendingRevocations()
			}

			if shouldCertScan {
				p.checkObservedCertificates()
			}
		}
	}
}

// checks DKG status and acknowledge, keygen, and completion actions.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).StartPollingLoop.
// Triggered: polling tick while reconciling DKG, governance, and session state.
func (p *TSSPeer) checkPendingDKG() {
	dkg, err := p.GetDKGSession(0)
	if err != nil {
		p.clearKeySessionProgress("dkg:0")
		return
	}

	status, ok := dkg["status"].(string)
	if !ok {
		return
	}

	// Check if in the DKG session members
	members, _ := dkg["members"].([]interface{})
	isMember := false
	for _, m := range members {
		if memberStr, ok := m.(string); ok && memberStr == p.MemberID {
			isMember = true
			break
		}
	}

	if !isMember {
		// Not in this DKG session - this can happen if DKG was initiated before joined
		// silently skip
		p.clearKeySessionProgress("dkg:0")
		return
	}

	ackCount := intFromAny(dkg["ackCount"])
	completionAckCount := intFromAny(dkg["completionAckCount"])
	if status == "initiated" || status == "ready" || status == "proposed" {
		if shouldEscalate, stalledFor := p.checkKeySessionStall("dkg:0", status, ackCount, completionAckCount); shouldEscalate {
			reason := fmt.Sprintf("stuck_dkg_status_%s_epoch_0_%ds", status, int(stalledFor.Seconds()))
			log.Printf("[%s] DKG session appears stalled (%s, ack=%d, complete=%d, stalled=%s); evaluating fresh DKG recovery", p.NodeID, status, ackCount, completionAckCount, stalledFor.Round(time.Second))
			p.tryAutoForceFreshDKG(0, reason, true, true)
		}
	} else {
		p.clearKeySessionProgress("dkg:0")
	}

	if status == "initiated" {
		ackedBy := toStringSlice(dkg["ackedBy"])
		if containsString(ackedBy, p.MemberID) {
			return
		}
		log.Printf("[%s] DKG Status: %s", p.NodeID, status)
		log.Printf("[%s] Found pending DKG, acknowledging...", p.NodeID)
		if err := p.AcknowledgeDKG(0); err != nil {
			// Treat concurrent status/ack races as converged, not failures.
			lowerErr := strings.ToLower(err.Error())
			if strings.Contains(lowerErr, "already acknowledged") || strings.Contains(lowerErr, "not in initiated state") {
				return
			}
			if refreshed, refreshErr := p.GetDKGSession(0); refreshErr == nil {
				statusNow, _ := refreshed["status"].(string)
				ackedNow := containsString(toStringSlice(refreshed["ackedBy"]), p.MemberID)
				if statusNow != "initiated" || ackedNow {
					return
				}
			}
			log.Printf("[%s] Acknowledge failed: %v", p.NodeID, err)
		}
	} else if status == "ready" {
		// Skip if keygen is already in progress.
		p.mutex.RLock()
		inProgress := p.keygenInProgress
		inProgressEpoch := p.keygenEpoch
		keyShare := p.TSSKeyShare
		p.mutex.RUnlock()
		if inProgress {
			// If a fresh DKG is ready while a previous reshare session is still
			// marked active locally, preempt the stale reshare session so cfresh DKG can proceed.
			if inProgressEpoch > 0 {
				preempted := false
				p.mutex.Lock()
				if p.keygenInProgress && p.keygenEpoch == inProgressEpoch {
					p.keygenInProgress = false
					p.keygenEpoch = -1
					preempted = true
				}
				p.mutex.Unlock()
				if preempted {
					select {
					case <-p.keygenDone:
					default:
						close(p.keygenDone)
					}
					log.Printf("[%s] Preempted stale local reshare session (epoch=%d) because DKG is ready", p.NodeID, inProgressEpoch)
					p.emitMetric("reshare_preempted_for_dkg", map[string]interface{}{
						"reshare_epoch": inProgressEpoch,
					})
				}
			} else {
				return
			}
		}

		// If a non-stale key share present, keep trying to submit completion.
		// This prevents "ready" from stalling forever after restarts/transient failures.
		if keyShare != nil {
			stale, reason := p.isKeyShareStale()
			if !stale {
				if keyShare.ECDSAPub == nil {
					stale = true
					reason = "local key share missing public key"
				} else {
					pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
					pubKeyHex := hex.EncodeToString(pubBytes)
					log.Printf("[%s] DKG ready with local key share; submitting completion acknowledgement", p.NodeID)
					p.completeDKG(0, pubKeyHex)
					return
				}
			}
			if strings.TrimSpace(reason) == "" {
				reason = "unknown"
			}
			log.Printf("[%s] Existing key share is stale (%s); re-running DKG", p.NodeID, reason)
		}
		log.Printf("[%s] DKG Status: %s", p.NodeID, status)
		membersToReach := toStringSlice(dkg["members"])
		if len(membersToReach) == 0 {
			log.Printf("[%s] DKG ready but session members are empty; waiting for valid session data", p.NodeID)
			return
		}

		// Load peer addresses for P2P
		if err := p.LoadPeerAddresses(); err != nil {
			log.Printf("[%s] Failed to load peer addresses: %v", p.NodeID, err)
			return
		}

		// Wait only for DKG session members. Waiting on all discovered peers can
		// false-stall when stale/offline peers remain registered.
		if !p.waitForPeersSubset(membersToReach, 30*time.Second) {
			log.Printf("[%s] Not all DKG members reachable yet, will retry...", p.NodeID)
			return
		}

		log.Printf("[%s] DKG is ready - starting TSS keygen...", p.NodeID)
		p.executeTSSKeygen(0, dkg)
	} else if status == "proposed" {
		// DKG completion proposed; acknowledge if we have a key share
		completionAckedBy := toStringSlice(dkg["completionAckedBy"])
		if containsString(completionAckedBy, p.MemberID) {
			return
		}
		p.mutex.RLock()
		keyShare := p.TSSKeyShare
		keygenInProgress := p.keygenInProgress
		keygenEpoch := p.keygenEpoch
		keygenDone := p.keygenDone
		p.mutex.RUnlock()
		proposedPubKey, _ := dkg["publicKey"].(string)
		proposedPubKey = strings.TrimSpace(proposedPubKey)

		pubKeyHex := ""
		localPubKey := ""
		if keyShare != nil && keyShare.ECDSAPub != nil {
			pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
			localPubKey = hex.EncodeToString(pubBytes)
		}

		if proposedPubKey != "" {
			// If local DKG keygen is still running, give it a short chance to finish so we
			// can persist the local share before reconciling against on-chain proposed key.
			if keygenInProgress && keygenEpoch == 0 && keygenDone != nil && (localPubKey == "" || localPubKey != proposedPubKey) {
				select {
				case <-keygenDone:
				case <-time.After(20 * time.Second):
				}
				p.mutex.RLock()
				keyShare = p.TSSKeyShare
				keygenInProgress = p.keygenInProgress
				keygenEpoch = p.keygenEpoch
				keygenDone = p.keygenDone
				p.mutex.RUnlock()
				localPubKey = ""
				if keyShare != nil && keyShare.ECDSAPub != nil {
					pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
					localPubKey = hex.EncodeToString(pubBytes)
				}
			}

			// If the proposed key doesn't match our local share, clear it and still ack the proposal
			// so the DKG can complete and a reshare can fix our missing share.
			if localPubKey != "" && localPubKey != proposedPubKey {
				if keygenInProgress && keygenEpoch == 0 {
					log.Printf("[%s] DKG proposal public key mismatch while local DKG keygen is still running; deferring local key-share purge", p.NodeID)
				} else {
					log.Printf("[%s] DKG proposal public key mismatch; clearing local key share and acknowledging proposal", p.NodeID)
					p.purgeLocalKeyShare("dkg proposal public key mismatch")
				}
			}
			pubKeyHex = proposedPubKey
		} else {
			// No proposed key yet; fall back to local key share if available.
			if localPubKey == "" {
				return
			}
			pubKeyHex = localPubKey
		}

		log.Printf("[%s] DKG completion proposed; acknowledging with public key", p.NodeID)
		p.completeDKG(0, pubKeyHex)
	} else if status == "completed" {
		p.clearKeySessionProgress("dkg:0")
		// Avoid forcing keygen state to idle while the keygen handler is still active.
		// The handler lifecycle owns keygenInProgress/keygenEpoch and closes keygenDone.
		p.mutex.Lock()
		keygenHandlerExited := true
		if p.keygenDone != nil {
			select {
			case <-p.keygenDone:
				keygenHandlerExited = true
			default:
				keygenHandlerExited = false
			}
		}
		if keygenHandlerExited && p.keygenEpoch <= 0 {
			p.keygenInProgress = false
			p.keygenEpoch = -1
		}
		hasShare := p.TSSKeyShare != nil
		// If chaincode is already completed but local keygen is still running,
		// defer "missing share" recovery to avoid forcing a premature reshare.
		if !hasShare && !keygenHandlerExited {
			p.mutex.Unlock()
			return
		}
		if !p.dkgCompletedLogged {
			p.dkgCompletedLogged = true
			p.mutex.Unlock()
			if hasShare {
				log.Printf("[%s] DKG completed on-chain; local key share is present.", p.NodeID)
			} else {
				log.Printf("[%s] DKG completed on-chain, but local key share is missing (expected path: %s).", p.NodeID, p.keySharePath())
			}
		} else {
			p.mutex.Unlock()
		}
		if !hasShare {
			p.autoForceReshareMissingShare()
		}
	}
}

// triggers ForceReshare when local key material is missing or mismatching
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: recovery path when stalled sessions or missing key shares are detected.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) autoForceReshareMissingShare() {
	p.mutex.RLock()
	keyShareInvalid := p.keyShareInvalid
	keyShareInvalidMsg := p.keyShareInvalidMsg
	alreadyLogged := p.keyShareInvalidLog
	hasShare := p.TSSKeyShare != nil
	keySessionInProgress := p.keygenInProgress
	keySessionEpoch := p.keygenEpoch
	p.mutex.RUnlock()
	if keyShareInvalid {
		if !alreadyLogged {
			log.Printf("[%s] Local key share invalid (%s); skipping auto reshare. Run Force Fresh DKG or reset local state.", p.NodeID, keyShareInvalidMsg)
			p.mutex.Lock()
			p.keyShareInvalidLog = true
			p.mutex.Unlock()
		}
		return
	}
	// Do not trigger follow-up reshare while local reshare/DKG processing is still active.
	// This avoids overlapping epoch storms that can stall subsequent sessions.
	if keySessionInProgress {
		log.Printf("[%s] Skipping auto reshare while local key session is in progress (epoch=%d)", p.NodeID, keySessionEpoch)
		return
	}
	triggerReason := "auto_reshare_missing_share"
	logReason := "missing local key share"
	if hasShare {
		stale, staleReason := p.isKeyShareStale()
		if !stale {
			return
		}
		if strings.TrimSpace(staleReason) == "" {
			staleReason = "stale key share"
		}
		logReason = fmt.Sprintf("stale local key share (%s)", staleReason)
		triggerReason = "auto_reshare_stale_share"
	}
	ca, err := p.GetCA()
	if err != nil {
		return
	}
	if pubKey, _ := ca["publicKey"].(string); strings.TrimSpace(pubKey) == "" {
		// No CA public key yet; reshare cannot proceed safely.
		return
	}
	epochVal, ok := ca["epoch"].(float64)
	if !ok {
		return
	}
	epoch := int(epochVal)

	// If a reshare is already in progress for the current epoch, do not spam ForceReshare.
	if result, err := p.Query("GetReshareSession", fmt.Sprintf("%d", epoch)); err == nil {
		if len(result) > 0 && string(result) != "null" {
			var reshare map[string]interface{}
			if err := json.Unmarshal(result, &reshare); err == nil {
				if status, _ := reshare["status"].(string); status == "initiated" || status == "acknowledged" || status == "proposed" {
					return
				}
			}
		}
	}

	// Throttle auto-reshare requests to avoid epoch storms
	p.mutex.Lock()
	if p.lastAutoReshareEpoch == epoch && time.Since(p.lastAutoReshareAt) < 60*time.Second {
		p.mutex.Unlock()
		return
	}
	p.lastAutoReshareEpoch = epoch
	p.lastAutoReshareAt = time.Now()
	p.mutex.Unlock()

	log.Printf("[%s] %s while CA key is active; forcing reshare (epoch %d)", p.NodeID, logReason, epoch)
	if _, err := p.Execute("ForceReshare", DefaultCAID, triggerReason); err != nil {
		log.Printf("[%s] Auto reshare failed: %v", p.NodeID, err)
	}
}

// reports whether old-committee quorum is possible without this nodes lost share to not have to unnecessarily complete a fresh dkg
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: polling/runtime control flow for DKG and membership.
func canReshareWithoutLocalOldShare(oldN, oldThreshold int) bool {
	requiredOldShares := oldThreshold + 1
	if requiredOldShares < 1 {
		requiredOldShares = 1
	}
	maxSharesWithoutLocal := oldN - 1
	return maxSharesWithoutLocal >= requiredOldShares
}

// evaluates recovery guards when key shares are missing/stale etc. and can submit a coordinated ForceFreshDKG.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: (*TSSPeer).checkPendingDKG, (*TSSPeer).checkReshareSessions, (*TSSPeer).executeTSSReshare.
// Triggered: recovery path when stalled sessions or missing key shares are detected.
func (p *TSSPeer) tryAutoForceFreshDKG(epoch int, reason string, allowActiveReshare bool, requireFullReachability bool) {
	if !p.autoFreshDKGEnabled {
		log.Printf("[%s] Auto fresh DKG suppressed: disabled (reason=%s)", p.NodeID, reason)
		p.emitMetric("auto_fresh_dkg_suppressed", map[string]interface{}{
			"epoch":  epoch,
			"reason": reason,
			"cause":  "disabled",
		})
		p.setRecoveryStatus("auto_fresh_dkg_disabled")
		return
	}

	ca, err := p.GetCA()
	if err != nil {
		log.Printf("[%s] Auto fresh DKG skipped: failed to load CA state: %v", p.NodeID, err)
		return
	}
	if pub, _ := ca["publicKey"].(string); strings.TrimSpace(pub) == "" {
		log.Printf("[%s] Auto fresh DKG skipped: CA public key already empty", p.NodeID)
		p.setRecoveryStatus("auto_fresh_dkg_skipped_no_pubkey")
		return
	}

	if epochNowF, ok := ca["epoch"].(float64); ok {
		epochNow := int(epochNowF)
		if reshareRaw, err := p.Query("GetReshareSession", fmt.Sprintf("%d", epochNow)); err == nil && len(reshareRaw) > 0 && string(reshareRaw) != "null" {
			var reshare map[string]interface{}
			if err := json.Unmarshal(reshareRaw, &reshare); err == nil {
				if status, _ := reshare["status"].(string); status == "initiated" || status == "acknowledged" || status == "proposed" {
					if allowActiveReshare {
						log.Printf("[%s] Auto fresh DKG override: reshare epoch %d is %s (reason=%s)", p.NodeID, epochNow, status, reason)
					} else {
						log.Printf("[%s] Auto fresh DKG suppressed: reshare epoch %d is %s", p.NodeID, epochNow, status)
						p.emitMetric("auto_fresh_dkg_suppressed", map[string]interface{}{
							"epoch":  epoch,
							"reason": reason,
							"cause":  "active_reshare",
							"status": status,
						})
						p.setRecoveryStatus("auto_fresh_dkg_waiting_reshare")
						return
					}
				}
			}
		}
	}

	pendingJoinCount := 0
	if raw, err := p.Query("ListPendingJoinRequests", DefaultCAID); err == nil && len(raw) > 0 && string(raw) != "null" {
		var pending []map[string]interface{}
		if err := json.Unmarshal(raw, &pending); err == nil {
			pendingJoinCount = len(pending)
		}
	}
	pendingRemovalCount := 0
	if raw, err := p.Query("ListPendingRemoveMemberProposals", DefaultCAID); err == nil && len(raw) > 0 && string(raw) != "null" {
		var pending []map[string]interface{}
		if err := json.Unmarshal(raw, &pending); err == nil {
			pendingRemovalCount = len(pending)
		}
	}
	overridePendingGovernance := strings.Contains(reason, "reshare_degraded_new_only") ||
		strings.Contains(reason, "auto_fresh_dkg_impossible_reshare")
	if pendingJoinCount > 0 || pendingRemovalCount > 0 {
		if overridePendingGovernance {
			log.Printf("[%s] Auto fresh DKG override: pending membership governance (join=%d, removal=%d) due reason=%s", p.NodeID, pendingJoinCount, pendingRemovalCount, reason)
		} else {
			log.Printf("[%s] Auto fresh DKG suppressed: pending membership governance (join=%d, removal=%d)", p.NodeID, pendingJoinCount, pendingRemovalCount)
			p.emitMetric("auto_fresh_dkg_suppressed", map[string]interface{}{
				"epoch":           epoch,
				"reason":          reason,
				"cause":           "pending_membership_governance",
				"pending_join":    pendingJoinCount,
				"pending_removal": pendingRemovalCount,
			})
			p.setRecoveryStatus("auto_fresh_dkg_waiting_governance")
			return
		}
	}

	members := toStringSlice(ca["members"])
	if len(members) == 0 {
		log.Printf("[%s] Auto fresh DKG skipped: no CA members in state", p.NodeID)
		return
	}
	sort.Strings(members)
	coordinator := members[0]
	if p.MemberID != coordinator {
		log.Printf("[%s] Auto fresh DKG suppressed: coordinator is %s", p.NodeID, coordinator)
		p.emitMetric("auto_fresh_dkg_suppressed", map[string]interface{}{
			"epoch":       epoch,
			"reason":      reason,
			"coordinator": coordinator,
		})
		p.setRecoveryStatus("auto_fresh_dkg_waiting_coordinator")
		return
	}

	if requireFullReachability {
		if err := p.LoadPeerAddresses(); err != nil {
			log.Printf("[%s] Auto fresh DKG suppressed: failed to load peer addresses for reachability check: %v", p.NodeID, err)
			p.emitMetric("auto_fresh_dkg_suppressed", map[string]interface{}{
				"epoch":  epoch,
				"reason": reason,
				"cause":  "peer_address_load_failed",
			})
			p.setRecoveryStatus("auto_fresh_dkg_waiting_peers")
			return
		}
		if !p.waitForPeersSubset(members, 20*time.Second) {
			log.Printf("[%s] Auto fresh DKG suppressed: not all CA members reachable", p.NodeID)
			p.emitMetric("auto_fresh_dkg_suppressed", map[string]interface{}{
				"epoch":  epoch,
				"reason": reason,
				"cause":  "peers_unreachable",
			})
			p.setRecoveryStatus("auto_fresh_dkg_waiting_peers")
			return
		}
	}

	now := time.Now()
	p.mutex.Lock()
	if p.lastAutoFreshDKGEpoch == epoch && now.Sub(p.lastAutoFreshDKGAt) < p.autoFreshDKGCooldown {
		p.mutex.Unlock()
		log.Printf("[%s] Auto fresh DKG suppressed by cooldown (%s)", p.NodeID, p.autoFreshDKGCooldown)
		p.setRecoveryStatus("auto_fresh_dkg_cooldown")
		return
	}
	p.lastAutoFreshDKGEpoch = epoch
	p.lastAutoFreshDKGAt = now
	p.mutex.Unlock()

	log.Printf("[%s] Auto-triggering ForceFreshDKG (epoch=%d, reason=%s)", p.NodeID, epoch, reason)
	p.emitMetric("auto_fresh_dkg_triggered", map[string]interface{}{
		"epoch":  epoch,
		"reason": reason,
	})
	p.setRecoveryStatus("auto_fresh_dkg_triggered")
	if _, err := p.Execute("ForceFreshDKG", DefaultCAID, reason); err != nil {
		log.Printf("[%s] Auto ForceFreshDKG failed: %v", p.NodeID, err)
		p.setRecoveryStatus("auto_fresh_dkg_failed")
	}
}

// waits until a target subset of peers (in this case especially ca members for tss operations) is reachable over strict mTLS.
// Lifecycle: Polling-driven coordination and automatic recovery.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: pre-execution gating before multiparty TSS operations.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) waitForPeersSubset(peerIDs []string, timeout time.Duration) bool {
	if len(peerIDs) == 0 {
		return true
	}

	targets := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		rawID := strings.TrimSpace(id)
		if rawID == "" {
			continue
		}
		// Accept either canonical member IDs (x509::...) or already-short node IDs.
		shortID := rawID
		if strings.HasPrefix(rawID, "x509::") {
			shortID = p.extractShortNodeID(rawID)
		}
		if shortID == "" {
			continue
		}
		if shortID == p.NodeID {
			continue
		}
		targets[shortID] = struct{}{}
	}

	if len(targets) == 0 {
		return true
	}

	p.mutex.RLock()
	peers := make(map[string]string)
	for k, v := range p.peerAddrs {
		peers[k] = v
	}
	p.mutex.RUnlock()

	deadline := time.Now().Add(timeout)

	for peerID := range targets {
		addr, ok := peers[peerID]
		if !ok {
			log.Printf("[%s] Peer %s address not found in discovery", p.NodeID, peerID)
			return false
		}

		for time.Now().Before(deadline) {
			conn, err := p.dialPeerTLS(context.Background(), addr, 2*time.Second)
			if err == nil {
				conn.Close()
				log.Printf("[%s] Peer %s is reachable at %s (mTLS)", p.NodeID, peerID, addr)
				break
			}
			log.Printf("[%s] Waiting for peer %s at %s...", p.NodeID, peerID, addr)
			time.Sleep(2 * time.Second)
		}

		// Final check
		conn, err := p.dialPeerTLS(context.Background(), addr, 2*time.Second)
		if err != nil {
			log.Printf("[%s] Peer %s still not reachable", p.NodeID, peerID)
			return false
		}
		conn.Close()
	}

	log.Printf("[%s] All targeted peers are reachable!", p.NodeID)
	return true
}
