// tss_key_management.go orchestrates TSS keygen/reshare execution, completion proposals, and key-share consistency checks.
// Runtime flow: DKG/reshare/session handlers invoke these routines to run multiparty protocols and finalize on-chain state.
package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/tss"
)

// ===================== Setup and Fallback during setup =====================

// parses ca public key point as a fallback from the hex string in the preparation for a reshare session.
// Called by: (*TSSPeer).getCAPublicKeyPointFallback.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func parseCAPublicKeyPoint(pubHex string) *tsscrypto.ECPoint {
	pubHex = strings.TrimSpace(pubHex)
	if pubHex == "" {
		return nil
	}
	raw, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil || y == nil {
		return nil
	}
	point, err := tsscrypto.NewECPoint(elliptic.P256(), x, y)
	if err != nil {
		return nil
	}
	return point
}

// Extracts the new CA public key from the reshare session. Used for the check and during setup of the session as a fallback.
// Called by: (*TSSPeer).checkReshareSessions, (*TSSPeer).getCAPublicKeyPointFallback.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func getResharePublicKeyHex(reshare map[string]interface{}) string {
	if reshare == nil {
		return ""
	}
	// Accept both legacy and struct-tag JSON keys.
	if v, ok := reshare["newCAPublicKey"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := reshare["newCaPublicKey"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

// A fallback function to get the CA public key point for reshare sessions, trying the reshare session data first, then falling back to the CA info.
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func (p *TSSPeer) getCAPublicKeyPointFallback(reshare map[string]interface{}) *tsscrypto.ECPoint {
	if reshare != nil {
		if pubHex := getResharePublicKeyHex(reshare); pubHex != "" {
			if pt := parseCAPublicKeyPoint(pubHex); pt != nil {
				return pt
			}
		}
	}
	ca, err := p.GetCA()
	if err != nil {
		return nil
	}
	if v, ok := ca["publicKey"].(string); ok && strings.TrimSpace(v) != "" {
		return parseCAPublicKeyPoint(v)
	}
	return nil
}

// Injects the Ca public key point into the reshare party to properly generate the right one.
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func setResharePartyECDSAPub(party tss.Party, pub *tsscrypto.ECPoint) {
	if party == nil || pub == nil {
		return
	}
	lp, ok := party.(*resharing.LocalParty)
	if !ok {
		return
	}
	val := reflect.ValueOf(lp).Elem()
	field := val.FieldByName("save")
	if !field.IsValid() || !field.CanAddr() {
		return
	}
	savePtr := unsafe.Pointer(field.UnsafeAddr())
	save := (*keygen.LocalPartySaveData)(savePtr)
	if save.ECDSAPub == nil {
		save.ECDSAPub = pub
	}
}

// ===================== TSS KEYGEN =====================

// Creates party IDs/params/channels and starts keygen goroutines; called when DKG status becomes ready from ledger state.
// Called by: (*TSSPeer).checkPendingDKG.
// Triggered: DKG/reshare/signing session execution when protocol state becomes ready.
func (p *TSSPeer) executeTSSKeygen(epoch int, dkg map[string]interface{}) {
	// Mark keygen as in progress and recreate keygenDone channel
	p.mutex.Lock()
	p.keygenInProgress = true
	p.keygenEpoch = epoch
	// Recreate keygenDone channel for this keygen session
	// (previous one may be closed from a prior keygen)
	select {
	case <-p.keygenDone:
		// Was closed, make a fresh one
		p.keygenDone = make(chan struct{})
	default:
		// Still open, fine
	}
	p.mutex.Unlock()

	// Get members from DKG session
	membersRaw, _ := dkg["members"].([]interface{})
	members := make([]string, 0, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}

	threshold := 1
	if t, ok := dkg["threshold"].(float64); ok {
		threshold = int(t)
	}
	p.Threshold = threshold

	log.Printf("[%s] TSS Keygen: %d members, threshold %d", p.NodeID, len(members), threshold)
	p.emitMetric("tss_keygen_start", map[string]interface{}{
		"epoch":     epoch,
		"n":         len(members),
		"threshold": threshold,
	})

	// Sort members for deterministic party ID assignment
	sort.Strings(members)

	// Create party IDs with proper key generation
	partyIDs := make([]*tss.PartyID, len(members))
	var myIndex int = -1

	// Build index mapping: partyIndex -> nodeID (dynamic, supports N orgs)
	p.mutex.Lock()
	p.partyIndexMap = make(map[int]string)
	for i, member := range members {
		// Use deterministic key based on member identity
		keyBytes := []byte(member)
		key := new(big.Int).SetBytes(keyBytes[:min(len(keyBytes), 32)])

		shortID := fmt.Sprintf("party-%d", i)
		partyIDs[i] = tss.NewPartyID(shortID, fmt.Sprintf("Member %d", i), key)

		// Dynamically derive short node ID from canonical member ID
		p.partyIndexMap[i] = p.extractShortNodeID(member)

		if member == p.MemberID {
			myIndex = i
			p.TSSPartyID = partyIDs[i]
			log.Printf("[%s] I am party %d (%s)", p.NodeID, i, shortID)
		}
	}
	p.mutex.Unlock()

	if myIndex == -1 || p.TSSPartyID == nil {
		log.Printf("[%s] Error: Not a member of this DKG session", p.NodeID)
		p.mutex.Lock()
		p.keygenInProgress = false
		p.keygenEpoch = -1
		p.completedEpochs[epoch] = true // Prevent infinite retry
		p.mutex.Unlock()
		return
	}

	// Create TSS context
	sortedPartyIDs := tss.SortPartyIDs(partyIDs)
	peerCtx := tss.NewPeerContext(sortedPartyIDs)

	// Create keygen parameters
	params := tss.NewParameters(
		elliptic.P256(), // NIST P-256 curve (secp256r1)
		peerCtx,
		p.TSSPartyID,
		len(partyIDs), // N (total parties)
		threshold,     // T (threshold)
	)

	log.Printf("[%s] Starting TSS keygen: N=%d, T=%d, myIndex=%d",
		p.NodeID, len(partyIDs), threshold, myIndex)
	dkgSessionID := deriveDKGSessionID(epoch, dkg)
	log.Printf("[%s] DKG session ID: %s", p.NodeID, dkgSessionID)

	// Create channels for TSS protocol
	outCh := make(chan tss.Message, len(partyIDs)*20)
	endCh := make(chan keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// Create keygen party with on-demand pre-params when available.
	var preParams *keygen.LocalPreParams
	if pp, err := p.ensurePreParams(); err != nil {
		log.Printf("[%s] Warning: failed to prepare pre-params, using slower on-the-fly generation: %v", p.NodeID, err)
	} else {
		preParams = pp
	}

	// Create keygen party with or without pre-params.
	var party tss.Party
	if preParams != nil {
		log.Printf("[%s] Using pre-generated parameters", p.NodeID)
		party = keygen.NewLocalParty(params, outCh, endCh, *preParams)
	} else {
		log.Printf("[%s] No pre-params, will generate on the fly (slower)", p.NodeID)
		party = keygen.NewLocalParty(params, outCh, endCh)
	}

	// Start message handler goroutine
	p.wg.Add(1)
	go p.handleTSSKeygenMessages(party, partyIDs, outCh, endCh, errCh, epoch, myIndex, members, dkgSessionID)

	// Start keygen protocol
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		log.Printf("[%s] Starting keygen party...", p.NodeID)
		if err := party.Start(); err != nil {
			log.Printf("[%s] TSS keygen start error: %v", p.NodeID, err)
			errCh <- err
		}
		log.Printf("[%s] Keygen party started (will continue processing)", p.NodeID)
	}()
}

// Core keygen event loop: sends/receives TSS messages, updates party, persists share, submits DKG completion
// Called by: (*TSSPeer).executeTSSKeygen.
// Triggered: goroutine callback while processing TSS protocol message channels.
func (p *TSSPeer) handleTSSKeygenMessages(
	party tss.Party,
	partyIDs []*tss.PartyID,
	outCh <-chan tss.Message,
	endCh <-chan keygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	epoch int,
	myIndex int,
	members []string,
	sessionID string,
) {
	defer p.wg.Done()
	defer func() {
		p.mutex.Lock()
		p.keygenInProgress = false
		p.keygenEpoch = -1
		p.mutex.Unlock()
		// Signal that the keygen handler has exited so the tssMessages channel is free
		select {
		case <-p.keygenDone:
			// already closed
		default:
			close(p.keygenDone)
		}
	}()

	timeout := time.After(10 * time.Minute) // Long timeout for safe prime generation
	messagesSent := 0
	messagesReceived := 0

	log.Printf("[%s] Message handler started, waiting for messages...", p.NodeID)

	for {
		select {
		case <-p.ctx.Done():
			log.Printf("[%s] Context cancelled", p.NodeID)
			return

		case <-timeout:
			log.Printf("[%s] TSS keygen timeout after sent=%d, received=%d messages",
				p.NodeID, messagesSent, messagesReceived)
			return

		case err := <-errCh:
			if err != nil {
				log.Printf("[%s] TSS ERROR: %v (culprits: %v)", p.NodeID, err.Error(), err.Culprits())
			}
			return

		case msg := <-outCh:
			if msg == nil {
				continue
			}

			// Get wire bytes for network transmission
			wireBytes, routing, err := msg.WireBytes()
			if err != nil {
				log.Printf("[%s] Failed to get wire bytes: %v", p.NodeID, err)
				continue
			}

			messagesSent++

			if routing.IsBroadcast {
				log.Printf("[%s] [SEND #%d] Broadcasting TSS message", p.NodeID, messagesSent)

				// Send to all OTHER parties (not to self!)
				for i, pid := range partyIDs {
					if i == myIndex {
						continue // Skip self
					}

					targetNodeID := p.getNodeIDForPartyIndex(i)
					tssMsg := &TSSMessage{
						From:        p.NodeID,
						FromIndex:   myIndex,
						To:          targetNodeID,
						ToIndex:     i,
						SessionID:   sessionID,
						MsgType:     "keygen",
						Payload:     wireBytes,
						IsBroadcast: true,
						Round:       messagesSent,
					}

					// Retry sending with exponential backoff
					if err := p.SendTSSMessageWithRetry(targetNodeID, tssMsg, 5); err != nil {
						log.Printf("[%s] CRITICAL: Failed to send broadcast to %s after retries: %v", p.NodeID, targetNodeID, err)
					} else {
						log.Printf("[%s] Sent broadcast to %s (party %d, %s)", p.NodeID, targetNodeID, i, pid.Id)
					}
				}
			} else {
				// Point-to-point message
				for _, to := range routing.To {
					targetIndex := to.Index
					targetNodeID := p.getNodeIDForPartyIndex(targetIndex)

					log.Printf("[%s] [SEND #%d] Sending P2P TSS message to party %d (%s)",
						p.NodeID, messagesSent, targetIndex, targetNodeID)

					tssMsg := &TSSMessage{
						From:        p.NodeID,
						FromIndex:   myIndex,
						To:          targetNodeID,
						ToIndex:     targetIndex,
						SessionID:   sessionID,
						MsgType:     "keygen",
						Payload:     wireBytes,
						IsBroadcast: false,
						Round:       messagesSent,
					}

					// Retry sending with exponential backoff
					if err := p.SendTSSMessageWithRetry(targetNodeID, tssMsg, 5); err != nil {
						log.Printf("[%s] CRITICAL: Failed to send P2P to %s after retries: %v", p.NodeID, targetNodeID, err)
					}
				}
			}

		case incoming := <-p.tssMessages:
			if incoming == nil {
				continue
			}
			if incoming.SessionID != sessionID {
				log.Printf("[%s] Ignoring keygen message with session %q (expected %q)", p.NodeID, incoming.SessionID, sessionID)
				continue
			}

			// Priority check: if endCh is ready, handle keygen completion first
			select {
			case keyShare := <-endCh:
				if keyShare.ShareID != nil {
					log.Printf("[%s] TSS keygen COMPLETED (priority check)! Sent=%d, Received=%d",
						p.NodeID, messagesSent, messagesReceived)
					p.emitMetric("tss_keygen_complete", map[string]interface{}{
						"epoch": epoch,
					})
					keyCopy := keyShare
					p.mutex.Lock()
					p.TSSKeyShare = &keyCopy
					p.cachedPartyIDs = tss.SortPartyIDs(partyIDs)
					p.cachedMembers = append([]string(nil), members...)
					p.myPartyIndex = myIndex
					p.mutex.Unlock()
					if err := p.SaveKeyShare(); err != nil {
						log.Printf("[%s] Warning: failed to persist key share: %v", p.NodeID, err)
					}
					pubKey := keyShare.ECDSAPub
					pubKeyBytes := elliptic.Marshal(pubKey.Curve(), pubKey.X(), pubKey.Y())
					pubKeyHex := hex.EncodeToString(pubKeyBytes)
					log.Printf("[%s] CA Public Key: %s...", p.NodeID, pubKeyHex[:40])
					log.Printf("[%s] Submitting DKG completion to blockchain...", p.NodeID)
					p.completeDKG(epoch, pubKeyHex)
					return
				}
				log.Printf("[%s] TSS keygen failed (nil ShareID) during priority check", p.NodeID)
				return
			default:
			}

			messagesReceived++
			log.Printf("[%s] [RECV #%d] Processing TSS message from %s (party %d), isBroadcast=%v",
				p.NodeID, messagesReceived, incoming.From, incoming.FromIndex, incoming.IsBroadcast)

			// Find the sender's party ID
			var fromParty *tss.PartyID
			if incoming.FromIndex >= 0 && incoming.FromIndex < len(partyIDs) {
				fromParty = partyIDs[incoming.FromIndex]
			} else {
				// Fallback: find by node ID
				for i, pid := range partyIDs {
					nodeID := p.getNodeIDForPartyIndex(i)
					if nodeID == incoming.From {
						fromParty = pid
						break
					}
				}
			}

			if fromParty == nil {
				log.Printf("[%s] Unknown sender: %s (index %d)", p.NodeID, incoming.From, incoming.FromIndex)
				continue
			}

			// Update party state with incoming message
			ok, err := party.UpdateFromBytes(incoming.Payload, fromParty, incoming.IsBroadcast)
			if err != nil {
				log.Printf("[%s] TSS update error from %s: %v", p.NodeID, incoming.From, err)
				continue
			}
			if ok {
				log.Printf("[%s] [RECV #%d] Message processed successfully", p.NodeID, messagesReceived)
			} else {
				log.Printf("[%s] [RECV #%d] Message processing returned false (may be duplicate)", p.NodeID, messagesReceived)
			}

		case keyShare := <-endCh:
			if keyShare.ShareID == nil {
				log.Printf("[%s] TSS keygen failed (nil ShareID)", p.NodeID)
				return
			}

			log.Printf("[%s] TSS keygen COMPLETED! Sent=%d, Received=%d",
				p.NodeID, messagesSent, messagesReceived)
			p.emitMetric("tss_keygen_complete", map[string]interface{}{
				"epoch": epoch,
			})
			keyCopy := keyShare

			// Cache key share and party info for later signing
			p.mutex.Lock()
			p.TSSKeyShare = &keyCopy
			p.cachedPartyIDs = tss.SortPartyIDs(partyIDs)
			p.cachedMembers = append([]string(nil), members...)
			p.myPartyIndex = myIndex
			p.mutex.Unlock()
			if err := p.SaveKeyShare(); err != nil {
				log.Printf("[%s] Warning: failed to persist key share: %v", p.NodeID, err)
			}

			// Extract public key
			pubKey := keyShare.ECDSAPub
			pubKeyBytes := elliptic.Marshal(pubKey.Curve(), pubKey.X(), pubKey.Y())
			pubKeyHex := hex.EncodeToString(pubKeyBytes)

			log.Printf("[%s] CA Public Key: %s...", p.NodeID, pubKeyHex[:40])
			log.Printf("[%s] Share ID: %s", p.NodeID, keyShare.ShareID.String()[:20]+"...")

			// Both peers submit DKG completion - first one wins, other gets "not in ready state" (handled gracefully)
			log.Printf("[%s] Submitting DKG completion to blockchain...", p.NodeID)
			p.completeDKG(epoch, pubKeyHex)
			return
		}
	}
}

// Core per-party resharing loop for old/new committees: routes committee-aware messages and handles end conditions
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: goroutine callback while processing TSS protocol message channels.
func (p *TSSPeer) handleTSSReshareParty(
	role string,
	party tss.Party,
	partyID *tss.PartyID,
	oldCommittee *reshareCommittee,
	newCommittee *reshareCommittee,
	partyKeyToNodeID map[string]string,
	oldPartyKeys map[string]struct{},
	newPartyKeys map[string]struct{},
	partyPtrToCommittee map[*tss.PartyID]string,
	incoming <-chan *TSSMessage,
	outCh <-chan tss.Message,
	endCh <-chan keygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	epoch int,
	isNew bool,
	newThreshold int,
	markDone func(),
) {
	defer p.wg.Done()
	defer markDone()

	timeout := time.After(10 * time.Minute)
	messagesSent := 0
	messagesReceived := 0

	log.Printf("[%s] Reshare %s-committee message handler started", p.NodeID, role)

	partyCommitteeForKey := func(keyHex string) string {
		_, inOld := oldPartyKeys[keyHex]
		_, inNew := newPartyKeys[keyHex]
		switch {
		case inOld && inNew:
			return "old+new"
		case inOld:
			return "old"
		case inNew:
			return "new"
		default:
			return ""
		}
	}
	preferNewCommittee := role == "new"
	resolveFromParty := func(incomingMsg *TSSMessage) *tss.PartyID {
		lookup := func(committee string) *tss.PartyID {
			switch committee {
			case "old":
				if pid := oldCommittee.nodeIDToParty[incomingMsg.From]; pid != nil {
					return pid
				}
				if incomingMsg.FromIndex >= 0 && incomingMsg.FromIndex < len(oldCommittee.partyIDs) {
					return oldCommittee.partyIDs[incomingMsg.FromIndex]
				}
			case "new":
				if pid := newCommittee.nodeIDToParty[incomingMsg.From]; pid != nil {
					return pid
				}
				if incomingMsg.FromIndex >= 0 && incomingMsg.FromIndex < len(newCommittee.partyIDs) {
					return newCommittee.partyIDs[incomingMsg.FromIndex]
				}
			}
			return nil
		}

		tryOldThenNew := func() *tss.PartyID {
			if pid := lookup("old"); pid != nil {
				return pid
			}
			return lookup("new")
		}
		tryNewThenOld := func() *tss.PartyID {
			if pid := lookup("new"); pid != nil {
				return pid
			}
			return lookup("old")
		}

		switch incomingMsg.FromCommittee {
		case "old":
			return tryOldThenNew()
		case "new":
			return tryNewThenOld()
		case "old+new":
			if preferNewCommittee {
				return tryNewThenOld()
			}
			return tryOldThenNew()
		default:
			if preferNewCommittee {
				return tryNewThenOld()
			}
			return tryOldThenNew()
		}
	}

	sendOutgoing := func(msg tss.Message) {
		if msg == nil {
			return
		}

		wireBytes, routing, err := msg.WireBytes()
		if err != nil {
			log.Printf("[%s] Reshare %s-committee failed to get wire bytes: %v", p.NodeID, role, err)
			return
		}

		messagesSent++

		var targets []*tss.PartyID
		if routing.IsBroadcast {
			if routing.IsToOldAndNewCommittees {
				targets = append(targets, oldCommittee.partyIDs...)
				targets = append(targets, newCommittee.partyIDs...)
			} else if routing.IsToOldCommittee {
				targets = oldCommittee.partyIDs
			} else {
				targets = newCommittee.partyIDs
			}
		} else {
			targets = routing.To
		}

		for _, pid := range targets {
			keyHex := hex.EncodeToString(pid.Key)
			toCommittee := partyCommitteeForKey(keyHex)
			if toCommittee == "" {
				toCommittee = partyPtrToCommittee[pid]
			}
			if toCommittee == "" {
				if routing.IsToOldCommittee {
					toCommittee = "old"
				} else if routing.IsToOldAndNewCommittees {
					toCommittee = "old+new"
				} else {
					toCommittee = "new"
				}
			}
			if routing.From != nil && pid.KeyInt().Cmp(routing.From.KeyInt()) == 0 {
				continue
			}
			targetNodeID := partyKeyToNodeID[keyHex]
			if targetNodeID == "" {
				log.Printf("[%s] Reshare %s-committee unknown target for party %s", p.NodeID, role, pid.Id)
				continue
			}
			fromCommittee := ""
			if routing.From != nil {
				fromCommittee = partyCommitteeForKey(hex.EncodeToString(routing.From.Key))
			}
			if fromCommittee == "old+new" || fromCommittee == "" {
				if preferNewCommittee {
					fromCommittee = "new"
				} else {
					fromCommittee = "old"
				}
			}
			tssMsg := &TSSMessage{
				From:          p.NodeID,
				FromIndex:     partyID.Index,
				FromCommittee: fromCommittee,
				To:            targetNodeID,
				ToIndex:       pid.Index,
				ToCommittee:   toCommittee,
				SessionID:     fmt.Sprintf("reshare-%d", epoch),
				MsgType:       "reshare",
				Payload:       wireBytes,
				IsBroadcast:   routing.IsBroadcast,
				Round:         messagesSent,
			}
			if err := p.SendTSSMessageWithRetry(targetNodeID, tssMsg, 5); err != nil {
				log.Printf("[%s] Reshare %s-committee send to %s failed: %v", p.NodeID, role, targetNodeID, err)
			}
		}
	}

	flushPendingOutgoing := func(maxWait time.Duration) {
		if maxWait <= 0 {
			return
		}
		deadline := time.Now().Add(maxWait)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return
			}
			timer := time.NewTimer(remaining)
			select {
			case pending := <-outCh:
				if !timer.Stop() {
					<-timer.C
				}
				sendOutgoing(pending)
			case <-timer.C:
				return
			}
		}
	}

	for {
		select {
		case <-p.ctx.Done():
			return

		case <-timeout:
			log.Printf("[%s] Reshare %s-committee timeout after sent=%d, received=%d",
				p.NodeID, role, messagesSent, messagesReceived)
			return

		case err := <-errCh:
			if err != nil {
				log.Printf("[%s] Reshare %s-committee ERROR: %v (culprits: %v)", p.NodeID, role, err.Error(), err.Culprits())
			}
			return

		case msg := <-outCh:
			sendOutgoing(msg)

		case incomingMsg := <-incoming:
			if incomingMsg == nil {
				continue
			}
			messagesReceived++

			fromParty := resolveFromParty(incomingMsg)
			if fromParty == nil {
				log.Printf("[%s] Reshare %s-committee unknown sender %s", p.NodeID, role, incomingMsg.From)
				continue
			}

			ok, err := party.UpdateFromBytes(incomingMsg.Payload, fromParty, incomingMsg.IsBroadcast)
			if err != nil {
				log.Printf("[%s] Reshare %s-committee update error from %s: %v", p.NodeID, role, incomingMsg.From, err)
				continue
			}
			if ok {
				log.Printf("[%s] Reshare %s-committee message processed (recv #%d)", p.NodeID, role, messagesReceived)
			}

		case keyShare := <-endCh:
			// Flush pending outbound messages before exiting to avoid leaving peers one message short.
			flushPendingOutgoing(2 * time.Second)
			if isNew {
				// Ignore stale reshare completion from a preempted session.
				p.mutex.RLock()
				sessionStillActive := p.keygenInProgress && p.keygenEpoch == epoch
				p.mutex.RUnlock()
				if !sessionStillActive {
					log.Printf("[%s] Ignoring stale reshare completion output for epoch %d (session no longer active)", p.NodeID, epoch)
					return
				}
				if keyShare.ShareID == nil || keyShare.ECDSAPub == nil {
					log.Printf("[%s] Reshare new-committee completed with empty share", p.NodeID)
					return
				}
				keyCopy := keyShare
				p.mutex.Lock()
				p.TSSKeyShare = &keyCopy
				p.cachedPartyIDs = newCommittee.partyIDs
				p.cachedMembers = append([]string(nil), newCommittee.members...)
				p.myPartyIndex = partyID.Index
				p.Threshold = newThreshold
				p.mutex.Unlock()
				p.updatePartyIndexMap(newCommittee.members)
				if err := p.SaveKeyShare(); err != nil {
					log.Printf("[%s] Warning: failed to persist reshare key share: %v", p.NodeID, err)
				}
				pubBytes := elliptic.Marshal(keyCopy.ECDSAPub.Curve(), keyCopy.ECDSAPub.X(), keyCopy.ECDSAPub.Y())
				pubKeyHex := hex.EncodeToString(pubBytes)
				log.Printf("[%s] Reshare completed (new committee). Submitting completion...", p.NodeID)
				p.emitMetric("tss_reshare_complete", map[string]interface{}{
					"epoch": epoch,
				})
				p.completeReshare(epoch, pubKeyHex)
			} else {
				log.Printf("[%s] Reshare old-committee completed", p.NodeID)
			}
			return
		}
	}
}

// Maps TSS index -> node ID for network sends; used in keygen/signing message handlers.
// Called by: (*TSSPeer).handleTSSKeygenMessages, (*TSSPeer).handleTSSSigningMessages.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func (p *TSSPeer) getNodeIDForPartyIndex(index int) string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if nodeID, ok := p.partyIndexMap[index]; ok {
		return nodeID
	}
	// Fallback to a deterministic generic node ID.
	return fmt.Sprintf("peer-%d", index)
}

// Rebuilds local index map after committee changes; called when reshare new-share completes.
// Called by: (*TSSPeer).handleTSSReshareParty.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func (p *TSSPeer) updatePartyIndexMap(members []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.partyIndexMap = make(map[int]string)
	for i, member := range members {
		p.partyIndexMap[i] = p.extractShortNodeID(member)
	}
}

// Compares sorted member sets; used in signing cache validation and stale-share checks.
// Called by: (*TSSPeer).executeTSSSigning, (*TSSPeer).isKeyShareStale.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
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

type reshareCommittee struct {
	members       []string
	partyIDs      tss.SortedPartyIDs
	memberToParty map[string]*tss.PartyID
	nodeIDToParty map[string]*tss.PartyID
}

// Builds deterministic committee/party-ID mappings (with optional salt); used across reshare/snapshot validation paths.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: TSS key-management helper during DKG/reshare orchestration.
// See CALL_MAP.md for the full direct-caller and trigger context.
func (p *TSSPeer) buildReshareCommittee(members []string, label, salt string) *reshareCommittee {
	sortedMembers := append([]string(nil), members...)
	sort.Strings(sortedMembers)

	ids := make([]*tss.PartyID, len(sortedMembers))
	keyHexToMember := make(map[string]string, len(sortedMembers))
	for i, member := range sortedMembers {
		keyBytes := []byte(member)
		if salt != "" {
			sum := sha256.Sum256([]byte(salt + "|" + member))
			keyBytes = sum[:]
		} else if len(keyBytes) > 32 {
			keyBytes = keyBytes[:32]
		}
		key := new(big.Int).SetBytes(keyBytes)
		keyHex := hex.EncodeToString(key.Bytes())
		keyHexToMember[keyHex] = member
		ids[i] = tss.NewPartyID(fmt.Sprintf("%s-%d", label, i), fmt.Sprintf("Member %d", i), key)
	}

	sortedIDs := tss.SortPartyIDs(ids)
	memberToParty := make(map[string]*tss.PartyID, len(sortedMembers))
	nodeIDToParty := make(map[string]*tss.PartyID, len(sortedMembers))
	for _, pid := range sortedIDs {
		member := keyHexToMember[hex.EncodeToString(pid.Key)]
		if member == "" {
			continue
		}
		memberToParty[member] = pid
		nodeIDToParty[p.extractShortNodeID(member)] = pid
	}

	return &reshareCommittee{
		members:       sortedMembers,
		partyIDs:      sortedIDs,
		memberToParty: memberToParty,
		nodeIDToParty: nodeIDToParty,
	}
}

// Verifies key share exactly matches expected committee IDs; used in reshare/snapshot logic
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: TSS key-management helper during DKG/reshare orchestration.
// See CALL_MAP.md for the full direct-caller and trigger context.
func keyShareMatchesPartyIDs(keyShare *keygen.LocalPartySaveData, partyIDs tss.SortedPartyIDs) bool {
	if keyShare == nil {
		return false
	}
	if len(keyShare.Ks) != len(partyIDs) {
		return false
	}
	keySet := make(map[string]bool, len(keyShare.Ks))
	for _, k := range keyShare.Ks {
		if k == nil {
			continue
		}
		keySet[hex.EncodeToString(k.Bytes())] = true
	}
	for _, pid := range partyIDs {
		if !keySet[hex.EncodeToString(pid.Key)] {
			return false
		}
	}
	return true
}

// Verifies key share includes expected IDs subset; used during transition/compatibility checks.
// Called by: (*TSSPeer).checkReshareSessions, (*TSSPeer).executeTSSReshare.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func keyShareContainsPartyIDs(keyShare *keygen.LocalPartySaveData, partyIDs tss.SortedPartyIDs) bool {
	if keyShare == nil {
		return false
	}
	if len(keyShare.Ks) == 0 {
		return false
	}
	keySet := make(map[string]bool, len(keyShare.Ks))
	for _, k := range keyShare.Ks {
		if k == nil {
			continue
		}
		keySet[hex.EncodeToString(k.Bytes())] = true
	}
	for _, pid := range partyIDs {
		if !keySet[hex.EncodeToString(pid.Key)] {
			return false
		}
	}
	return true
}

// Validates key-share completeness (preparams/proofs/points/paillier data); used before loading/resharing/restoring. To detect stale keys
// Called by: (*TSSPeer).LoadKeyShare, (*TSSPeer).executeTSSReshare, (*TSSPeer).tryRestoreKeyShareSnapshotForReshare.
// Triggered: session completion stage when on-chain acknowledgements are submitted.
func keyShareHasCompleteData(keyShare *keygen.LocalPartySaveData) (bool, string) {
	if keyShare == nil {
		return false, "nil key share"
	}
	if !keyShare.LocalPreParams.Validate() {
		return false, "missing Paillier/pre-params"
	}
	if keyShare.ShareID == nil || keyShare.Xi == nil {
		return false, "missing secret share"
	}
	if len(keyShare.Ks) == 0 {
		return false, "missing Ks"
	}
	if len(keyShare.NTildej) != len(keyShare.Ks) || len(keyShare.H1j) != len(keyShare.Ks) || len(keyShare.H2j) != len(keyShare.Ks) ||
		len(keyShare.BigXj) != len(keyShare.Ks) || len(keyShare.PaillierPKs) != len(keyShare.Ks) {
		return false, "incomplete key share arrays"
	}
	for i := range keyShare.Ks {
		if keyShare.Ks[i] == nil {
			return false, "nil Ks entry"
		}
		if keyShare.NTildej[i] == nil || keyShare.H1j[i] == nil || keyShare.H2j[i] == nil {
			return false, "nil proof parameters"
		}
		if keyShare.BigXj[i] == nil || !keyShare.BigXj[i].ValidateBasic() {
			return false, "nil or invalid public key point"
		}
		if keyShare.PaillierPKs[i] == nil || keyShare.PaillierPKs[i].N == nil {
			return false, "nil public key data"
		}
	}
	return true, ""
}

// Safely subsets save data for reduced old committee, with panic guard; used in executeTSSReshare.
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func buildLocalSaveDataSubsetSafe(sourceData keygen.LocalPartySaveData, sortedIDs tss.SortedPartyIDs) (subset keygen.LocalPartySaveData, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in BuildLocalSaveDataSubset: %v", r)
		}
	}()
	subset = keygen.BuildLocalSaveDataSubset(sourceData, sortedIDs)
	return subset, nil
}

// Repairs missing Ks entries against committee keys if needed; used in executeTSSReshare.
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func normalizeKeyShareForCommittee(keyShare *keygen.LocalPartySaveData, committee *reshareCommittee) (bool, string) {
	if keyShare == nil || committee == nil {
		return false, "missing key share or committee"
	}
	if len(committee.partyIDs) == 0 {
		return false, "empty committee"
	}
	targetLen := len(committee.partyIDs)
	if len(keyShare.Ks) != targetLen {
		return false, "key share Ks length mismatch"
	}
	needsRepair := false
	for i := 0; i < targetLen; i++ {
		if keyShare.Ks[i] == nil {
			needsRepair = true
			break
		}
	}
	if !needsRepair {
		return false, ""
	}
	keyShare.Ks = committee.partyIDs.Keys()
	return true, ""
}

// Clears tracked progress for a key session; called by DKG/reshare polling handlers
// Called by: (*TSSPeer).checkPendingDKG, (*TSSPeer).checkReshareSessions.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func (p *TSSPeer) clearKeySessionProgress(sessionKey string) {
	p.mutex.Lock()
	delete(p.sessionProgress, sessionKey)
	p.mutex.Unlock()
}

// Detects stalled session state and throttles escalations; called by DKG/reshare polling handlers.
// Called by: (*TSSPeer).checkPendingDKG, (*TSSPeer).checkReshareSessions.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func (p *TSSPeer) checkKeySessionStall(sessionKey, status string, ackCount, completionAckCount int) (bool, time.Duration) {
	if p.stuckSessionTimeout <= 0 {
		return false, 0
	}
	now := time.Now()
	p.mutex.Lock()
	rec, exists := p.sessionProgress[sessionKey]
	if !exists || rec.Status != status || rec.AckCount != ackCount || rec.CompletionAckCount != completionAckCount {
		p.sessionProgress[sessionKey] = keySessionProgress{
			Status:             status,
			AckCount:           ackCount,
			CompletionAckCount: completionAckCount,
			LastProgressAt:     now,
		}
		p.mutex.Unlock()
		return false, 0
	}
	stalledFor := now.Sub(rec.LastProgressAt)
	if stalledFor < p.stuckSessionTimeout {
		p.mutex.Unlock()
		return false, stalledFor
	}
	// Throttle escalation attempts per session key to avoid log and transaction storms.
	if !rec.LastEscalationAt.IsZero() && now.Sub(rec.LastEscalationAt) < 30*time.Second {
		p.mutex.Unlock()
		return false, stalledFor
	}
	rec.LastEscalationAt = now
	p.sessionProgress[sessionKey] = rec
	p.mutex.Unlock()
	return true, stalledFor
}

// Creates deterministic DKG session ID from epoch/initiation metadata for message filtering.
// Called by: (*TSSPeer).executeTSSKeygen.
// Triggered: TSS key-management helper during DKG/reshare orchestration.
func deriveDKGSessionID(epoch int, dkg map[string]interface{}) string {
	seed := fmt.Sprintf("epoch:%d", epoch)
	if dkg != nil {
		if raw, ok := dkg["initiatedAt"]; ok {
			switch v := raw.(type) {
			case string:
				if s := strings.TrimSpace(v); s != "" {
					seed += "|initiatedAt:" + s
				}
			case float64:
				seed += fmt.Sprintf("|initiatedAt:%d", int64(v))
			case int:
				seed += fmt.Sprintf("|initiatedAt:%d", v)
			case int64:
				seed += fmt.Sprintf("|initiatedAt:%d", v)
			}
		}
	}
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("dkg-%d-%x", epoch, sum[:6])
}

// Full reshare orchestrator: committee derivation, share normalization/recovery, party startup, channel fanout. Called when reshare reaches acknowledged/proposed progression
// Called by: (*TSSPeer).checkReshareSessions.
// Triggered: DKG/reshare/signing session execution when protocol state becomes ready.
func (p *TSSPeer) executeTSSReshare(epoch int, reshare map[string]interface{}) {
	p.mutex.Lock()
	if p.keygenInProgress {
		p.mutex.Unlock()
		return
	}
	p.keygenInProgress = true
	p.keygenEpoch = epoch
	select {
	case <-p.keygenDone:
		p.keygenDone = make(chan struct{})
	default:
	}
	p.mutex.Unlock()

	finishEarly := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			log.Printf("[%s] Reshare aborted: %s", p.NodeID, reason)
		}
		closeKeyDone := false
		p.mutex.Lock()
		if p.keygenInProgress && p.keygenEpoch == epoch {
			p.keygenInProgress = false
			p.keygenEpoch = -1
			closeKeyDone = true
		}
		p.mutex.Unlock()
		if closeKeyDone {
			select {
			case <-p.keygenDone:
			default:
				close(p.keygenDone)
			}
		}
	}

	oldMembers := toStringSlice(reshare["oldNodeSet"])
	newMembers := toStringSlice(reshare["newNodeSet"])
	if len(newMembers) == 0 {
		finishEarly("empty new node set")
		return
	}
	if len(oldMembers) == 0 {
		oldMembers = append([]string(nil), newMembers...)
	}

	oldThreshold := 0
	if v, ok := reshare["oldThreshold"].(float64); ok {
		oldThreshold = int(v)
	}
	newThreshold := 0
	if v, ok := reshare["newThreshold"].(float64); ok {
		newThreshold = int(v)
	}
	if oldThreshold <= 0 {
		oldThreshold = newThreshold
	}
	if newThreshold <= 0 {
		newThreshold = oldThreshold
	}
	if oldThreshold <= 0 {
		oldThreshold = 1
	}
	if newThreshold <= 0 {
		newThreshold = 1
	}

	p.mutex.RLock()
	keyShare := p.TSSKeyShare
	preParams := p.TSSPreParams
	p.mutex.RUnlock()

	isOldMember := false
	for _, m := range oldMembers {
		if m == p.MemberID {
			isOldMember = true
			break
		}
	}
	if isOldMember && keyShare == nil {
		if err := p.LoadKeyShare(); err == nil {
			p.mutex.RLock()
			keyShare = p.TSSKeyShare
			p.mutex.RUnlock()
		}
	}
	if isOldMember && keyShare == nil {
		p.mutex.RLock()
		keygenInProgress := p.keygenInProgress
		keygenEpoch := p.keygenEpoch
		keygenDone := p.keygenDone
		p.mutex.RUnlock()
		if keygenInProgress && keygenEpoch == 0 && keygenDone != nil {
			select {
			case <-keygenDone:
				p.mutex.RLock()
				keyShare = p.TSSKeyShare
				p.mutex.RUnlock()
			case <-time.After(20 * time.Second):
			}
		}
	}

	getString := func(key string) string {
		if v, ok := reshare[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	oldSalt := getString("oldPartySalt")
	newSalt := getString("newPartySalt")
	explicitSalts := oldSalt != "" || newSalt != ""

	oldCommittee := (*reshareCommittee)(nil)
	newCommittee := (*reshareCommittee)(nil)
	if explicitSalts {
		oldCommittee = p.buildReshareCommittee(oldMembers, "old", oldSalt)
		newCommittee = p.buildReshareCommittee(newMembers, "new", newSalt)
		if isOldMember && keyShare != nil && !keyShareMatchesPartyIDs(keyShare, oldCommittee.partyIDs) {
			altOldSalt := ""
			if oldSalt == "" {
				altOldSalt = "new"
			} else if oldSalt == "new" {
				altOldSalt = ""
			}
			if altOldSalt != oldSalt {
				altOldCommittee := p.buildReshareCommittee(oldMembers, "old", altOldSalt)
				if keyShareMatchesPartyIDs(keyShare, altOldCommittee.partyIDs) {
					log.Printf("[%s] Local key share salt mismatch: local old salt appears %q, but on-chain reshare requires old salt %q", p.NodeID, altOldSalt, oldSalt)
				} else {
					log.Printf("[%s] Local key share does not match on-chain old committee IDs (old salt %q)", p.NodeID, oldSalt)
				}
			} else {
				log.Printf("[%s] Local key share does not match on-chain old committee IDs (old salt %q)", p.NodeID, oldSalt)
			}
		}
		log.Printf("[%s] Using reshare party salts (old=%q new=%q)", p.NodeID, oldSalt, newSalt)
	} else {
		oldUnsalted := p.buildReshareCommittee(oldMembers, "old", "")
		oldSalted := p.buildReshareCommittee(oldMembers, "old", "new")
		newUnsalted := p.buildReshareCommittee(newMembers, "new", "")
		newSalted := p.buildReshareCommittee(newMembers, "new", "new")

		// Choose old committee based on current key share; use opposite salt for new committee.
		useKeyShare := keyShare
		if !isOldMember {
			useKeyShare = nil
		}
		oldCommittee = oldUnsalted
		newCommittee = newSalted
		if useKeyShare != nil {
			if keyShareContainsPartyIDs(useKeyShare, oldSalted.partyIDs) {
				oldCommittee = oldSalted
				newCommittee = newUnsalted
			} else if keyShareContainsPartyIDs(useKeyShare, oldUnsalted.partyIDs) {
				oldCommittee = oldUnsalted
				newCommittee = newSalted
			}
		}
	}

	oldPartyID := oldCommittee.memberToParty[p.MemberID]
	newPartyID := newCommittee.memberToParty[p.MemberID]
	if newPartyID == nil {
		finishEarly("not in reshare new node set")
		p.mutex.Lock()
		p.completedEpochs[epoch] = true
		p.mutex.Unlock()
		return
	}

	keyCollidesWithOld := false
	if oldPartyID == nil && newPartyID != nil {
		for _, pid := range oldCommittee.partyIDs {
			if pid.KeyInt().Cmp(newPartyID.KeyInt()) == 0 {
				keyCollidesWithOld = true
				break
			}
		}
	}

	log.Printf("[%s] TSS Reshare: oldN=%d oldT=%d newN=%d newT=%d", p.NodeID, len(oldCommittee.members), oldThreshold, len(newCommittee.members), newThreshold)
	p.emitMetric("tss_reshare_start", map[string]interface{}{
		"epoch": epoch,
		"old_n": len(oldCommittee.members),
		"old_t": oldThreshold,
		"new_n": len(newCommittee.members),
		"new_t": newThreshold,
	})

	pubPoint := p.getCAPublicKeyPointFallback(reshare)
	if pubPoint == nil {
		finishEarly("missing CA public key for reshare")
		return
	}
	if explicitSalts && isOldMember && (keyShare == nil || !keyShareMatchesPartyIDs(keyShare, oldCommittee.partyIDs)) {
		restoredKeyShare, err := p.tryRestoreKeyShareSnapshotForReshare(oldMembers, oldSalt, oldCommittee, pubPoint)
		if err != nil {
			log.Printf("[%s] Key-share snapshot restore failed: %v", p.NodeID, err)
			p.emitMetric("keyshare_snapshot_restore_failed", map[string]interface{}{
				"epoch": epoch,
				"salt":  oldSalt,
				"error": err.Error(),
			})
			p.setRecoveryStatus("snapshot_restore_failed")
		} else {
			keyShare = restoredKeyShare
			p.mutex.Lock()
			p.TSSKeyShare = restoredKeyShare
			p.myPartyIndex = -1
			p.partyIndexMap = nil
			p.mutex.Unlock()
			if err := p.SaveKeyShare(); err != nil {
				log.Printf("[%s] Warning: failed to persist restored key share: %v", p.NodeID, err)
			}
		}
	}
	if keyShare != nil && keyShare.ECDSAPub != nil && !keyShare.ECDSAPub.Equals(pubPoint) {
		if !isOldMember {
			// New committee member with stale key share; drop it and continue as new-only.
			p.purgeLocalKeyShare("key share public key mismatch with CA")
			keyShare = nil
		} else {
			// Old committee member must have a matching key share to proceed.
			p.purgeLocalKeyShare("key share public key mismatch with CA")
			p.mutex.Lock()
			p.missingShareReshares[epoch] = true
			p.mutex.Unlock()
			finishEarly("local key share public key mismatch with CA; reset local state")
			return
		}
	}
	if keyShare != nil && keyShare.ECDSAPub == nil {
		keyShare.ECDSAPub = pubPoint
	}

	// If the old committee is a strict subset (e.g., after member removal),
	// reduce the key share data to match the old committee.
	if isOldMember && keyShare != nil && len(keyShare.Ks) > len(oldCommittee.partyIDs) {
		if ok, reason := keyShareHasCompleteData(keyShare); !ok {
			log.Printf("[%s] Skipping key share subset: %s", p.NodeID, reason)
		} else if keyShareContainsPartyIDs(keyShare, oldCommittee.partyIDs) {
			subset, err := buildLocalSaveDataSubsetSafe(*keyShare, oldCommittee.partyIDs)
			if err != nil {
				log.Printf("[%s] Skipping key share subset: %v", p.NodeID, err)
			} else {
				keyShare = &subset
				p.mutex.Lock()
				p.TSSKeyShare = keyShare
				p.myPartyIndex = -1
				p.partyIndexMap = nil
				p.mutex.Unlock()
				if err := p.SaveKeyShare(); err != nil {
					log.Printf("[%s] Warning: failed to persist key share subset: %v", p.NodeID, err)
				} else {
					log.Printf("[%s] Reduced key share to old committee subset for reshare (n=%d)", p.NodeID, len(oldCommittee.partyIDs))
				}
			}
		}
	}

	if isOldMember {
		if repaired, reason := normalizeKeyShareForCommittee(keyShare, oldCommittee); repaired {
			log.Printf("[%s] Repaired key share Ks for reshare old committee", p.NodeID)
		} else if reason != "" {
			log.Printf("[%s] Key share normalization skipped: %s", p.NodeID, reason)
		}
	}

	validOldData := false
	if keyShare != nil {
		if ok, reason := keyShareHasCompleteData(keyShare); ok {
			validOldData = true
		} else {
			log.Printf("[%s] Key share incomplete for reshare: %s", p.NodeID, reason)
		}
	}
	hasOld := oldPartyID != nil && validOldData && keyShareMatchesPartyIDs(keyShare, oldCommittee.partyIDs)
	allowNewOnly := false
	degradedNewOnly := false
	if (oldPartyID != nil || keyCollidesWithOld) && !hasOld {
		if explicitSalts {
			requiredOldShares := oldThreshold + 1
			if requiredOldShares < 1 {
				requiredOldShares = 1
			}
			maxSharesWithoutLocal := len(oldCommittee.partyIDs) - 1
			if canReshareWithoutLocalOldShare(len(oldCommittee.partyIDs), oldThreshold) && newPartyID != nil {
				allowNewOnly = true
				degradedNewOnly = true
				log.Printf("[%s] Missing old key share for explicit-salt reshare; proceeding as new-only (requiredOldShares=%d, maxWithoutLocal=%d)", p.NodeID, requiredOldShares, maxSharesWithoutLocal)
				p.emitMetric("reshare_degraded_new_only", map[string]interface{}{
					"epoch":               epoch,
					"required_old_shares": requiredOldShares,
					"max_without_local":   maxSharesWithoutLocal,
					"old_committee_size":  len(oldCommittee.partyIDs),
					"old_threshold":       oldThreshold,
				})
				p.setRecoveryStatus("reshare_degraded_new_only")
				p.tryAutoForceFreshDKG(
					epoch,
					fmt.Sprintf("reshare_degraded_new_only_explicit_epoch_%d", epoch),
					true,
					true,
				)
			} else {
				log.Printf("[%s] Same-key reshare impossible: missing old share (requiredOldShares=%d, maxWithoutLocal=%d)", p.NodeID, requiredOldShares, maxSharesWithoutLocal)
				p.emitMetric("reshare_impossible_missing_old_share", map[string]interface{}{
					"epoch":               epoch,
					"required_old_shares": requiredOldShares,
					"max_without_local":   maxSharesWithoutLocal,
					"old_committee_size":  len(oldCommittee.partyIDs),
					"old_threshold":       oldThreshold,
				})
				p.mutex.Lock()
				p.missingShareReshares[epoch] = true
				p.mutex.Unlock()
				p.setRecoveryStatus("reshare_impossible_missing_old_share")
				p.tryAutoForceFreshDKG(epoch, fmt.Sprintf("auto_fresh_dkg_impossible_reshare_epoch_%d", epoch), true, true)
				finishEarly("missing or mismatched key share for on-chain old committee (same-key reshare impossible)")
				return
			}
		}
		if !explicitSalts && newPartyID != nil && oldThreshold <= 1 {
			allowNewOnly = true
			log.Printf("[%s] Missing old key share (oldT=%d); proceeding as new committee only", p.NodeID, oldThreshold)
		} else if !explicitSalts {
			p.mutex.Lock()
			p.missingShareReshares[epoch] = true
			p.mutex.Unlock()
			finishEarly("missing or mismatched key share for old committee member; reshare cannot proceed")
			return
		}
	}
	hasNew := newPartyID != nil
	isOverlap := hasOld && hasNew
	startOld := hasOld
	// Overlap members must run both old and new parties; otherwise the new committee can never complete.
	startNew := hasNew
	if allowNewOnly {
		startOld = false
		isOverlap = false
		if degradedNewOnly {
			log.Printf("[%s] Reshare running in degraded new-only mode for epoch %d; fresh DKG auto-recovery has been evaluated", p.NodeID, epoch)
		}
	}

	oldCtx := tss.NewPeerContext(oldCommittee.partyIDs)
	newCtx := tss.NewPeerContext(newCommittee.partyIDs)

	partyKeyToNodeID := make(map[string]string)
	oldPartyKeys := make(map[string]struct{}, len(oldCommittee.partyIDs))
	newPartyKeys := make(map[string]struct{}, len(newCommittee.partyIDs))
	for nodeID, pid := range oldCommittee.nodeIDToParty {
		keyHex := hex.EncodeToString(pid.Key)
		partyKeyToNodeID[keyHex] = nodeID
		oldPartyKeys[keyHex] = struct{}{}
	}
	for nodeID, pid := range newCommittee.nodeIDToParty {
		keyHex := hex.EncodeToString(pid.Key)
		partyKeyToNodeID[keyHex] = nodeID
		newPartyKeys[keyHex] = struct{}{}
	}

	partyPtrToCommittee := make(map[*tss.PartyID]string)
	for _, pid := range oldCommittee.partyIDs {
		partyPtrToCommittee[pid] = "old"
	}
	for _, pid := range newCommittee.partyIDs {
		partyPtrToCommittee[pid] = "new"
	}

	oldIn := make(chan *TSSMessage, 200)
	newIn := make(chan *TSSMessage, 200)
	sessionID := fmt.Sprintf("reshare-%d", epoch)

	remaining := 0
	if startOld {
		remaining++
	}
	if startNew {
		remaining++
	}
	var remainingMu sync.Mutex
	doneCh := make(chan struct{})
	markDone := func() {
		remainingMu.Lock()
		if remaining > 0 {
			remaining--
			if remaining == 0 {
				closeKeyDone := false
				p.mutex.Lock()
				if p.keygenInProgress && p.keygenEpoch == epoch {
					p.keygenInProgress = false
					p.keygenEpoch = -1
					closeKeyDone = true
				}
				p.mutex.Unlock()
				if closeKeyDone {
					select {
					case <-p.keygenDone:
					default:
						close(p.keygenDone)
					}
				}
				close(doneCh)
			}
		}
		remainingMu.Unlock()
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-doneCh:
				return
			case msg := <-p.reshareMessages:
				if msg == nil || msg.SessionID != sessionID {
					continue
				}
				switch msg.ToCommittee {
				case "old":
					if startOld {
						oldIn <- msg
					}
				case "new":
					if startNew {
						newIn <- msg
					} else if isOverlap && startOld {
						oldIn <- msg
					}
				case "old+new":
					if startOld {
						oldIn <- msg
					}
					if startNew {
						newIn <- msg
					}
				default:
					if startNew {
						newIn <- msg
					} else if startOld {
						oldIn <- msg
					}
				}
			}
		}
	}()

	if startOld {
		oldOutCh := make(chan tss.Message, len(oldCommittee.partyIDs)*20)
		oldEndCh := make(chan keygen.LocalPartySaveData, 1)
		oldErrCh := make(chan *tss.Error, 1)

		params := tss.NewReSharingParameters(
			elliptic.P256(),
			oldCtx,
			newCtx,
			oldPartyID,
			len(oldCommittee.partyIDs),
			oldThreshold,
			len(newCommittee.partyIDs),
			newThreshold,
		)
		party := resharing.NewLocalParty(params, *keyShare, oldOutCh, oldEndCh)
		setResharePartyECDSAPub(party, pubPoint)
		roleLabel := "old"
		if isOverlap {
			roleLabel = "old+new"
		}

		p.wg.Add(1)
		go p.handleTSSReshareParty(roleLabel, party, oldPartyID, oldCommittee, newCommittee, partyKeyToNodeID, oldPartyKeys, newPartyKeys, partyPtrToCommittee, oldIn, oldOutCh, oldEndCh, oldErrCh, epoch, false, newThreshold, markDone)

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			log.Printf("[%s] Starting reshare old-committee party...", p.NodeID)
			if err := party.Start(); err != nil {
				oldErrCh <- err
			}
		}()
	}

	if startNew {
		// New-party setup needs valid pre-params. Reuse old key-share input only
		// when the local share already matches the new committee IDs exactly.
		// If old/new party IDs differ (e.g. salt flip with same member set), reusing
		// old input can leave the new party stuck without progressing past round 1.
		reuseOldInputForNew := hasOld &&
			keyShare != nil &&
			len(keyShare.Ks) == len(newCommittee.partyIDs) &&
			keyShareMatchesPartyIDs(keyShare, newCommittee.partyIDs)
		if !reuseOldInputForNew {
			if preParams == nil {
				if pp, err := p.ensurePreParams(); err != nil {
					log.Printf("[%s] Warning: failed to prepare pre-params for reshare new party: %v", p.NodeID, err)
				} else {
					preParams = pp
				}
			}
		}

		newOutCh := make(chan tss.Message, len(newCommittee.partyIDs)*20)
		newEndCh := make(chan keygen.LocalPartySaveData, 1)
		newErrCh := make(chan *tss.Error, 1)

		params := tss.NewReSharingParameters(
			elliptic.P256(),
			oldCtx,
			newCtx,
			newPartyID,
			len(oldCommittee.partyIDs),
			oldThreshold,
			len(newCommittee.partyIDs),
			newThreshold,
		)
		newInput := keygen.NewLocalPartySaveData(len(newCommittee.partyIDs))
		if reuseOldInputForNew {
			// Overlap member (old+new): tss-lib may treat this party as old committee too.
			// Reuse the old key share input to avoid nil-Ks panics in internal subset logic.
			newInput = *keyShare
		} else if preParams != nil {
			newInput.LocalPreParams = *preParams
		} else if keyShare != nil && keyShare.LocalPreParams.Validate() {
			newInput.LocalPreParams = keyShare.LocalPreParams
		}
		party := resharing.NewLocalParty(params, newInput, newOutCh, newEndCh)
		setResharePartyECDSAPub(party, pubPoint)

		p.wg.Add(1)
		go p.handleTSSReshareParty("new", party, newPartyID, oldCommittee, newCommittee, partyKeyToNodeID, oldPartyKeys, newPartyKeys, partyPtrToCommittee, newIn, newOutCh, newEndCh, newErrCh, epoch, true, newThreshold, markDone)

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			log.Printf("[%s] Starting reshare new-committee party...", p.NodeID)
			if err := party.Start(); err != nil {
				newErrCh <- err
			}
		}()
	}
}

// Compares local share vs CA public key/member set/threshold to decide if reshare/recovery is needed.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: TSS key-management helper during DKG/reshare orchestration.
// See CALL_MAP.md for the full direct-caller and trigger context.
func (p *TSSPeer) isKeyShareStale() (bool, string) {
	p.mutex.RLock()
	keyShare := p.TSSKeyShare
	cachedMembers := append([]string(nil), p.cachedMembers...)
	p.mutex.RUnlock()

	if keyShare == nil {
		return true, "no key share"
	}

	ca, err := p.GetCA()
	if err != nil {
		return false, ""
	}

	// Compare public key to CA state
	if caPub, ok := ca["publicKey"].(string); ok {
		caPub = strings.TrimSpace(caPub)
		if caPub == "" {
			return true, "CA public key not set"
		}
		if keyShare.ECDSAPub != nil {
			pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
			localPub := hex.EncodeToString(pubBytes)
			if localPub != caPub {
				return true, "public key mismatch"
			}
		}
	}

	// Compare member set if cached
	membersRaw, _ := ca["members"].([]interface{})
	members := make([]string, 0, len(membersRaw))
	for _, m := range membersRaw {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}
	sort.Strings(members)
	if len(cachedMembers) > 0 {
		if !equalStringSlices(cachedMembers, members) {
			return true, "member set mismatch"
		}
	} else {
		// Fallback: compare against key share party count to catch stale shares after restart
		if keyShare != nil && len(keyShare.BigXj) > 0 && len(keyShare.BigXj) != len(members) {
			return true, "member count mismatch"
		}
	}

	// Compare threshold if available
	if t, ok := ca["thresholdParams"].(map[string]interface{}); ok {
		if th, ok := t["threshold"].(float64); ok {
			if int(th) != p.Threshold {
				return true, "threshold mismatch"
			}
		}
	}

	return false, ""
}

// Submits CompleteDKG and reconciles ack/completion state. Called after local keygen completion and proposed-state handling.
// Called by: (*TSSPeer).checkPendingDKG, (*TSSPeer).handleTSSKeygenMessages.
// Triggered: session completion stage when on-chain acknowledgements are submitted.
func (p *TSSPeer) completeDKG(epoch int, publicKey string) {
	// Mark this epoch as completed locally
	p.mutex.Lock()
	p.completedEpochs[epoch] = true
	p.mutex.Unlock()

	if epoch == 0 {
		log.Printf("[%s] Submitting DKG completion (epoch 0) with public key...", p.NodeID)
		_, err := p.Execute("CompleteDKG", fmt.Sprintf("%d", epoch), publicKey)
		if err != nil {
			if containsIgnoreCase(err.Error(), "not in ready state") || containsIgnoreCase(err.Error(), "already") {
				log.Printf("[%s] DKG already completed by another node", p.NodeID)
			} else {
				log.Printf("[%s] CompleteDKG failed: %v", p.NodeID, err)
			}
			return
		}
		if dkg, err := p.GetDKGSession(epoch); err == nil {
			if status, ok := dkg["status"].(string); ok {
				if status == "completed" {
					log.Printf("[%s] OK DKG completed and recorded on blockchain!", p.NodeID)
				} else {
					ackCount := 0
					required := 0
					threshold := 0
					if v, ok := dkg["completionAckCount"].(float64); ok {
						ackCount = int(v)
					}
					if v, ok := dkg["completionRequiredAcks"].(float64); ok {
						required = int(v)
					}
					if v, ok := dkg["threshold"].(float64); ok {
						threshold = int(v)
					}
					if required <= 0 {
						required = threshold + 1
					}
					if required < 1 {
						required = 1
					}
					if members, ok := dkg["members"].([]interface{}); ok && len(members) > 0 && required > len(members) {
						required = len(members)
					}
					log.Printf("[%s] DKG completion pending acknowledgements (%d/%d), status=%s", p.NodeID, ackCount, required, status)
				}
			}
		}
		return
	}
	log.Printf("[%s] CompleteDKG called for non-zero epoch %d; use CompleteReshare", p.NodeID, epoch)
}

// Submits CompleteDKG and reconciles ack/completion state. Called after local keygen completion and proposed-state handling.
// Called by: (*TSSPeer).checkReshareSessions, (*TSSPeer).handleTSSReshareParty.
// Triggered: session completion stage when on-chain acknowledgements are submitted.
func (p *TSSPeer) completeReshare(epoch int, publicKey string) {
	log.Printf("[%s] Completing reshare (epoch %d) with public key...", p.NodeID, epoch)
	p.emitMetric("reshare_complete_submitted", map[string]interface{}{
		"epoch": epoch,
	})
	_, err := p.Execute("CompleteReshare", fmt.Sprintf("%d", epoch), publicKey)
	if err != nil {
		errMsg := err.Error()
		if containsIgnoreCase(errMsg, "not acknowledged") || containsIgnoreCase(errMsg, "threshold not reached") {
			log.Printf("[%s] Reshare completion not yet eligible (ack threshold not reached, expected while peers finalize): %v", p.NodeID, err)
		} else if containsIgnoreCase(errMsg, "already") {
			log.Printf("[%s] Reshare completion already submitted by another peer (expected): %v", p.NodeID, err)
		} else {
			log.Printf("[%s] CompleteReshare failed: %v", p.NodeID, err)
		}
		return
	}

	if reshareBytes, err := p.Query("GetReshareSession", fmt.Sprintf("%d", epoch)); err == nil {
		var reshare map[string]interface{}
		if err := json.Unmarshal(reshareBytes, &reshare); err == nil {
			if status, ok := reshare["status"].(string); ok {
				if status == "completed" {
					log.Printf("[%s] OK Reshare completed and recorded on blockchain!", p.NodeID)
					p.emitMetric("reshare_complete_recorded", map[string]interface{}{
						"epoch": epoch,
					})
					return
				}
				ackCount := 0
				if v, ok := reshare["completionAckCount"].(float64); ok {
					ackCount = int(v)
				}
				required := 0
				if list, ok := reshare["newNodeSet"].([]interface{}); ok {
					required = len(list)
				}
				if required > 0 {
					log.Printf("[%s] Reshare completion pending (%d/%d acks)", p.NodeID, ackCount, required)
				}
			}
		}
	}
}
