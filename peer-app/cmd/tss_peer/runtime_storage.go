// runtime_storage.go owns durable state persistence for key shares, pre-params, encrypted snapshots, and metrics files.
// Runtime flow: startup/shutdown/session-completion paths call these helpers to load, save, restore, and prune state.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type keyShareSnapshotMetadata struct {
	Version       int    `json:"version"`
	NodeID        string `json:"nodeId"`
	Epoch         int    `json:"epoch"`
	PartySalt     string `json:"partySalt"`
	CAPublicHash  string `json:"caPublicKeyHash"`
	CommitteeHash string `json:"committeeHash"`
	CreatedAt     string `json:"createdAt"`
}

type keyShareSnapshotEnvelope struct {
	Metadata   keyShareSnapshotMetadata `json:"metadata"`
	Nonce      string                   `json:"nonce"`
	Ciphertext string                   `json:"ciphertext"`
}

type keyShareSnapshotPayload struct {
	Metadata keyShareSnapshotMetadata `json:"metadata"`
	KeyShare []byte                   `json:"keyShare"`
}

// snapshotHashString returns a stable SHA-256 hex digest for snapshot identity fields.
// Lifecycle: Snapshot metadata generation.
// Called by: (*TSSPeer).snapshotMetadataFromCA, caPublicHashFromPoint, committeeIdentityHash.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func snapshotHashString(input string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(input)))
	return hex.EncodeToString(sum[:])
}

// committeeIdentityHash hashes the committee member set and salt to bind snapshots to one committee context.
// Lifecycle: Snapshot metadata generation.
// Called by: (*TSSPeer).snapshotMetadataFromCA, (*TSSPeer).tryRestoreKeyShareSnapshotForReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func committeeIdentityHash(members []string, partySalt string) string {
	if len(members) == 0 {
		return ""
	}
	sorted := append([]string(nil), members...)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	return snapshotHashString(strings.TrimSpace(partySalt) + "|" + joined)
}

// setRecoveryStatus updates local recovery status used by automated recovery decisions.
// Lifecycle: Recovery-state tracking.
// Called by: (*TSSPeer).executeTSSReshare, (*TSSPeer).tryAutoForceFreshDKG, (*TSSPeer).tryRestoreKeyShareSnapshotForReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) setRecoveryStatus(status string) {
	status = strings.TrimSpace(status)
	if status == "" {
		return
	}
	p.mutex.Lock()
	p.recoveryStatus = status
	p.mutex.Unlock()
}

// keyShareSnapshotDir returns the node-specific directory for encrypted key-share snapshots.
// Lifecycle: Snapshot path resolution.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: startup/runtime/shutdown persistence or recovery path.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) keyShareSnapshotDir() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, "snapshots", "keyshare", p.NodeID)
}

// snapshotMetadataFromCA builds snapshot metadata from CA state and local key-share context.
// Lifecycle: Snapshot serialization and write preparation.
// Called by: (*TSSPeer).writeEncryptedKeyShareSnapshot.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) snapshotMetadataFromCA(keyShare *keygen.LocalPartySaveData) keyShareSnapshotMetadata {
	meta := keyShareSnapshotMetadata{
		Version:   1,
		NodeID:    p.NodeID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ca, err := p.GetCA()
	if err != nil {
		return meta
	}
	if v, ok := ca["epoch"].(float64); ok {
		meta.Epoch = int(v)
	}
	if v, ok := ca["partySalt"].(string); ok {
		meta.PartySalt = strings.TrimSpace(v)
	}
	p.mutex.RLock()
	cachedMembers := append([]string(nil), p.cachedMembers...)
	p.mutex.RUnlock()
	if len(cachedMembers) == 0 {
		cachedMembers = toStringSlice(ca["members"])
	}
	if keyShare != nil && len(cachedMembers) > 0 {
		unsalted := p.buildReshareCommittee(cachedMembers, "snap", "")
		salted := p.buildReshareCommittee(cachedMembers, "snap", "new")
		if keyShareMatchesPartyIDs(keyShare, salted.partyIDs) {
			meta.PartySalt = "new"
		} else if keyShareMatchesPartyIDs(keyShare, unsalted.partyIDs) {
			meta.PartySalt = ""
		}
	}
	if keyShare != nil && keyShare.ECDSAPub != nil {
		pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
		meta.CAPublicHash = snapshotHashString(hex.EncodeToString(pubBytes))
	} else if v, ok := ca["publicKey"].(string); ok && strings.TrimSpace(v) != "" {
		meta.CAPublicHash = snapshotHashString(v)
	}
	meta.CommitteeHash = committeeIdentityHash(cachedMembers, meta.PartySalt)
	return meta
}

// encryptSnapshot encrypts snapshot payload bytes with AES-GCM using the configured snapshot key.
// Lifecycle: Snapshot serialization and encryption.
// Called by: (*TSSPeer).writeEncryptedKeyShareSnapshot.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) encryptSnapshot(plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	if len(p.snapshotKey) != 32 {
		return nil, nil, fmt.Errorf("snapshot key missing or invalid")
	}
	block, err := aes.NewCipher(p.snapshotKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// decryptSnapshot decrypts encrypted snapshot payload bytes with AES-GCM.
// Lifecycle: Snapshot restore and recovery.
// Called by: (*TSSPeer).tryRestoreKeyShareSnapshotForReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) decryptSnapshot(nonce, ciphertext []byte) ([]byte, error) {
	if len(p.snapshotKey) != 32 {
		return nil, fmt.Errorf("snapshot key missing or invalid")
	}
	block, err := aes.NewCipher(p.snapshotKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// pruneKeyShareSnapshots deletes oldest snapshots beyond the configured retention window.
// Lifecycle: Snapshot retention housekeeping.
// Called by: (*TSSPeer).writeEncryptedKeyShareSnapshot.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) pruneKeyShareSnapshots() error {
	if p.snapshotRetention <= 0 {
		return nil
	}
	dir := p.keyShareSnapshotDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	type snapshotEntry struct {
		name    string
		modTime time.Time
	}
	files := make([]snapshotEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, snapshotEntry{name: entry.Name(), modTime: info.ModTime()})
	}
	if len(files) <= p.snapshotRetention {
		return nil
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})
	toDelete := len(files) - p.snapshotRetention
	for i := 0; i < toDelete; i++ {
		_ = os.Remove(filepath.Join(dir, files[i].name))
	}
	return nil
}

// writeEncryptedKeyShareSnapshot serializes, encrypts, and stores a key-share snapshot on disk.
// Lifecycle: Runtime key-share persistence after key updates.
// Called by: (*TSSPeer).SaveKeyShare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) writeEncryptedKeyShareSnapshot(keyShare *keygen.LocalPartySaveData) error {
	if keyShare == nil || len(p.snapshotKey) != 32 {
		return nil
	}
	var keyShareBuf bytes.Buffer
	if err := gob.NewEncoder(&keyShareBuf).Encode(keyShare); err != nil {
		return err
	}
	meta := p.snapshotMetadataFromCA(keyShare)
	payload := keyShareSnapshotPayload{
		Metadata: meta,
		KeyShare: keyShareBuf.Bytes(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := p.encryptSnapshot(payloadBytes)
	if err != nil {
		return err
	}
	envelope := keyShareSnapshotEnvelope{
		Metadata:   meta,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	path := filepath.Join(p.keyShareSnapshotDir(), fmt.Sprintf("snapshot_%d.json", time.Now().UTC().UnixNano()))
	if err := writeFileAtomic(path, envBytes, 0600); err != nil {
		return err
	}
	if err := p.pruneKeyShareSnapshots(); err != nil {
		return err
	}
	return nil
}

// caPublicHashFromPoint derives a stable hash fingerprint from a CA public key point.
// Lifecycle: Snapshot restore matching and validation.
// Called by: (*TSSPeer).tryRestoreKeyShareSnapshotForReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func caPublicHashFromPoint(point *tsscrypto.ECPoint) string {
	if point == nil {
		return ""
	}
	raw := elliptic.Marshal(point.Curve(), point.X(), point.Y())
	if len(raw) == 0 {
		return ""
	}
	return snapshotHashString(hex.EncodeToString(raw))
}

// tryRestoreKeyShareSnapshotForReshare restores a compatible encrypted snapshot for reshare recovery.
// Lifecycle: Reshare recovery when old key-share context is missing or mismatched.
// Called by: (*TSSPeer).executeTSSReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) tryRestoreKeyShareSnapshotForReshare(oldMembers []string, oldSalt string, oldCommittee *reshareCommittee, caPub *tsscrypto.ECPoint) (*keygen.LocalPartySaveData, error) {
	if !p.autoRestoreSnapshot {
		return nil, fmt.Errorf("auto snapshot restore disabled")
	}
	if len(p.snapshotKey) != 32 {
		return nil, fmt.Errorf("snapshot key missing")
	}
	if oldCommittee == nil || len(oldCommittee.partyIDs) == 0 {
		return nil, fmt.Errorf("missing old committee context")
	}
	expectedSalt := strings.TrimSpace(oldSalt)
	expectedCommitteeHash := committeeIdentityHash(oldMembers, expectedSalt)
	expectedPubHash := caPublicHashFromPoint(caPub)

	entries, err := os.ReadDir(p.keyShareSnapshotDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no snapshots found")
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(p.keyShareSnapshotDir(), entry.Name())
		blob, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var envelope keyShareSnapshotEnvelope
		if err := json.Unmarshal(blob, &envelope); err != nil {
			continue
		}
		meta := envelope.Metadata
		if meta.NodeID != "" && meta.NodeID != p.NodeID {
			continue
		}
		if strings.TrimSpace(meta.PartySalt) != expectedSalt {
			continue
		}
		if expectedCommitteeHash != "" && strings.TrimSpace(meta.CommitteeHash) != expectedCommitteeHash {
			continue
		}
		if expectedPubHash != "" && strings.TrimSpace(meta.CAPublicHash) != expectedPubHash {
			continue
		}

		nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			continue
		}
		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			continue
		}
		payloadBytes, err := p.decryptSnapshot(nonce, ciphertext)
		if err != nil {
			continue
		}
		var payload keyShareSnapshotPayload
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			continue
		}
		var restored keygen.LocalPartySaveData
		if err := gob.NewDecoder(bytes.NewReader(payload.KeyShare)).Decode(&restored); err != nil {
			continue
		}
		if ok, _ := keyShareHasCompleteData(&restored); !ok {
			continue
		}
		if !keyShareMatchesPartyIDs(&restored, oldCommittee.partyIDs) {
			continue
		}
		if caPub != nil && restored.ECDSAPub != nil && !restored.ECDSAPub.Equals(caPub) {
			continue
		}
		if restored.ECDSAPub == nil && caPub != nil {
			restored.ECDSAPub = caPub
		}

		log.Printf("[%s] Restored key share from encrypted snapshot %s", p.NodeID, entry.Name())
		p.emitMetric("keyshare_snapshot_restored", map[string]interface{}{
			"snapshot": entry.Name(),
		})
		p.setRecoveryStatus("snapshot_restored")
		return &restored, nil
	}
	return nil, fmt.Errorf("no matching snapshot for old salt=%q", expectedSalt)
}

// keySharePath returns the canonical local path for persisted key-share state.
// Lifecycle: Key-share file path resolution.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: startup/runtime/shutdown persistence or recovery path.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) keySharePath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("keyshare_%s.gob", p.NodeID))
}

// writeFileAtomic writes a file atomically using a temporary file and rename strategy.
// Lifecycle: Safe persistence primitive for key-share and snapshot writes.
// Called by: (*TSSPeer).SaveKeyShare, (*TSSPeer).writeEncryptedKeyShareSnapshot.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Windows cannot rename over an existing file.
		_ = os.Remove(path)
		if err2 := os.Rename(tmpName, path); err2 != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	return nil
}

// markKeyShareInvalid flags local key-share state as invalid with a reason string.
// Lifecycle: Key-share load/validation failure handling.
// Called by: (*TSSPeer).LoadKeyShare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) markKeyShareInvalid(reason string) {
	p.mutex.Lock()
	p.keyShareInvalid = true
	p.keyShareInvalidMsg = reason
	p.mutex.Unlock()
}

// clearKeyShareInvalid clears invalid-key-share flags after successful validation.
// Lifecycle: Key-share load/validation success path.
// Called by: (*TSSPeer).LoadKeyShare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) clearKeyShareInvalid() {
	p.mutex.Lock()
	p.keyShareInvalid = false
	p.keyShareInvalidMsg = ""
	p.keyShareInvalidLog = false
	p.mutex.Unlock()
}

// SaveKeyShare persists the current local key share and writes an encrypted recovery snapshot.
// Lifecycle: Runtime key-share persistence and shutdown durability.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: startup/runtime/shutdown persistence or recovery path.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) SaveKeyShare() error {
	p.mutex.RLock()
	if p.TSSKeyShare == nil {
		p.mutex.RUnlock()
		return fmt.Errorf("no key share to save")
	}
	keyShare := p.TSSKeyShare
	p.mutex.RUnlock()

	path := p.keySharePath()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(keyShare); err != nil {
		return err
	}
	if err := writeFileAtomic(path, buf.Bytes(), 0600); err != nil {
		return err
	}
	if err := p.writeEncryptedKeyShareSnapshot(keyShare); err != nil {
		log.Printf("[%s] Warning: failed to persist encrypted key-share snapshot: %v", p.NodeID, err)
	}
	return nil
}

// LoadKeyShare loads and validates persisted key-share state from local storage.
// Lifecycle: Startup restoration and reshare preparation.
// Called by: (*TSSPeer).executeTSSReshare, NewTSSPeer.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) LoadKeyShare() error {
	path := p.keySharePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		legacyPath := strings.TrimSuffix(path, ".gob") + ".json"
		if _, legacyErr := os.Stat(legacyPath); legacyErr == nil {
			legacyMsg := fmt.Sprintf("legacy key share file detected at %s; legacy format is no longer supported (delete it and run fresh DKG)", legacyPath)
			p.markKeyShareInvalid(legacyMsg)
			return fmt.Errorf("%s", legacyMsg)
		} else if legacyErr != nil && !os.IsNotExist(legacyErr) {
			return legacyErr
		}
		return err
	}

	var keyShare keygen.LocalPartySaveData
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&keyShare); err != nil {
		p.markKeyShareInvalid(err.Error())
		return err
	}
	if ok, reason := keyShareHasCompleteData(&keyShare); !ok {
		err := fmt.Errorf("persisted key share invalid: %s", reason)
		p.markKeyShareInvalid(err.Error())
		return err
	}

	p.mutex.Lock()
	p.TSSKeyShare = &keyShare
	p.mutex.Unlock()
	p.clearKeyShareInvalid()
	log.Printf("[%s] Loaded persisted key share from %s", p.NodeID, path)
	return nil
}

// preParamsPath returns the canonical local path for persisted TSS pre-parameters.
// Lifecycle: Pre-params file path resolution.
// Called by: (*TSSPeer).LoadPreParams, (*TSSPeer).SavePreParams, (*TSSPeer).resetLocalState.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) preParamsPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("preparams_%s.gob", p.NodeID))
}

// SavePreParams persists generated TSS pre-parameters for reuse.
// Lifecycle: Runtime cryptographic precomputation persistence.
// Called by: (*TSSPeer).ensurePreParams.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) SavePreParams() error {
	p.mutex.RLock()
	if p.TSSPreParams == nil {
		p.mutex.RUnlock()
		return fmt.Errorf("no pre-params to save")
	}
	preParams := p.TSSPreParams
	p.mutex.RUnlock()

	path := p.preParamsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(preParams); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0600)
}

// LoadPreParams loads persisted TSS pre-parameters into memory.
// Lifecycle: Startup restoration and lazy pre-params reuse.
// Called by: (*TSSPeer).ensurePreParams, NewTSSPeer.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) LoadPreParams() error {
	path := p.preParamsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var preParams keygen.LocalPreParams
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&preParams); err != nil {
		return err
	}

	p.mutex.Lock()
	p.TSSPreParams = &preParams
	p.mutex.Unlock()

	log.Printf("[%s] Loaded persisted pre-params from %s", p.NodeID, path)
	return nil
}

// ensurePreParams returns cached pre-params or loads/generates and persists them on demand.
// Lifecycle: Keygen/reshare prerequisite preparation.
// Called by: (*TSSPeer).executeTSSKeygen, (*TSSPeer).executeTSSReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) ensurePreParams() (*keygen.LocalPreParams, error) {
	p.mutex.RLock()
	if p.TSSPreParams != nil {
		pre := p.TSSPreParams
		p.mutex.RUnlock()
		return pre, nil
	}
	p.mutex.RUnlock()

	p.preParamsMu.Lock()
	defer p.preParamsMu.Unlock()

	p.mutex.RLock()
	if p.TSSPreParams != nil {
		pre := p.TSSPreParams
		p.mutex.RUnlock()
		return pre, nil
	}
	p.mutex.RUnlock()

	if err := p.LoadPreParams(); err != nil && !os.IsNotExist(err) {
		log.Printf("[%s] Warning: failed to load pre-params: %v", p.NodeID, err)
	}
	p.mutex.RLock()
	if p.TSSPreParams != nil {
		pre := p.TSSPreParams
		p.mutex.RUnlock()
		return pre, nil
	}
	p.mutex.RUnlock()

	log.Printf("[%s] Generating TSS pre-parameters on demand (safe primes, may take 2-3 min)...", p.NodeID)
	preParams, err := keygen.GeneratePreParams(3 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-params: %w", err)
	}

	p.mutex.Lock()
	p.TSSPreParams = preParams
	p.mutex.Unlock()
	if err := p.SavePreParams(); err != nil {
		log.Printf("[%s] Warning: failed to persist pre-params: %v", p.NodeID, err)
	}
	log.Printf("[%s] TSS pre-parameters generated successfully", p.NodeID)
	return preParams, nil
}

// resetLocalState clears persisted local key-share, pre-params, and snapshot artifacts.
// Lifecycle: Explicit local recovery reset path.
// Called by: (*TSSPeer).resetLocalStateOnce.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) resetLocalState() {
	paths := []string{p.keySharePath(), p.preParamsPath()}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to remove %s: %v", p.NodeID, path, err)
		}
	}
	if err := os.RemoveAll(p.keyShareSnapshotDir()); err != nil && !os.IsNotExist(err) {
		log.Printf("[%s] Warning: failed to remove snapshot dir %s: %v", p.NodeID, p.keyShareSnapshotDir(), err)
	}
}

// purgeLocalKeyShare clears local in-memory and on-disk key-share state when it is unsafe to keep.
// Lifecycle: Runtime recovery from stale or inconsistent key-share state.
// Called by: (*TSSPeer).checkPendingDKG, (*TSSPeer).executeTSSReshare.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) purgeLocalKeyShare(reason string) {
	p.mutex.Lock()
	hadShare := p.TSSKeyShare != nil
	p.TSSKeyShare = nil
	p.myPartyIndex = -1
	p.partyIndexMap = nil
	p.cachedMembers = nil
	p.mutex.Unlock()

	paths := []string{p.keySharePath()}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to remove %s: %v", p.NodeID, path, err)
		}
	}
	if hadShare {
		if strings.TrimSpace(reason) == "" {
			reason = "unknown"
		}
		log.Printf("[%s] Local key share cleared (%s)", p.NodeID, reason)
	}
}

// resetMarkerPath returns the marker-file path used for one-time reset semantics.
// Lifecycle: Startup reset idempotency support.
// Called by: (*TSSPeer).resetLocalStateOnce.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) resetMarkerPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("reset_%s.done", p.NodeID))
}

// resetLocalStateOnce applies env-driven local reset exactly once using a marker guard.
// Lifecycle: Startup reset and state bootstrapping.
// Called by: NewTSSPeer.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) resetLocalStateOnce(resetSet, resetState bool) {
	if !resetSet || !resetState {
		return
	}
	marker := p.resetMarkerPath()
	if _, err := os.Stat(marker); err == nil {
		log.Printf("[%s] TSS_RESET_STATE already applied previously; skipping reset", p.NodeID)
		return
	}
	log.Printf("[%s] Resetting local state (key share and pre-params) due to TSS_RESET_STATE", p.NodeID)
	p.resetLocalState()
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err == nil {
		_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0600)
	}
}

// metricsPath returns the path to the JSONL metrics output file.
// Lifecycle: Metrics storage setup.
// Called by: (*TSSPeer).initMetrics.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) metricsPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, "metrics.jsonl")
}

// initMetrics initializes optional on-disk metrics collection for this peer.
// Lifecycle: Startup observability initialization.
// Called by: NewTSSPeer.
// Triggered: startup/runtime/shutdown persistence or recovery path.
func (p *TSSPeer) initMetrics() {
	enabled := strings.ToLower(strings.TrimSpace(envOrDefault("TSS_METRICS_ENABLED", "false")))
	if enabled == "false" || enabled == "0" {
		return
	}
	path := p.metricsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("[%s] Warning: failed to create metrics dir: %v", p.NodeID, err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[%s] Warning: failed to open metrics file: %v", p.NodeID, err)
		return
	}
	p.metricsFile = f
	p.metricsEnabled = true
	log.Printf("[%s] Metrics enabled: %s", p.NodeID, path)
}

// emitMetric writes one structured metric event record when metrics are enabled.
// Lifecycle: Runtime observability emission across protocol and governance workflows.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: startup/runtime/shutdown persistence or recovery path.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) emitMetric(event string, fields map[string]interface{}) {
	if !p.metricsEnabled || p.metricsFile == nil {
		return
	}
	payload := map[string]interface{}{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"event": event,
		"org":   p.Organization,
		"node":  p.NodeID,
	}
	for k, v := range fields {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	p.metricsMu.Lock()
	defer p.metricsMu.Unlock()
	_, _ = p.metricsFile.Write(append(b, '\n'))
}
