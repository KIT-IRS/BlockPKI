// runtime_gateway_events.go handles Fabric gateway calls, retry/receipt logic, metrics, and chaincode event ingestion.
// Runtime flow: operations call Query/Execute helpers while an event listener goroutine streams chaincode events.

// It is a interaction point between the runtime, webui and the chaincode side. So the chaincode emitted events are processed here
// and logged if for the benchmark metrics. It also contains retry for other functions to outsource these executions.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	commonpb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	peerpb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
)

// captures transaction metadata for benchmarks.
type TxReceipt struct {
	Function      string `json:"function"`
	TxID          string `json:"tx_id"`
	CommitStatus  string `json:"commit_status"`
	BlockNumber   uint64 `json:"block_number"`
	LocalSubmitTS string `json:"local_submit_ts"`
	LocalCommitTS string `json:"local_commit_ts"`
}

// captures per-transaction/block metadata for benchmark attribution.
type txLedgerMetadata struct {
	LedgerTxTS                   string
	ValidationCode               string
	TxEnvelopeBytes              int
	TxPayloadBytes               int
	TxIndexInBlock               int
	BlockBytes                   int
	BlockDataBytes               int
	BlockOverheadBytes           int
	BlockTxCount                 int
	BlockSharedOverheadPerTxByte float64
}

// ===================== FABRIC GATEWAY =====================

// Generic query
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: runtime chaincode I/O path from polling, menu, and API workflows.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) Query(function string, args ...string) ([]byte, error) {
	return p.contract.EvaluateTransaction(function, args...)
}

// whether error is a mvcc or phantom read conflict that is similar to mvcc  (instead of the keyed version being changed, the set of matched keys changed)
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: isRetryableExecuteError.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func isMVCCConflictError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "MVCC_READ_CONFLICT") || strings.Contains(msg, "PHANTOM_READ_CONFLICT")
}

// Endorsment failure because the r/w sets of endorsers divierged or not enough endorsments could be collected
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: isRetryableExecuteError.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func isTransientEndorsementDivergenceError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "proposalresponsepayloads do not match") {
		return true
	}

	if strings.Contains(msg, "failed to collect enough transaction endorsements") &&
		!strings.Contains(msg, "chaincode response 500") {
		return true
	}
	return false
}

// Checks wheter the signing session completion was achieved while still in progress or not competion acked on other nodes
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).tryRegisterCertificate, isRetryableExecuteError.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func isTransientSigningSessionLagError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "signing session not completed yet")
}

// checks whether the recieved error is due to a retry errot (by mvcc etc.)
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).ExecuteWithReceipt.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func isRetryableExecuteError(err error) bool {
	return isMVCCConflictError(err) || isTransientEndorsementDivergenceError(err) || isTransientSigningSessionLagError(err)
}

// reports whether mvcc or phantom read conflict
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).ExecuteWithReceipt.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func isMVCCValidationCode(code peerpb.TxValidationCode) bool {
	return code == peerpb.TxValidationCode_MVCC_READ_CONFLICT || code == peerpb.TxValidationCode_PHANTOM_READ_CONFLICT
}

// checks whether certain dkg conflics have appeared on the chaincode
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).checkPendingJoinRequests, (*TSSPeer).checkPendingRemoveMemberProposals, (*TSSPeer).checkPendingRevocations.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func isSessionSerializationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "while dkg session is") ||
		strings.Contains(msg, "while reshare epoch") ||
		strings.Contains(msg, "membership governance is pending") ||
		strings.Contains(msg, "cannot initiate dkg while reshare") ||
		strings.Contains(msg, "dkg already in progress")
}

// for metrics to match hashes instead of full raw arguments
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: buildTxMetricFields.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func hashInvokeArgs(args []string) string {
	sum := sha256.Sum256([]byte(strings.Join(args, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// Normalization of names for the grouping during benchmarks
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: buildTxMetricFields.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func inferTxWorkflow(function string) string {
	switch function {
	case "SubmitCSR", "VoteOnCSR", "SubmitPartialSignature", "RegisterCombinedCertificateWithSignature":
		return "csr"
	case "ProposeRevocation", "VoteOnRevocation":
		return "revocation"
	case "RequestJoinCA", "VoteOnJoinRequest":
		return "join"
	case "ProposeRemoveMember", "VoteOnRemoveMember":
		return "removal"
	case "AcknowledgeReshare", "ProposeReshareCompletion", "AcknowledgeReshareCompletion", "ForceReshare":
		return "reshare"
	case "InitiateDKG", "AcknowledgeDKG", "ProposeDKGCompletion", "AcknowledgeDKGCompletion", "ForceFreshDKG":
		return "dkg"
	default:
		return ""
	}
}

// Normalization of names for the grouping during benchmarks
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: buildTxMetricFields.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func inferTxIDs(function string, args []string) (proposalID string, epoch string) {
	switch function {
	case "SubmitCSR", "VoteOnCSR", "SubmitPartialSignature", "RegisterCombinedCertificateWithSignature", "ProposeRevocation", "VoteOnRevocation":
		if len(args) > 0 {
			proposalID = strings.TrimSpace(args[0])
		}
	case "RequestJoinCA", "VoteOnJoinRequest":
		if len(args) > 1 {
			proposalID = strings.TrimSpace(args[1])
		}
	case "ProposeRemoveMember", "VoteOnRemoveMember":
		if len(args) > 1 {
			proposalID = strings.TrimSpace(args[1])
		}
	case "AcknowledgeReshare", "ProposeReshareCompletion", "AcknowledgeReshareCompletion":
		if len(args) > 0 {
			epoch = strings.TrimSpace(args[0])
		}
	case "AcknowledgeDKG", "ProposeDKGCompletion", "AcknowledgeDKGCompletion":
		if len(args) > 0 {
			epoch = strings.TrimSpace(args[0])
		}
	}
	return proposalID, epoch
}

// Builts the metrics of a transaction for benchmarks
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).ExecuteWithReceipt.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func buildTxMetricFields(function string, args []string) map[string]interface{} {
	workflow := inferTxWorkflow(function)
	proposalID, epoch := inferTxIDs(function, args)
	operationID := proposalID
	if operationID == "" {
		operationID = epoch
	}
	fields := map[string]interface{}{
		"function":  function,
		"args_hash": hashInvokeArgs(args),
	}
	if workflow != "" {
		fields["workflow"] = workflow
	}
	if proposalID != "" {
		fields["proposal_id"] = proposalID
	}
	if epoch != "" {
		fields["epoch"] = epoch
	}
	if operationID != "" {
		fields["operation_id"] = operationID
	}
	return fields
}

// computes the backoff time of the execution function. Scales exponetially
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).ExecuteWithReceipt, (*TSSPeer).tryRegisterCertificate.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func computeExecuteBackoff(baseBackoff, maxBackoff time.Duration, jitterPct int, attempt int) time.Duration {
	backoff := baseBackoff
	for i := 1; i < attempt; i++ {
		if backoff >= maxBackoff/2 {
			backoff = maxBackoff
			break
		}
		backoff *= 2
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	if jitterPct > 0 && backoff > 0 {
		spread := int64(backoff) * int64(jitterPct) / 100
		if spread > 0 {
			offset := (time.Now().UnixNano() % (2*spread + 1)) - spread
			backoff = time.Duration(int64(backoff) + offset)
			if backoff < 0 {
				backoff = 0
			}
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	return backoff
}

// Executes a function with retry and returns a receipt with metadata for benchmarks. Can be used for functions that expect mvcc conflicts
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).Execute.
// Triggered: runtime chaincode I/O path from polling, menu, and API workflows.
func (p *TSSPeer) ExecuteWithReceipt(function string, args ...string) ([]byte, *TxReceipt, error) {
	maxAttempts := p.executeMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 8
	}
	baseBackoff := p.executeBackoffBase
	if baseBackoff <= 0 {
		baseBackoff = 250 * time.Millisecond
	}
	maxBackoff := p.executeBackoffMax
	if maxBackoff < baseBackoff {
		maxBackoff = baseBackoff
	}
	jitterPct := p.executeBackoffJitterPct
	if jitterPct < 0 {
		jitterPct = 0
	}
	if jitterPct > 100 {
		jitterPct = 100
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		localSubmitTS := time.Now().UTC()
		baseFields := buildTxMetricFields(function, args)
		baseFields["attempt"] = attempt
		baseFields["local_submit_ts"] = localSubmitTS.Format(time.RFC3339Nano)
		p.emitMetric("tx_submit_started", baseFields)

		proposal, err := p.contract.NewProposal(function, client.WithArguments(args...))
		if err != nil {
			fail := buildTxMetricFields(function, args)
			fail["attempt"] = attempt
			fail["phase"] = "proposal"
			fail["error"] = err.Error()
			p.emitMetric("tx_failed", fail)
			if !isRetryableExecuteError(err) || attempt == maxAttempts {
				return nil, nil, err
			}
			backoff := computeExecuteBackoff(baseBackoff, maxBackoff, jitterPct, attempt)
			log.Printf("[%s] Retryable conflict on %s, retry %d/%d in %v", p.NodeID, function, attempt+1, maxAttempts, backoff)
			time.Sleep(backoff)
			continue
		}
		txID := proposal.TransactionID()

		endorsedTx, err := proposal.Endorse()
		if err != nil {
			fail := buildTxMetricFields(function, args)
			fail["attempt"] = attempt
			fail["tx_id"] = txID
			fail["phase"] = "endorse"
			fail["error"] = err.Error()
			p.emitMetric("tx_failed", fail)
			if !isRetryableExecuteError(err) || attempt == maxAttempts {
				return nil, nil, err
			}
			backoff := computeExecuteBackoff(baseBackoff, maxBackoff, jitterPct, attempt)
			log.Printf("[%s] Retryable conflict on %s, retry %d/%d in %v", p.NodeID, function, attempt+1, maxAttempts, backoff)
			time.Sleep(backoff)
			continue
		}

		commit, err := endorsedTx.Submit()
		if err != nil {
			fail := buildTxMetricFields(function, args)
			fail["attempt"] = attempt
			fail["tx_id"] = txID
			fail["phase"] = "submit"
			fail["error"] = err.Error()
			p.emitMetric("tx_failed", fail)
			if !isRetryableExecuteError(err) || attempt == maxAttempts {
				return nil, nil, err
			}
			backoff := computeExecuteBackoff(baseBackoff, maxBackoff, jitterPct, attempt)
			log.Printf("[%s] Retryable conflict on %s, retry %d/%d in %v", p.NodeID, function, attempt+1, maxAttempts, backoff)
			time.Sleep(backoff)
			continue
		}

		submitted := buildTxMetricFields(function, args)
		submitted["attempt"] = attempt
		submitted["tx_id"] = txID
		submitted["local_submit_ts"] = localSubmitTS.Format(time.RFC3339Nano)
		p.emitMetric("tx_submitted", submitted)

		status, err := commit.Status()
		if err != nil {
			fail := buildTxMetricFields(function, args)
			fail["attempt"] = attempt
			fail["tx_id"] = txID
			fail["phase"] = "commit_status"
			fail["error"] = err.Error()
			p.emitMetric("tx_failed", fail)
			if !isRetryableExecuteError(err) || attempt == maxAttempts {
				return nil, nil, err
			}
			backoff := computeExecuteBackoff(baseBackoff, maxBackoff, jitterPct, attempt)
			log.Printf("[%s] Retryable conflict on %s, retry %d/%d in %v", p.NodeID, function, attempt+1, maxAttempts, backoff)
			time.Sleep(backoff)
			continue
		}

		localCommitTS := time.Now().UTC()
		receipt := &TxReceipt{
			Function:      function,
			TxID:          status.TransactionID,
			CommitStatus:  status.Code.String(),
			BlockNumber:   status.BlockNumber,
			LocalSubmitTS: localSubmitTS.Format(time.RFC3339Nano),
			LocalCommitTS: localCommitTS.Format(time.RFC3339Nano),
		}

		if !status.Successful {
			failErr := fmt.Errorf("transaction %s failed with status %s (%d) in block %d", status.TransactionID, status.Code.String(), status.Code, status.BlockNumber)
			fail := buildTxMetricFields(function, args)
			fail["attempt"] = attempt
			fail["tx_id"] = status.TransactionID
			fail["block_number"] = status.BlockNumber
			fail["phase"] = "validation"
			fail["validation_code"] = status.Code.String()
			fail["error"] = failErr.Error()
			p.emitMetric("tx_failed", fail)
			if !isMVCCValidationCode(status.Code) || attempt == maxAttempts {
				return nil, receipt, failErr
			}
			backoff := computeExecuteBackoff(baseBackoff, maxBackoff, jitterPct, attempt)
			log.Printf("[%s] MVCC conflict on %s, retry %d/%d in %v", p.NodeID, function, attempt+1, maxAttempts, backoff)
			time.Sleep(backoff)
			continue
		}

		committed := buildTxMetricFields(function, args)
		committed["attempt"] = attempt
		committed["tx_id"] = receipt.TxID
		committed["block_number"] = receipt.BlockNumber
		committed["commit_status"] = receipt.CommitStatus
		committed["validation_code"] = receipt.CommitStatus
		committed["local_submit_ts"] = receipt.LocalSubmitTS
		committed["local_commit_ts"] = receipt.LocalCommitTS
		p.emitMetric("tx_committed", committed)
		return endorsedTx.Result(), receipt, nil
	}
	return nil, nil, fmt.Errorf("submit failed after %d attempts", maxAttempts)
}

// Executes a feneric function
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: runtime chaincode I/O path from polling, menu, and API workflows.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) Execute(function string, args ...string) ([]byte, error) {
	result, _, err := p.ExecuteWithReceipt(function, args...)
	return result, err
}

// Gets the Fabric id from the chaincode
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: NewTSSPeer.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) WhoAmI() (string, error) {
	payload, err := p.Query("WhoAmI")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// Returns the ca from chaincode
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: runtime gateway/metrics helper during transaction and event processing.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) GetCA() (map[string]interface{}, error) {
	payload, err := p.Query("GetDistributedCA", DefaultCAID)
	if err != nil {
		return nil, err
	}

	var ca map[string]interface{}
	if err := json.Unmarshal(payload, &ca); err != nil {
		return nil, err
	}
	p.persistCAPublicKey(ca)
	return ca, nil
}

// checks on the chaincode wether the ca has mekle trees enabled
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).apiGetMerkle, (*TSSPeer).applyMerkleConfigFromEnv, (*TSSPeer).viewCertificateMerkleTree.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) GetMerkleEnabled() (bool, error) {
	payload, err := p.Query("GetMerkleEnabled", DefaultCAID)
	if err != nil {
		return true, err
	}
	value := strings.Trim(string(payload), "\" \n\r\t")
	switch strings.ToLower(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return true, fmt.Errorf("unexpected Merkle enabled value: %s", value)
	}
}

// sends the merkle config from the set envvars
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: main.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) applyMerkleConfigFromEnv() {
	raw := strings.TrimSpace(os.Getenv("MERKLE_TREE_ENABLED"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("TSS_MERKLE_TREE_ENABLED"))
	}
	if raw == "" {
		return
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("[%s] Invalid MERKLE_TREE_ENABLED=%q (expected true/false)", p.NodeID, raw)
		return
	}
	p.merkleConfigSet = true
	p.merkleConfigEnabled = enabled
	current, err := p.GetMerkleEnabled()
	if err == nil && current == enabled {
		return
	}
	if _, err := p.Execute("SetMerkleEnabled", DefaultCAID, strconv.FormatBool(enabled)); err != nil {
		log.Printf("[%s] Failed to set Merkle config: %v", p.NodeID, err)
		return
	}
	log.Printf("[%s] Merkle tree enabled=%t", p.NodeID, enabled)
}

// stores the CA pub key locally after every getCA call
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).GetCA.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) persistCAPublicKey(ca map[string]interface{}) {
	caPublicKeyHex, _ := ca["caPublicKey"].(string)
	if caPublicKeyHex == "" {
		caPublicKeyHex, _ = ca["publicKey"].(string)
	}
	p.persistCAPublicKeyHex(caPublicKeyHex)
}

// Persists the CA public key locally for reference and debugging, isnt used for cert verification as this is done in chaincode (getCA)
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).persistCAPublicKey, (*TSSPeer).tryRegisterCertificate.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) persistCAPublicKeyHex(caPublicKeyHex string) {
	if caPublicKeyHex == "" {
		return
	}
	certsDir := filepath.Join("certs", p.Organization)
	os.MkdirAll(certsDir, 0700)
	caKeyPath := filepath.Join(certsDir, "ca-pubkey.hex")
	if b, err := os.ReadFile(caKeyPath); err == nil {
		if strings.TrimSpace(string(b)) == caPublicKeyHex {
			return
		}
	}
	if err := os.WriteFile(caKeyPath, []byte(caPublicKeyHex), 0644); err != nil {
		log.Printf("[%s] Warning: failed to save CA public key: %v", p.NodeID, err)
	}
}

// Types for Web UI block overview
type BlockTxSummary struct {
	TxID      string `json:"txId"`
	Type      string `json:"type"`
	Chaincode string `json:"chaincode"`
	Function  string `json:"function"`
}

// Types for Web UI block overview
type BlockSummary struct {
	Number  uint64           `json:"number"`
	TxCount int              `json:"txCount"`
	Txs     []BlockTxSummary `json:"txs"`
}

// gets the recent blocks for the UI overview
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).apiGetRecentBlocks.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) getRecentBlocks(limit int) ([]BlockSummary, error) {
	if limit <= 0 {
		limit = 5
	}
	if limit > maxBlocksToShow {
		limit = maxBlocksToShow
	}

	qscc := p.network.GetContract("qscc")
	infoBytes, err := qscc.EvaluateTransaction("GetChainInfo", DefaultChannel)
	if err != nil {
		return nil, err
	}

	var info commonpb.BlockchainInfo
	if err := proto.Unmarshal(infoBytes, &info); err != nil {
		return nil, err
	}

	height := info.Height
	if height == 0 {
		return []BlockSummary{}, nil
	}

	start := int64(height) - int64(limit)
	if start < 0 {
		start = 0
	}

	summaries := make([]BlockSummary, 0, limit)
	for i := int64(height) - 1; i >= start; i-- {
		blockBytes, err := qscc.EvaluateTransaction("GetBlockByNumber", DefaultChannel, strconv.FormatInt(i, 10))
		if err != nil {
			continue
		}
		var block commonpb.Block
		if err := proto.Unmarshal(blockBytes, &block); err != nil {
			continue
		}
		summaries = append(summaries, summarizeBlock(&block))
	}

	return summaries, nil
}

// Block summary for UI block overview
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).getRecentBlocks.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func summarizeBlock(block *commonpb.Block) BlockSummary {
	summary := BlockSummary{
		Number:  0,
		TxCount: 0,
		Txs:     []BlockTxSummary{},
	}
	if block == nil || block.Header == nil || block.Data == nil {
		return summary
	}
	summary.Number = block.Header.Number
	if block.Data.Data == nil {
		return summary
	}
	summary.TxCount = len(block.Data.Data)
	for _, envBytes := range block.Data.Data {
		tx := parseTxSummary(envBytes)
		summary.Txs = append(summary.Txs, tx)
	}
	return summary
}

// TX summary for UI and block overview (inside the block function)
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: summarizeBlock.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func parseTxSummary(envBytes []byte) BlockTxSummary {
	out := BlockTxSummary{
		Type:      "UNKNOWN",
		Chaincode: "-",
		Function:  "-",
	}
	var env commonpb.Envelope
	if err := proto.Unmarshal(envBytes, &env); err != nil {
		return out
	}
	var payload commonpb.Payload
	if err := proto.Unmarshal(env.Payload, &payload); err != nil {
		return out
	}
	if payload.Header != nil && payload.Header.ChannelHeader != nil {
		var ch commonpb.ChannelHeader
		if err := proto.Unmarshal(payload.Header.ChannelHeader, &ch); err == nil {
			out.TxID = ch.TxId
			if name, ok := commonpb.HeaderType_name[ch.Type]; ok {
				out.Type = name
			}
			if ch.Type != int32(commonpb.HeaderType_ENDORSER_TRANSACTION) {
				return out
			}
		}
	}

	var tx peerpb.Transaction
	if err := proto.Unmarshal(payload.Data, &tx); err != nil {
		return out
	}
	if len(tx.Actions) == 0 {
		return out
	}
	var action peerpb.TransactionAction
	if err := proto.Unmarshal(tx.Actions[0].Payload, &action); err != nil {
		return out
	}
	var cap peerpb.ChaincodeActionPayload
	if err := proto.Unmarshal(action.Payload, &cap); err != nil {
		return out
	}

	// Try to get chaincode name from the response payload (more reliable)
	if cap.Action != nil && cap.Action.ProposalResponsePayload != nil {
		var prp peerpb.ProposalResponsePayload
		if err := proto.Unmarshal(cap.Action.ProposalResponsePayload, &prp); err == nil {
			var cca peerpb.ChaincodeAction
			if err := proto.Unmarshal(prp.Extension, &cca); err == nil {
				if cca.ChaincodeId != nil && cca.ChaincodeId.Name != "" {
					out.Chaincode = cca.ChaincodeId.Name
				}
			}
		}
	}

	var cpp peerpb.ChaincodeProposalPayload
	if err := proto.Unmarshal(cap.ChaincodeProposalPayload, &cpp); err != nil {
		return out
	}
	var cis peerpb.ChaincodeInvocationSpec
	if err := proto.Unmarshal(cpp.Input, &cis); err != nil {
		return out
	}
	if cis.ChaincodeSpec != nil && cis.ChaincodeSpec.ChaincodeId != nil {
		out.Chaincode = cis.ChaincodeSpec.ChaincodeId.Name
	}
	if cis.ChaincodeSpec != nil && cis.ChaincodeSpec.Input != nil && len(cis.ChaincodeSpec.Input.Args) > 0 {
		out.Function = string(cis.ChaincodeSpec.Input.Args[0])
	}
	return out
}

// is primarily used to actually get the metric data of the blocks for benchmarking
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).handleChaincodeEvent.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) lookupTxLedgerMetadata(blockNumber uint64, txID string) txLedgerMetadata {
	meta := txLedgerMetadata{
		TxIndexInBlock: -1,
	}
	if txID == "" {
		return meta
	}
	qscc := p.network.GetContract("qscc")
	blockBytes, err := qscc.EvaluateTransaction("GetBlockByNumber", DefaultChannel, strconv.FormatUint(blockNumber, 10))
	if err != nil {
		return meta
	}
	meta.BlockBytes = len(blockBytes)
	var block commonpb.Block
	if err := proto.Unmarshal(blockBytes, &block); err != nil {
		return meta
	}
	if block.Data == nil {
		return meta
	}
	meta.BlockTxCount = len(block.Data.Data)
	blockDataBytes := 0
	for _, envBytes := range block.Data.Data {
		blockDataBytes += len(envBytes)
	}
	meta.BlockDataBytes = blockDataBytes
	overhead := meta.BlockBytes - meta.BlockDataBytes
	if overhead < 0 {
		overhead = 0
	}
	meta.BlockOverheadBytes = overhead
	if meta.BlockTxCount > 0 {
		meta.BlockSharedOverheadPerTxByte = float64(meta.BlockOverheadBytes) / float64(meta.BlockTxCount)
	}
	if len(block.Data.Data) == 0 {
		return meta
	}

	filter := []byte(nil)
	if block.Metadata != nil && len(block.Metadata.Metadata) > int(commonpb.BlockMetadataIndex_TRANSACTIONS_FILTER) {
		filter = block.Metadata.Metadata[commonpb.BlockMetadataIndex_TRANSACTIONS_FILTER]
	}

	for idx, envBytes := range block.Data.Data {
		var env commonpb.Envelope
		if err := proto.Unmarshal(envBytes, &env); err != nil {
			continue
		}
		var payload commonpb.Payload
		if err := proto.Unmarshal(env.Payload, &payload); err != nil {
			continue
		}
		if payload.Header == nil || payload.Header.ChannelHeader == nil {
			continue
		}
		var ch commonpb.ChannelHeader
		if err := proto.Unmarshal(payload.Header.ChannelHeader, &ch); err != nil {
			continue
		}
		candidateTxID := strings.TrimSpace(ch.TxId)
		if candidateTxID != txID {
			continue
		}
		meta.TxEnvelopeBytes = len(envBytes)
		meta.TxPayloadBytes = len(env.Payload)
		meta.TxIndexInBlock = idx
		if ch.Timestamp != nil {
			meta.LedgerTxTS = time.Unix(ch.Timestamp.Seconds, int64(ch.Timestamp.Nanos)).UTC().Format(time.RFC3339Nano)
		}
		if idx >= 0 && idx < len(filter) {
			meta.ValidationCode = peerpb.TxValidationCode(filter[idx]).String()
		}
		return meta
	}
	return meta
}

// syncs the own certificate from the chaincode and world state
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: NewTSSPeer, (*TSSPeer).StartPollingLoop, (*TSSPeer).syncOwnedCertificateWithRetry.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) syncOwnedCertificateOnce() bool {
	if p.MemberID == "" {
		return false
	}

	result, err := p.Query("GetCertificate", p.MemberID)
	if err != nil {
		return false
	}

	var cert struct {
		CertID         string `json:"certId"`
		ProposalID     string `json:"proposalId"`
		MemberID       string `json:"memberId"`
		CertificatePEM string `json:"certificatePem"`
	}
	if err := json.Unmarshal(result, &cert); err != nil {
		return false
	}
	if cert.MemberID != "" && cert.MemberID != p.MemberID {
		return false
	}
	if cert.CertificatePEM == "" {
		return false
	}

	certID := cert.ProposalID
	if certID == "" && cert.CertID != "" {
		certID = strings.TrimPrefix(cert.CertID, "CERT:")
	}
	if certID == "" {
		certID = "active-cert"
	}

	certsDir := filepath.Join("certs", p.Organization)
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		log.Printf("[%s] Warning: failed to create certs dir: %v", p.NodeID, err)
		return false
	}
	certPath := filepath.Join(certsDir, certID+".cert.pem")
	certBytes := []byte(cert.CertificatePEM)
	if existing, err := os.ReadFile(certPath); err == nil && bytes.Equal(existing, certBytes) {
		return true
	}
	if err := os.WriteFile(certPath, certBytes, 0644); err != nil {
		log.Printf("[%s] Warning: failed to save certificate: %v", p.NodeID, err)
		return false
	}
	log.Printf("[%s] Certificate synced to %s", p.NodeID, certPath)
	return true
}

// This syncs the own certificate from the chaincode with retries (calls actual function)
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: runtime gateway/metrics helper during transaction and event processing.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) syncOwnedCertificateWithRetry(attempts int, delay time.Duration) {
	if attempts <= 0 {
		return
	}
	for i := 0; i < attempts; i++ {
		if p.syncOwnedCertificateOnce() {
			return
		}
		time.Sleep(delay)
	}
}

type certificateRegisteredEventPayload struct {
	NodeID          string `json:"nodeId"`
	CertificateHash string `json:"certificateHash"`
	Epoch           string `json:"epoch"`
	Action          string `json:"action"`
	ProposalID      string `json:"proposalId"`
}

// This attributes the chaincode events to the markings used in the metrics and plots
var chaincodeEventAliases = map[string]string{
	"CSRSubmitted":              "csr_submitted_observed",
	"CSRVoted":                  "csr_voted_observed",
	"SigningInitiated":          "signing_initiated_observed",
	"ThresholdReached":          "threshold_reached_observed",
	"CertificateRegistered":     "certificate_registered_observed",
	"RevocationProposed":        "revocation_proposed_observed",
	"RevocationVoted":           "revocation_voted_observed",
	"NodeRevoked":               "node_revoked_observed",
	"MemberJoinRequested":       "join_request_submitted_observed",
	"MemberJoinVoted":           "join_request_voted_observed",
	"MemberJoinApproved":        "member_join_approved_observed",
	"MemberRemovalProposed":     "member_removal_proposed_observed",
	"MemberRemovalVoted":        "member_removal_voted_observed",
	"MemberRemoved":             "member_removed_observed",
	"ReshareInitiated":          "reshare_initiated_observed",
	"ReshareCompletionProposed": "reshare_completion_proposed_observed",
	"ReshareCompleted":          "reshare_complete_observed",
	"DKGInitiated":              "dkg_initiated_observed",
	"DKGReady":                  "dkg_ready_observed",
	"DKGCompletionProposed":     "dkg_completion_proposed_observed",
	"DKGCompleted":              "dkg_completed_observed",
}

// This attributes the chaincode events to the operations
var chaincodeEventWorkflowHints = map[string]string{
	"CSRSubmitted":              "csr",
	"CSRVoted":                  "csr",
	"SigningInitiated":          "csr",
	"ThresholdReached":          "csr",
	"CertificateRegistered":     "csr",
	"RevocationProposed":        "revocation",
	"RevocationVoted":           "revocation",
	"NodeRevoked":               "revocation",
	"MemberJoinRequested":       "join",
	"MemberJoinVoted":           "join",
	"MemberJoinApproved":        "join",
	"MemberRemovalProposed":     "removal",
	"MemberRemovalVoted":        "removal",
	"MemberRemoved":             "removal",
	"ReshareInitiated":          "reshare",
	"ReshareCompletionProposed": "reshare",
	"ReshareCompleted":          "reshare",
	"ReshareRequired":           "reshare",
	"DKGInitiated":              "dkg",
	"DKGReady":                  "dkg",
	"DKGCompletionProposed":     "dkg",
	"DKGCompleted":              "dkg",
}

// handle chaincode reades different types, this normalizes to the raw value
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).handleChaincodeEvent, metricPayloadJSON, metricPayloadString.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func metricPayloadValue(payload map[string]interface{}, keys ...string) (interface{}, bool) {
	if payload == nil {
		return nil, false
	}
	for _, key := range keys {
		if v, ok := payload[key]; ok {
			return v, true
		}
	}
	return nil, false
}

// handle chaincode reades different types, this normalizes them into a string
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).handleChaincodeEvent.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func metricPayloadString(payload map[string]interface{}, keys ...string) string {
	v, ok := metricPayloadValue(payload, keys...)
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case fmt.Stringer:
		return strings.TrimSpace(t.String())
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(t, 'f', -1, 64))
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case json.Number:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

// handle chaincode reades different types, this normalizes them into a json string
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).handleChaincodeEvent.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func metricPayloadJSON(payload map[string]interface{}, keys ...string) string {
	v, ok := metricPayloadValue(payload, keys...)
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// function to enable waiting during the event listener polling loop. When the context has been canceled, it closes.
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).StartChaincodeEventListener.
// Triggered: runtime gateway/metrics helper during transaction and event processing.
func (p *TSSPeer) waitOrDone(delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-p.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Starts the listener for the chaincode emitted events, cycles controlled by envvars
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: main.
// Triggered: startup goroutine that subscribes to chaincode event streams.
func (p *TSSPeer) StartChaincodeEventListener() {
	const (
		baseBackoff = 1 * time.Second
		maxBackoff  = 30 * time.Second
	)
	backoff := baseBackoff

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		events, err := p.network.ChaincodeEvents(p.ctx, DefaultContract)
		if err != nil {
			log.Printf("[%s] Chaincode event stream error: %v (retry in %s)", p.NodeID, err, backoff)
			if !p.waitOrDone(backoff) {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("[%s] Chaincode event listener active for %s", p.NodeID, DefaultContract)
		backoff = baseBackoff

		reconnect := false
		for !reconnect {
			select {
			case <-p.ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					reconnect = true
					continue
				}
				p.handleChaincodeEvent(event)
			}
		}
		if !p.waitOrDone(backoff) {
			return
		}
	}
}

// handles a general chaincode event.
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).StartChaincodeEventListener.
// Triggered: event stream callback when chaincode events are delivered.
func (p *TSSPeer) handleChaincodeEvent(event *client.ChaincodeEvent) {
	if event == nil {
		return
	}

	payload := map[string]interface{}{}
	if len(event.Payload) > 0 {
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			log.Printf("[%s] Failed to decode chaincode event %s payload: %v", p.NodeID, event.EventName, err)
			payload = map[string]interface{}{}
		}
	}

	localObservedTS := time.Now().UTC().Format(time.RFC3339Nano)
	ledgerMeta := p.lookupTxLedgerMetadata(event.BlockNumber, event.TransactionID)

	fields := map[string]interface{}{
		"event_name":         event.EventName,
		"tx_id":              event.TransactionID,
		"block_number":       event.BlockNumber,
		"local_observed_ts":  localObservedTS,
		"poll_fallback_mode": p.measurePollFallback,
	}
	if ledgerMeta.LedgerTxTS != "" {
		fields["ledger_tx_ts"] = ledgerMeta.LedgerTxTS
	}
	if ledgerMeta.ValidationCode != "" {
		fields["validation_code"] = ledgerMeta.ValidationCode
	}
	if ledgerMeta.TxEnvelopeBytes > 0 {
		fields["tx_envelope_bytes"] = ledgerMeta.TxEnvelopeBytes
	}
	if ledgerMeta.TxPayloadBytes > 0 {
		fields["tx_payload_bytes"] = ledgerMeta.TxPayloadBytes
	}
	if ledgerMeta.TxIndexInBlock >= 0 {
		fields["tx_index_in_block"] = ledgerMeta.TxIndexInBlock
	}
	if ledgerMeta.BlockBytes > 0 {
		fields["block_bytes"] = ledgerMeta.BlockBytes
	}
	if ledgerMeta.BlockDataBytes > 0 {
		fields["block_data_bytes"] = ledgerMeta.BlockDataBytes
	}
	if ledgerMeta.BlockOverheadBytes > 0 {
		fields["block_overhead_bytes"] = ledgerMeta.BlockOverheadBytes
	}
	if ledgerMeta.BlockTxCount > 0 {
		fields["block_tx_count"] = ledgerMeta.BlockTxCount
		fields["block_shared_overhead_per_tx_bytes"] = ledgerMeta.BlockSharedOverheadPerTxByte
	}

	// This part stores the metric for the benchmark scipts
	if v, ok := metricPayloadValue(payload, "eventVersion"); ok {
		fields["event_version"] = v
	}

	workflow := metricPayloadString(payload, "workflow")
	if workflow == "" {
		workflow = chaincodeEventWorkflowHints[event.EventName]
	}
	if workflow != "" {
		fields["workflow"] = workflow
	}

	if action := metricPayloadString(payload, "action"); action != "" {
		fields["action"] = action
	}
	if proposalID := metricPayloadString(payload, "proposal_id", "proposalId", "proposalID"); proposalID != "" {
		fields["proposal_id"] = proposalID
		fields["operation_id"] = proposalID
	}
	if epoch := metricPayloadString(payload, "epoch"); epoch != "" {
		fields["epoch"] = epoch
		if _, exists := fields["operation_id"]; !exists {
			fields["operation_id"] = epoch
		}
	}

	// Write and delete metrics
	if logicalWrite, ok := metricPayloadValue(payload, "logicalWriteBytesTotal"); ok {
		fields["logical_write_bytes_total"] = logicalWrite
	}
	if logicalDelete, ok := metricPayloadValue(payload, "logicalDeleteBytesTotal"); ok {
		fields["logical_delete_bytes_total"] = logicalDelete
	}
	if logicalByCategory := metricPayloadJSON(payload, "logicalWriteByCategory"); logicalByCategory != "" {
		fields["logical_write_by_category"] = logicalByCategory
	}
	if logicalDeleteByCategory := metricPayloadJSON(payload, "logicalDeleteByCategory"); logicalDeleteByCategory != "" {
		fields["logical_delete_by_category"] = logicalDeleteByCategory
	}

	for _, key := range []string{
		"nodeId", "memberId", "targetMemberId", "candidateId", "submitterId", "voterId",
		"decision", "votesFor", "votesAgainst", "certificateHash", "reason",
	} {
		if v, ok := payload[key]; ok {
			fields[key] = v
		}
	}

	p.emitMetric("cc_event_observed", fields)
	_, hasLogicalWrite := fields["logical_write_bytes_total"]
	_, hasLogicalDelete := fields["logical_delete_bytes_total"]
	if hasLogicalWrite || hasLogicalDelete {
		storageFields := map[string]interface{}{}
		for k, v := range fields {
			storageFields[k] = v
		}
		storageFields["event_name"] = "StorageAttribution"
		p.emitMetric("cc_event_observed", storageFields)
	}
	if alias, ok := chaincodeEventAliases[event.EventName]; ok && alias != "" {
		p.emitMetric(alias, fields)
	}

	switch event.EventName {
	case "CertificateRegistered":
		p.handleCertificateRegisteredEvent(event)
	}
}

// handles certificate registered event from chaincode, certificate registration is a special function as an owner also syncs its cert
// Lifecycle: Gateway transaction execution and chaincode event processing.
// Called by: (*TSSPeer).handleChaincodeEvent.
// Triggered: event stream callback when chaincode events are delivered.
func (p *TSSPeer) handleCertificateRegisteredEvent(event *client.ChaincodeEvent) {
	if event == nil || len(event.Payload) == 0 {
		return
	}

	var payload certificateRegisteredEventPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		log.Printf("[%s] Failed to decode CertificateRegistered event payload: %v", p.NodeID, err)
		return
	}

	memberID := strings.TrimSpace(payload.NodeID)
	if memberID == "" || memberID != p.MemberID {
		return
	}

	log.Printf("[%s] CertificateRegistered event for this member (tx=%s block=%d); syncing owned certificate", p.NodeID, event.TransactionID, event.BlockNumber)
	p.emitMetric("cert_registered_event_observed", map[string]interface{}{
		"member_id": memberID,
		"tx_id":     event.TransactionID,
		"block":     event.BlockNumber,
		"proposal":  payload.ProposalID,
		"cert_hash": payload.CertificateHash,
	})
	go p.syncOwnedCertificateWithRetry(10, 1*time.Second)
}
