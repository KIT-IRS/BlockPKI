// main.go composes process startup, configuration loading, and peer lifecycle wiring for the TSS binary.
// Runtime flow: main() constructs TSSPeer state, starts listeners/pollers/UI workers, and blocks until shutdown.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var irsLogoSVG []byte

// GatewayConfig holds Fabric connection configuration
type GatewayConfig struct {
	MSPID                string
	CryptoPath           string
	OrgDomain            string
	MSPUser              string
	PeerEndpoint         string
	PeerHostname         string
	P2PPort              int
	P2PAdvertise         string // Address registered on-chain for other peers
	WebUIPort            int
	WebUIEnabled         bool
	WebUIBind            string
	WebUIAutostart       bool
	StateDir             string // Directory for persisted data (keyshare, snapshots, private key, etc)
	JoinMode             string // "member", "request" (for membership after start), or "none"
	PollIntervalSeconds  int
	P2PTLSServerCertPath string
	P2PTLSServerKeyPath  string
	P2PTLSClientCertPath string
	P2PTLSClientKeyPath  string
}

// TSSPeer is a node
type TSSPeer struct {
	NodeID       string
	Organization string
	MemberID     string // member ID from Fabric
	joinMode     string
	isMember     bool

	// Fabric Gateway
	gateway  *client.Gateway
	network  *client.Network
	contract *client.Contract
	conn     *grpc.ClientConn

	// TSS State
	TSSPartyID         *tss.PartyID
	TSSKeyShare        *keygen.LocalPartySaveData
	TSSPreParams       *keygen.LocalPreParams // Pre-generated primes for the ecdsa library
	Threshold          int
	keygenInProgress   bool // Track if keygen is running
	keygenEpoch        int  // Current keygen; -1 when idle
	signingInProgress  bool // Track if signing is running
	dkgCompletedLogged bool // Track if already logged DKG completion
	keyShareInvalid    bool
	keyShareInvalidMsg string
	keyShareInvalidLog bool

	// P2P Network
	p2pListener       net.Listener
	p2pPort           int
	p2pAdvertise      string // Reachable address registered on-chain
	webuiPort         int    // Web UI port
	webuiEnabled      bool
	webuiBind         string
	webuiAutostart    bool
	interactiveMenu   bool
	pollInterval      time.Duration
	heavyPollEvery    int
	certFullScanEvery int
	stateDir          string            // Directory for persisted data (keyshare, snapshots, private key, etc)
	peerAddrs         map[string]string // nodeID is address
	tssMessages       chan *TSSMessage  // keygen messages
	reshareMessages   chan *TSSMessage  // reshare messages
	signingMessages   chan *TSSMessage  // signing messages (separate channel)
	keygenDone        chan struct{}     // closed when keygen handler exits
	p2pStats          *P2PMessageStats

	// Metrics for the benchmarking scripts
	metricsFile    *os.File
	metricsEnabled bool
	metricsMu      sync.Mutex

	// Web UI log buffer (only active when Web UI is running)
	webuiLog         *webUILogBuffer
	logDefaultWriter io.Writer

	// Completed signing proposals
	completedProposals map[string]bool

	// Completed keygen epochs
	completedEpochs map[int]bool

	// Observed on-chain completions for the benchmarking scripts
	observedCerts             map[string]bool
	observedCSRSubmits        map[string]bool
	observedJoinSubmits       map[string]bool
	observedRemovalSubmits    map[string]bool
	observedRevocationSubmits map[string]bool
	observedRevocations       map[string]bool
	observedJoinApprovals     map[string]bool
	observedRemovals          map[string]bool
	observedReshares          map[int]bool
	missingShareReshares      map[int]bool
	lastReshareResumeAttempt  map[int]time.Time
	lastAutoReshareEpoch      int
	lastAutoReshareAt         time.Time
	lastAutoFreshDKGEpoch     int
	lastAutoFreshDKGAt        time.Time
	autoVoteSkipped           map[string]bool
	recoveryStatus            string
	autoFreshDKGEnabled       bool
	autoFreshDKGCooldown      time.Duration
	autoRestoreSnapshot       bool
	snapshotRetention         int
	snapshotKey               []byte
	autoVoteJitterMax         time.Duration
	executeMaxAttempts        int
	executeBackoffBase        time.Duration
	executeBackoffMax         time.Duration
	executeBackoffJitterPct   int
	measurePollFallback       bool
	stuckSessionTimeout       time.Duration
	sessionProgress           map[string]keySessionProgress

	// Pending proposals for observation mapping
	pendingRevocations  map[string]string // proposalID -> targetNodeID
	pendingJoinRequests map[string]string // proposalID -> candidateID
	pendingRemovals     map[string]string // proposalID -> targetMemberID

	// CSR generated private keys stored by proposalID until certificate is registered
	csrPrivateKeys map[string]*ecdsa.PrivateKey

	// Index mapping for TSS
	partyIndexMap map[int]string // partyIndex -> nodeID

	// TSS Party IDs (cached for signing)
	cachedPartyIDs tss.SortedPartyIDs
	cachedMembers  []string // Sorted member IDs used for the current key share
	myPartyIndex   int

	// Context for the signing lib
	ctx         context.Context
	cancel      context.CancelFunc
	mutex       sync.RWMutex
	preParamsMu sync.Mutex
	wg          sync.WaitGroup

	// P2P TLS
	p2pTLSConfig        *tls.Config
	p2pServerTLSCert    tls.Certificate
	p2pClientTLSCert    tls.Certificate
	p2pHandshakeSigner  crypto.Signer
	p2pHandshakeCertPEM []byte

	// P2P identity for handshake authentication from the msps
	mspSigner    crypto.Signer
	mspCertPEM   []byte
	trustedRoots *x509.CertPool

	//  Web UI
	webServer *http.Server

	// Merkle config (from envvar)
	merkleConfigSet     bool
	merkleConfigEnabled bool
}

// TSSMessage is a TSS protocol message
type TSSMessage struct {
	From          string `json:"from"`
	To            string `json:"to"`        // Target node ID or "" for broadcast
	ToIndex       int    `json:"toIndex"`   // Target party index (-1 for broadcast)
	FromIndex     int    `json:"fromIndex"` // Sender party index
	FromCommittee string `json:"fromCommittee,omitempty"`
	ToCommittee   string `json:"toCommittee,omitempty"`
	SessionID     string `json:"sessionId"`
	MsgType       string `json:"msgType"` // "keygen", "reshare", or "signing"
	Payload       []byte `json:"payload"`
	IsBroadcast   bool   `json:"isBroadcast"`
	Round         int    `json:"round"`
}

// This is the same as the chaincode and hardcoded, this could maybe be synrchronized in a single place in the future
const (
	DefaultCAID     = "root-ca-001"
	DefaultChannel  = "mychannel"
	DefaultContract = "bpki"
	maxBlocksToShow = 20
)

// starts the TSS peer process and coordinates startup and shutdown.
// Lifecycle: Process startup and peer runtime composition.
// Called by: entrypoint.
// Triggered: startup process entrypoint when the peer binary is launched.
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <org-id>")
		fmt.Println("  Example org IDs: irs1, irs2, irs3")
		fmt.Println("  Configure via environment variables (see tss-<org>.env) or use built-in defaults.")
		os.Exit(1)
	}

	org := strings.TrimSpace(os.Args[1])
	if org == "" {
		fmt.Println("Organization argument cannot be empty")
		os.Exit(1)
	}

	fmt.Printf("=== Starting TSS Peer for %s ===\n", org)

	// Print configuration
	config := getConfig(org)
	fmt.Printf("  MSPID:          %s\n", config.MSPID)
	fmt.Printf("  CryptoPath:     %s\n", config.CryptoPath)
	fmt.Printf("  MSP User:       %s\n", config.MSPUser)
	fmt.Printf("  PeerEndpoint:   %s\n", config.PeerEndpoint)
	fmt.Printf("  PeerHostname:   %s\n", config.PeerHostname)
	fmt.Printf("  P2P Listen:     0.0.0.0:%d\n", config.P2PPort)
	fmt.Printf("  P2P Advertise:  %s\n", config.P2PAdvertise)
	fmt.Printf("  WebUI Port:     %d\n", config.WebUIPort)
	fmt.Printf("  WebUI Enabled:  %v\n", config.WebUIEnabled)
	fmt.Printf("  WebUI Bind:     %s\n", config.WebUIBind)
	fmt.Printf("  WebUI Auto:     %v\n", config.WebUIAutostart)
	fmt.Printf("  Poll Interval:  %ds\n", config.PollIntervalSeconds)
	fmt.Printf("  Join Mode:      %s\n", config.JoinMode)
	fmt.Printf("  P2P TLS Server: %s\n", config.P2PTLSServerCertPath)
	fmt.Printf("  P2P TLS Client: %s\n", config.P2PTLSClientCertPath)
	if v, set, err := envBool("TSS_INTERACTIVE_MENU"); err == nil && set {
		fmt.Printf("  Interactive:    %v (env)\n", v)
	}
	if os.Getenv("TSS_MSPID") != "" {
		fmt.Println("  Config source:  environment variables")
	} else {
		fmt.Println("  Config source:  built-in defaults")
	}

	// Register P256 curve with tss-lib (needed for JSON serialization of EC points)
	tss.RegisterCurve("P-256", elliptic.P256())
	// Ensure tss-lib global curve matches P-256 usage (needed for gob decode of ECPoint)
	tss.SetCurve(elliptic.P256())

	// Create the peer instance
	peer, err := NewTSSPeer(org)
	if err != nil {
		log.Fatalf("Failed to create peer: %v", err)
	}
	defer peer.Close()

	// Create P2P listener
	if err := peer.StartP2P(); err != nil {
		log.Fatalf("Failed to start P2P: %v", err)
	}

	// Register P2P address on blockchain -> Debugging: If this prints with something like "policy check failed" there is an issue with the cryptographic material probably from different generation runs, rerun generation
	// If something like "chaincode not installed on sufficient peers" this may be due to a wrong chaincode installation (maybe just a commit with a wrong chaincode name or package id)
	if err := peer.RegisterPeerAddress(); err != nil {
		log.Printf("Failed to register peer address: %v", err)
	}

	// Gets the ca
	fmt.Println("\n--- Testing GetDistributedCA ---")
	ca, err := peer.GetCA()
	if err != nil {
		log.Printf("GetCA failed: %v", err)
	} else {
		caJSON, _ := json.MarshalIndent(ca, "", "  ")
		fmt.Printf("CA State:\n%s\n", caJSON)
	}

	// Check if the CA is initialized
	fmt.Println("\n--- Ensuring CA Initialized ---")
	if err := peer.EnsureCAInitialized(); err != nil {
		log.Printf("EnsureCAInitialized failed: %v", err)
	}
	peer.applyMerkleConfigFromEnv()

	// Start polling loop
	fmt.Println("\n--- Starting Event Polling Loop ---")
	go peer.StartPollingLoop()
	go peer.StartChaincodeEventListener()

	// Optionally start Web UI immediately for headless mode.
	if peer.webuiAutostart {
		if peer.webuiEnabled {
			log.Printf("[%s] Web UI autostart enabled; starting Web UI...", peer.NodeID)
			peer.toggleWebUI()
		} else {
			log.Printf("[%s] Web UI autostart requested but Web UI is disabled (set TSS_WEBUI_ENABLED=true)", peer.NodeID)
		}
	}

	// Start interactive menu, disable when headless
	if peer.interactiveMenu {
		go peer.StartInteractiveMenu()
	} else {
		log.Printf("[%s] Interactive menu disabled (headless mode)", peer.NodeID)
	}

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down...")
}

// constructs a fully initialized TSS peer runtime.
// Lifecycle: Process startup and peer runtime composition.
// Called by: main.
// Triggered: startup bootstrap during peer construction.
func NewTSSPeer(org string) (*TSSPeer, error) {
	config := getConfig(org)

	// Load certificate
	certDir := filepath.Join(config.CryptoPath, "users", config.MSPUser, "msp", "signcerts")
	certPEM, err := findFirstPEMFile(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	certificate, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyDir := filepath.Join(config.CryptoPath, "users", config.MSPUser, "msp", "keystore")
	keyPEM, err := findFirstFile(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	// Create identity and signer
	id, err := identity.NewX509Identity(config.MSPID, certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Load TLS certificate
	tlsCertPath := filepath.Join(config.CryptoPath, "peers", config.PeerHostname, "tls", "ca.crt")
	tlsCertPEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(tlsCertPEM) {
		return nil, fmt.Errorf("failed to add TLS certificate to pool")
	}

	transportCredentials := credentials.NewClientTLSFromCert(certPool, config.PeerHostname)

	// Create gRPC connection
	grpcConn, err := grpc.NewClient(config.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	// Create Gateway connection
	gw, err := client.Connect(id, client.WithSign(sign), client.WithClientConnection(grpcConn),
		client.WithEvaluateTimeout(30*time.Second),
		client.WithEndorseTimeout(60*time.Second),
		client.WithSubmitTimeout(30*time.Second),
		client.WithCommitStatusTimeout(2*time.Minute))
	if err != nil {
		grpcConn.Close()
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}

	network := gw.GetNetwork(DefaultChannel)
	contract := network.GetContract(DefaultContract)

	memberIDFromCert := canonicalIDFromCert(certificate)
	derivedNodeID := shortNodeIDFromCanonical(memberIDFromCert)
	nodeID := strings.TrimSpace(os.Getenv("TSS_NODE_ID"))
	if nodeID == "" {
		nodeID = derivedNodeID
	}
	if nodeID == "" {
		nodeID = fmt.Sprintf("%s-peer", org)
	}
	if derivedNodeID != "" && nodeID != derivedNodeID {
		log.Printf("[startup] Warning: TSS_NODE_ID=%s does not match identity-derived ID %s; P2P routing may fail", nodeID, derivedNodeID)
	}

	p2pServerTLSCert, p2pClientTLSCert, p2pHandshakeSigner, p2pHandshakeCertPEM, err := loadP2PMTLSMaterial(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load P2P mTLS material: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Configurations for polling and voting intervalls
	// TSS signing operations depend on all active peers to be in the same session, jitter and backoff are integrated due to MVCC invalidated transacrions (refer to the master thesis for explanation)

	pollInterval := time.Duration(config.PollIntervalSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	heavyPollEvery := 2
	if raw := strings.TrimSpace(envOrDefault("TSS_HEAVY_POLL_EVERY", "2")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			heavyPollEvery = v
		}
	}
	certFullScanEvery := 6
	if raw := strings.TrimSpace(envOrDefault("TSS_CERT_FULL_SCAN_EVERY", "6")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			certFullScanEvery = v
		}
	}
	autoVoteJitterMs := 300
	if raw := strings.TrimSpace(envOrDefault("TSS_AUTOVOTE_JITTER_MS", "300")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			autoVoteJitterMs = v
		}
	}

	executeMaxAttempts := 8
	if raw := strings.TrimSpace(envOrDefault("TSS_EXECUTE_MAX_ATTEMPTS", "8")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			executeMaxAttempts = v
		}
	}
	executeBackoffBaseMs := 250
	if raw := strings.TrimSpace(envOrDefault("TSS_EXECUTE_BACKOFF_BASE_MS", "250")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			executeBackoffBaseMs = v
		}
	}
	executeBackoffMaxMs := 4000
	if raw := strings.TrimSpace(envOrDefault("TSS_EXECUTE_BACKOFF_MAX_MS", "4000")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			executeBackoffMaxMs = v
		}
	}
	if executeBackoffMaxMs < executeBackoffBaseMs {
		executeBackoffMaxMs = executeBackoffBaseMs
	}
	executeBackoffJitterPct := 20
	if raw := strings.TrimSpace(envOrDefault("TSS_EXECUTE_BACKOFF_JITTER_PCT", "20")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			executeBackoffJitterPct = v
		}
	}

	// Snapshots of the keys were integrated as sometimes the keys werent loaded properly
	snapshotRetention := 30
	if raw := strings.TrimSpace(envOrDefault("TSS_KEYSHARE_SNAPSHOT_RETENTION", "30")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			snapshotRetention = v
		}
	}
	autoFreshDKGEnabled := true
	if v, set, err := envBool("TSS_AUTO_FRESH_DKG_ENABLED"); err == nil && set {
		autoFreshDKGEnabled = v
	}
	autoFreshDKGCooldownSeconds := 300
	if raw := strings.TrimSpace(envOrDefault("TSS_AUTO_FRESH_DKG_COOLDOWN_SECONDS", "300")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			autoFreshDKGCooldownSeconds = v
		}
	}
	autoRestoreSnapshot := true
	if v, set, err := envBool("TSS_AUTO_RESTORE_SNAPSHOT_ENABLED"); err == nil && set {
		autoRestoreSnapshot = v
	}
	measurePollFallback := true
	if v, set, err := envBool("TSS_MEASURE_POLL_FALLBACK"); err != nil {
		log.Printf("[%s] Invalid TSS_MEASURE_POLL_FALLBACK: %v", nodeID, err)
	} else if set {
		measurePollFallback = v
	}

	// If the session appears to be stuck it may be due to a mismatch of membersets -> if enabled forces a fresh reshare. Maybe change the time for the number of signers to not falsely override session

	stuckSessionTimeoutSeconds := 300
	if raw := strings.TrimSpace(envOrDefault("TSS_STUCK_SESSION_TIMEOUT_SECONDS", "180")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			stuckSessionTimeoutSeconds = v
		}
	}

	interactiveMenu := true
	if v, set, err := envBool("TSS_INTERACTIVE_MENU"); err != nil {
		log.Printf("[%s] Invalid TSS_INTERACTIVE_MENU: %v", nodeID, err)
	} else if set {
		interactiveMenu = v
	} else {
		// Default to headless mode when stdin is not a character device.
		if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
			interactiveMenu = false
		}
	}

	// Snapshots
	var snapshotKey []byte
	snapshotKeyB64 := strings.TrimSpace(os.Getenv("TSS_KEYSHARE_SNAPSHOT_KEY_B64"))
	if snapshotKeyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(snapshotKeyB64)
		if err != nil {
			log.Printf("[%s] Invalid TSS_KEYSHARE_SNAPSHOT_KEY_B64 (base64 decode failed): %v", nodeID, err)
		} else if len(decoded) != 32 {
			log.Printf("[%s] Invalid TSS_KEYSHARE_SNAPSHOT_KEY_B64 length: got %d bytes, need 32", nodeID, len(decoded))
		} else {
			snapshotKey = decoded
		}
	}
	if autoRestoreSnapshot && len(snapshotKey) == 0 {
		log.Printf("[%s] Snapshot auto-restore disabled: set TSS_KEYSHARE_SNAPSHOT_KEY_B64 (32-byte base64 AES key) to enable encrypted key-share snapshots", nodeID)
		autoRestoreSnapshot = false
	}

	// Actual creation of the instance
	peer := &TSSPeer{
		NodeID:                    nodeID,
		Organization:              org,
		joinMode:                  config.JoinMode,
		gateway:                   gw,
		network:                   network,
		contract:                  contract,
		conn:                      grpcConn,
		ctx:                       ctx,
		cancel:                    cancel,
		p2pPort:                   config.P2PPort,
		p2pAdvertise:              config.P2PAdvertise,
		webuiPort:                 config.WebUIPort,
		webuiEnabled:              config.WebUIEnabled,
		webuiBind:                 config.WebUIBind,
		webuiAutostart:            config.WebUIAutostart,
		interactiveMenu:           interactiveMenu,
		logDefaultWriter:          log.Writer(),
		pollInterval:              pollInterval,
		heavyPollEvery:            heavyPollEvery,
		certFullScanEvery:         certFullScanEvery,
		stateDir:                  config.StateDir,
		p2pServerTLSCert:          p2pServerTLSCert,
		p2pClientTLSCert:          p2pClientTLSCert,
		p2pHandshakeSigner:        p2pHandshakeSigner,
		p2pHandshakeCertPEM:       p2pHandshakeCertPEM,
		mspSigner:                 signer,
		mspCertPEM:                certPEM,
		peerAddrs:                 make(map[string]string),
		tssMessages:               make(chan *TSSMessage, 100),
		reshareMessages:           make(chan *TSSMessage, 100),
		signingMessages:           make(chan *TSSMessage, 100),
		keygenDone:                make(chan struct{}),
		p2pStats:                  newP2PMessageStats(),
		completedProposals:        make(map[string]bool),
		completedEpochs:           make(map[int]bool),
		observedCerts:             make(map[string]bool),
		observedCSRSubmits:        make(map[string]bool),
		observedJoinSubmits:       make(map[string]bool),
		observedRemovalSubmits:    make(map[string]bool),
		observedRevocationSubmits: make(map[string]bool),
		observedRevocations:       make(map[string]bool),
		observedJoinApprovals:     make(map[string]bool),
		observedRemovals:          make(map[string]bool),
		observedReshares:          make(map[int]bool),
		missingShareReshares:      make(map[int]bool),
		lastReshareResumeAttempt:  make(map[int]time.Time),
		lastAutoReshareEpoch:      -1,
		lastAutoFreshDKGEpoch:     -1,
		autoVoteSkipped:           make(map[string]bool),
		pendingRevocations:        make(map[string]string),
		pendingJoinRequests:       make(map[string]string),
		pendingRemovals:           make(map[string]string),
		csrPrivateKeys:            make(map[string]*ecdsa.PrivateKey),
		partyIndexMap:             make(map[int]string),
		Threshold:                 1,  // updated from CA on-chain
		keygenEpoch:               -1, // -1 is no keygen running
		autoFreshDKGEnabled:       autoFreshDKGEnabled,
		autoFreshDKGCooldown:      time.Duration(autoFreshDKGCooldownSeconds) * time.Second,
		autoRestoreSnapshot:       autoRestoreSnapshot,
		snapshotRetention:         snapshotRetention,
		snapshotKey:               snapshotKey,
		autoVoteJitterMax:         time.Duration(autoVoteJitterMs) * time.Millisecond,
		executeMaxAttempts:        executeMaxAttempts,
		executeBackoffBase:        time.Duration(executeBackoffBaseMs) * time.Millisecond,
		executeBackoffMax:         time.Duration(executeBackoffMaxMs) * time.Millisecond,
		executeBackoffJitterPct:   executeBackoffJitterPct,
		measurePollFallback:       measurePollFallback,
		stuckSessionTimeout:       time.Duration(stuckSessionTimeoutSeconds) * time.Second,
		sessionProgress:           make(map[string]keySessionProgress),
	}

	// keygenDone is in the keygen handler lifecycle
	close(peer.keygenDone)

	peerOrgsDir := filepath.Clean(filepath.Dir(config.CryptoPath))
	if roots, err := loadTrustedRoots(peerOrgsDir); err != nil {
		return nil, fmt.Errorf("failed to load MSP roots for P2P auth: %w", err)
	} else {
		peer.trustedRoots = roots
	}

	log.Printf("[%s] Connected to Fabric via Gateway API", nodeID)

	// Get member ID from chaincode (the fabric ID)
	memberID, err := peer.WhoAmI()
	if err != nil {
		log.Printf("[%s] Warning: couldn't get member ID: %v", nodeID, err)
	} else {
		peer.MemberID = memberID
		displayID := memberID
		if len(displayID) > 60 {
			displayID = displayID[:60] + "..."
		}
		log.Printf("[%s] Member ID: %s", nodeID, displayID)
	}

	resetState, resetSet, resetErr := envBool("TSS_RESET_STATE")
	if resetErr != nil {
		log.Printf("[%s] Invalid TSS_RESET_STATE: %v", nodeID, resetErr)
	}
	peer.resetLocalStateOnce(resetSet, resetState)
	stateDirForLog := peer.stateDir
	if stateDirForLog == "" {
		stateDirForLog = filepath.Join("state", peer.Organization)
	}
	if absStateDir, err := filepath.Abs(stateDirForLog); err == nil {
		log.Printf("[%s] Local state dir: %s", nodeID, absStateDir)
		log.Printf("[%s] Expected key share path: %s", nodeID, filepath.Join(absStateDir, fmt.Sprintf("keyshare_%s.gob", nodeID)))
	} else {
		log.Printf("[%s] Local state dir: %s", nodeID, stateDirForLog)
		log.Printf("[%s] Expected key share path: %s", nodeID, peer.keySharePath())
	}

	// Load key share if present
	if err := peer.LoadKeyShare(); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to load key share: %v", nodeID, err)
		}
	} else {
		peer.dkgCompletedLogged = true
	}

	peer.initMetrics()

	// If a certificate for this member is already present on-chain sync it locally.
	_ = peer.syncOwnedCertificateOnce()

	// Load persisted pre-params if present
	if err := peer.LoadPreParams(); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to load pre-params: %v", nodeID, err)
		}
	}
	if peer.TSSPreParams == nil {
		log.Printf("[%s] No pre-params on disk; will generate lazily on first TSS keygen/reshare", nodeID)
	}
	log.Printf("[%s] Execute retry config: attempts=%d base=%s max=%s jitter=%d%%",
		nodeID, peer.executeMaxAttempts, peer.executeBackoffBase, peer.executeBackoffMax, peer.executeBackoffJitterPct)
	log.Printf("[%s] Poll profile: heavyEvery=%d certFullScanEvery=%d autoVoteJitter=%s",
		nodeID, peer.heavyPollEvery, peer.certFullScanEvery, peer.autoVoteJitterMax)
	log.Printf("[%s] Measurement mode: event-first with poll fallback=%v", nodeID, peer.measurePollFallback)
	log.Printf("[%s] Recovery mode: stuck-session-timeout=%s auto-fresh-dkg=%v cooldown=%s",
		nodeID, peer.stuckSessionTimeout, peer.autoFreshDKGEnabled, peer.autoFreshDKGCooldown)
	log.Printf("[%s] Interactive menu: %v", nodeID, peer.interactiveMenu)
	log.Printf("[%s] Web UI autostart: %v", nodeID, peer.webuiAutostart)

	return peer, nil
}

// releases runtime resources and terminates active services.
// Lifecycle: Process shutdown and resource teardown.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: shutdown path after SIGINT/SIGTERM or deferred cleanup.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) Close() {
	p.cancel()
	p.mutex.RLock()
	hasKeyShare := p.TSSKeyShare != nil
	p.mutex.RUnlock()
	if hasKeyShare {
		if err := p.SaveKeyShare(); err != nil {
			log.Printf("[%s] Warning: failed to persist key share on shutdown: %v", p.NodeID, err)
		}
	}
	if p.p2pListener != nil {
		p.p2pListener.Close()
	}
	if p.gateway != nil {
		p.gateway.Close()
	}
	if p.conn != nil {
		p.conn.Close()
	}
	if p.metricsFile != nil {
		p.metricsMu.Lock()
		p.metricsFile.Close()
		p.metricsMu.Unlock()
	}
	p.wg.Wait()
}

// ===================== HELPERS =====================

// builds the runtime configuration for an org from env overrides and defaults.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: NewTSSPeer, main.
// Triggered: startup/runtime helper during process composition.
func getConfig(org string) *GatewayConfig {
	// Environment variables override everything (set by tss-<org>.env)
	// This allows the SAME binary to run on any host for any org.
	if envMSPID := os.Getenv("TSS_MSPID"); envMSPID != "" {
		p2pPort := envOrDefault("TSS_P2P_PORT", "6001")
		p2pPortInt := 6001
		fmt.Sscanf(p2pPort, "%d", &p2pPortInt)

		webuiPort := envOrDefault("TSS_WEBUI_PORT", "8080")
		webuiPortInt := 8080
		fmt.Sscanf(webuiPort, "%d", &webuiPortInt)
		webuiEnabled := false
		if v, set, err := envBool("TSS_WEBUI_ENABLED"); err == nil && set {
			webuiEnabled = v
		}
		webuiAutostart := false
		if v, set, err := envBool("TSS_WEBUI_AUTOSTART"); err == nil && set {
			webuiAutostart = v
		}
		webuiBind := envOrDefault("TSS_WEBUI_BIND", "127.0.0.1")
		pollIntervalSeconds := 10
		if raw := envOrDefault("TSS_POLL_INTERVAL_SECONDS", "10"); raw != "" {
			if _, err := fmt.Sscanf(raw, "%d", &pollIntervalSeconds); err != nil || pollIntervalSeconds < 1 {
				pollIntervalSeconds = 10
			}
		}
		orgDomain := envOrDefault("TSS_DOMAIN", org+".kit.edu")
		stateDir := envOrDefault("TSS_STATE_DIR", filepath.Join("state", org))
		joinMode := normalizeJoinMode(envOrDefault("TSS_JOIN_MODE", "none"))
		mspUser := envOrDefault("TSS_MSP_USER", envOrDefault("TSS_USER", fmt.Sprintf("Member1@%s", orgDomain)))

		return applyP2PTLSPathDefaults(&GatewayConfig{
			MSPID:               envMSPID,
			CryptoPath:          os.Getenv("TSS_CRYPTO_PATH"),
			OrgDomain:           orgDomain,
			MSPUser:             mspUser,
			PeerEndpoint:        envOrDefault("TSS_PEER_ENDPOINT", "localhost:7051"),
			PeerHostname:        envOrDefault("TSS_PEER_HOSTNAME", "peer0."+org+".kit.edu"),
			P2PPort:             p2pPortInt,
			P2PAdvertise:        envOrDefault("TSS_P2P_ADVERTISE", fmt.Sprintf("localhost:%d", p2pPortInt)),
			WebUIPort:           webuiPortInt,
			WebUIEnabled:        webuiEnabled,
			WebUIBind:           webuiBind,
			WebUIAutostart:      webuiAutostart,
			StateDir:            stateDir,
			JoinMode:            joinMode,
			PollIntervalSeconds: pollIntervalSeconds,
		})
	}

	// Built-in defaults for local development.
	orgNum := extractTrailingNumber(org)
	if orgNum == "" {
		orgNum = "1"
	}
	n := 1
	fmt.Sscanf(orgNum, "%d", &n)
	if n < 1 {
		n = 1
	}
	baseDomain := fmt.Sprintf("%s.kit.edu", org)
	defaultPeerPort := 7051 + 2000*(n-1)
	defaultP2PPort := 6000 + n
	defaultWebUIPort := 8079 + n
	defaultMSPID := fmt.Sprintf("%sMSP", strings.ToUpper(org))

	switch org {
	case "irs2":
		return applyP2PTLSPathDefaults(&GatewayConfig{
			MSPID:               "IRS2MSP",
			CryptoPath:          findCryptoPath("irs2.kit.edu"),
			OrgDomain:           "irs2.kit.edu",
			MSPUser:             "Member1@irs2.kit.edu",
			PeerEndpoint:        "localhost:9051",
			PeerHostname:        "peer0.irs2.kit.edu",
			P2PPort:             6002,
			P2PAdvertise:        "localhost:6002",
			WebUIPort:           8081,
			WebUIEnabled:        false,
			WebUIBind:           "127.0.0.1",
			WebUIAutostart:      false,
			StateDir:            filepath.Join("state", org),
			JoinMode:            "none",
			PollIntervalSeconds: 10,
		})
	case "irs1":
		return applyP2PTLSPathDefaults(&GatewayConfig{
			MSPID:               "IRS1MSP",
			CryptoPath:          findCryptoPath("irs1.kit.edu"),
			OrgDomain:           "irs1.kit.edu",
			MSPUser:             "Member1@irs1.kit.edu",
			PeerEndpoint:        "localhost:7051",
			PeerHostname:        "peer0.irs1.kit.edu",
			P2PPort:             6001,
			P2PAdvertise:        "localhost:6001",
			WebUIPort:           8080,
			WebUIEnabled:        false,
			WebUIBind:           "127.0.0.1",
			WebUIAutostart:      false,
			StateDir:            filepath.Join("state", org),
			JoinMode:            "none",
			PollIntervalSeconds: 10,
		})
	default:
		return applyP2PTLSPathDefaults(&GatewayConfig{
			MSPID:               defaultMSPID,
			CryptoPath:          findCryptoPath(baseDomain),
			OrgDomain:           baseDomain,
			MSPUser:             fmt.Sprintf("Member1@%s", baseDomain),
			PeerEndpoint:        fmt.Sprintf("localhost:%d", defaultPeerPort),
			PeerHostname:        fmt.Sprintf("peer0.%s", baseDomain),
			P2PPort:             defaultP2PPort,
			P2PAdvertise:        fmt.Sprintf("localhost:%d", defaultP2PPort),
			WebUIPort:           defaultWebUIPort,
			WebUIEnabled:        false,
			WebUIBind:           "127.0.0.1",
			WebUIAutostart:      false,
			StateDir:            filepath.Join("state", org),
			JoinMode:            "none",
			PollIntervalSeconds: 10,
		})
	}
}

// applies default/override paths for P2P mTLS certificates and keys.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: getConfig.
// Triggered: startup/runtime helper during process composition.
func applyP2PTLSPathDefaults(cfg *GatewayConfig) *GatewayConfig {
	if cfg == nil {
		return nil
	}
	serverTLSDir := filepath.Join(cfg.CryptoPath, "peers", cfg.PeerHostname, "tls")
	clientTLSDir := filepath.Join(cfg.CryptoPath, "users", cfg.MSPUser, "tls")
	clientMSPDir := filepath.Join(cfg.CryptoPath, "users", cfg.MSPUser, "msp")
	serverCertDefault := filepath.Join(serverTLSDir, "server.crt")
	serverKeyDefault := filepath.Join(serverTLSDir, "server.key")
	userClientCertDefault := filepath.Join(clientTLSDir, "client.crt")
	userClientKeyDefault := filepath.Join(clientTLSDir, "client.key")
	userMSPSignCertDefault := filepath.Join(clientMSPDir, "signcerts", fmt.Sprintf("%s-cert.pem", cfg.MSPUser))
	userMSPSignCertFallback := firstFilePathInDir(filepath.Join(clientMSPDir, "signcerts"))
	userMSPKeyDefault := filepath.Join(clientMSPDir, "keystore", "priv_sk")
	userMSPKeyFallback := firstFilePathInDir(filepath.Join(clientMSPDir, "keystore"))
	// Prefer per-member identities for outbound mTLS so each process can run as a
	// distinct member on the same peer host. Keep peer TLS server cert as legacy
	// fallback for older bundles.
	peerClientCertFallback := serverCertDefault
	peerClientKeyFallback := serverKeyDefault

	cfg.P2PTLSServerCertPath = strings.TrimSpace(envOrDefault("TSS_P2P_TLS_SERVER_CERT_PATH", serverCertDefault))
	cfg.P2PTLSServerKeyPath = strings.TrimSpace(envOrDefault("TSS_P2P_TLS_SERVER_KEY_PATH", serverKeyDefault))

	cfg.P2PTLSClientCertPath = strings.TrimSpace(os.Getenv("TSS_P2P_TLS_CLIENT_CERT_PATH"))
	if cfg.P2PTLSClientCertPath == "" {
		cfg.P2PTLSClientCertPath = firstExistingPath(
			userClientCertDefault,
			userMSPSignCertDefault,
			userMSPSignCertFallback,
			peerClientCertFallback,
		)
	}
	cfg.P2PTLSClientKeyPath = strings.TrimSpace(os.Getenv("TSS_P2P_TLS_CLIENT_KEY_PATH"))
	if cfg.P2PTLSClientKeyPath == "" {
		cfg.P2PTLSClientKeyPath = firstExistingPath(
			userClientKeyDefault,
			userMSPKeyDefault,
			userMSPKeyFallback,
			peerClientKeyFallback,
		)
	}
	return cfg
}

// returns the first existing path from candidates, or the first non-empty candidate if none exist.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: applyP2PTLSPathDefaults.
// Triggered: startup/runtime helper during process composition.
func firstExistingPath(candidates ...string) string {
	firstNonEmpty := ""
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if firstNonEmpty == "" {
			firstNonEmpty = candidate
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return firstNonEmpty
}

// returns the first existing file path in a directory.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: applyP2PTLSPathDefaults.
// Triggered: startup/runtime helper during process composition.
func firstFilePathInDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		return filepath.Join(dir, entry.Name())
	}
	return ""
}

// extracts trailing digits from an input string.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: getConfig.
// Triggered: startup/runtime helper during process composition.
func extractTrailingNumber(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	i := len(input) - 1
	for i >= 0 {
		if input[i] < '0' || input[i] > '9' {
			break
		}
		i--
	}
	if i == len(input)-1 {
		return ""
	}
	return input[i+1:]
}

// returns an environment value or a fallback when unset/blank.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: (*TSSPeer).initMetrics, NewTSSPeer, getConfig.
// Triggered: startup/runtime helper during process composition.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parses an optional environment boolean and reports whether it was explicitly set.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: NewTSSPeer, getConfig, main.
// Triggered: startup/runtime helper during process composition.
func envBool(key string) (bool, bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false, false, nil
	}
	val, err := strconv.ParseBool(raw)
	if err != nil {
		return false, true, err
	}
	return val, true, nil
}

// normalizes configured join-mode values to supported runtime modes.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: (*TSSPeer).EnsureCAInitialized, getConfig.
// Triggered: startup/runtime helper during process composition.
func normalizeJoinMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "member", "full", "ca":
		return "member"
	case "request", "apply":
		return "request"
	case "none", "skip", "disabled", "no":
		return "none"
	default:
		return "none"
	}
}

// resolves the organization crypto-material base path from known deployment layouts.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: getConfig.
// Triggered: startup/runtime helper during process composition.
func findCryptoPath(domain string) string {
	// Check relative to current working directory first (deployment bundle)
	candidates := []string{
		filepath.Join("organizations", "peerOrganizations", domain),
		filepath.Join("..", "organizations", "peerOrganizations", domain),
		filepath.Join("..", "..", "test-network", "organizations", "peerOrganizations", domain),
		filepath.Join("..", "..", "..", "test-network", "organizations", "peerOrganizations", domain),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	// Fallback: original hardcoded path for dev
	return filepath.Join("D:", "fabric", "fabric-samples", "test-network", "organizations", "peerOrganizations", domain)
}

// reads the first PEM file found in a directory.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: NewTSSPeer.
// Triggered: startup/runtime helper during process composition.
func findFirstPEMFile(dir string) ([]byte, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".pem" {
			return os.ReadFile(filepath.Join(dir, f.Name()))
		}
	}
	return nil, fmt.Errorf("no .pem file found in %s", dir)
}

// reads the first non-directory file found in a directory.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: NewTSSPeer.
// Triggered: startup/runtime helper during process composition.
func findFirstFile(dir string) ([]byte, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !f.IsDir() {
			return os.ReadFile(filepath.Join(dir, f.Name()))
		}
	}
	return nil, fmt.Errorf("no file found in %s", dir)
}

// converts a generic []interface{} value into a []string list.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: startup/runtime helper during process composition.
// See CALL_MAP.md for the full caller list.
func toStringSlice(raw interface{}) []string {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			if strings.TrimSpace(s) == "" {
				continue
			}
			out = append(out, s)
		}
	}
	return out
}

// converts numeric/string dynamic values into int when possible.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: (*TSSPeer).checkPendingDKG, (*TSSPeer).checkReshareSessions.
// Triggered: startup/runtime helper during process composition.
func intFromAny(raw interface{}) int {
	switch v := raw.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return i
		}
	}
	return 0
}

// reports whether a string slice contains an exact item.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: (*TSSPeer).checkPendingDKG.
// Triggered: startup/runtime helper during process composition.
func containsString(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

// reports whether a string contains a substring case-insensitively.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: startup/runtime helper during process composition.
// See CALL_MAP.md for the full caller list.
func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// returns the smaller of two integers.
// Lifecycle: Startup configuration and bootstrap helpers.
// Called by: (*TSSPeer).executeTSSKeygen.
// Triggered: startup/runtime helper during process composition.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
