// tss_peer.go - A peer node with real TSS keygen using Gateway API + P2P
// This version implements actual Threshold Signature Scheme key generation
// FIXED: Uses proper tss-lib message routing and pre-params generation

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/bnb-chain/tss-lib/common"
	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	commonpb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	peerpb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// GatewayConfig holds Fabric connection configuration
type GatewayConfig struct {
	MSPID        string
	CryptoPath   string
	OrgDomain    string
	MSPUser      string
	PeerEndpoint string
	PeerHostname string
	P2PPort      int
	P2PAdvertise string // Address registered on-chain for other peers (e.g. "192.168.1.101:6001")
	WebUIPort    int
	StateDir     string // Directory for persisted node state (key shares, etc.)
	JoinMode     string // "member", "observer", "request", or "none"
}

// TSSPeer is a peer node with real TSS keygen capability
type TSSPeer struct {
	NodeID       string
	Organization string
	MemberID     string // Full canonical member ID from Fabric
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
	TSSPreParams       *keygen.LocalPreParams // Pre-generated safe primes
	Threshold          int
	keygenInProgress   bool // Track if keygen is running
	keygenEpoch        int  // Current keygen epoch; -1 when idle
	signingInProgress  bool // Track if signing is running
	dkgCompletedLogged bool // Track if we already logged DKG completion
	keyShareInvalid    bool
	keyShareInvalidMsg string
	keyShareInvalidLog bool

	// P2P Network
	p2pListener     net.Listener
	p2pPort         int
	p2pAdvertise    string            // Reachable address registered on-chain (e.g. "192.168.1.101:6001")
	webuiPort       int               // Web UI listen port
	stateDir        string            // Persistent state directory (key shares, etc.)
	peerAddrs       map[string]string // nodeID -> address
	tssMessages     chan *TSSMessage  // keygen messages
	reshareMessages chan *TSSMessage  // reshare messages
	signingMessages chan *TSSMessage  // signing messages (separate channel)
	keygenDone      chan struct{}     // closed when keygen handler exits
	p2pStats        *P2PMessageStats

	// Metrics
	metricsFile    *os.File
	metricsEnabled bool
	metricsMu      sync.Mutex

	// Completed signing proposals (skip re-processing)
	completedProposals map[string]bool

	// Completed keygen epochs (skip re-processing reshares)
	completedEpochs map[int]bool

	// Observed on-chain completions (for metrics)
	observedCerts         map[string]bool
	observedCSRSubmits    map[string]bool
	observedJoinSubmits   map[string]bool
	observedRemovalSubmits map[string]bool
	observedRevocationSubmits map[string]bool
	observedRevocations   map[string]bool
	observedJoinApprovals map[string]bool
	observedRemovals      map[string]bool
	observedReshares      map[int]bool
	missingShareReshares  map[int]bool
	lastAutoReshareEpoch  int
	lastAutoReshareAt     time.Time
	autoVoteSkipped       map[string]bool

	// Pending proposals for observation mapping
	pendingRevocations  map[string]string // proposalID -> targetMemberID
	pendingJoinRequests map[string]string // proposalID -> candidateID
	pendingRemovals     map[string]string // proposalID -> targetMemberID

	// CSR private keys stored by proposalID until certificate is registered
	csrPrivateKeys map[string]*ecdsa.PrivateKey

	// Index mapping for TSS
	partyIndexMap map[int]string // partyIndex -> nodeID

	// TSS Party IDs (cached for signing)
	cachedPartyIDs tss.SortedPartyIDs
	cachedMembers  []string // Sorted member IDs used for the current key share
	myPartyIndex   int

	// Context
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
	wg     sync.WaitGroup

	// P2P TLS
	p2pTLSConfig *tls.Config

	// P2P identity (MSP) for handshake authentication
	mspSigner     crypto.Signer
	mspCertPEM    []byte
	trustedRoots  *x509.CertPool
	warnedNoRoots bool

	// Optional Web UI
	webServer *http.Server

	// Merkle config (from env), for UI diagnostics
	merkleConfigSet     bool
	merkleConfigEnabled bool
}

// TSSMessage represents a TSS protocol message
type TSSMessage struct {
	From        string `json:"from"`
	To          string `json:"to"`        // Target node ID or "" for broadcast
	ToIndex     int    `json:"toIndex"`   // Target party index (-1 for broadcast)
	FromIndex   int    `json:"fromIndex"` // Sender party index
	FromCommittee string `json:"fromCommittee,omitempty"`
	ToCommittee   string `json:"toCommittee,omitempty"`
	SessionID   string `json:"sessionId"`
	MsgType     string `json:"msgType"` // "keygen", "reshare", or "signing"
	Payload     []byte `json:"payload"`
	IsBroadcast bool   `json:"isBroadcast"`
	Round       int    `json:"round"`
}

// P2PHandshake authenticates the sender using its MSP identity.
// The certificate is verified against known MSP roots, and the nonce is signed.
type P2PHandshake struct {
	MemberID string `json:"memberId"`
	CertPEM  string `json:"certPem"`
	Nonce    string `json:"nonce"` // hex
	Sig      string `json:"sig"`   // base64
}

type P2PMessageStats struct {
	mu            sync.Mutex
	sentTotal     uint64
	recvTotal     uint64
	sentBroadcast uint64
	sentDirect    uint64
	recvBroadcast uint64
	recvDirect    uint64
	sentByType    map[string]uint64
	recvByType    map[string]uint64
}

func newP2PMessageStats() *P2PMessageStats {
	return &P2PMessageStats{
		sentByType: make(map[string]uint64),
		recvByType: make(map[string]uint64),
	}
}

func (s *P2PMessageStats) incSent(msg *TSSMessage) {
	if s == nil || msg == nil {
		return
	}
	typ := msg.MsgType
	if typ == "" {
		typ = "unknown"
	}
	s.mu.Lock()
	s.sentTotal++
	if msg.IsBroadcast {
		s.sentBroadcast++
	} else {
		s.sentDirect++
	}
	s.sentByType[typ]++
	s.mu.Unlock()
}

func (s *P2PMessageStats) incRecv(msg *TSSMessage) {
	if s == nil || msg == nil {
		return
	}
	typ := msg.MsgType
	if typ == "" {
		typ = "unknown"
	}
	s.mu.Lock()
	s.recvTotal++
	if msg.IsBroadcast {
		s.recvBroadcast++
	} else {
		s.recvDirect++
	}
	s.recvByType[typ]++
	s.mu.Unlock()
}

func (s *P2PMessageStats) snapshot(reset bool) map[string]interface{} {
	if s == nil {
		return map[string]interface{}{}
	}
	s.mu.Lock()
	out := map[string]interface{}{
		"sent_total":      s.sentTotal,
		"recv_total":      s.recvTotal,
		"sent_broadcast":  s.sentBroadcast,
		"sent_direct":     s.sentDirect,
		"recv_broadcast":  s.recvBroadcast,
		"recv_direct":     s.recvDirect,
		"sent_by_type":    copyUint64Map(s.sentByType),
		"recv_by_type":    copyUint64Map(s.recvByType),
	}
	if reset {
		s.sentTotal = 0
		s.recvTotal = 0
		s.sentBroadcast = 0
		s.sentDirect = 0
		s.recvBroadcast = 0
		s.recvDirect = 0
		s.sentByType = make(map[string]uint64)
		s.recvByType = make(map[string]uint64)
	}
	s.mu.Unlock()
	return out
}

func copyUint64Map(in map[string]uint64) map[string]uint64 {
	if len(in) == 0 {
		return map[string]uint64{}
	}
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// SigningSession holds local state for a signing operation
type SigningSession struct {
	ProposalID string
	CSRHash    string
	Message    *big.Int
	Party      tss.Party
	OutCh      chan tss.Message
	EndCh      chan common.SignatureData
}

const (
	DefaultCAID     = "root-ca-001"
	DefaultChannel  = "mychannel"
	maxBlocksToShow = 20
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <org1|org2|org3|...>")
		fmt.Println("  Configure via environment variables (see tss-<org>.env) or use built-in defaults for org1/org2.")
		os.Exit(1)
	}

	org := os.Args[1]
	if !strings.HasPrefix(org, "org") {
		fmt.Println("Organization must be 'org1', 'org2', 'org3', etc.")
		os.Exit(1)
	}

	fmt.Printf("=== Starting TSS Peer for %s ===\n", org)

	// Print resolved configuration
	config := getConfig(org)
	fmt.Printf("  MSPID:          %s\n", config.MSPID)
	fmt.Printf("  CryptoPath:     %s\n", config.CryptoPath)
	fmt.Printf("  MSP User:       %s\n", config.MSPUser)
	fmt.Printf("  PeerEndpoint:   %s\n", config.PeerEndpoint)
	fmt.Printf("  PeerHostname:   %s\n", config.PeerHostname)
	fmt.Printf("  P2P Listen:     0.0.0.0:%d\n", config.P2PPort)
	fmt.Printf("  P2P Advertise:  %s\n", config.P2PAdvertise)
	fmt.Printf("  WebUI Port:     %d\n", config.WebUIPort)
	fmt.Printf("  Join Mode:      %s\n", config.JoinMode)
	if os.Getenv("TSS_MSPID") != "" {
		fmt.Println("  Config source:  environment variables")
	} else {
		fmt.Println("  Config source:  built-in defaults")
	}

	// Register P256 curve with tss-lib (needed for JSON serialization of EC points)
	tss.RegisterCurve("P-256", elliptic.P256())
	// Ensure tss-lib global curve matches our P-256 usage (needed for gob decode of ECPoint)
	tss.SetCurve(elliptic.P256())

	peer, err := NewTSSPeer(org)
	if err != nil {
		log.Fatalf("Failed to create peer: %v", err)
	}
	defer peer.Close()

	// Start P2P listener
	if err := peer.StartP2P(); err != nil {
		log.Fatalf("Failed to start P2P: %v", err)
	}

	// Register P2P address on blockchain
	if err := peer.RegisterPeerAddress(); err != nil {
		log.Printf("Failed to register peer address: %v", err)
	}

	// Test basic operations
	fmt.Println("\n--- Testing GetDistributedCA ---")
	ca, err := peer.GetCA()
	if err != nil {
		log.Printf("GetCA failed: %v", err)
	} else {
		caJSON, _ := json.MarshalIndent(ca, "", "  ")
		fmt.Printf("CA State:\n%s\n", caJSON)
	}

	// Ensure CA initialized and join
	fmt.Println("\n--- Ensuring CA Initialized and Joining ---")
	if err := peer.EnsureCAInitialized(); err != nil {
		log.Printf("EnsureCAInitialized failed: %v", err)
	}
	peer.applyMerkleConfigFromEnv()

	// Start polling loop
	fmt.Println("\n--- Starting Event Polling Loop ---")
	go peer.StartPollingLoop()

	// Start interactive menu
	go peer.StartInteractiveMenu()

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down...")
}

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
	contract := network.GetContract("bpki")

	ctx, cancel := context.WithCancel(context.Background())

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

	peer := &TSSPeer{
		NodeID:             nodeID,
		Organization:       org,
		joinMode:           config.JoinMode,
		gateway:            gw,
		network:            network,
		contract:           contract,
		conn:               grpcConn,
		ctx:                ctx,
		cancel:             cancel,
		p2pPort:            config.P2PPort,
		p2pAdvertise:       config.P2PAdvertise,
		webuiPort:          config.WebUIPort,
		stateDir:           config.StateDir,
		mspSigner:          signer,
		mspCertPEM:         certPEM,
		peerAddrs:          make(map[string]string),
		tssMessages:        make(chan *TSSMessage, 100),
		reshareMessages:    make(chan *TSSMessage, 100),
		signingMessages:    make(chan *TSSMessage, 100),
		keygenDone:         make(chan struct{}),
		p2pStats:           newP2PMessageStats(),
		completedProposals: make(map[string]bool),
		completedEpochs:    make(map[int]bool),
		observedCerts:         make(map[string]bool),
		observedCSRSubmits:    make(map[string]bool),
		observedJoinSubmits:   make(map[string]bool),
		observedRemovalSubmits: make(map[string]bool),
		observedRevocationSubmits: make(map[string]bool),
		observedRevocations:   make(map[string]bool),
		observedJoinApprovals: make(map[string]bool),
		observedRemovals:      make(map[string]bool),
		observedReshares:      make(map[int]bool),
		missingShareReshares:  make(map[int]bool),
		lastAutoReshareEpoch:  -1,
		autoVoteSkipped:       make(map[string]bool),
		pendingRevocations:    make(map[string]string),
		pendingJoinRequests:   make(map[string]string),
		pendingRemovals:       make(map[string]string),
		csrPrivateKeys:     make(map[string]*ecdsa.PrivateKey),
		partyIndexMap:      make(map[int]string),
		Threshold:          1, // Will be updated from CA
		keygenEpoch:        -1,
	}

	// keygenDone represents the keygen handler lifecycle. Closed == no keygen running.
	close(peer.keygenDone)

	peerOrgsDir := filepath.Clean(filepath.Dir(config.CryptoPath))
	if roots, err := loadTrustedRoots(peerOrgsDir); err != nil {
		log.Printf("[%s] Warning: failed to load MSP roots for P2P auth: %v", nodeID, err)
	} else {
		peer.trustedRoots = roots
	}

	log.Printf("[%s] Connected to Fabric via Gateway API", nodeID)

	// Get member ID from chaincode
	memberID, err := peer.WhoAmI()
	if err != nil {
		log.Printf("[%s] Warning: couldn't get member ID: %v", nodeID, err)
	} else {
		peer.MemberID = memberID
		log.Printf("[%s] Member ID: %s", nodeID, memberID[:60]+"...")
	}

	resetState, resetSet, resetErr := envBool("TSS_RESET_STATE")
	if resetErr != nil {
		log.Printf("[%s] Invalid TSS_RESET_STATE: %v", nodeID, resetErr)
	}
	peer.resetLocalStateOnce(resetSet, resetState)

	// Load persisted key share if present
	if err := peer.LoadKeyShare(); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to load key share: %v", nodeID, err)
		}
	} else {
		peer.dkgCompletedLogged = true
	}

	peer.initMetrics()

	// If a certificate for this member was already registered, sync it locally
	peer.syncOwnedCertificate()

	// Load persisted pre-params if present; otherwise generate and persist
	if err := peer.LoadPreParams(); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to load pre-params: %v", nodeID, err)
		}
	}
	if peer.TSSPreParams == nil {
		log.Printf("[%s] Generating TSS pre-parameters (safe primes, may take 2-3 min)...", nodeID)
		preParams, err := keygen.GeneratePreParams(3 * time.Minute)
		if err != nil {
			log.Printf("[%s] Warning: failed to generate pre-params, will use slower method: %v", nodeID, err)
		} else {
			peer.TSSPreParams = preParams
			if err := peer.SavePreParams(); err != nil {
				log.Printf("[%s] Warning: failed to persist pre-params: %v", nodeID, err)
			}
			log.Printf("[%s] TSS pre-parameters generated successfully", nodeID)
		}
	}

	return peer, nil
}

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

// ===================== P2P NETWORKING =====================

// generateP2PTLSConfig creates a self-signed TLS config for P2P communication.
// All TSS messages are encrypted in transit; peers accept any certificate since
// authentication is handled by Fabric MSP identities, not by TLS certs.
func generateP2PTLSConfig(nodeID string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID + "-p2p"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true, // Peers use Fabric MSP for identity, not TLS certs
		MinVersion:         tls.VersionTLS12,
	}, nil
}

func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func canonicalIDFromCert(cert *x509.Certificate) string {
	return fmt.Sprintf("x509::%s::%s", cert.Subject.String(), cert.Issuer.String())
}

func normalizeMemberID(id string) string {
	if strings.HasPrefix(id, "x509::") {
		return id
	}
	if decoded, err := base64.StdEncoding.DecodeString(id); err == nil {
		s := string(decoded)
		if strings.HasPrefix(s, "x509::") {
			return s
		}
	}
	return id
}

func parseCanonicalSubject(canonicalID string) map[string]string {
	out := map[string]string{}
	if !strings.HasPrefix(canonicalID, "x509::") {
		return out
	}
	parts := strings.SplitN(canonicalID, "::", 3)
	if len(parts) < 2 {
		return out
	}
	subject := parts[1]
	for _, kv := range strings.Split(subject, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		idx := strings.Index(kv, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(kv[:idx])
		val := strings.TrimSpace(kv[idx+1:])
		if key != "" && val != "" {
			out[key] = val
		}
	}
	return out
}

func loadTrustedRoots(peerOrgsDir string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := 0

	patterns := []string{
		filepath.Join(peerOrgsDir, "*", "msp", "cacerts", "*"),
		filepath.Join(peerOrgsDir, "*", "msp", "tlscacerts", "*"),
	}
	for _, pattern := range patterns {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if pool.AppendCertsFromPEM(data) {
				added++
			}
		}
	}

	if added == 0 {
		return nil, fmt.Errorf("no MSP root certs found under %s", peerOrgsDir)
	}
	return pool, nil
}

func (p *TSSPeer) buildHandshake() (*P2PHandshake, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(nonce)
	if p.mspSigner == nil {
		return nil, fmt.Errorf("no MSP signer available")
	}
	sig, err := p.mspSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	memberID := p.MemberID
	if memberID == "" && len(p.mspCertPEM) > 0 {
		if cert, err := parseCertPEM(p.mspCertPEM); err == nil {
			memberID = canonicalIDFromCert(cert)
		}
	}
	return &P2PHandshake{
		MemberID: memberID,
		CertPEM:  string(p.mspCertPEM),
		Nonce:    hex.EncodeToString(nonce),
		Sig:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

func (p *TSSPeer) verifyHandshake(hs *P2PHandshake) (string, error) {
	if hs == nil {
		return "", fmt.Errorf("empty handshake")
	}
	nonceBytes, err := hex.DecodeString(hs.Nonce)
	if err != nil || len(nonceBytes) == 0 {
		return "", fmt.Errorf("invalid nonce")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(hs.Sig)
	if err != nil || len(sigBytes) == 0 {
		return "", fmt.Errorf("invalid signature encoding")
	}
	cert, err := parseCertPEM([]byte(hs.CertPEM))
	if err != nil {
		return "", fmt.Errorf("invalid certificate")
	}

	if p.trustedRoots != nil {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:       p.trustedRoots,
			CurrentTime: time.Now(),
		}); err != nil {
			return "", fmt.Errorf("certificate verification failed: %v", err)
		}
	} else if !p.warnedNoRoots {
		p.warnedNoRoots = true
		log.Printf("[%s] Warning: no trusted MSP roots loaded; skipping cert chain verification for P2P", p.NodeID)
	}

	canonical := canonicalIDFromCert(cert)
	claimed := normalizeMemberID(hs.MemberID)
	if claimed != canonical {
		return "", fmt.Errorf("member ID mismatch (claimed %s, cert %s)", claimed, canonical)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported public key type")
	}
	hash := sha256.Sum256(nonceBytes)
	if !ecdsa.VerifyASN1(pub, hash[:], sigBytes) {
		return "", fmt.Errorf("signature verification failed")
	}
	return claimed, nil
}

func (p *TSSPeer) StartP2P() error {
	// Generate TLS config for encrypted P2P
	tlsConfig, err := generateP2PTLSConfig(p.NodeID)
	if err != nil {
		return fmt.Errorf("failed to generate P2P TLS config: %w", err)
	}
	p.p2pTLSConfig = tlsConfig

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", p.p2pPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start P2P listener: %w", err)
	}
	p.p2pListener = listener
	log.Printf("[%s] P2P listening on 0.0.0.0:%d (TLS encrypted), advertise: %s", p.NodeID, p.p2pPort, p.p2pAdvertise)

	p.wg.Add(1)
	go p.acceptP2PConnections()

	return nil
}

func (p *TSSPeer) acceptP2PConnections() {
	defer p.wg.Done()

	for {
		conn, err := p.p2pListener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				log.Printf("[%s] P2P accept error: %v", p.NodeID, err)
				continue
			}
		}
		go p.handleP2PConnection(conn)
	}
}

func (p *TSSPeer) handleP2PConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	var hs P2PHandshake
	if err := decoder.Decode(&hs); err != nil {
		// EOF is expected from health-check connections (waitForPeers dial+close)
		if err != io.EOF && err.Error() != "EOF" {
			log.Printf("[%s] P2P handshake decode error: %v", p.NodeID, err)
		}
		return
	}
	peerMemberID, err := p.verifyHandshake(&hs)
	if err != nil {
		log.Printf("[%s] P2P handshake verification failed: %v", p.NodeID, err)
		return
	}
	peerShortID := p.extractShortNodeID(peerMemberID)

	var msg TSSMessage
	if err := decoder.Decode(&msg); err != nil {
		// EOF is expected from health-check connections (waitForPeers dial+close)
		if err != io.EOF && err.Error() != "EOF" {
			log.Printf("[%s] P2P decode error: %v", p.NodeID, err)
		}
		return
	}

	if msg.From == "" || msg.From != peerShortID {
		if msg.From != "" && msg.From != peerShortID {
			log.Printf("[%s] P2P sender mismatch: msg.From=%s, handshake=%s (using %s)", p.NodeID, msg.From, peerMemberID, peerShortID)
		}
		msg.From = peerShortID
	}

	log.Printf("[%s] Received TSS message from %s (type=%s, round %d)", p.NodeID, msg.From, msg.MsgType, msg.Round)
	p.p2pStats.incRecv(&msg)
	switch msg.MsgType {
	case "signing":
		p.signingMessages <- &msg
		// If we're not currently signing, trigger an immediate check so we
		// start our signing party before the remote peer's messages expire.
		p.mutex.RLock()
		isSigning := p.signingInProgress
		p.mutex.RUnlock()
		if !isSigning {
			go p.checkSigningSessions()
		}
	case "reshare":
		p.reshareMessages <- &msg
	default:
		p.tssMessages <- &msg
	}
}

func (p *TSSPeer) SendTSSMessage(to string, msg *TSSMessage) error {
	p.mutex.RLock()
	addr, ok := p.peerAddrs[to]
	p.mutex.RUnlock()

	if !ok {
		return fmt.Errorf("peer address not found: %s", to)
	}

	// TLS-encrypted connection to peer
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: true, // Peers use Fabric MSP for identity
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := tlsDialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to peer %s: %w", to, err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	hs, err := p.buildHandshake()
	if err != nil {
		return fmt.Errorf("failed to build handshake: %w", err)
	}
	if err := enc.Encode(hs); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}
	if err := enc.Encode(msg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	p.p2pStats.incSent(msg)
	return nil
}

// SendTSSMessageWithRetry attempts to send a message with exponential backoff retry
func (p *TSSPeer) SendTSSMessageWithRetry(to string, msg *TSSMessage, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := p.SendTSSMessage(to, msg)
		if err == nil {
			return nil
		}
		lastErr = err

		// Exponential backoff: 1s, 2s, 4s, 8s, 16s
		backoff := time.Duration(1<<attempt) * time.Second
		if backoff > 16*time.Second {
			backoff = 16 * time.Second
		}
		log.Printf("[%s] Retry %d/%d sending to %s in %v: %v", p.NodeID, attempt+1, maxRetries, to, backoff, err)
		time.Sleep(backoff)
	}
	return lastErr
}

func (p *TSSPeer) BroadcastTSSMessage(msg *TSSMessage) {
	p.mutex.RLock()
	peers := make(map[string]string)
	for k, v := range p.peerAddrs {
		peers[k] = v
	}
	p.mutex.RUnlock()

	for peerID := range peers {
		if peerID != p.NodeID {
			msgCopy := *msg
			msgCopy.To = peerID
			if err := p.SendTSSMessageWithRetry(peerID, &msgCopy, 3); err != nil {
				log.Printf("[%s] Failed to send to %s after retries: %v", p.NodeID, peerID, err)
			}
		}
	}
}

func (p *TSSPeer) RegisterPeerAddress() error {
	// Parse the advertise address to extract host and port
	advHost, advPort, err := net.SplitHostPort(p.p2pAdvertise)
	if err != nil {
		// Fallback if advertise address is malformed
		advHost = "localhost"
		advPort = fmt.Sprintf("%d", p.p2pPort)
	}
	_, err = p.Execute("RegisterPeerAddress", advHost, advPort, "7051")
	if err != nil {
		return err
	}
	log.Printf("[%s] Registered P2P address: %s:%s", p.NodeID, advHost, advPort)
	return nil
}

func (p *TSSPeer) LoadPeerAddresses() error {
	payload, err := p.Query("GetAllPeerAddresses")
	if err != nil {
		return err
	}

	var peers []map[string]interface{}
	if err := json.Unmarshal(payload, &peers); err != nil {
		return err
	}

	// Convert to map: shortNodeID -> address:port
	// The nodeId from chaincode is the full canonical member ID (x509::CN=Admin@org1...)
	// We map this to short node IDs like "org1-peer", "org2-peer"
	addrs := make(map[string]string)
	for _, peer := range peers {
		if nodeID, ok := peer["nodeId"].(string); ok {
			if address, ok := peer["address"].(string); ok {
				if p2pPort, ok := peer["p2pPort"].(float64); ok {
					// Extract short node ID from canonical member ID
					shortID := p.extractShortNodeID(nodeID)
					addrs[shortID] = fmt.Sprintf("%s:%d", address, int(p2pPort))
					log.Printf("[%s] Mapped peer %s -> %s:%d", p.NodeID, shortID, address, int(p2pPort))
				}
			}
		}
	}

	p.mutex.Lock()
	p.peerAddrs = addrs
	p.mutex.Unlock()

	log.Printf("[%s] Loaded %d peer addresses", p.NodeID, len(addrs))
	return nil
}

// extractShortNodeID converts a canonical member ID to a short node ID.
// Backwards compatible: Admin@orgN -> orgN-peer. Other users -> orgN-<user>.
func (p *TSSPeer) extractShortNodeID(canonicalID string) string {
	return shortNodeIDFromCanonical(canonicalID)
}

func shortNodeIDFromCanonical(canonicalID string) string {
	canonicalID = strings.TrimSpace(canonicalID)
	if canonicalID == "" {
		return ""
	}

	orgLabel := extractOrgLabelFromCanonical(canonicalID)
	subject := parseCanonicalSubject(canonicalID)
	cn := strings.TrimSpace(subject["CN"])
	if cn != "" {
		local := cn
		if at := strings.Index(cn, "@"); at > 0 {
			local = cn[:at]
		}
		local = sanitizeNodeLabel(local)
		if local != "" {
			if orgLabel != "" && strings.EqualFold(local, "admin") {
				return fmt.Sprintf("%s-peer", orgLabel)
			}
			if orgLabel != "" {
				return fmt.Sprintf("%s-%s", orgLabel, local)
			}
			return local
		}
	}

	if orgLabel != "" {
		return fmt.Sprintf("%s-peer", orgLabel)
	}

	h := sha256.Sum256([]byte(canonicalID))
	return fmt.Sprintf("peer-%x", h[:4])
}

func extractOrgLabelFromCanonical(canonicalID string) string {
	search := canonicalID
	offset := 0
	for {
		idx := strings.Index(search, "org")
		if idx < 0 {
			return ""
		}
		rest := search[idx+3:]
		digits := ""
		for _, c := range rest {
			if c >= '0' && c <= '9' {
				digits += string(c)
			} else {
				break
			}
		}
		if digits != "" {
			return fmt.Sprintf("org%s", digits)
		}
		offset += idx + 3
		if offset >= len(canonicalID) {
			return ""
		}
		search = canonicalID[offset:]
	}
}

func sanitizeNodeLabel(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	var b strings.Builder
	prevDash := false
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			prevDash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
			prevDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}

func ensureCanonicalOrExternal(id string) error {
	if strings.HasPrefix(id, "external::") {
		return nil
	}
	if strings.HasPrefix(id, "x509::") {
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(id); err == nil {
		if strings.HasPrefix(string(decoded), "x509::") {
			return nil
		}
	}
	return fmt.Errorf("member ID must be canonical x509::... or base64(x509::...)")
}

func (p *TSSPeer) getKnownMemberIDs() []string {
	ca, err := p.GetCA()
	if err != nil {
		return nil
	}
	var ids []string
	if members, ok := ca["members"].([]interface{}); ok {
		for _, m := range members {
			if s, ok := m.(string); ok && s != "" {
				ids = append(ids, s)
			}
		}
	}
	if observers, ok := ca["observers"].([]interface{}); ok {
		for _, m := range observers {
			if s, ok := m.(string); ok && s != "" {
				ids = append(ids, s)
			}
		}
	}
	return ids
}

func (p *TSSPeer) resolveMemberIDInput(input string) (string, error) {
	id := strings.TrimSpace(input)
	if id == "" {
		return "", fmt.Errorf("member ID cannot be empty")
	}
	if strings.HasPrefix(id, "x509::") || strings.HasPrefix(id, "external::") {
		return id, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(id); err == nil {
		if strings.HasPrefix(string(decoded), "x509::") {
			return string(decoded), nil
		}
	}

	known := p.getKnownMemberIDs()
	if len(known) == 0 {
		return id, nil
	}
	lower := strings.ToLower(id)
	var matches []string
	for _, k := range known {
		if strings.Contains(strings.ToLower(k), lower) {
			matches = append(matches, k)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("input matches multiple member IDs; use full canonical ID")
	}
	return id, nil
}

// ===================== FABRIC GATEWAY =====================

func (p *TSSPeer) Query(function string, args ...string) ([]byte, error) {
	return p.contract.EvaluateTransaction(function, args...)
}

func (p *TSSPeer) Execute(function string, args ...string) ([]byte, error) {
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		result, err := p.contract.SubmitTransaction(function, args...)
		if err == nil {
			return result, nil
		}
		if !strings.Contains(err.Error(), "MVCC_READ_CONFLICT") {
			return nil, err
		}
		// Exponential backoff: 500ms, 1s, 2s
		backoff := time.Duration(500<<attempt) * time.Millisecond
		log.Printf("[%s] MVCC conflict on %s, retry %d/%d in %v", p.NodeID, function, attempt+1, maxRetries, backoff)
		time.Sleep(backoff)
	}
	return p.contract.SubmitTransaction(function, args...)
}

func (p *TSSPeer) WhoAmI() (string, error) {
	payload, err := p.Query("WhoAmI")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

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

func (p *TSSPeer) persistCAPublicKey(ca map[string]interface{}) {
	caPublicKeyHex, _ := ca["caPublicKey"].(string)
	if caPublicKeyHex == "" {
		caPublicKeyHex, _ = ca["publicKey"].(string)
	}
	p.persistCAPublicKeyHex(caPublicKeyHex)
}

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

func (p *TSSPeer) getCAPublicKeyPointFallback(reshare map[string]interface{}) *tsscrypto.ECPoint {
	if reshare != nil {
		if v, ok := reshare["newCAPublicKey"].(string); ok && strings.TrimSpace(v) != "" {
			if pt := parseCAPublicKeyPoint(v); pt != nil {
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

func (p *TSSPeer) keySharePath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("keyshare_%s.gob", p.NodeID))
}

func (p *TSSPeer) keyShareLegacyPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("keyshare_%s.json", p.NodeID))
}

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

func (p *TSSPeer) markKeyShareInvalid(reason string) {
	p.mutex.Lock()
	p.keyShareInvalid = true
	p.keyShareInvalidMsg = reason
	p.mutex.Unlock()
}

func (p *TSSPeer) clearKeyShareInvalid() {
	p.mutex.Lock()
	p.keyShareInvalid = false
	p.keyShareInvalidMsg = ""
	p.keyShareInvalidLog = false
	p.mutex.Unlock()
}

// SaveKeyShare persists the current TSS key share to disk.
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
	return writeFileAtomic(path, buf.Bytes(), 0600)
}

// LoadKeyShare loads a persisted TSS key share from disk, if present.
func (p *TSSPeer) LoadKeyShare() error {
	var lastErr error
	path := p.keySharePath()
	data, err := os.ReadFile(path)
	if err == nil {
		var keyShare keygen.LocalPartySaveData
		if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&keyShare); err == nil {
			if ok, reason := keyShareHasCompleteData(&keyShare); ok {
				p.mutex.Lock()
				p.TSSKeyShare = &keyShare
				p.mutex.Unlock()
				p.clearKeyShareInvalid()
				log.Printf("[%s] Loaded persisted key share from %s", p.NodeID, path)
				return nil
			} else {
				lastErr = fmt.Errorf("persisted key share invalid: %s", reason)
			}
		} else {
			lastErr = err
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	legacyPath := p.keyShareLegacyPath()
	data, err = os.ReadFile(legacyPath)
	if err != nil {
		if lastErr != nil {
			p.markKeyShareInvalid(lastErr.Error())
			return lastErr
		}
		return err
	}

	var keyShare keygen.LocalPartySaveData
	if err := json.Unmarshal(data, &keyShare); err != nil {
		p.markKeyShareInvalid(err.Error())
		return err
	}
	if ok, reason := keyShareHasCompleteData(&keyShare); !ok {
		lastErr = fmt.Errorf("legacy key share invalid: %s (delete %s and run fresh DKG)", reason, legacyPath)
		p.markKeyShareInvalid(lastErr.Error())
		return lastErr
	}

	p.mutex.Lock()
	p.TSSKeyShare = &keyShare
	p.mutex.Unlock()
	p.clearKeyShareInvalid()

	log.Printf("[%s] Loaded legacy key share from %s", p.NodeID, legacyPath)
	_ = p.SaveKeyShare() // migrate to gob
	return nil
}

func (p *TSSPeer) preParamsPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("preparams_%s.gob", p.NodeID))
}

// SavePreParams persists pre-generated TSS parameters to disk.
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

// LoadPreParams loads persisted TSS pre-parameters, if present.
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

func (p *TSSPeer) resetLocalState() {
	paths := []string{p.keySharePath(), p.keyShareLegacyPath(), p.preParamsPath()}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[%s] Warning: failed to remove %s: %v", p.NodeID, path, err)
		}
	}
}

func (p *TSSPeer) purgeLocalKeyShare(reason string) {
	p.mutex.Lock()
	hadShare := p.TSSKeyShare != nil
	p.TSSKeyShare = nil
	p.myPartyIndex = -1
	p.partyIndexMap = nil
	p.cachedMembers = nil
	p.mutex.Unlock()

	paths := []string{p.keySharePath(), p.keyShareLegacyPath()}
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

func (p *TSSPeer) resetMarkerPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, fmt.Sprintf("reset_%s.done", p.NodeID))
}

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

func (p *TSSPeer) metricsPath() string {
	dir := p.stateDir
	if dir == "" {
		dir = filepath.Join("state", p.Organization)
	}
	return filepath.Join(dir, "metrics.jsonl")
}

func (p *TSSPeer) initMetrics() {
	enabled := strings.ToLower(strings.TrimSpace(envOrDefault("TSS_METRICS_ENABLED", "true")))
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

func (p *TSSPeer) emitMetric(event string, fields map[string]interface{}) {
	if !p.metricsEnabled || p.metricsFile == nil {
		return
	}
	payload := map[string]interface{}{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"event": event,
		"org":  p.Organization,
		"node": p.NodeID,
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

type BlockTxSummary struct {
	TxID      string `json:"txId"`
	Type      string `json:"type"`
	Chaincode string `json:"chaincode"`
	Function  string `json:"function"`
}

type BlockSummary struct {
	Number  uint64           `json:"number"`
	TxCount int              `json:"txCount"`
	Txs     []BlockTxSummary `json:"txs"`
}

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

// syncOwnedCertificate fetches the active certificate for this member from chaincode
// and writes it to the local certs directory if present.
func (p *TSSPeer) syncOwnedCertificate() {
	_ = p.syncOwnedCertificateOnce()
}

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
	if err := os.WriteFile(certPath, []byte(cert.CertificatePEM), 0644); err != nil {
		log.Printf("[%s] Warning: failed to save certificate: %v", p.NodeID, err)
		return false
	}
	log.Printf("[%s] Certificate synced to %s", p.NodeID, certPath)
	return true
}

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

func (p *TSSPeer) EnsureCAInitialized() error {
	log.Printf("[%s] Checking if CA exists...", p.NodeID)

	// Try to initialize CA with MVCC retry
	for attempt := 0; attempt < 3; attempt++ {
		_, err := p.GetCA()
		if err != nil {
			// CA doesn't exist, try to initialize
			log.Printf("[%s] Initializing CA...", p.NodeID)
			_, err = p.Execute("InitializeDistributedCA", DefaultCAID, "Decentralized PKI CA", p.Organization, "2", "")
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
	case "observer":
		log.Printf("[%s] Attempting observer join...", p.NodeID)
		if _, err := p.Execute("JoinAsObserver", DefaultCAID); err != nil {
			if containsIgnoreCase(err.Error(), "already") {
				log.Printf("[%s] Already an observer", p.NodeID)
			} else {
				log.Printf("[%s] Observer join warning: %v", p.NodeID, err)
			}
		} else {
			log.Printf("[%s] Successfully joined as observer", p.NodeID)
		}
		return nil
	case "request":
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
					log.Printf("[%s] Bootstrap period ended - need sponsorship to join", p.NodeID)
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

		// Check if we're a member, if not, we need sponsorship
		p.checkMembershipStatus()
	}

	return nil
}

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
		log.Printf("[%s] WARNING: Not a CA member. Need sponsorship from existing member.", p.NodeID)
		log.Printf("[%s] Another peer should run: Sponsor New Member with ID:", p.NodeID)
		log.Printf("[%s]   %s", p.NodeID, p.MemberID)
	} else {
		log.Printf("[%s] Confirmed as CA member", p.NodeID)

		// Check if DKG needs to be initiated
		p.checkAndInitiateDKG()
	}
}

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

	// If a key already exists on-chain and we don't have a local share, trigger reshare.
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

	// Auto-initiate DKG once we have at least 2 members and no key exists yet.
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

func (p *TSSPeer) setMemberStatus(isMember bool) {
	p.mutex.Lock()
	prev := p.isMember
	p.isMember = isMember
	if isMember && !prev {
		// Clear any skipped auto-votes once we become a member.
		p.autoVoteSkipped = make(map[string]bool)
	}
	p.mutex.Unlock()
}

func (p *TSSPeer) isCAMember() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.isMember
}

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

func (p *TSSPeer) StartPollingLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Printf("[%s] Starting polling loop (5s interval)...", p.NodeID)

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.checkPendingDKG()
			p.checkPendingCSRs()
			p.checkPendingJoinRequests()
			p.checkPendingSponsorships()
			p.checkPendingRemoveMemberProposals()
			p.checkSigningSessions()
			p.checkReshareSessions()
			p.checkPendingRevocations()
			p.checkObservedCertificates()
			p.checkObservedMembershipChanges()
		}
	}
}

func (p *TSSPeer) checkPendingDKG() {
	dkg, err := p.GetDKGSession(0)
	if err != nil {
		return
	}

	status, ok := dkg["status"].(string)
	if !ok {
		return
	}

	// Check if we're in the DKG session members
	members, _ := dkg["members"].([]interface{})
	isMember := false
	for _, m := range members {
		if memberStr, ok := m.(string); ok && memberStr == p.MemberID {
			isMember = true
			break
		}
	}

	if !isMember {
		// Not in this DKG session - this can happen if DKG was initiated before we joined
		// Just silently skip - don't spam logs
		return
	}

	if status == "initiated" {
		log.Printf("[%s] DKG Status: %s", p.NodeID, status)
		log.Printf("[%s] Found pending DKG, acknowledging...", p.NodeID)
		if err := p.AcknowledgeDKG(0); err != nil {
			log.Printf("[%s] Acknowledge failed: %v", p.NodeID, err)
		}
	} else if status == "ready" {
		// Skip if keygen is already in progress or we already have a key share
		p.mutex.RLock()
		inProgress := p.keygenInProgress
		hasShare := p.TSSKeyShare != nil
		p.mutex.RUnlock()
		if inProgress {
			return
		}
		if hasShare {
			stale, reason := p.isKeyShareStale()
			if !stale {
				return
			}
			if strings.TrimSpace(reason) == "" {
				reason = "unknown"
			}
			log.Printf("[%s] Existing key share is stale (%s); re-running DKG", p.NodeID, reason)
		}
		log.Printf("[%s] DKG Status: %s", p.NodeID, status)

		// Load peer addresses for P2P
		if err := p.LoadPeerAddresses(); err != nil {
			log.Printf("[%s] Failed to load peer addresses: %v", p.NodeID, err)
			return
		}

		// Wait for all peers to be reachable before starting keygen
		if !p.waitForPeers(30 * time.Second) {
			log.Printf("[%s] Not all peers reachable yet, will retry...", p.NodeID)
			return
		}

		log.Printf("[%s] DKG is ready - starting TSS keygen...", p.NodeID)
		p.executeTSSKeygen(0, dkg)
	} else if status == "proposed" {
		// DKG completion proposed; acknowledge if we have a key share
		p.mutex.RLock()
		keyShare := p.TSSKeyShare
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
			// If the proposed key doesn't match our local share, clear it and still ack the proposal
			// so the DKG can complete and a reshare can fix our missing share.
			if localPubKey != "" && localPubKey != proposedPubKey {
				log.Printf("[%s] DKG proposal public key mismatch; clearing local key share and acknowledging proposal", p.NodeID)
				p.purgeLocalKeyShare("dkg proposal public key mismatch")
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
		// Avoid resetting keygen state if a reshare keygen is running
		p.mutex.Lock()
		if p.keygenEpoch <= 0 {
			p.keygenInProgress = false
			p.keygenEpoch = -1
		}
		hasShare := p.TSSKeyShare != nil
		if !p.dkgCompletedLogged {
			p.dkgCompletedLogged = true
			p.mutex.Unlock()
			log.Printf("[%s] DKG completed! Key shares are ready.", p.NodeID)
		} else {
			p.mutex.Unlock()
		}
		if !hasShare {
			p.autoForceReshareMissingShare()
		}
	}
}

func (p *TSSPeer) autoForceReshareMissingShare() {
	p.mutex.RLock()
	keyShareInvalid := p.keyShareInvalid
	keyShareInvalidMsg := p.keyShareInvalidMsg
	alreadyLogged := p.keyShareInvalidLog
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
				if status, _ := reshare["status"].(string); status == "initiated" || status == "acknowledged" {
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

	log.Printf("[%s] No local key share but DKG is completed; forcing reshare (epoch %d)", p.NodeID, epoch)
	if _, err := p.Execute("ForceReshare", DefaultCAID, "auto_reshare_missing_share"); err != nil {
		log.Printf("[%s] Auto reshare failed: %v", p.NodeID, err)
	}
}

// waitForPeers checks that all other peers are reachable via P2P
func (p *TSSPeer) waitForPeers(timeout time.Duration) bool {
	p.mutex.RLock()
	peers := make(map[string]string)
	for k, v := range p.peerAddrs {
		peers[k] = v
	}
	p.mutex.RUnlock()

	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 2 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}

	deadline := time.Now().Add(timeout)

	for peerID, addr := range peers {
		if peerID == p.NodeID {
			continue
		}

		for time.Now().Before(deadline) {
			conn, err := tlsDialer.DialContext(context.Background(), "tcp", addr)
			if err == nil {
				conn.Close()
				log.Printf("[%s] Peer %s is reachable at %s (TLS)", p.NodeID, peerID, addr)
				break
			}
			log.Printf("[%s] Waiting for peer %s at %s...", p.NodeID, peerID, addr)
			time.Sleep(2 * time.Second)
		}

		// Final check
		conn, err := tlsDialer.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			log.Printf("[%s] Peer %s still not reachable", p.NodeID, peerID)
			return false
		}
		conn.Close()
	}

	log.Printf("[%s] All peers are reachable!", p.NodeID)
	return true
}

// waitForPeersSubset checks that a subset of peers (by node ID) are reachable via P2P.
func (p *TSSPeer) waitForPeersSubset(peerIDs []string, timeout time.Duration) bool {
	if len(peerIDs) == 0 {
		return true
	}

	targets := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		if strings.TrimSpace(id) == "" {
			continue
		}
		shortID := p.extractShortNodeID(id)
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

	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 2 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}

	deadline := time.Now().Add(timeout)

	for peerID := range targets {
		addr, ok := peers[peerID]
		if !ok {
			log.Printf("[%s] Peer %s address not found in discovery", p.NodeID, peerID)
			return false
		}

		for time.Now().Before(deadline) {
			conn, err := tlsDialer.DialContext(context.Background(), "tcp", addr)
			if err == nil {
				conn.Close()
				log.Printf("[%s] Peer %s is reachable at %s (TLS)", p.NodeID, peerID, addr)
				break
			}
			log.Printf("[%s] Waiting for peer %s at %s...", p.NodeID, peerID, addr)
			time.Sleep(2 * time.Second)
		}

		// Final check
		conn, err := tlsDialer.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			log.Printf("[%s] Peer %s still not reachable", p.NodeID, peerID)
			return false
		}
		conn.Close()
	}

	log.Printf("[%s] All targeted peers are reachable!", p.NodeID)
	return true
}

// ===================== CSR POLLING & AUTO-VOTING =====================

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

		// Auto-vote approve (in production, you'd validate the CSR)
		log.Printf("[%s] Auto-voting on CSR proposal %s", p.NodeID, proposalID)
		_, err := p.Execute("VoteOnCSR", proposalID, "approve", "Autonomous approval")
		if err != nil {
			errMsg := err.Error()
			// Stop retrying permanently on non-transient errors
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "revoked") {
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

// ===================== RESHARE SESSION POLLING =====================

func (p *TSSPeer) checkReshareSessions() {
	// Get CA to check epoch
	ca, err := p.GetCA()
	if err != nil {
		return
	}

	// Check if we're still a CA member - if not, skip reshare entirely
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
		return
	}
	if isKeygen {
		// Avoid interleaving reshare while DKG/keygen is running.
		return
	}

	// Check for reshare at current epoch
	result, err := p.Query("GetReshareSession", fmt.Sprintf("%d", int(epoch)))
	if err != nil {
		// "not found" is expected when no reshare is active; avoid log spam.
		if containsIgnoreCase(err.Error(), "reshare session not found") {
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

	switch status {
	case "initiated":
		// Check if we already acknowledged
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
			// We've been removed from the CA - mark this epoch done so we stop retrying
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
			// If we're not in the node set, stop retrying
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

		// Verify we are in the new node set
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

		targetPeers := make([]string, 0, len(newNodeSet))
		for _, m := range newNodeSet {
			targetPeers = append(targetPeers, p.extractShortNodeID(m))
		}
		if !p.waitForPeersSubset(targetPeers, 30*time.Second) {
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
		// Reshare completion proposed; acknowledge if we have a key share
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
		p.mutex.RLock()
		keyShare := p.TSSKeyShare
		p.mutex.RUnlock()
		if keyShare == nil || keyShare.ECDSAPub == nil {
			return
		}
		pubBytes := elliptic.Marshal(keyShare.ECDSAPub.Curve(), keyShare.ECDSAPub.X(), keyShare.ECDSAPub.Y())
		pubKeyHex := hex.EncodeToString(pubBytes)
		log.Printf("[%s] Reshare completion proposed; acknowledging with local public key", p.NodeID)
		p.completeReshare(int(epoch), pubKeyHex)

	case "completed":
		shouldEmit := false
		p.mutex.Lock()
		if !p.completedEpochs[int(epoch)] {
			p.completedEpochs[int(epoch)] = true
		}
		if !p.observedReshares[int(epoch)] {
			p.observedReshares[int(epoch)] = true
			shouldEmit = true
		}
		p.mutex.Unlock()
		if shouldEmit {
			reason, _ := reshare["triggerReason"].(string)
			p.emitMetric("reshare_complete_observed", map[string]interface{}{
				"epoch":  int(epoch),
				"reason": reason,
			})
		}
	case "superseded":
		p.mutex.Lock()
		p.completedEpochs[int(epoch)] = true
		p.mutex.Unlock()
		return
	}
}

// ===================== REVOCATION AUTO-VOTING =====================

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
		if targetID, ok := proposal["targetMemberId"].(string); ok && targetID != "" {
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
			p.logAutoVoteSkip("revocation", proposalID, "not a CA member")
			continue
		}

		// Auto-vote approve on revocations
		log.Printf("[%s] Auto-voting approve on revocation proposal %s", p.NodeID, proposalID)
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

	type metricEvent struct {
		name   string
		fields map[string]interface{}
	}
	events := make([]metricEvent, 0)
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
			events = append(events, metricEvent{
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
					events = append(events, metricEvent{
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

	type metricEvent struct {
		name   string
		fields map[string]interface{}
	}
	events := make([]metricEvent, 0)

	p.mutex.Lock()
	for proposalID, candidate := range p.pendingJoinRequests {
		if candidate != "" && memberSet[candidate] && !p.observedJoinApprovals[proposalID] {
			p.observedJoinApprovals[proposalID] = true
			delete(p.pendingJoinRequests, proposalID)
			events = append(events, metricEvent{
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
			events = append(events, metricEvent{
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

		// Auto-vote approve (placeholder; replace with policy validation as needed)
		log.Printf("[%s] Auto-voting on join request %s", p.NodeID, proposalID)
		_, err := p.Execute("VoteOnJoinRequest", DefaultCAID, proposalID, "approve", "Autonomous approval")
		if err != nil {
			errMsg := err.Error()
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "not a member") ||
				containsIgnoreCase(errMsg, "revoked") {
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

// ===================== SPONSORSHIP AUTO-ENDORSE =====================

func (p *TSSPeer) checkPendingSponsorships() {
	result, err := p.Query("ListPendingSponsorships", DefaultCAID)
	if err != nil {
		return
	}

	if len(result) == 0 || string(result) == "null" {
		return
	}

	var sponsorships []map[string]interface{}
	if err := json.Unmarshal(result, &sponsorships); err != nil {
		return
	}

	for _, s := range sponsorships {
		memberID, _ := s["memberId"].(string)
		if memberID == "" {
			continue
		}
		status, _ := s["status"].(string)
		if status != "" && status != "pending" {
			continue
		}

		alreadyEndorsed := false
		if endorsementsRaw, ok := s["endorsements"].([]interface{}); ok {
			for _, e := range endorsementsRaw {
				if eStr, ok := e.(string); ok && eStr == p.MemberID {
					alreadyEndorsed = true
					break
				}
			}
		}
		if alreadyEndorsed {
			continue
		}

		if !p.isCAMember() {
			p.logAutoVoteSkip("sponsorship", memberID, "not a CA member")
			continue
		}

		log.Printf("[%s] Auto-endorsing sponsored member %s", p.NodeID, memberID)
		_, err := p.Execute("EndorseSponsoredMember", DefaultCAID, memberID)
		if err != nil {
			errMsg := err.Error()
			if containsIgnoreCase(errMsg, "already endorsed") ||
				containsIgnoreCase(errMsg, "already") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "not a member") ||
				containsIgnoreCase(errMsg, "revoked") {
				continue
			}
			log.Printf("[%s] Failed to endorse sponsored member %s: %v", p.NodeID, memberID, err)
		} else {
			log.Printf("[%s] Endorsed sponsored member %s", p.NodeID, memberID)
			p.emitMetric("sponsorship_endorsed", map[string]interface{}{
				"member_id": memberID,
			})
		}
	}
}

// ===================== MEMBER REMOVAL AUTO-VOTING =====================

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
			p.logAutoVoteSkip("member_removal", proposalID, "not a CA member")
			continue
		}

		// Auto-vote approve (placeholder; replace with policy validation as needed)
		log.Printf("[%s] Auto-voting approve on member removal %s", p.NodeID, proposalID)
		_, err := p.Execute("VoteOnRemoveMember", DefaultCAID, proposalID, "approve", "auto-approved by peer")
		if err != nil {
			errMsg := err.Error()
			if containsIgnoreCase(errMsg, "already voted") ||
				containsIgnoreCase(errMsg, "not authorized") ||
				containsIgnoreCase(errMsg, "not a member") ||
				containsIgnoreCase(errMsg, "revoked") {
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

// ===================== TSS KEYGEN =====================

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

	// Create channels for TSS protocol
	outCh := make(chan tss.Message, len(partyIDs)*20)
	endCh := make(chan keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// Create keygen party with or without pre-params
	var party tss.Party
	if p.TSSPreParams != nil {
		log.Printf("[%s] Using pre-generated parameters", p.NodeID)
		party = keygen.NewLocalParty(params, outCh, endCh, *p.TSSPreParams)
	} else {
		log.Printf("[%s] No pre-params, will generate on the fly (slower)", p.NodeID)
		party = keygen.NewLocalParty(params, outCh, endCh)
	}

	// Start message handler goroutine
	p.wg.Add(1)
	go p.handleTSSKeygenMessages(party, partyIDs, outCh, endCh, errCh, epoch, myIndex, members)

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

func (p *TSSPeer) handleTSSKeygenMessages(
	party tss.Party,
	partyIDs []*tss.PartyID,
	outCh <-chan tss.Message,
	endCh <-chan keygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	epoch int,
	myIndex int,
	members []string,
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
						SessionID:   fmt.Sprintf("dkg-%d", epoch),
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
						SessionID:   fmt.Sprintf("dkg-%d", epoch),
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

func (p *TSSPeer) handleTSSReshareParty(
	role string,
	party tss.Party,
	partyID *tss.PartyID,
	oldCommittee *reshareCommittee,
	newCommittee *reshareCommittee,
	partyKeyToNodeID map[string]string,
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
			if msg == nil {
				continue
			}

			wireBytes, routing, err := msg.WireBytes()
			if err != nil {
				log.Printf("[%s] Reshare %s-committee failed to get wire bytes: %v", p.NodeID, role, err)
				continue
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
				toCommittee := partyPtrToCommittee[pid]
				if routing.From != nil && pid.KeyInt().Cmp(routing.From.KeyInt()) == 0 {
					continue
				}
				targetNodeID := partyKeyToNodeID[hex.EncodeToString(pid.Key)]
				if targetNodeID == "" {
					log.Printf("[%s] Reshare %s-committee unknown target for party %s", p.NodeID, role, pid.Id)
					continue
				}
				fromCommittee := role
				if routing.From != nil {
					if c, ok := partyPtrToCommittee[routing.From]; ok && c != "" {
						fromCommittee = c
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

		case incomingMsg := <-incoming:
			if incomingMsg == nil {
				continue
			}
			messagesReceived++

			var fromParty *tss.PartyID
			switch incomingMsg.FromCommittee {
			case "old":
				fromParty = oldCommittee.nodeIDToParty[incomingMsg.From]
				if fromParty == nil && incomingMsg.FromIndex >= 0 && incomingMsg.FromIndex < len(oldCommittee.partyIDs) {
					fromParty = oldCommittee.partyIDs[incomingMsg.FromIndex]
				}
			case "new":
				fromParty = newCommittee.nodeIDToParty[incomingMsg.From]
				if fromParty == nil && incomingMsg.FromIndex >= 0 && incomingMsg.FromIndex < len(newCommittee.partyIDs) {
					fromParty = newCommittee.partyIDs[incomingMsg.FromIndex]
				}
			default:
				fromParty = newCommittee.nodeIDToParty[incomingMsg.From]
				if fromParty == nil && incomingMsg.FromIndex >= 0 && incomingMsg.FromIndex < len(newCommittee.partyIDs) {
					fromParty = newCommittee.partyIDs[incomingMsg.FromIndex]
				}
			}

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
			if isNew {
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

func (p *TSSPeer) getNodeIDForPartyIndex(index int) string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if nodeID, ok := p.partyIndexMap[index]; ok {
		return nodeID
	}
	// Fallback
	if index == 0 {
		return "org1-peer"
	}
	return "org2-peer"
}

func (p *TSSPeer) updatePartyIndexMap(members []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.partyIndexMap = make(map[int]string)
	for i, member := range members {
		p.partyIndexMap[i] = p.extractShortNodeID(member)
	}
}

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
		p.mutex.Lock()
		p.keygenInProgress = false
		p.keygenEpoch = -1
		p.mutex.Unlock()
		select {
		case <-p.keygenDone:
		default:
			close(p.keygenDone)
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

	oldCommittee := (*reshareCommittee)(nil)
	newCommittee := (*reshareCommittee)(nil)
	if oldSalt != "" || newSalt != "" {
		oldCommittee = p.buildReshareCommittee(oldMembers, "old", oldSalt)
		newCommittee = p.buildReshareCommittee(newMembers, "new", newSalt)
		if isOldMember && keyShare != nil && !keyShareMatchesPartyIDs(keyShare, oldCommittee.partyIDs) {
			altOldSalt := ""
			if oldSalt == "" {
				altOldSalt = "new"
			}
			altOldCommittee := p.buildReshareCommittee(oldMembers, "old", altOldSalt)
			if keyShareMatchesPartyIDs(keyShare, altOldCommittee.partyIDs) {
				log.Printf("[%s] Reshare old party salt mismatch; overriding old salt %q -> %q", p.NodeID, oldSalt, altOldSalt)
				oldSalt = altOldSalt
				oldCommittee = altOldCommittee
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
		if keyShareContainsPartyIDs(keyShare, oldCommittee.partyIDs) {
			subset := keygen.BuildLocalSaveDataSubset(*keyShare, oldCommittee.partyIDs)
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
	if (oldPartyID != nil || keyCollidesWithOld) && !hasOld {
		if newPartyID != nil && oldThreshold <= 1 {
			allowNewOnly = true
			log.Printf("[%s] Missing old key share (oldT=%d); proceeding as new committee only", p.NodeID, oldThreshold)
		} else {
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
	}

	oldCtx := tss.NewPeerContext(oldCommittee.partyIDs)
	newCtx := tss.NewPeerContext(newCommittee.partyIDs)

	partyKeyToNodeID := make(map[string]string)
	for nodeID, pid := range oldCommittee.nodeIDToParty {
		partyKeyToNodeID[hex.EncodeToString(pid.Key)] = nodeID
	}
	for nodeID, pid := range newCommittee.nodeIDToParty {
		partyKeyToNodeID[hex.EncodeToString(pid.Key)] = nodeID
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
				p.mutex.Lock()
				p.keygenInProgress = false
				p.keygenEpoch = -1
				p.mutex.Unlock()
				select {
				case <-p.keygenDone:
				default:
					close(p.keygenDone)
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
		go p.handleTSSReshareParty(roleLabel, party, oldPartyID, oldCommittee, newCommittee, partyKeyToNodeID, partyPtrToCommittee, oldIn, oldOutCh, oldEndCh, oldErrCh, epoch, false, newThreshold, markDone)

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
		save := keygen.NewLocalPartySaveData(len(newCommittee.partyIDs))
		if preParams != nil {
			save.LocalPreParams = *preParams
		}
		party := resharing.NewLocalParty(params, save, newOutCh, newEndCh)
		setResharePartyECDSAPub(party, pubPoint)

		p.wg.Add(1)
		go p.handleTSSReshareParty("new", party, newPartyID, oldCommittee, newCommittee, partyKeyToNodeID, partyPtrToCommittee, newIn, newOutCh, newEndCh, newErrCh, epoch, true, newThreshold, markDone)

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
					if v, ok := dkg["completionAckCount"].(float64); ok {
						ackCount = int(v)
					}
					if members, ok := dkg["members"].([]interface{}); ok {
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

func (p *TSSPeer) completeReshare(epoch int, publicKey string) {
	log.Printf("[%s] Completing reshare (epoch %d) with public key...", p.NodeID, epoch)
	p.emitMetric("reshare_complete_submitted", map[string]interface{}{
		"epoch": epoch,
	})
	_, err := p.Execute("CompleteReshare", fmt.Sprintf("%d", epoch), publicKey)
	if err != nil {
		if containsIgnoreCase(err.Error(), "already") || containsIgnoreCase(err.Error(), "not acknowledged") {
			log.Printf("[%s] Reshare completion already in progress: %v", p.NodeID, err)
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

// ===================== TSS SIGNING =====================

func (p *TSSPeer) executeTSSSigning(proposalID, csrHash string) {
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

	// Wait for peers
	if !p.waitForPeers(30 * time.Second) {
		log.Printf("[%s] Not all peers reachable for signing", p.NodeID)
		return
	}

	// Parse the CSR hash as the message to sign
	hashBytes, err := hex.DecodeString(csrHash)
	if err != nil {
		log.Printf("[%s] Failed to decode CSR hash: %v", p.NodeID, err)
		return
	}

	// TSS-lib expects a 32-byte hash
	if len(hashBytes) != 32 {
		// Re-hash to get 32 bytes
		h := sha256.Sum256(hashBytes)
		hashBytes = h[:]
	}

	message := new(big.Int).SetBytes(hashBytes)
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

	// Create signing party - need to wrap endCh since signing.NewLocalParty expects value channel
	// Note: The lint warning about mutex copy is safe here - SignatureData's mutex is internal to protobuf
	valueEndCh := make(chan common.SignatureData, 1)
	go func() {
		select {
		case sig, ok := <-valueEndCh:
			if !ok {
				return
			}
			// Extract fields we need - the mutex is internal to proto message
			endCh <- &common.SignatureData{
				R:                 sig.R,
				S:                 sig.S,
				Signature:         sig.Signature,
				SignatureRecovery: sig.SignatureRecovery,
				M:                 sig.M,
			}
		case <-p.ctx.Done():
			return
		}
	}()
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
				p.mutex.Lock()
				p.completedProposals[proposalID] = true
				p.mutex.Unlock()
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

			// Mark this proposal as completed so we don't retry it
			p.mutex.Lock()
			p.completedProposals[proposalID] = true
			p.mutex.Unlock()

			// Submit partial signature to blockchain
			p.submitPartialSignature(proposalID, sig)
			return
		}
	}
}

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
			// Another peer likely completed registration. If we are the owner,
			// sync the cert from chaincode so it is saved locally.
			go p.syncOwnedCertificateWithRetry(5, 2*time.Second)
			return
		}
		log.Printf("[%s] Failed to submit partial signature: %v", p.NodeID, err)
		return
	}

	log.Printf("[%s] OK Partial signature submitted for %s", p.NodeID, proposalID)
	p.emitMetric("partial_signature_submitted", map[string]interface{}{
		"proposal_id": proposalID,
	})

	// Every peer tries to register the certificate after submitting their partial sig.
	// The first to succeed wins; others get a harmless "already registered" error.
	go p.tryRegisterCertificate(proposalID, sigR, sigS)
}

func (p *TSSPeer) tryRegisterCertificate(proposalID, sigR, sigS string) {
	// Wait a bit for other signatures
	time.Sleep(5 * time.Second)

	// Get signing session to check if completed
	result, err := p.Query("GetSigningSession", proposalID)
	if err != nil {
		log.Printf("[%s] Failed to get signing session: %v", p.NodeID, err)
		return
	}

	var session map[string]interface{}
	if err := json.Unmarshal(result, &session); err != nil {
		return
	}

	status, _ := session["status"].(string)
	if status != "completed" {
		log.Printf("[%s] Signing session not completed yet", p.NodeID)
		return
	}

	// Get the CSR proposal to get member info and CSR data
	proposalResult, err := p.Query("GetCSRProposal", proposalID)
	if err != nil {
		log.Printf("[%s] Failed to get CSR proposal: %v", p.NodeID, err)
		return
	}

	var proposal map[string]interface{}
	if err := json.Unmarshal(proposalResult, &proposal); err != nil {
		return
	}

	csrData, _ := proposal["csrData"].(string)
	memberID, _ := proposal["memberId"].(string)

	// Parse the CSR PEM to extract subject and public key
	csrBlock, _ := pem.Decode([]byte(csrData))
	if csrBlock == nil {
		log.Printf("[%s] Failed to decode CSR PEM", p.NodeID)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		log.Printf("[%s] Failed to parse CSR: %v", p.NodeID, err)
		return
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Printf("[%s] Failed to generate serial number: %v", p.NodeID, err)
		return
	}

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

	isOwner := memberID != "" && memberID == p.MemberID
	if !isOwner {
		// Give the owner a small head start to avoid unnecessary races.
		time.Sleep(2 * time.Second)
	}

	// Build a proper X.509 certificate using the CSR data + TSS signature
	now := time.Now().UTC()
	validityDays := 365

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		Issuer: pkix.Name{
			CommonName:   "Decentralized PKI CA",
			Organization: []string{"BPKI"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Copy SANs from CSR
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Decentralized PKI CA",
			Organization: []string{"BPKI"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
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
	certDER, err := buildX509WithTSSSignature(certTemplate, issuerTemplate, csr.PublicKey, rBytes, sBytes)
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

	// Extract subject string and public key hex for the chaincode record
	subject := csr.Subject.String()
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	publicKeyHex := hex.EncodeToString(pubKeyBytes)

	serialNumberStr := serialNumber.String()

	log.Printf("[%s] Registering X.509 certificate for %s...", p.NodeID, memberID)

	_, err = p.Execute("RegisterCombinedCertificateWithSignature",
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

	if err != nil {
		// Handle race: another peer may have already registered
		if containsIgnoreCase(err.Error(), "already") || containsIgnoreCase(err.Error(), "MVCC_READ_CONFLICT") {
			log.Printf("[%s] Certificate already registered for %s (another peer beat us)", p.NodeID, memberID)
		} else {
			log.Printf("[%s] Failed to register certificate: %v", p.NodeID, err)
		}
		// If we're the owner, try to sync the cert from chaincode.
		if isOwner {
			p.syncOwnedCertificateWithRetry(5, 2*time.Second)
		}
		if caPublicKeyHex != "" {
			p.persistCAPublicKeyHex(caPublicKeyHex)
		}
		return
	}

	log.Printf("[%s] OK X.509 certificate registered for %s!", p.NodeID, memberID)
	p.emitMetric("cert_registered", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   memberID,
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
		log.Printf("[%s] Skipping certificate save for %s (owned by %s)", p.NodeID, proposalID, memberID)
	}

	// Also save CA public key for verification
	if caPublicKeyHex != "" {
		p.persistCAPublicKeyHex(caPublicKeyHex)
	}
}

// buildX509WithTSSSignature constructs a DER-encoded X.509 certificate
// using the TSS-generated ECDSA signature (R, S) as the certificate signature.
// This creates a structurally valid X.509 cert that OpenSSL can parse.
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

func (p *TSSPeer) SubmitCSR(cn, org, locality, province, country string) (string, error) {
	return p.SubmitCSRWithID(cn, org, locality, province, country, "")
}

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

// Helper for ECDSA key generation
func ecdsa256GenerateKey() (interface{}, error) {
	return ecdsa256GenerateKeyInternal()
}

func ecdsa256GenerateKeyInternal() (interface{}, error) {
	curve := elliptic.P256()
	key, err := ecdsa256GenerateKeyWithCurve(curve)
	return key, err
}

func ecdsa256GenerateKeyWithCurve(curve elliptic.Curve) (interface{}, error) {
	type ecdsaKey struct {
		D, X, Y *big.Int
		Curve   elliptic.Curve
	}

	d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ecdsaKey{D: new(big.Int).SetBytes(d), X: x, Y: y, Curve: curve}, nil
}

func base64Encode(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(data)+2)/3*4)

	for i := 0; i < len(data); i += 3 {
		var n uint32
		remaining := len(data) - i

		n = uint32(data[i]) << 16
		if remaining > 1 {
			n |= uint32(data[i+1]) << 8
		}
		if remaining > 2 {
			n |= uint32(data[i+2])
		}

		result = append(result, base64Chars[(n>>18)&0x3F])
		result = append(result, base64Chars[(n>>12)&0x3F])

		if remaining > 1 {
			result = append(result, base64Chars[(n>>6)&0x3F])
		} else {
			result = append(result, '=')
		}

		if remaining > 2 {
			result = append(result, base64Chars[n&0x3F])
		} else {
			result = append(result, '=')
		}
	}

	return string(result)
}

// ===================== HELPERS =====================

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
		orgDomain := envOrDefault("TSS_DOMAIN", org+".example.com")
		stateDir := envOrDefault("TSS_STATE_DIR", filepath.Join("state", org))
		joinMode := normalizeJoinMode(envOrDefault("TSS_JOIN_MODE", "none"))
		mspUser := envOrDefault("TSS_MSP_USER", envOrDefault("TSS_USER", fmt.Sprintf("Admin@%s", orgDomain)))

		return &GatewayConfig{
			MSPID:        envMSPID,
			CryptoPath:   os.Getenv("TSS_CRYPTO_PATH"),
			OrgDomain:    orgDomain,
			MSPUser:      mspUser,
			PeerEndpoint: envOrDefault("TSS_PEER_ENDPOINT", "localhost:7051"),
			PeerHostname: envOrDefault("TSS_PEER_HOSTNAME", "peer0."+org+".example.com"),
			P2PPort:      p2pPortInt,
			P2PAdvertise: envOrDefault("TSS_P2P_ADVERTISE", fmt.Sprintf("localhost:%d", p2pPortInt)),
			WebUIPort:    webuiPortInt,
			StateDir:     stateDir,
			JoinMode:     joinMode,
		}
	}

	// Built-in defaults for local development (original test-network on one machine)
	orgNum := strings.TrimPrefix(org, "org")
	switch org {
	case "org2":
		return &GatewayConfig{
			MSPID:        "Org2MSP",
			CryptoPath:   findCryptoPath("org2.example.com"),
			OrgDomain:    "org2.example.com",
			MSPUser:      "Admin@org2.example.com",
			PeerEndpoint: "localhost:9051",
			PeerHostname: "peer0.org2.example.com",
			P2PPort:      6002,
			P2PAdvertise: "localhost:6002",
			WebUIPort:    8081,
			StateDir:     filepath.Join("state", org),
			JoinMode:     "none",
		}
	case "org1":
		return &GatewayConfig{
			MSPID:        "Org1MSP",
			CryptoPath:   findCryptoPath("org1.example.com"),
			OrgDomain:    "org1.example.com",
			MSPUser:      "Admin@org1.example.com",
			PeerEndpoint: "localhost:7051",
			PeerHostname: "peer0.org1.example.com",
			P2PPort:      6001,
			P2PAdvertise: "localhost:6001",
			WebUIPort:    8080,
			StateDir:     filepath.Join("state", org),
			JoinMode:     "none",
		}
	default:
		// Dynamic default for org3, org4, ... org10
		n := 0
		fmt.Sscanf(orgNum, "%d", &n)
		return &GatewayConfig{
			MSPID:        fmt.Sprintf("Org%sMSP", orgNum),
			CryptoPath:   findCryptoPath(fmt.Sprintf("org%s.example.com", orgNum)),
			OrgDomain:    fmt.Sprintf("org%s.example.com", orgNum),
			MSPUser:      fmt.Sprintf("Admin@org%s.example.com", orgNum),
			PeerEndpoint: fmt.Sprintf("localhost:%d", 7051+2000*(n-1)),
			PeerHostname: fmt.Sprintf("peer0.org%s.example.com", orgNum),
			P2PPort:      6000 + n,
			P2PAdvertise: fmt.Sprintf("localhost:%d", 6000+n),
			WebUIPort:    8079 + n,
			StateDir:     filepath.Join("state", org),
			JoinMode:     "none",
		}
	}
}

// envOrDefault returns the value of an environment variable or a default.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

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

func normalizeJoinMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "member", "full", "ca":
		return "member"
	case "observer", "observe":
		return "observer"
	case "request", "apply":
		return "request"
	case "none", "skip", "disabled", "no":
		return "none"
	default:
		return "none"
	}
}

// findCryptoPath looks for crypto material in common locations.
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

func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ===================== INTERACTIVE MENU =====================

func (p *TSSPeer) StartInteractiveMenu() {
	reader := bufio.NewReader(os.Stdin)

	time.Sleep(2 * time.Second) // Wait for initial setup to complete

	for {
		fmt.Println("\n========== TSS Peer Menu ==========")
		fmt.Println("1. View CA State")
		fmt.Println("2. Submit CSR (Certificate Request)")
		fmt.Println("3. List Issued Certificates")
		fmt.Println("4. Propose Certificate Revocation")
		fmt.Println("5. View Certificate Merkle Tree")
		fmt.Println("6. View My Key Share Info")
		fmt.Println("7. Show My Member ID")
		fmt.Println("8. Advanced Options >>>")
		if p.webServer != nil {
			fmt.Println("9. Stop Web UI")
		} else {
			fmt.Println("9. Start Web UI")
		}
		fmt.Println("0. Exit")
		fmt.Print("Select option: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			p.displayCAState()
		case "2":
			p.submitCSRMenu(reader)
		case "3":
			p.listIssuedCertificates()
		case "4":
			p.proposeRevocationMenu(reader)
		case "5":
			p.viewCertificateMerkleTree()
		case "6":
			p.viewKeyShareInfo()
		case "7":
			p.showMyMemberID()
		case "8":
			p.advancedMenu(reader)
		case "9":
			p.toggleWebUI()
		case "0":
			fmt.Println("Use Ctrl+C to exit properly")
		default:
			fmt.Println("Invalid option")
		}
	}
}

func (p *TSSPeer) advancedMenu(reader *bufio.Reader) {
	for {
		fmt.Println("\n--- Advanced Options ---")
		fmt.Println("1. View DKG Session")
		fmt.Println("2. Trigger Manual DKG Acknowledge")
		fmt.Println("3. Initiate DKG Manually")
		fmt.Println("4. View Pending CSR Proposals")
		fmt.Println("5. View Signing Sessions")
		fmt.Println("6. View Pending Revocations")
		fmt.Println("7. Sponsor New Member")
		fmt.Println("8. Endorse Sponsored Member")
		fmt.Println("9. List Pending Sponsorships")
		fmt.Println("10. View Node Role")
		fmt.Println("11. Promote Observer to Full Member")
		fmt.Println("12. Force Reshare (Manual)")
		fmt.Println("13. Request CA Membership (Self)")
		fmt.Println("14. Vote on Join Request")
		fmt.Println("15. List Pending Join Requests")
		fmt.Println("16. Propose Member Removal")
		fmt.Println("17. Vote on Member Removal")
		fmt.Println("18. List Pending Member Removals")
		fmt.Println("19. Force Fresh DKG (Reset CA Key)")
		fmt.Println("0. Back to Main Menu")
		fmt.Print("Select option: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			p.displayDKGSession()
		case "2":
			p.manualAcknowledgeDKG()
		case "3":
			p.manualInitiateDKG()
		case "4":
			p.viewPendingCSRs()
		case "5":
			p.viewSigningSessions()
		case "6":
			p.viewPendingRevocations()
		case "7":
			p.sponsorNewMember(reader)
		case "8":
			p.endorseSponsoredMember(reader)
		case "9":
			p.listPendingSponsorships()
		case "10":
			p.viewNodeRole()
		case "11":
			p.promoteObserverMenu(reader)
		case "12":
			p.forceReshareMenu(reader)
		case "13":
			p.requestJoinMenu(reader)
		case "14":
			p.voteJoinRequestMenu(reader)
		case "15":
			p.listPendingJoinRequests()
		case "16":
			p.proposeRemoveMemberMenu(reader)
		case "17":
			p.voteRemoveMemberMenu(reader)
		case "18":
			p.listPendingRemoveMemberProposals()
		case "19":
			p.manualFreshDKG(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option")
		}
	}
}

func (p *TSSPeer) displayCAState() {
	ca, err := p.GetCA()
	if err != nil {
		fmt.Printf("Error getting CA state: %v\n", err)
		return
	}
	caJSON, _ := json.MarshalIndent(ca, "", "  ")
	fmt.Printf("\nCA State:\n%s\n", caJSON)
}

func (p *TSSPeer) displayDKGSession() {
	dkg, err := p.GetDKGSession(0)
	if err != nil {
		fmt.Printf("Error getting DKG session: %v\n", err)
		return
	}
	dkgJSON, _ := json.MarshalIndent(dkg, "", "  ")
	fmt.Printf("\nDKG Session:\n%s\n", dkgJSON)
}

func (p *TSSPeer) sponsorNewMember(reader *bufio.Reader) {
	fmt.Print("Enter new member ID (canonical x509::... or base64; you can also type a substring to match known members): ")
	rawID, _ := reader.ReadString('\n')
	memberID, err := p.resolveMemberIDInput(rawID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Print("Enter reason for sponsorship: ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)

	if err := ensureCanonicalOrExternal(memberID); err != nil {
		fmt.Printf("Invalid member ID: %v\n", err)
		fmt.Println("Hint: use canonical x509::... (or base64(x509::...)) for Fabric identities.")
		return
	}

	err = p.SponsorJoinCA(memberID, reason)
	if err != nil {
		fmt.Printf("Error sponsoring member: %v\n", err)
		return
	}
	fmt.Printf("Successfully sponsored %s\n", memberID)
}

func (p *TSSPeer) SponsorJoinCA(newMemberID, reason string) error {
	_, err := p.contract.SubmitTransaction("SponsorJoinCA", "root-ca-001", newMemberID, reason)
	return err
}

func (p *TSSPeer) endorseSponsoredMember(reader *bufio.Reader) {
	fmt.Print("Enter member ID to endorse (canonical x509::... or base64; you can also type a substring to match known members): ")
	rawID, _ := reader.ReadString('\n')
	memberID, err := p.resolveMemberIDInput(rawID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if err := ensureCanonicalOrExternal(memberID); err != nil {
		fmt.Printf("Invalid member ID: %v\n", err)
		fmt.Println("Hint: use canonical x509::... (or base64(x509::...)) for Fabric identities.")
		return
	}

	err = p.EndorseSponsoredMember(memberID)
	if err != nil {
		fmt.Printf("Error endorsing member: %v\n", err)
		return
	}
	fmt.Printf("Successfully endorsed %s\n", memberID)
}

func (p *TSSPeer) EndorseSponsoredMember(memberID string) error {
	_, err := p.contract.SubmitTransaction("EndorseSponsoredMember", "root-ca-001", memberID)
	return err
}

func (p *TSSPeer) listPendingSponsorships() {
	result, err := p.contract.EvaluateTransaction("ListPendingSponsorships", "root-ca-001")
	if err != nil {
		fmt.Printf("Error listing sponsorships: %v\n", err)
		return
	}

	var sponsorships []map[string]interface{}
	if err := json.Unmarshal(result, &sponsorships); err != nil {
		fmt.Printf("Error parsing sponsorships: %v\n", err)
		return
	}

	if len(sponsorships) == 0 {
		fmt.Println("\nNo pending sponsorships")
		return
	}

	fmt.Println("\n=== Pending Sponsorships ===")
	for i, s := range sponsorships {
		fmt.Printf("%d. Member: %v\n", i+1, s["member_id"])
		fmt.Printf("   Sponsored by: %v\n", s["sponsored_by"])
		fmt.Printf("   Endorsements: %v\n", s["endorsements"])
		fmt.Printf("   Required: %v\n", s["required_endorsements"])
		fmt.Printf("   Reason: %v\n", s["reason"])
		fmt.Println()
	}
}

func (p *TSSPeer) requestJoinMenu(reader *bufio.Reader) {
	fmt.Print("Enter reason for join request: ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)

	fmt.Print("Enter proposal ID (blank = auto): ")
	proposalID, _ := reader.ReadString('\n')
	proposalID = strings.TrimSpace(proposalID)
	if proposalID == "" {
		proposalID = fmt.Sprintf("join-%s-%d", p.Organization, time.Now().Unix())
	}

	if err := p.RequestJoinCA(proposalID, reason); err != nil {
		fmt.Printf("Error requesting join: %v\n", err)
		return
	}
	fmt.Printf("OK Join request submitted (%s)\n", proposalID)
}

func (p *TSSPeer) RequestJoinCA(proposalID, reason string) error {
	_, err := p.contract.SubmitTransaction("RequestJoinCA", "root-ca-001", proposalID, reason)
	if err != nil {
		return err
	}
	p.emitMetric("join_request_submitted", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   p.MemberID,
	})
	return nil
}

func (p *TSSPeer) voteJoinRequestMenu(reader *bufio.Reader) {
	// List pending join requests for easy selection
	result, err := p.contract.EvaluateTransaction("ListPendingJoinRequests", "root-ca-001")
	if err != nil {
		fmt.Printf("Error listing join requests: %v\n", err)
		return
	}

	var requests []map[string]interface{}
	if err := json.Unmarshal(result, &requests); err != nil {
		fmt.Printf("Error parsing join requests: %v\n", err)
		return
	}

	if len(requests) == 0 {
		fmt.Println("\nNo pending join requests")
		return
	}

	fmt.Println("\n=== Pending Join Requests ===")
	for i, r := range requests {
		fmt.Printf("%d. Proposal: %v\n", i+1, r["proposalId"])
		fmt.Printf("   Candidate: %v\n", r["candidateId"])
		fmt.Printf("   Reason: %v\n", r["reason"])
		fmt.Println()
	}

	fmt.Print("Enter the number to vote on (or 0 to cancel): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	idx := 0
	fmt.Sscanf(input, "%d", &idx)
	if idx <= 0 || idx > len(requests) {
		fmt.Println("Cancelled")
		return
	}

	proposalID := fmt.Sprintf("%v", requests[idx-1]["proposalId"])

	fmt.Print("Decision (approve/reject): ")
	decision, _ := reader.ReadString('\n')
	decision = strings.TrimSpace(decision)

	fmt.Print("Rationale (optional): ")
	rationale, _ := reader.ReadString('\n')
	rationale = strings.TrimSpace(rationale)

	if proposalID == "" {
		fmt.Println("Proposal ID cannot be empty")
		return
	}

	if err := p.VoteOnJoinRequest(proposalID, decision, rationale); err != nil {
		fmt.Printf("Error voting on join request: %v\n", err)
		return
	}
	fmt.Println("OK Vote submitted")
}

func (p *TSSPeer) VoteOnJoinRequest(proposalID, decision, rationale string) error {
	_, err := p.contract.SubmitTransaction("VoteOnJoinRequest", "root-ca-001", proposalID, decision, rationale)
	return err
}

func (p *TSSPeer) listPendingJoinRequests() {
	result, err := p.contract.EvaluateTransaction("ListPendingJoinRequests", "root-ca-001")
	if err != nil {
		fmt.Printf("Error listing join requests: %v\n", err)
		return
	}

	var requests []map[string]interface{}
	if err := json.Unmarshal(result, &requests); err != nil {
		fmt.Printf("Error parsing join requests: %v\n", err)
		return
	}

	if len(requests) == 0 {
		fmt.Println("\nNo pending join requests")
		return
	}

	fmt.Println("\n=== Pending Join Requests ===")
	for i, r := range requests {
		fmt.Printf("%d. Proposal: %v\n", i+1, r["proposalId"])
		fmt.Printf("   Candidate: %v\n", r["candidateId"])
		fmt.Printf("   Reason: %v\n", r["reason"])
		fmt.Println()
	}
}

func (p *TSSPeer) proposeRemoveMemberMenu(reader *bufio.Reader) {
	// Show current CA members and let user choose
	ca, err := p.GetCA()
	if err != nil {
		fmt.Printf("Error getting CA state: %v\n", err)
		return
	}

	membersRaw, _ := ca["members"].([]interface{})
	if len(membersRaw) == 0 {
		fmt.Println("\nNo CA members found")
		return
	}

	fmt.Println("\n=== CA Members ===")
	memberIDs := make([]string, 0, len(membersRaw))
	for i, m := range membersRaw {
		idStr := fmt.Sprintf("%v", m)
		memberIDs = append(memberIDs, idStr)
		display := idStr
		if len(display) > 60 {
			display = display[:60] + "..."
		}
		fmt.Printf("%d. %s\n", i+1, display)
	}
	fmt.Println()

	fmt.Print("Enter the number of the member to remove (or 0 to cancel): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	idx := 0
	fmt.Sscanf(input, "%d", &idx)
	if idx <= 0 || idx > len(memberIDs) {
		fmt.Println("Cancelled")
		return
	}

	memberID := memberIDs[idx-1]
	shortLabel := strings.TrimSuffix(p.extractShortNodeID(memberID), "-peer")

	fmt.Print("Enter reason for removal: ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)

	fmt.Print("Enter proposal ID (blank = auto): ")
	proposalID, _ := reader.ReadString('\n')
	proposalID = strings.TrimSpace(proposalID)
	if proposalID == "" {
		proposalID = fmt.Sprintf("remove-%s-%d", shortLabel, time.Now().Unix())
	}

	if memberID == "" {
		fmt.Println("Member ID cannot be empty")
		return
	}

	if err := p.ProposeRemoveMember(proposalID, memberID, reason); err != nil {
		fmt.Printf("Error proposing removal: %v\n", err)
		return
	}
	fmt.Printf("Removal proposal submitted (target: %s, id: %s)\n", shortLabel, proposalID)
}

func (p *TSSPeer) ProposeRemoveMember(proposalID, memberID, reason string) error {
	_, err := p.contract.SubmitTransaction("ProposeRemoveMember", "root-ca-001", proposalID, memberID, reason)
	if err != nil {
		return err
	}
	p.emitMetric("member_removal_proposed", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   memberID,
	})
	return nil
}

func (p *TSSPeer) voteRemoveMemberMenu(reader *bufio.Reader) {
	result, err := p.contract.EvaluateTransaction("ListPendingRemoveMemberProposals", "root-ca-001")
	if err != nil {
		fmt.Printf("Error listing removal proposals: %v\n", err)
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		fmt.Printf("Error parsing removal proposals: %v\n", err)
		return
	}

	if len(proposals) == 0 {
		fmt.Println("\nNo pending removal proposals")
		return
	}

	fmt.Println("\n=== Pending Member Removal Proposals ===")
	for i, r := range proposals {
		fmt.Printf("%d. Proposal: %v\n", i+1, r["proposalId"])
		fmt.Printf("   Target: %v\n", r["targetMemberId"])
		fmt.Printf("   Reason: %v\n", r["reason"])
		fmt.Println()
	}

	fmt.Print("Enter the number to vote on (or 0 to cancel): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	idx := 0
	fmt.Sscanf(input, "%d", &idx)
	if idx <= 0 || idx > len(proposals) {
		fmt.Println("Cancelled")
		return
	}

	proposalID := fmt.Sprintf("%v", proposals[idx-1]["proposalId"])

	fmt.Print("Decision (approve/reject): ")
	decision, _ := reader.ReadString('\n')
	decision = strings.TrimSpace(decision)

	fmt.Print("Rationale (optional): ")
	rationale, _ := reader.ReadString('\n')
	rationale = strings.TrimSpace(rationale)

	if proposalID == "" {
		fmt.Println("Proposal ID cannot be empty")
		return
	}

	if err := p.VoteOnRemoveMember(proposalID, decision, rationale); err != nil {
		fmt.Printf("Error voting on removal: %v\n", err)
		return
	}
	fmt.Println("OK Vote submitted")
}

func (p *TSSPeer) VoteOnRemoveMember(proposalID, decision, rationale string) error {
	_, err := p.contract.SubmitTransaction("VoteOnRemoveMember", "root-ca-001", proposalID, decision, rationale)
	return err
}

func (p *TSSPeer) listPendingRemoveMemberProposals() {
	result, err := p.contract.EvaluateTransaction("ListPendingRemoveMemberProposals", "root-ca-001")
	if err != nil {
		fmt.Printf("Error listing removal proposals: %v\n", err)
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		fmt.Printf("Error parsing removal proposals: %v\n", err)
		return
	}

	if len(proposals) == 0 {
		fmt.Println("\nNo pending removal proposals")
		return
	}

	fmt.Println("\n=== Pending Member Removal Proposals ===")
	for i, r := range proposals {
		fmt.Printf("%d. Proposal: %v\n", i+1, r["proposalId"])
		fmt.Printf("   Target: %v\n", r["targetMemberId"])
		fmt.Printf("   Reason: %v\n", r["reason"])
		fmt.Println()
	}
}

func (p *TSSPeer) viewNodeRole() {
	result, err := p.contract.EvaluateTransaction("GetNodeRole", "root-ca-001", p.MemberID)
	if err != nil {
		fmt.Printf("Error getting node role: %v\n", err)
		return
	}
	role := strings.Trim(string(result), "\"")
	fmt.Printf("\nNode: %s\n", p.MemberID)
	switch role {
	case "full":
		fmt.Println("Role: FULL MEMBER (DKG, signing, voting)")
	case "observer":
		fmt.Println("Role: OBSERVER (query, CSR only - no signing/voting)")
	default:
		fmt.Println("Role: NONE (not part of this CA)")
	}
}

func (p *TSSPeer) promoteObserverMenu(reader *bufio.Reader) {
	fmt.Print("Enter observer's member ID to promote: ")
	observerID, _ := reader.ReadString('\n')
	observerID = strings.TrimSpace(observerID)
	if observerID == "" {
		fmt.Println("Cancelled")
		return
	}

	fmt.Print("Reason for promotion: ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)

	_, err := p.contract.SubmitTransaction("PromoteObserver", "root-ca-001", observerID, reason)
	if err != nil {
		fmt.Printf("Error promoting observer: %v\n", err)
		return
	}
	fmt.Printf("OK Promotion endorsed for %s\n", observerID)
}

func (p *TSSPeer) forceReshareMenu(reader *bufio.Reader) {
	fmt.Print("Enter reason for reshare (optional): ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)

	if reason == "" {
		reason = "manual_reshare"
	}

	_, err := p.contract.SubmitTransaction("ForceReshare", DefaultCAID, reason)
	if err != nil {
		fmt.Printf("Error forcing reshare: %v\n", err)
		return
	}

	fmt.Println("OK Reshare initiated")
}

func (p *TSSPeer) manualAcknowledgeDKG() {
	if err := p.AcknowledgeDKG(0); err != nil {
		fmt.Printf("Error acknowledging DKG: %v\n", err)
		return
	}
	fmt.Println("OK DKG acknowledged")
}
func (p *TSSPeer) submitCSRMenu(reader *bufio.Reader) {
	fmt.Println("\n--- Certificate Subject Fields ---")
	fmt.Println("Press Enter to use default values.")

	fmt.Printf("Common Name (CN) [%s-app]: ", p.Organization)
	cn, _ := reader.ReadString('\n')
	cn = strings.TrimSpace(cn)
	if cn == "" {
		cn = fmt.Sprintf("%s-app", p.Organization)
	}

	fmt.Printf("Organization (O) [%s]: ", p.Organization)
	org, _ := reader.ReadString('\n')
	org = strings.TrimSpace(org)
	if org == "" {
		org = p.Organization
	}

	fmt.Print("Locality (L) []: ")
	locality, _ := reader.ReadString('\n')
	locality = strings.TrimSpace(locality)

	fmt.Print("State/Province (ST) []: ")
	province, _ := reader.ReadString('\n')
	province = strings.TrimSpace(province)

	fmt.Print("Country (C) []: ")
	country, _ := reader.ReadString('\n')
	country = strings.TrimSpace(country)

	// Build subject string for display
	subject := fmt.Sprintf("CN=%s,O=%s", cn, org)
	if locality != "" {
		subject += ",L=" + locality
	}
	if province != "" {
		subject += ",ST=" + province
	}
	if country != "" {
		subject += ",C=" + country
	}

	fmt.Printf("Subject: %s\n", subject)

	proposalID, err := p.SubmitCSR(cn, org, locality, province, country)
	if err != nil {
		fmt.Printf("Error submitting CSR: %v\n", err)
		return
	}
	fmt.Printf("OK CSR submitted successfully! (proposal: %s)\n", proposalID)
}

func (p *TSSPeer) viewPendingCSRs() {
	result, err := p.Query("GetPendingCSRProposals")
	if err != nil {
		fmt.Printf("Error getting pending CSRs: %v\n", err)
		return
	}

	// Handle empty or null response
	if len(result) == 0 || string(result) == "null" {
		fmt.Println("\nNo pending CSR proposals")
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		fmt.Printf("No pending CSR proposals (empty response)\n")
		return
	}

	if len(proposals) == 0 {
		fmt.Println("\nNo pending CSR proposals")
		return
	}

	fmt.Println("\n=== Pending CSR Proposals ===")
	for i, p := range proposals {
		fmt.Printf("%d. Proposal ID: %v\n", i+1, p["proposalId"])
		fmt.Printf("   Member: %v\n", p["memberId"])
		fmt.Printf("   Status: %v\n", p["status"])
		fmt.Printf("   Votes For: %v\n", p["votesFor"])
		fmt.Printf("   Votes Against: %v\n", p["votesAgainst"])
		fmt.Println()
	}
}

func (p *TSSPeer) viewSigningSessions() {
	result, err := p.Query("GetPendingSigningSessions")
	if err != nil {
		fmt.Printf("Error getting signing sessions: %v\n", err)
		return
	}

	// Handle empty or null response
	if len(result) == 0 || string(result) == "null" {
		fmt.Println("\nNo active signing sessions")
		return
	}

	var sessions []map[string]interface{}
	if err := json.Unmarshal(result, &sessions); err != nil {
		fmt.Println("\nNo active signing sessions (empty response)")
		return
	}

	if len(sessions) == 0 {
		fmt.Println("\nNo active signing sessions")
		return
	}

	fmt.Println("\n=== Active Signing Sessions ===")
	for i, s := range sessions {
		fmt.Printf("%d. Proposal ID: %v\n", i+1, s["proposalId"])
		fmt.Printf("   CSR Hash: %v\n", s["csrHash"])
		fmt.Printf("   Status: %v\n", s["status"])
		fmt.Printf("   Required Signers: %v\n", s["requiredSigners"])

		if sigs, ok := s["partialSignatures"].([]interface{}); ok {
			fmt.Printf("   Partial Signatures: %d\n", len(sigs))
		}
		fmt.Println()
	}
}

func (p *TSSPeer) viewKeyShareInfo() {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if p.TSSKeyShare == nil {
		fmt.Println("\nNo TSS key share available (DKG not completed)")
		return
	}

	fmt.Println("\n=== TSS Key Share Info ===")
	fmt.Printf("Share ID: %s\n", p.TSSKeyShare.ShareID.String())

	if p.TSSKeyShare.ECDSAPub != nil {
		pubBytes := elliptic.Marshal(
			p.TSSKeyShare.ECDSAPub.Curve(),
			p.TSSKeyShare.ECDSAPub.X(),
			p.TSSKeyShare.ECDSAPub.Y(),
		)
		fmt.Printf("CA Public Key: %s\n", hex.EncodeToString(pubBytes))
	}

	fmt.Printf("Threshold: %d\n", p.Threshold)
	fmt.Printf("My Party Index: %d\n", p.myPartyIndex)
	fmt.Printf("Party IDs cached: %v\n", len(p.cachedPartyIDs) > 0)
}

func (p *TSSPeer) showMyMemberID() {
	fmt.Println("\n=== My Member ID ===")
	fmt.Println("Full ID (use this for sponsorship):")
	fmt.Println(p.MemberID)
	fmt.Println("")
	fmt.Println("To sponsor this peer, run on another peer:")
	fmt.Println("  Menu option 3 -> paste the above ID")
}

func (p *TSSPeer) manualInitiateDKG() {
	fmt.Println("Initiating DKG...")
	_, err := p.Execute("InitiateDKG", DefaultCAID)
	if err != nil {
		fmt.Printf("Error initiating DKG: %v\n", err)
		return
	}
	fmt.Println("OK DKG initiated successfully!")
}

func (p *TSSPeer) manualFreshDKG(reader *bufio.Reader) {
	fmt.Print("Reason for fresh DKG (optional): ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "fresh_dkg"
	}
	fmt.Println("Forcing fresh DKG (this resets the CA public key)...")
	_, err := p.Execute("ForceFreshDKG", DefaultCAID, reason)
	if err != nil {
		fmt.Printf("Error forcing fresh DKG: %v\n", err)
		return
	}
	fmt.Println("OK Fresh DKG initiated successfully!")
}

func (p *TSSPeer) proposeRevocationMenu(reader *bufio.Reader) {
	// First, list certificates so the user can choose
	result, err := p.Query("GetAllCertificates")
	if err != nil {
		fmt.Printf("Error getting certificates: %v\n", err)
		return
	}

	if len(result) == 0 || string(result) == "null" {
		fmt.Println("\nNo issued certificates to revoke")
		return
	}

	var certs []map[string]interface{}
	if err := json.Unmarshal(result, &certs); err != nil {
		fmt.Println("\nNo issued certificates")
		return
	}

	// Filter to non-revoked certificates
	var activeCerts []map[string]interface{}
	for _, c := range certs {
		revoked, _ := c["isRevoked"].(bool)
		if !revoked {
			activeCerts = append(activeCerts, c)
		}
	}

	if len(activeCerts) == 0 {
		fmt.Println("\nNo active certificates to revoke")
		return
	}

	fmt.Println("\n=== Active Certificates ===")
	for i, c := range activeCerts {
		fmt.Printf("%d. Subject: %v\n", i+1, c["subject"])
		if memberID, ok := c["memberId"]; ok {
			idStr := fmt.Sprintf("%v", memberID)
			if len(idStr) > 60 {
				idStr = idStr[:60] + "..."
			}
			fmt.Printf("   Member ID: %v\n", idStr)
		}
		fmt.Println()
	}

	fmt.Print("Enter the number of the certificate to revoke (or 0 to cancel): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	idx := 0
	fmt.Sscanf(input, "%d", &idx)
	if idx <= 0 || idx > len(activeCerts) {
		fmt.Println("Cancelled")
		return
	}

	cert := activeCerts[idx-1]
	targetMemberID := fmt.Sprintf("%v", cert["memberId"])

	fmt.Print("Enter reason for revocation: ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "revoked by CA member"
	}

	proposalID := fmt.Sprintf("revoke-%s-%d", p.Organization, time.Now().Unix())

	displayID := targetMemberID
	if len(displayID) > 60 {
		displayID = displayID[:60] + "..."
	}
	log.Printf("[%s] Proposing revocation for %s", p.NodeID, displayID)
	_, err = p.Execute("ProposeRevocation", proposalID, targetMemberID, reason)
	if err != nil {
		fmt.Printf("Error proposing revocation: %v\n", err)
		return
	}
	fmt.Printf("OK Revocation proposed: %s\n", proposalID)
	fmt.Println("  Other CA members will auto-vote on this proposal.")
	p.emitMetric("revocation_proposed", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   targetMemberID,
	})
}

func (p *TSSPeer) viewPendingRevocations() {
	result, err := p.Query("GetPendingRevocations")
	if err != nil {
		fmt.Printf("Error getting pending revocations: %v\n", err)
		return
	}

	if len(result) == 0 || string(result) == "null" {
		fmt.Println("\nNo pending revocation proposals")
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		fmt.Println("\nNo pending revocation proposals")
		return
	}

	if len(proposals) == 0 {
		fmt.Println("\nNo pending revocation proposals")
		return
	}

	fmt.Println("\n=== Pending Revocation Proposals ===")
	for i, p := range proposals {
		fmt.Printf("%d. Proposal ID: %v\n", i+1, p["proposalId"])
		targetID := fmt.Sprintf("%v", p["targetMemberId"])
		if len(targetID) > 60 {
			targetID = targetID[:60] + "..."
		}
		fmt.Printf("   Target: %v\n", targetID)
		fmt.Printf("   Reason: %v\n", p["reason"])
		fmt.Printf("   Votes For: %v / Against: %v\n", p["votesFor"], p["votesAgainst"])
		fmt.Printf("   Status: %v\n", p["status"])
		fmt.Println()
	}
}

func (p *TSSPeer) listIssuedCertificates() {
	result, err := p.Query("GetAllCertificates")
	if err != nil {
		fmt.Printf("Error getting certificates: %v\n", err)
		return
	}

	// Handle empty or null response
	if len(result) == 0 || string(result) == "null" {
		fmt.Println("\nNo issued certificates")
		return
	}

	var certs []map[string]interface{}
	if err := json.Unmarshal(result, &certs); err != nil {
		fmt.Println("\nNo issued certificates (empty response)")
		return
	}

	if len(certs) == 0 {
		fmt.Println("\nNo issued certificates")
		return
	}

	fmt.Println("\n=== Issued Certificates ===")
	for i, c := range certs {
		fmt.Printf("%d. Subject: %v\n", i+1, c["subject"])
		fmt.Printf("   Serial: %v\n", c["serialNumber"])
		status := "active"
		if revoked, _ := c["isRevoked"].(bool); revoked {
			status = "revoked"
		}
		if s, ok := c["status"].(string); ok && s != "" {
			status = s
		}
		fmt.Printf("   Status: %s\n", status)
		fmt.Printf("   Issued At: %v\n", c["issuedAt"])
		fmt.Printf("   Expires At: %v\n", c["expiresAt"])
		if hash, ok := c["certHash"]; ok {
			hashStr := fmt.Sprintf("%v", hash)
			if len(hashStr) > 20 {
				hashStr = hashStr[:20] + "..."
			}
			fmt.Printf("   Cert Hash: %v\n", hashStr)
		}
		if proposalID, ok := c["proposalId"]; ok {
			fmt.Printf("   Proposal ID: %v\n", proposalID)
		}
		fmt.Println()
	}
	fmt.Printf("Total: %d certificate(s)\n", len(certs))
}

func (p *TSSPeer) viewCertificateMerkleTree() {
	enabled, err := p.GetMerkleEnabled()
	if err != nil {
		fmt.Printf("Error getting Merkle config: %v\n", err)
		return
	}
	if !enabled {
		fmt.Println("\nMerkle tree is disabled.")
		return
	}

	result, err := p.Query("GetCertificateMerkleRoot")
	if err != nil {
		fmt.Printf("Error getting Merkle root: %v\n", err)
		return
	}

	var state map[string]interface{}
	if err := json.Unmarshal(result, &state); err != nil {
		fmt.Printf("Failed to parse Merkle state: %v\n", err)
		return
	}

	fmt.Println("\n=== Certificate Merkle Tree ===")
	root, _ := state["merkleRoot"].(string)
	if root == "" {
		fmt.Println("No Merkle root computed yet (no active certificates)")
		return
	}
	count, _ := state["activeCertCount"].(float64)
	fmt.Printf("  Merkle Root:       %s\n", root)
	fmt.Printf("  Active Certs:      %d\n", int(count))
	fmt.Printf("  Last Updated:      %v\n", state["updatedAt"])
	fmt.Printf("  Trigger Action:    %v\n", state["triggerAction"])
	fmt.Printf("  Trigger Cert ID:   %v\n", state["triggerCertId"])

	if leaves, ok := state["leafHashes"].([]interface{}); ok {
		fmt.Printf("  Leaf Hashes (%d):\n", len(leaves))
		for i, leaf := range leaves {
			h := fmt.Sprintf("%v", leaf)
			if len(h) > 20 {
				h = h[:20] + "..."
			}
			fmt.Printf("    [%d] %s\n", i, h)
		}
	}
}

// ===================== WEB UI =====================

func (p *TSSPeer) toggleWebUI() {
	if p.webServer != nil {
		fmt.Println("Stopping Web UI...")
		p.webServer.Close()
		p.webServer = nil
		fmt.Println("OK Web UI stopped")
		return
	}

	port := p.webuiPort // Configured via TSS_WEBUI_PORT env or config defaults
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/ca", p.apiGetCA)
	mux.HandleFunc("/api/certificates", p.apiGetCertificates)
	mux.HandleFunc("/api/merkle", p.apiGetMerkle)
	mux.HandleFunc("/api/merkle/proof", p.apiGetMerkleProof)
	mux.HandleFunc("/api/dkg", p.apiGetDKGStatus)
	mux.HandleFunc("/api/dkg/fresh", p.apiForceFreshDKG)
	mux.HandleFunc("/api/csr/submit", p.apiSubmitCSR)
	mux.HandleFunc("/api/revoke", p.apiProposeRevocation)
	mux.HandleFunc("/api/membership/request", p.apiSubmitJoinRequest)
	mux.HandleFunc("/api/membership/observer", p.apiJoinObserver)
	mux.HandleFunc("/api/membership/observer/remove", p.apiRemoveObserver)
	mux.HandleFunc("/api/membership/promote_observer", p.apiPromoteObserver)
	mux.HandleFunc("/api/membership/remove", p.apiProposeMemberRemoval)
	mux.HandleFunc("/api/membership/sponsor", p.apiSponsorMember)
	mux.HandleFunc("/api/membership/endorse", p.apiEndorseSponsoredMember)
	mux.HandleFunc("/api/sponsorships", p.apiListSponsorships)
	mux.HandleFunc("/api/reshare/force", p.apiForceReshare)
	mux.HandleFunc("/api/blocks", p.apiGetRecentBlocks)
	mux.HandleFunc("/api/keyshare", p.apiGetKeyShareInfo)
	mux.HandleFunc("/api/metrics/p2p", p.apiGetP2PStats)
	mux.HandleFunc("/", p.serveWebUI)

	p.webServer = &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: mux,
	}

	go func() {
		fmt.Printf("OK Web UI started at http://0.0.0.0:%d (accessible from other devices)\n", port)
		if err := p.webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] Web UI error: %v", p.NodeID, err)
			p.webServer = nil
		}
	}()
}

// jsonError writes a JSON-safe error response (properly escapes special chars).
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := map[string]string{"error": msg}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiGetCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	result, err := p.Query("GetDistributedCA", DefaultCAID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	w.Write(result)
}

func (p *TSSPeer) apiGetCertificates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	result, err := p.Query("GetAllCertificates")
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if len(result) == 0 || string(result) == "null" {
		w.Write([]byte("[]"))
		return
	}
	w.Write(result)
}

func (p *TSSPeer) apiGetMerkle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, err := p.GetMerkleEnabled()
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if !enabled {
		resp := map[string]interface{}{
			"enabled":   false,
			"configSet": p.merkleConfigSet,
		}
		if p.merkleConfigSet {
			resp["configEnabled"] = p.merkleConfigEnabled
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	result, err := p.Query("GetCertificateMerkleRoot")
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if len(result) == 0 || string(result) == "null" {
		result = []byte(`{}`)
	}

	var state map[string]interface{}
	if err := json.Unmarshal(result, &state); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	state["enabled"] = true
	state["configSet"] = p.merkleConfigSet
	if p.merkleConfigSet {
		state["configEnabled"] = p.merkleConfigEnabled
	}
	enc := json.NewEncoder(w)
	_ = enc.Encode(state)
}

func (p *TSSPeer) apiGetMerkleProof(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if hash == "" {
		jsonError(w, "hash required", 400)
		return
	}
	result, err := p.Query("GetCertificateMerkleProof", hash)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if len(result) == 0 || string(result) == "null" {
		w.Write([]byte(`{}`))
		return
	}
	w.Write(result)
}

func (p *TSSPeer) apiGetDKGStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dkg, err := p.GetDKGSession(0)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	status, _ := dkg["status"].(string)
	ackCount := 0
	if v, ok := dkg["ackCount"].(float64); ok {
		ackCount = int(v)
	}
	threshold := 0
	if v, ok := dkg["threshold"].(float64); ok {
		threshold = int(v)
	}
	memberCount := 0
	if members, ok := dkg["members"].([]interface{}); ok {
		memberCount = len(members)
	}
	completedAt, _ := dkg["completedAt"].(string)

	p.mutex.RLock()
	hasKeyShare := p.TSSKeyShare != nil
	p.mutex.RUnlock()

	resp := map[string]interface{}{
		"status":      status,
		"ackCount":    ackCount,
		"threshold":   threshold,
		"members":     memberCount,
		"completedAt": completedAt,
		"hasKeyShare": hasKeyShare,
	}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiForceFreshDKG(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "fresh_dkg"
	}

	if _, err := p.Execute("ForceFreshDKG", DefaultCAID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok", "message": "fresh dkg initiated"}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiSubmitCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		CN string `json:"cn"`
		O  string `json:"o"`
		L  string `json:"l"`
		ST string `json:"st"`
		C  string `json:"c"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if req.CN == "" || req.O == "" || req.L == "" || req.ST == "" || req.C == "" {
		subj := parseCanonicalSubject(p.MemberID)
		if req.CN == "" {
			req.CN = subj["CN"]
		}
		if req.O == "" {
			req.O = subj["O"]
		}
		if req.L == "" {
			req.L = subj["L"]
		}
		if req.ST == "" {
			req.ST = subj["ST"]
		}
		if req.C == "" {
			req.C = subj["C"]
		}
	}
	if req.CN == "" {
		req.CN = fmt.Sprintf("%s-app", p.Organization)
	}
	if req.O == "" {
		req.O = p.Organization
	}

	proposalID := fmt.Sprintf("csr-%s-%d", p.Organization, time.Now().Unix())
	p.emitMetric("csr_api_received", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   p.MemberID,
	})
	proposalID, err := p.SubmitCSRWithID(req.CN, req.O, req.L, req.ST, req.C, proposalID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{
		"status":     "ok",
		"message":    "CSR submitted successfully",
		"proposalId": proposalID,
		"memberId":   p.MemberID,
	}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiProposeRevocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		MemberID string `json:"memberId"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if req.MemberID == "" {
		jsonError(w, "memberId required", 400)
		return
	}
	if req.Reason == "" {
		req.Reason = "revoked via web UI"
	}

	proposalID := fmt.Sprintf("revoke-%s-%d", p.Organization, time.Now().Unix())
	_, err := p.Execute("ProposeRevocation", proposalID, req.MemberID, req.Reason)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	p.emitMetric("revocation_proposed", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   req.MemberID,
	})
	resp := map[string]string{"status": "ok", "proposalId": proposalID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiSubmitJoinRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}

	proposalID := fmt.Sprintf("join-%s-%d", p.Organization, time.Now().Unix())
	if _, err := p.Execute("RequestJoinCA", DefaultCAID, proposalID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	p.emitMetric("join_request_submitted", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   p.MemberID,
	})

	resp := map[string]string{"status": "ok", "proposalId": proposalID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiJoinObserver(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if _, err := p.Execute("JoinAsObserver", DefaultCAID); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok"}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiRemoveObserver(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ObserverID string `json:"observerId"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.ObserverID) == "" {
		jsonError(w, "observerId required", 400)
		return
	}

	if _, err := p.Execute("RemoveObserver", DefaultCAID, req.ObserverID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok", "observerId": req.ObserverID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiPromoteObserver(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ObserverID string `json:"observerId"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.ObserverID) == "" {
		jsonError(w, "observerId required", 400)
		return
	}
	if req.Reason == "" {
		req.Reason = "observer promotion via web UI"
	}

	if _, err := p.Execute("PromoteObserver", DefaultCAID, req.ObserverID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok", "observerId": req.ObserverID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiProposeMemberRemoval(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		MemberID string `json:"memberId"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.MemberID) == "" {
		jsonError(w, "memberId required", 400)
		return
	}

	shortLabel := strings.TrimSuffix(p.extractShortNodeID(req.MemberID), "-peer")
	proposalID := fmt.Sprintf("remove-%s-%d", shortLabel, time.Now().Unix())
	if _, err := p.Execute("ProposeRemoveMember", DefaultCAID, proposalID, req.MemberID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	p.emitMetric("member_removal_proposed", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   req.MemberID,
	})

	resp := map[string]string{"status": "ok", "proposalId": proposalID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiForceReshare(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "manual_reshare"
	}

	log.Printf("[%s] API force reshare requested (reason=%s)", p.NodeID, req.Reason)
	if _, err := p.Execute("ForceReshare", DefaultCAID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok", "message": "reshare requested"}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiSponsorMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		MemberID string `json:"memberId"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.MemberID) == "" {
		jsonError(w, "memberId required", 400)
		return
	}
	if req.Reason == "" {
		req.Reason = "sponsored via web UI"
	}

	if _, err := p.Execute("SponsorJoinCA", DefaultCAID, req.MemberID, req.Reason); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok", "memberId": req.MemberID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiEndorseSponsoredMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		MemberID string `json:"memberId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.MemberID) == "" {
		jsonError(w, "memberId required", 400)
		return
	}

	if _, err := p.Execute("EndorseSponsoredMember", DefaultCAID, req.MemberID); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	resp := map[string]string{"status": "ok", "memberId": req.MemberID}
	json.NewEncoder(w).Encode(resp)
}

func (p *TSSPeer) apiListSponsorships(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	result, err := p.Query("ListPendingSponsorships", DefaultCAID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if len(result) == 0 || string(result) == "null" {
		w.Write([]byte("[]"))
		return
	}
	w.Write(result)
}

func (p *TSSPeer) apiGetRecentBlocks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit := 5
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			limit = v
		}
	}
	blocks, err := p.getRecentBlocks(limit)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(blocks)
}

func (p *TSSPeer) apiGetKeyShareInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	info := map[string]interface{}{
		"nodeId":       p.NodeID,
		"memberId":     p.MemberID,
		"organization": p.Organization,
		"threshold":    p.Threshold,
		"partyIndex":   p.myPartyIndex,
		"hasKeyShare":  p.TSSKeyShare != nil,
	}
	if p.TSSKeyShare != nil && p.TSSKeyShare.ECDSAPub != nil {
		pubBytes := elliptic.Marshal(
			p.TSSKeyShare.ECDSAPub.Curve(),
			p.TSSKeyShare.ECDSAPub.X(),
			p.TSSKeyShare.ECDSAPub.Y(),
		)
		info["caPublicKey"] = hex.EncodeToString(pubBytes)
	}
	json.NewEncoder(w).Encode(info)
}

func (p *TSSPeer) apiGetP2PStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reset := false
	if val := r.URL.Query().Get("reset"); val != "" {
		switch strings.ToLower(val) {
		case "1", "true", "yes", "y":
			reset = true
		}
	}
	stats := p.p2pStats.snapshot(reset)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (p *TSSPeer) serveWebUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, webUIHTML)
}

const webUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Decentralized PKI - Web UI</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Space Grotesk','Segoe UI',sans-serif;background:
radial-gradient(1200px 600px at 5% -10%,#1c2f2a 0%,transparent 60%),
radial-gradient(900px 400px at 95% -15%,#102823 0%,transparent 55%),
#0b0f0e;color:#e2e8f0;min-height:100vh}
.header{background:linear-gradient(135deg,#0f1f1c 0%,#152b26 60%,#0b1916 100%);padding:1.25rem 2rem;border-bottom:1px solid #1f3b34;display:flex;align-items:center;gap:0.75rem;box-shadow:0 10px 30px rgba(0,0,0,0.35)}
.header h1{font-size:1.35rem;font-weight:600;color:#7cf1da;letter-spacing:0.02em}
.header .badge{background:#1a4b41;color:#d6fff3;padding:0.2rem 0.75rem;border-radius:999px;font-size:0.78rem;border:1px solid #2a6b5e}
.container{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;padding:1.25rem;max-width:1400px;margin:0 auto}
.card{background:rgba(10,12,12,0.85);border:1px solid #1f2c28;border-radius:0.9rem;padding:1.1rem 1.2rem;overflow:hidden;box-shadow:0 16px 30px rgba(0,0,0,0.25)}
.card h2{font-size:0.95rem;color:#7cf1da;margin-bottom:0.85rem;display:flex;align-items:center;gap:0.5rem}
.card h2::before{content:'';display:inline-block;width:4px;height:1rem;background:#009682;border-radius:2px}
.full{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:0.85rem}
th{text-align:left;padding:0.55rem;color:#9fb6b0;border-bottom:1px solid #1f2c28;font-weight:500}
td{padding:0.55rem;border-bottom:1px solid #171c1b;word-break:break-all;max-width:300px}
.status{padding:0.15rem 0.5rem;border-radius:0.25rem;font-size:0.75rem;font-weight:600;display:inline-block}
.status.active{background:#065f46;color:#6ee7b7}
.status.revoked{background:#7f1d1d;color:#fca5a5}
.btn{padding:0.5rem 1rem;border:none;border-radius:0.6rem;cursor:pointer;font-size:0.85rem;font-weight:600;transition:all 0.2s}
.btn-primary{background:#0ea98f;color:#06201b}.btn-primary:hover{background:#13c6a5}
.btn-danger{background:#b91c1c;color:white}.btn-danger:hover{background:#991b1b}
.btn-sm{padding:0.3rem 0.6rem;font-size:0.75rem}
.actions{display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem}
input,select{background:#0a1110;color:#e2e8f0;border:1px solid #24322f;border-radius:0.45rem;padding:0.45rem 0.6rem;font-size:0.85rem;width:100%}
input:focus{outline:none;border-color:#0ea98f;box-shadow:0 0 0 2px rgba(14,169,143,0.25)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-bottom:0.5rem}
.member-grid{display:grid;gap:0.75rem}
.member-block{background:#0d1412;border:1px solid #1b2623;border-radius:0.7rem;padding:0.8rem}
.member-heading{font-size:0.72rem;text-transform:uppercase;letter-spacing:0.08em;color:#7ccfbe;margin-bottom:0.5rem}
label{font-size:0.75rem;color:#94a3b8;margin-bottom:0.2rem;display:block}
.merkle-root{font-family:monospace;font-size:0.8rem;background:#0a0a0a;padding:0.75rem;border-radius:0.375rem;word-break:break-all;color:#33c4b0}
.info-grid{display:grid;grid-template-columns:auto 1fr;gap:0.25rem 0.75rem;font-size:0.85rem}
.info-grid dt{color:#9fb6b0}.info-grid dd{color:#e2e8f0;word-break:break-all}
.warn{color:#fca5a5;font-weight:600}
.divider{height:1px;background:#1f2c28;margin:0.85rem 0}
.details{margin-top:0.75rem}
.details summary{list-style:none;cursor:pointer;color:#9fb6b0;font-weight:600;padding:0.35rem 0;display:flex;align-items:center;gap:0.5rem}
.details summary::-webkit-details-marker{display:none}
.details summary::before{content:'▸';color:#0ea98f;transition:transform 0.2s}
.details[open] summary::before{transform:rotate(90deg)}
.toast{position:fixed;top:1rem;right:1rem;padding:0.75rem 1.25rem;border-radius:0.5rem;color:white;font-size:0.85rem;z-index:999;animation:fade 3s forwards}
.toast.ok{background:#009682}.toast.err{background:#b91c1c}
@keyframes fade{0%,70%{opacity:1}100%{opacity:0}}
.spinner{display:inline-block;width:1rem;height:1rem;border:2px solid #2a3a38;border-top-color:#009682;border-radius:50%;animation:spin 0.6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.empty{color:#64748b;font-style:italic;padding:1rem;text-align:center}
.modal{position:fixed;inset:0;background:rgba(0,0,0,0.65);display:none;align-items:center;justify-content:center;z-index:1000}
.modal.show{display:flex}
.modal-content{background:#0f1413;border:1px solid #1e2e2c;border-radius:0.75rem;max-width:800px;width:92%;padding:1rem}
.modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem}
.modal-content pre{white-space:pre-wrap;word-break:break-all;font-size:0.8rem;background:#0a0a0a;padding:0.75rem;border-radius:0.5rem;max-height:60vh;overflow:auto}
</style>
</head>
<body>
<div class="header">
<h1>Decentralized PKI</h1>
<span class="badge" id="nodeLabel">loading...</span>
<span class="badge" style="background:#065f46" id="caStatus">CA: loading</span>
</div>
<div class="container">

<div class="card">
<h2>CA State</h2>
<dl class="info-grid" id="caInfo"><dt>Loading...</dt><dd></dd></dl>
</div>

<div class="card">
<h2>Key Share Info</h2>
<dl class="info-grid" id="keyInfo"><dt>Loading...</dt><dd></dd></dl>
</div>

<div class="card">
<h2>Request Certificate</h2>
<div class="form-row">
<div><label>Common Name (CN)</label><input id="csrCN" placeholder="e.g. User@IRS-X"></div>
<div><label>Organization (O)</label><input id="csrO" placeholder="e.g. IRS-X"></div>
</div>
<div class="form-row">
<div><label>Locality (L)</label><input id="csrL" placeholder="e.g. Karlsruhe"></div>
<div><label>State (ST)</label><input id="csrST" placeholder="e.g. BW"></div>
</div>
<div class="form-row">
<div><label>Country (C)</label><input id="csrC" placeholder="e.g. DE"></div>
<div style="display:flex;align-items:flex-end"><button class="btn btn-primary" onclick="submitCSR()">Submit CSR</button></div>
</div>
</div>

<div class="card">
<h2>Membership</h2>
<div class="member-grid">
<div class="member-block">
<div class="member-heading">Join</div>
<div class="form-row">
<div><label>Join Reason</label><input id="joinReason" placeholder="e.g. new node join"></div>
<div style="display:flex;align-items:flex-end"><button class="btn btn-primary" onclick="submitJoinRequest()">Request Membership</button></div>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="submitJoinObserver()">Join as Observer</button>
</div>
</div>
</div>
<details class="details">
<summary>Advanced Membership & Key Ops</summary>
<div class="member-grid">
<div class="member-block">
<div class="member-heading">Sponsor / Endorse</div>
<div class="form-row">
<div><label>Sponsor Member ID</label><input id="sponsorMemberId" placeholder="x509::CN=Admin@orgX... or external::..."></div>
<div><label>Reason</label><input id="sponsorReason" placeholder="e.g. new member"></div>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="submitSponsor()">Sponsor Member</button>
</div>
<div class="divider"></div>
<div class="form-row">
<div><label>Pending Sponsorships</label><select id="endorseMemberId"></select></div>
<div style="display:flex;align-items:flex-end"><button class="btn btn-primary" onclick="submitEndorse()">Endorse</button></div>
</div>
</div>
<div class="member-block">
<div class="member-heading">Observer Management</div>
<div class="form-row">
<div><label>Promote Observer</label><select id="promoteObserverId"></select></div>
<div><label>Reason</label><input id="promoteObserverReason" placeholder="e.g. promote to member"></div>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="submitPromoteObserver()">Promote Observer</button>
</div>
<div class="divider"></div>
<div class="form-row">
<div><label>Remove Observer</label><select id="removeObserverId"></select></div>
<div><label>Reason</label><input id="removeObserverReason" placeholder="e.g. no longer needed"></div>
</div>
<div class="actions">
<button class="btn btn-danger" onclick="submitRemoveObserver()">Remove Observer</button>
</div>
</div>
<div class="member-block">
<div class="member-heading">Member Removal</div>
<div class="form-row">
<div><label>Remove Member</label><select id="removeMemberId"></select></div>
<div><label>Reason</label><input id="removeReason" placeholder="e.g. compromised"></div>
</div>
<div class="actions">
<button class="btn btn-danger" onclick="submitRemoveMember()">Propose Removal</button>
</div>
</div>
<div class="member-block">
<div class="member-heading">Reshare / Reset</div>
<div class="form-row">
<div><label>Manual Reshare Reason</label><input id="forceReshareReason" placeholder="e.g. manual reshare"></div>
<div style="display:flex;align-items:flex-end"><button class="btn btn-primary" onclick="submitForceReshare()">Force Reshare</button></div>
</div>
<div class="divider"></div>
<div class="form-row">
<div><label>Fresh DKG Reason</label><input id="freshDkgReason" placeholder="e.g. reset key"></div>
<div style="display:flex;align-items:flex-end"><button class="btn btn-danger" onclick="submitFreshDKG()">Force Fresh DKG</button></div>
</div>
</div>
</div>
</details>
</div>

<div class="card full">
<h2>Issued Certificates</h2>
<table>
<thead><tr><th>Subject</th><th>Serial</th><th>Status</th><th>Issued</th><th>Expires</th><th>Actions</th></tr></thead>
<tbody id="certTable"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
</table>
</div>

<div class="card">
<details class="details">
<summary>Merkle Tree</summary>
<div id="merkleInfo" class="empty">Loading...</div>
</details>
</div>

<div class="card full">
<details class="details">
<summary>Recent Blocks</summary>
<table>
<thead><tr><th>Block</th><th>TxID</th><th>Type</th></tr></thead>
<tbody id="blockTable"><tr><td colspan="3" class="empty">Loading...</td></tr></tbody>
</table>
</details>
</div>

</div>

<div id="proofModal" class="modal" onclick="hideProof(event)">
<div class="modal-content" onclick="event.stopPropagation()">
  <div class="modal-header">
    <strong>Merkle Proof</strong>
    <button class="btn btn-sm" onclick="hideProof()">Close</button>
  </div>
  <pre id="proofContent">Loading...</pre>
</div>
</div>

<script>
const API='';
const csrDefaults={cn:'User@IRS-X',o:'IRS-X',l:'Karlsruhe',st:'BW',c:'DE'};
function toast(msg,ok){const d=document.createElement('div');d.className='toast '+(ok?'ok':'err');d.textContent=msg;document.body.appendChild(d);setTimeout(()=>d.remove(),3200)}
function showProof(data){
  const modal=document.getElementById('proofModal');
  const pre=document.getElementById('proofContent');
  if(pre){pre.textContent=JSON.stringify(data,null,2);}
  if(modal){modal.classList.add('show');}
}
function hideProof(){
  const modal=document.getElementById('proofModal');
  if(modal){modal.classList.remove('show');}
}
async function fetchMerkleProof(hash){
  if(!hash){toast('No cert hash available',false);return;}
  try{
    const r=await fetch(API+'/api/merkle/proof?hash='+encodeURIComponent(hash));
    const d=await r.json();
    if(r.ok){showProof(d);} else {toast(d.error||'Failed',false);}
  }catch(e){toast(e.message,false)}
}
function shortMember(id){
  if(!id) return '';
  const p=id.split('::');
  if(p.length>1){return p[1].split(',')[0];}
  return id.length>40? id.substring(0,40)+'...' : id;
}
function populateMemberSelect(members){
  const sel=document.getElementById('removeMemberId');
  if(!sel) return;
  sel.innerHTML='';
  if(!members || members.length===0){
    const opt=document.createElement('option');
    opt.value='';
    opt.textContent='No members';
    sel.appendChild(opt);
    sel.disabled=true;
    return;
  }
  sel.disabled=false;
  members.forEach(m=>{
    const opt=document.createElement('option');
    opt.value=m;
    opt.textContent=shortMember(m);
    sel.appendChild(opt);
  });
}

function populateObserverSelect(list, elementId, emptyLabel){
  const sel=document.getElementById(elementId);
  if(!sel) return;
  sel.innerHTML='';
  if(!list || list.length===0){
    const opt=document.createElement('option');
    opt.value='';
    opt.textContent=emptyLabel||'No observers';
    sel.appendChild(opt);
    sel.disabled=true;
    return;
  }
  sel.disabled=false;
  list.forEach(o=>{
    const opt=document.createElement('option');
    opt.value=o;
    opt.textContent=shortMember(o);
    sel.appendChild(opt);
  });
}

function populateSponsorshipSelect(list){
  const sel=document.getElementById('endorseMemberId');
  if(!sel) return;
  sel.innerHTML='';
  if(!list || list.length===0){
    const opt=document.createElement('option');
    opt.value='';
    opt.textContent='No pending sponsorships';
    sel.appendChild(opt);
    sel.disabled=true;
    return;
  }
  sel.disabled=false;
  list.forEach(s=>{
    const memberId=s.memberId||s.MemberID||'';
    const endorsements=(s.endorsements||[]).length;
    const opt=document.createElement('option');
    opt.value=memberId;
    opt.textContent=shortMember(memberId)+' (endorsements '+endorsements+')';
    sel.appendChild(opt);
  });
}

function setCsrDefaults(){
  const map={csrCN:'cn',csrO:'o',csrL:'l',csrST:'st',csrC:'c'};
  Object.keys(map).forEach(id=>{
    const el=document.getElementById(id);
    if(el && !el.value){el.value=csrDefaults[map[id]];}
  });
}

function orgSuffixFromOrg(org){
  if(!org) return 'X';
  const lower=org.toLowerCase();
  if(lower.startsWith('org')){
    const num=org.slice(3);
    if(num) return num;
  }
  return 'X';
}

function updateCsrDefaultsFromOrg(org){
  const n=orgSuffixFromOrg(org);
  csrDefaults.cn='User@IRS-'+n;
  csrDefaults.o='IRS-'+n;
}

let __caPublicKey='';
let __caMemberCount=0;
let __org='';

async function loadCA(){
  try{
    const r=await fetch(API+'/api/ca');const d=await r.json();
    let dkgInfo=null;
    try{const dr=await fetch(API+'/api/dkg');dkgInfo=await dr.json();}catch(e){dkgInfo=null}
    const el=document.getElementById('caInfo');
    const members=(d.members||[]).map(m=>shortMember(m)).join(', ');
    const observers=(d.observers||[]).length;
    const n=(d.thresholdParams?.totalNodes??0);
    const t=(d.thresholdParams?.threshold??null);
    const quorum=(d.governanceParams?.quorumPercentage??null);
    let required='-';
    if(n){
      if(t!==null && t!==undefined){
        required=t+1;
      }else if(quorum!==null && quorum!==undefined){
        required=Math.max(2, Math.ceil(n*quorum/100));
      }
    }
    let dkgLine='-';
    if(dkgInfo && dkgInfo.status){
      dkgLine=dkgInfo.status;
      if(dkgInfo.ackCount!==undefined && dkgInfo.threshold!==undefined){
        dkgLine+=' (ack '+dkgInfo.ackCount+'/'+dkgInfo.threshold+')';
      }
      if(dkgInfo.hasKeyShare){dkgLine+=' (key share ready)'}
    }
    el.innerHTML='<dt>Name</dt><dd>'+(d.name||'root-ca')+'</dd>'+
      '<dt>Epoch</dt><dd>'+d.epoch+'</dd>'+
      '<dt>Members</dt><dd>'+members+'</dd>'+
      '<dt>Observers</dt><dd>'+observers+' node'+(observers!==1?'s':'')+'</dd>'+
      '<dt>Required Signers</dt><dd>'+required+' of '+(n||'-')+(quorum!==null?' (quorum '+quorum+'%)':'')+'</dd>'+
      '<dt>TSS Threshold (t)</dt><dd>'+(t??'-')+'</dd>'+
      '<dt>DKG Status</dt><dd>'+dkgLine+'</dd>'+
      '<dt>Public Key</dt><dd style="font-family:monospace;font-size:0.75rem">'+(d.publicKey?d.publicKey.substring(0,40)+'...':'not set')+'</dd>';
      document.getElementById('caStatus').textContent='CA: '+(d.isActive?'Active':'Inactive')+' (epoch '+d.epoch+')';
      populateMemberSelect(d.members||[]);
      populateObserverSelect(d.observers||[],'promoteObserverId','No observers');
      populateObserverSelect(d.observers||[],'removeObserverId','No observers');
      __caPublicKey=d.publicKey||'';
    __caMemberCount=(d.members||[]).length;
  }catch(e){console.error(e)}
}

async function loadSponsorships(){
  try{
    const r=await fetch(API+'/api/sponsorships');const d=await r.json();
    populateSponsorshipSelect(d);
  }catch(e){console.error(e)}
}

async function loadCerts(){
  try{
    const r=await fetch(API+'/api/certificates');const d=await r.json();
    const el=document.getElementById('certTable');
    if(!d||d.length===0){el.innerHTML='<tr><td colspan="6" class="empty">No certificates issued yet</td></tr>';return}
    el.innerHTML=d.map(c=>{
      const st=c.isRevoked?'revoked':'active';
      const issued=c.issuedAt?new Date(c.issuedAt).toLocaleDateString():'-';
      const expires=c.expiresAt?new Date(c.expiresAt).toLocaleDateString():'-';
      const serial=c.serialNumber&&c.serialNumber.length>16?c.serialNumber.substring(0,16)+'...':c.serialNumber;
    const mid=c.memberId||'';
    const certHash=c.certHash||'';
    const revBtn=st==='active'?'<button class="btn btn-danger btn-sm" onclick="revokeCert(\''+mid.replace(/'/g,"\\'")+'\')">Revoke</button>':'';
    const proofBtn=certHash?'<button class="btn btn-primary btn-sm" onclick="fetchMerkleProof(\''+certHash.replace(/'/g,"\\'")+'\')">Proof</button>':'';
    const actions=[revBtn,proofBtn].filter(Boolean).join(' ');
    return '<tr><td>'+c.subject+'</td><td style="font-family:monospace;font-size:0.75rem">'+serial+'</td>'+
      '<td><span class="status '+st+'">'+st+'</span></td><td>'+issued+'</td><td>'+expires+'</td><td>'+actions+'</td></tr>';
  }).join('');
  }catch(e){console.error(e)}
}

async function loadMerkle(){
  try{
    const r=await fetch(API+'/api/merkle');const d=await r.json();
    const el=document.getElementById('merkleInfo');
    const enabled = d.enabled !== false;
    const configSet = d.configSet === true;
    const configEnabled = d.configEnabled === true;
    let html='<div style="margin-bottom:0.5rem"><strong>On-chain:</strong> '+(enabled?'Enabled':'Disabled')+'</div>';
    if(configSet){
      const mismatch = (configEnabled !== enabled);
      html+='<div style="margin-bottom:0.5rem"><strong>Config:</strong> '+(configEnabled?'Enabled':'Disabled')+(mismatch?' <span class="warn">(mismatch)</span>':'')+'</div>';
    } else {
      html+='<div style="margin-bottom:0.5rem"><strong>Config:</strong> not set</div>';
    }
    if(!enabled){el.innerHTML=html+'<span class="empty">Merkle tree disabled</span>';return}
    if(!d.merkleRoot){el.innerHTML=html+'<span class="empty">No Merkle root yet</span>';return}
    el.innerHTML=html+'<div class="merkle-root">'+d.merkleRoot+'</div>'+
      '<div style="margin-top:0.75rem;font-size:0.85rem"><strong>Active certs:</strong> '+d.activeCertCount+
      ' &nbsp; <strong>Updated:</strong> '+new Date(d.updatedAt).toLocaleString()+
      ' &nbsp; <strong>Action:</strong> '+d.triggerAction+'</div>';
  }catch(e){console.error(e)}
}

async function loadKeyInfo(){
  try{
    const r=await fetch(API+'/api/keyshare');const d=await r.json();
    const el=document.getElementById('keyInfo');
    document.getElementById('nodeLabel').textContent=d.nodeId+' ('+d.organization+')';
    __org=d.organization||'';
  updateCsrDefaultsFromOrg(__org);
    setCsrDefaults();
    const hasKey=!!d.hasKeyShare;
    let keyStatus='-';
    if(hasKey){
      if(__caPublicKey && d.caPublicKey && __caPublicKey!==d.caPublicKey){
        keyStatus='Stale (reshare needed)';
      }else{
        keyStatus='OK';
      }
    }
    el.innerHTML='<dt>Node ID</dt><dd>'+d.nodeId+'</dd>'+
      '<dt>Has Key Share</dt><dd>'+(hasKey?'Yes':'No')+'</dd>'+
      '<dt>Key Share Status</dt><dd class="'+(keyStatus.startsWith('Stale')?'warn':'')+'">'+keyStatus+'</dd>'+
      '<dt>TSS Threshold (t)</dt><dd>'+d.threshold+'</dd>'+
      '<dt>Party Index</dt><dd>'+d.partyIndex+'</dd>'+
      '<dt>CA Public Key</dt><dd style="font-family:monospace;font-size:0.75rem">'+(d.caPublicKey?d.caPublicKey.substring(0,40)+'...':'-')+'</dd>';
  }catch(e){console.error(e)}
}

async function loadBlocks(){
  try{
    const r=await fetch(API+'/api/blocks?limit=5');const d=await r.json();
    const el=document.getElementById('blockTable');
  if(!d || d.length===0){el.innerHTML='<tr><td colspan="3" class="empty">No blocks</td></tr>';return}
    const rows=[];
    d.forEach(b=>{
      const label='#'+b.number+' ('+b.txCount+')';
    if(!b.txs || b.txs.length===0){
      rows.push('<tr><td>'+label+'</td><td>-</td><td>-</td></tr>');
      return;
    }
    b.txs.forEach(tx=>{
      const txid=tx.txId? (tx.txId.length>12?tx.txId.substring(0,12)+'...':tx.txId) : '-';
      rows.push('<tr><td>'+label+'</td><td style="font-family:monospace;font-size:0.75rem">'+txid+
        '</td><td>'+ (tx.type||'-') +'</td></tr>');
    });
    });
    el.innerHTML=rows.join('');
  }catch(e){console.error(e)}
}

async function submitCSR(){
  const cnRaw=document.getElementById('csrCN').value;
  const oRaw=document.getElementById('csrO').value;
  const body={
    cn:cnRaw||csrDefaults.cn,
    o:oRaw||csrDefaults.o,
    l:document.getElementById('csrL').value||csrDefaults.l,
    st:document.getElementById('csrST').value||csrDefaults.st,
    c:document.getElementById('csrC').value||csrDefaults.c
  };
  try{
    const r=await fetch(API+'/api/csr/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(r.ok){toast('CSR submitted! Waiting for CA approval...',true);setCsrDefaults()}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitJoinRequest(){
  const reason=document.getElementById('joinReason').value||'';
  try{
    const r=await fetch(API+'/api/membership/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})});
    const d=await r.json();
    if(r.ok){toast('Join request submitted: '+(d.proposalId||''),true);document.getElementById('joinReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitJoinObserver(){
  try{
    const r=await fetch(API+'/api/membership/observer',{method:'POST',headers:{'Content-Type':'application/json'}});
    const d=await r.json();
    if(r.ok){toast('Joined as observer',true)}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitRemoveMember(){
  const sel=document.getElementById('removeMemberId');
  const memberId=sel?sel.value:'';
  const reason=document.getElementById('removeReason').value||'';
  if(!memberId){toast('Select a member to remove',false);return}
  try{
    const r=await fetch(API+'/api/membership/remove',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({memberId,reason})});
    const d=await r.json();
    if(r.ok){toast('Removal proposed: '+(d.proposalId||''),true);document.getElementById('removeReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitForceReshare(){
  if(!confirm('Force a manual reshare for the current CA membership?')){return}
  const reason=document.getElementById('forceReshareReason').value||'manual_reshare';
  try{
    const r=await fetch(API+'/api/reshare/force',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reason})});
    const d=await r.json();
    if(r.ok){toast('Reshare requested',true);document.getElementById('forceReshareReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitFreshDKG(){
  if(!confirm('Force a fresh DKG? This resets the CA public key and invalidates old certs.')){return}
  const reason=document.getElementById('freshDkgReason').value||'fresh_dkg';
  try{
    const r=await fetch(API+'/api/dkg/fresh',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reason})});
    const d=await r.json();
    if(r.ok){toast('Fresh DKG requested',true);document.getElementById('freshDkgReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitSponsor(){
  const memberId=document.getElementById('sponsorMemberId').value||'';
  const reason=document.getElementById('sponsorReason').value||'';
  if(!memberId){toast('Enter a member ID to sponsor',false);return}
  try{
    const r=await fetch(API+'/api/membership/sponsor',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({memberId,reason})});
    const d=await r.json();
    if(r.ok){toast('Sponsorship submitted for '+shortMember(memberId),true);document.getElementById('sponsorReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitEndorse(){
  const sel=document.getElementById('endorseMemberId');
  const memberId=sel?sel.value:'';
  if(!memberId){toast('Select a sponsorship to endorse',false);return}
  try{
    const r=await fetch(API+'/api/membership/endorse',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({memberId})});
    const d=await r.json();
    if(r.ok){toast('Endorsed '+shortMember(memberId),true)}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitPromoteObserver(){
  const sel=document.getElementById('promoteObserverId');
  const observerId=sel?sel.value:'';
  const reason=document.getElementById('promoteObserverReason').value||'';
  if(!observerId){toast('Select an observer to promote',false);return}
  try{
    const r=await fetch(API+'/api/membership/promote_observer',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({observerId,reason})});
    const d=await r.json();
    if(r.ok){toast('Promotion submitted for '+shortMember(observerId),true);document.getElementById('promoteObserverReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function submitRemoveObserver(){
  const sel=document.getElementById('removeObserverId');
  const observerId=sel?sel.value:'';
  const reason=document.getElementById('removeObserverReason').value||'';
  if(!observerId){toast('Select an observer to remove',false);return}
  try{
    const r=await fetch(API+'/api/membership/observer/remove',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({observerId,reason})});
    const d=await r.json();
    if(r.ok){toast('Observer removed '+shortMember(observerId),true);document.getElementById('removeObserverReason').value=''}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

async function revokeCert(memberId){
  if(!confirm('Revoke certificate for this member?'))return;
  const reason=prompt('Revocation reason:','key compromise');
  if(reason===null)return;
  try{
    const r=await fetch(API+'/api/revoke',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({memberId,reason})});
    const d=await r.json();
    if(r.ok){toast('Revocation proposed: '+d.proposalId,true)}
    else toast(d.error||'Failed',false);
  }catch(e){toast(e.message,false)}
}

function refreshAll(){loadCA();loadSponsorships();loadCerts();loadBlocks();loadMerkle();loadKeyInfo()}
setCsrDefaults();
refreshAll();
setInterval(refreshAll,10000);
</script>
</body>
</html>`



