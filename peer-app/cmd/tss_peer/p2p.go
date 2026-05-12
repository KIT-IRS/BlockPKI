// p2p.go owns peer-to-peer transport, TLS handshakes, and message routing for TSS protocol traffic.
// Runtime flow: startup creates the listener, then goroutines accept, authenticate, and route inbound/outbound messages.

// Used in p2p communivations, includes a lot of parsing and normalization of different IDs.
// Also extracts metrics from p2p messages
// Build tls sessions and verifications

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ===================== P2P NETWORKING =====================

//	authenticates the sender using its MSP identity.
//
// The certificate is verified against known MSP roots, and the nonce is signed.
type P2PHandshake struct {
	MemberID string `json:"memberId"`
	CertPEM  string `json:"certPem"`
	Nonce    string `json:"nonce"` // hex
	Sig      string `json:"sig"`   // base64
}

// tracks sent/received counts for TSS transport debugging and metrics.
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

// creates a fresh sent/received counter container for P2P traffic.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: NewTSSPeer.
// Triggered: P2P runtime helper for transport, identity, and routing.
func newP2PMessageStats() *P2PMessageStats {
	return &P2PMessageStats{
		sentByType: make(map[string]uint64),
		recvByType: make(map[string]uint64),
	}
}

// increments outbound P2P message counters by direction and type.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).SendTSSMessage.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// increments inbound P2P message counters by direction and type.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).handleP2PConnection.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// returns a copy of current P2P counters and optionally resets them.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).apiGetP2PStats.
// Triggered: P2P runtime helper for transport, identity, and routing.
func (s *P2PMessageStats) snapshot(reset bool) map[string]interface{} {
	if s == nil {
		return map[string]interface{}{}
	}
	s.mu.Lock()
	out := map[string]interface{}{
		"sent_total":     s.sentTotal,
		"recv_total":     s.recvTotal,
		"sent_broadcast": s.sentBroadcast,
		"sent_direct":    s.sentDirect,
		"recv_broadcast": s.recvBroadcast,
		"recv_direct":    s.recvDirect,
		"sent_by_type":   copyUint64Map(s.sentByType),
		"recv_by_type":   copyUint64Map(s.recvByType),
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

// clones a string->uint64 map for safe snapshot reporting.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*P2PMessageStats).snapshot.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// loads strict mTLS key material for P2P server/client transport and validates advertise-host SAN binding.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: NewTSSPeer.
// Triggered: startup/runtime helper during process composition.
func loadP2PMTLSMaterial(config *GatewayConfig) (tls.Certificate, tls.Certificate, crypto.Signer, []byte, error) {
	if config == nil {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("missing gateway config")
	}

	serverCertPath := strings.TrimSpace(config.P2PTLSServerCertPath)
	serverKeyPath := strings.TrimSpace(config.P2PTLSServerKeyPath)
	clientCertPath := strings.TrimSpace(config.P2PTLSClientCertPath)
	clientKeyPath := strings.TrimSpace(config.P2PTLSClientKeyPath)
	if serverCertPath == "" || serverKeyPath == "" || clientCertPath == "" || clientKeyPath == "" {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("missing P2P TLS certificate/key paths (set TSS_P2P_TLS_* overrides)")
	}

	serverTLSCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("failed to load P2P server TLS cert/key (%s, %s): %w", serverCertPath, serverKeyPath, err)
	}
	clientTLSCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("failed to load P2P client TLS cert/key (%s, %s): %w", clientCertPath, clientKeyPath, err)
	}

	clientCertPEM, err := os.ReadFile(clientCertPath)
	if err != nil {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("failed to read P2P client cert PEM %s: %w", clientCertPath, err)
	}
	if _, err := parseCertPEM(clientCertPEM); err != nil {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("invalid P2P client cert PEM %s: %w", clientCertPath, err)
	}

	clientSigner, ok := clientTLSCert.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, fmt.Errorf("P2P client TLS private key does not implement crypto.Signer")
	}

	if err := validateP2PServerAdvertiseHost(serverTLSCert, config.P2PAdvertise); err != nil {
		return tls.Certificate{}, tls.Certificate{}, nil, nil, err
	}

	return serverTLSCert, clientTLSCert, clientSigner, clientCertPEM, nil
}

// returns the parsed leaf certificate from a tls.Certificate bundle.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: loadP2PMTLSMaterial.
// Triggered: P2P runtime helper for transport, identity, and routing.
func tlsLeafCertificate(cert tls.Certificate) (*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS leaf certificate: %w", err)
	}
	return leaf, nil
}

// ensures the configured advertised host matches the server certificate SAN/CN for strict mTLS hostname verification.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: loadP2PMTLSMaterial.
// Triggered: startup/runtime helper during process composition.
func validateP2PServerAdvertiseHost(serverTLSCert tls.Certificate, advertise string) error {
	advHost, _, err := net.SplitHostPort(strings.TrimSpace(advertise))
	if err != nil {
		return fmt.Errorf("invalid TSS_P2P_ADVERTISE %q (must be host:port): %w", advertise, err)
	}
	if strings.TrimSpace(advHost) == "" {
		return fmt.Errorf("invalid TSS_P2P_ADVERTISE %q: empty host", advertise)
	}
	leaf, err := tlsLeafCertificate(serverTLSCert)
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(advHost); err != nil {
		return fmt.Errorf("P2P server TLS cert does not match TSS_P2P_ADVERTISE host %q: %w", advHost, err)
	}
	return nil
}

// parses a PEM-encoded certificate into x509 form.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).buildHandshake, (*TSSPeer).verifyHandshake.
// Triggered: P2P runtime helper for transport, identity, and routing.
func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// derives the canonical Fabric-style member ID from certificate subject/issuer.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).buildHandshake, (*TSSPeer).verifyHandshake, NewTSSPeer.
// Triggered: P2P runtime helper for transport, identity, and routing.
func canonicalIDFromCert(cert *x509.Certificate) string {
	return fmt.Sprintf("x509::%s::%s", cert.Subject.String(), cert.Issuer.String())
}

// normalizes raw or base64 member IDs into canonical x509:: form.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).verifyHandshake.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// extracts subject DN key/value fields from a canonical member ID.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).apiSubmitCSR, extractOrgLabelFromCanonical, shortNodeIDFromCanonical.
// Triggered: P2P runtime helper for transport, identity, and routing.
func parseCanonicalSubject(canonicalID string) map[string]string {
	out := map[string]string{}
	if !strings.HasPrefix(canonicalID, "x509::") {
		return out
	}
	parts := strings.SplitN(canonicalID, "::", 3)
	if len(parts) < 2 {
		return out
	}
	return parseCanonicalDN(parts[1])
}

// extracts issuer DN key/value fields from a canonical member ID.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: extractOrgLabelFromCanonical.
// Triggered: P2P runtime helper for transport, identity, and routing.
func parseCanonicalIssuer(canonicalID string) map[string]string {
	out := map[string]string{}
	if !strings.HasPrefix(canonicalID, "x509::") {
		return out
	}
	parts := strings.SplitN(canonicalID, "::", 3)
	if len(parts) < 3 {
		return out
	}
	return parseCanonicalDN(parts[2])
}

// parses a canonical DN string into key/value attributes.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: parseCanonicalIssuer, parseCanonicalSubject.
// Triggered: P2P runtime helper for transport, identity, and routing.
func parseCanonicalDN(raw string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(raw, ",") {
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

// loads MSP CA roots and TLS CA roots for handshake certificate verification.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: NewTSSPeer.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// constructs an authenticated handshake payload signed by the local MSP key.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).SendTSSMessage.
// Triggered: goroutine callback on inbound P2P TLS connection handling.
func (p *TSSPeer) buildHandshake() (*P2PHandshake, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(nonce)
	if p.p2pHandshakeSigner == nil {
		return nil, fmt.Errorf("no P2P handshake signer available")
	}
	sig, err := p.p2pHandshakeSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if len(p.p2pHandshakeCertPEM) == 0 {
		return nil, fmt.Errorf("missing P2P handshake certificate")
	}
	handshakeCert, err := parseCertPEM(p.p2pHandshakeCertPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid P2P handshake certificate: %w", err)
	}
	memberID := canonicalIDFromCert(handshakeCert)

	return &P2PHandshake{
		MemberID: memberID,
		CertPEM:  string(p.p2pHandshakeCertPEM),
		Nonce:    hex.EncodeToString(nonce),
		Sig:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// validates handshake certificate chain, member ID claim, and nonce signature.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).handleP2PConnection.
// Triggered: goroutine callback on inbound P2P TLS connection handling.
func (p *TSSPeer) verifyHandshake(hs *P2PHandshake, tlsPeerCert *x509.Certificate) (string, error) {
	if hs == nil {
		return "", fmt.Errorf("empty handshake")
	}
	if tlsPeerCert == nil {
		return "", fmt.Errorf("missing TLS peer certificate")
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
	if !bytes.Equal(cert.Raw, tlsPeerCert.Raw) {
		return "", fmt.Errorf("handshake certificate does not match TLS client certificate")
	}

	if p.trustedRoots != nil {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:       p.trustedRoots,
			CurrentTime: time.Now(),
		}); err != nil {
			return "", fmt.Errorf("certificate verification failed: %v", err)
		}
	} else {
		return "", fmt.Errorf("trusted MSP roots not configured")
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

// initializes TLS listener state and starts the inbound P2P accept loop.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: main.
// Triggered: startup initialization before polling and session workflows.
func (p *TSSPeer) StartP2P() error {
	if p.trustedRoots == nil {
		return fmt.Errorf("trusted MSP roots not configured")
	}
	if len(p.p2pServerTLSCert.Certificate) == 0 {
		return fmt.Errorf("missing P2P server TLS certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{p.p2pServerTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.trustedRoots,
		MinVersion:   tls.VersionTLS12,
	}
	p.p2pTLSConfig = tlsConfig

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", p.p2pPort), p.p2pTLSConfig)
	if err != nil {
		return fmt.Errorf("failed to start P2P listener: %w", err)
	}
	p.p2pListener = listener
	log.Printf("[%s] P2P listening on 0.0.0.0:%d (strict mTLS), advertise: %s", p.NodeID, p.p2pPort, p.p2pAdvertise)

	p.wg.Add(1)
	go p.acceptP2PConnections()

	return nil
}

// accepts inbound TLS sockets and dispatches connection handlers.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).StartP2P.
// Triggered: goroutine callback on inbound P2P TLS connection handling.
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

// authenticates one inbound peer and routes its TSS message to the correct channel.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).acceptP2PConnections.
// Triggered: goroutine callback on inbound P2P TLS connection handling.
func (p *TSSPeer) handleP2PConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("[%s] P2P rejected non-TLS connection type %T", p.NodeID, conn)
		return
	}

	decoder := json.NewDecoder(conn)
	var hs P2PHandshake
	if err := decoder.Decode(&hs); err != nil {
		// EOF is expected from health-check connections (waitForPeers dial+close)
		if err != io.EOF && err.Error() != "EOF" {
			log.Printf("[%s] P2P handshake decode error: %v", p.NodeID, err)
		}
		return
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("[%s] P2P handshake verification failed: missing TLS client certificate", p.NodeID)
		return
	}

	peerMemberID, err := p.verifyHandshake(&hs, state.PeerCertificates[0])
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

// opens a strict mTLS outbound connection to a discovered peer address.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).SendTSSMessage, (*TSSPeer).waitForPeersSubset.
// Triggered: outbound P2P dispatch and reachability gating before TSS rounds.
func (p *TSSPeer) dialPeerTLS(ctx context.Context, addr string, timeout time.Duration) (*tls.Conn, error) {
	if p.trustedRoots == nil {
		return nil, fmt.Errorf("trusted MSP roots not configured")
	}
	if len(p.p2pClientTLSCert.Certificate) == 0 {
		return nil, fmt.Errorf("missing P2P client TLS certificate")
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return nil, fmt.Errorf("invalid peer address %q: %w", addr, err)
	}
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("invalid peer address %q: empty host", addr)
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			RootCAs:      p.trustedRoots,
			Certificates: []tls.Certificate{p.p2pClientTLSCert},
			ServerName:   host,
			MinVersion:   tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("unexpected non-TLS connection type %T", conn)
	}
	return tlsConn, nil
}

// opens a TLS connection, sends handshake+message, and records send stats.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).SendTSSMessageWithRetry.
// Triggered: outbound P2P message dispatch during TSS protocol rounds.
func (p *TSSPeer) SendTSSMessage(to string, msg *TSSMessage) error {
	p.mutex.RLock()
	addr, ok := p.peerAddrs[to]
	p.mutex.RUnlock()

	if !ok {
		return fmt.Errorf("peer address not found: %s", to)
	}

	conn, err := p.dialPeerTLS(context.Background(), addr, 5*time.Second)
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

// retries outbound message delivery with exponential backoff.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).handleTSSKeygenMessages, (*TSSPeer).handleTSSReshareParty, (*TSSPeer).handleTSSSigningMessages.
// Triggered: outbound P2P message dispatch during TSS protocol rounds.
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

// registers this node advertised P2P endpoint in chaincode state (startup mostly)
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: main.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// loads and normalizes peer endpoint mappings from chaincode discovery
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: P2P runtime helper for transport, identity, and routing.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) LoadPeerAddresses() error {
	payload, err := p.Query("GetAllPeerAddresses")
	if err != nil {
		return err
	}

	var peers []map[string]interface{}
	if err := json.Unmarshal(payload, &peers); err != nil {
		return err
	}

	// Convert to map: shortNodeID -> address:port, long fabric ids are converted to short ones
	addrs := make(map[string]string)
	for _, peer := range peers {
		if nodeID, ok := peer["nodeId"].(string); ok {
			if address, ok := peer["address"].(string); ok {
				if p2pPort, ok := peer["p2pPort"].(float64); ok {
					shortID := p.extractShortNodeID(nodeID)
					if shortID == "" {
						log.Printf("[%s] Skipping peer with unparseable nodeId: %q", p.NodeID, nodeID)
						continue
					}
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

// converts canonical member IDs into short node IDs used by transport routing.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: multiple internal callers (see CALL_MAP.md).
// Triggered: P2P runtime helper for transport, identity, and routing.
// See CALL_MAP.md for the full caller list.
func (p *TSSPeer) extractShortNodeID(canonicalID string) string {
	return shortNodeIDFromCanonical(canonicalID)
}

// derives a deterministic short node label from canonical identity fields.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: (*TSSPeer).extractShortNodeID, NewTSSPeer.
// Triggered: P2P runtime helper for transport, identity, and routing.
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

// derives an organization label candidate from canonical identity data.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: shortNodeIDFromCanonical.
// Triggered: P2P runtime helper for transport, identity, and routing.
func extractOrgLabelFromCanonical(canonicalID string) string {
	canonicalID = strings.TrimSpace(canonicalID)
	if canonicalID == "" {
		return ""
	}

	issuer := parseCanonicalIssuer(canonicalID)
	for _, key := range []string{"O", "CN"} {
		label := orgLabelFromIdentityField(issuer[key])
		if label != "" {
			return label
		}
	}

	subject := parseCanonicalSubject(canonicalID)
	for _, key := range []string{"O", "CN"} {
		label := orgLabelFromIdentityField(subject[key])
		if label != "" {
			return label
		}
	}
	return ""
}

// extracts an org-style token from one identity DN field.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: extractOrgLabelFromCanonical.
// Triggered: P2P runtime helper for transport, identity, and routing.
func orgLabelFromIdentityField(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, ",", " ")
	value = strings.ReplaceAll(value, ";", " ")
	value = strings.ReplaceAll(value, "=", " ")
	tokens := strings.Fields(value)
	for _, tok := range tokens {
		parts := strings.Split(tok, ".")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if isOrgLabel(part) {
				return part
			}
		}
	}
	return ""
}

// reports whether a token matches supported org-label patterns.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: orgLabelFromIdentityField.
// Triggered: P2P runtime helper for transport, identity, and routing.
func isOrgLabel(label string) bool {
	if label == "" {
		return false
	}
	// Common explicit prefixes first.
	if strings.HasPrefix(label, "irs") || strings.HasPrefix(label, "org") {
		for i := 3; i < len(label); i++ {
			if label[i] < '0' || label[i] > '9' {
				return false
			}
		}
		return len(label) > 3
	}
	// Generic pattern: alpha prefix + numeric suffix (e.g. dept2).
	i := 0
	for i < len(label) && label[i] >= 'a' && label[i] <= 'z' {
		i++
	}
	if i == 0 || i == len(label) {
		return false
	}
	for j := i; j < len(label); j++ {
		if label[j] < '0' || label[j] > '9' {
			return false
		}
	}
	return true
}

// normalizes a node label into lowercase dash-separated form.
// Lifecycle: P2P transport setup, authentication, and message routing.
// Called by: shortNodeIDFromCanonical.
// Triggered: P2P runtime helper for transport, identity, and routing.
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
