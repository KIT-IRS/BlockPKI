// cert_client.go - Lightweight certificate-only client
// Connects to Fabric Gateway to request certificates from the Decentralized PKI
// Does NOT participate in TSS/DKG or P2P networking.
// Usage: go run . [org1|org2] [subject]

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// CertClient is a lightweight Fabric client for requesting certificates
type CertClient struct {
	Organization string
	gateway      *client.Gateway
	contract     *client.Contract
	conn         *grpc.ClientConn
}

func main() {
	org := "org1"
	if len(os.Args) > 1 {
		org = os.Args[1]
	}

	fmt.Println("============================================")
	fmt.Println("  Decentralized PKI - Certificate Client")
	fmt.Println("  (Lightweight - No TSS/P2P required)")
	fmt.Println("============================================")
	fmt.Printf("  Organization: %s\n\n", org)

	cc, err := NewCertClient(org)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer cc.Close()

	cc.StartMenu()
}

func NewCertClient(org string) (*CertClient, error) {
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

	grpcConn, err := grpc.NewClient(config.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	gw, err := client.Connect(id, client.WithSign(sign), client.WithClientConnection(grpcConn),
		client.WithEvaluateTimeout(30*time.Second),
		client.WithEndorseTimeout(60*time.Second),
		client.WithSubmitTimeout(30*time.Second),
		client.WithCommitStatusTimeout(2*time.Minute))
	if err != nil {
		grpcConn.Close()
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}

	network := gw.GetNetwork("mychannel")
	contract := network.GetContract("bpki")

	log.Printf("[cert-client] Connected to Fabric via %s", config.PeerEndpoint)

	return &CertClient{
		Organization: org,
		gateway:      gw,
		contract:     contract,
		conn:         grpcConn,
	}, nil
}

func (cc *CertClient) Close() {
	if cc.gateway != nil {
		cc.gateway.Close()
	}
	if cc.conn != nil {
		cc.conn.Close()
	}
}

// ===================== MENU =====================

func (cc *CertClient) StartMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n===== Certificate Client Menu =====")
		fmt.Println("1. Request Certificate (submit CSR)")
		fmt.Println("2. Check CSR Status")
		fmt.Println("3. List All Certificates")
		fmt.Println("4. View Certificate Details")
		fmt.Println("5. View CA State")
		fmt.Println("6. View Certificate Merkle Tree")
		fmt.Println("0. Exit")
		fmt.Print("Select option: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			cc.requestCertificate(reader)
		case "2":
			cc.checkCSRStatus(reader)
		case "3":
			cc.listCertificates()
		case "4":
			cc.viewCertificateDetails(reader)
		case "5":
			cc.viewCAState()
		case "6":
			cc.viewCertificateMerkleTree()
		case "0":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid option")
		}
	}
}

// ===================== CERTIFICATE REQUEST =====================

func (cc *CertClient) requestCertificate(reader *bufio.Reader) {
	fmt.Println("\n--- Certificate Subject Fields ---")
	fmt.Println("Press Enter to use default values.")

	fmt.Printf("Common Name (CN) [client-%s.example.com]: ", cc.Organization)
	cn, _ := reader.ReadString('\n')
	cn = strings.TrimSpace(cn)
	if cn == "" {
		cn = fmt.Sprintf("client-%s-%d.example.com", cc.Organization, time.Now().Unix())
	}

	fmt.Printf("Organization (O) [DecentralizedPKI]: ")
	org, _ := reader.ReadString('\n')
	org = strings.TrimSpace(org)
	if org == "" {
		org = "DecentralizedPKI"
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

	// Generate a new ECDSA key pair for this certificate request
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	// Build subject
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

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject:            subjectName,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		log.Printf("Failed to create CSR: %v", err)
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	proposalID := fmt.Sprintf("csr-client-%s-%d", cc.Organization, time.Now().Unix())

	log.Printf("Submitting CSR: %s (CN: %s)", proposalID, cn)

	_, err = cc.contract.SubmitTransaction("SubmitCSR", proposalID, string(csrPEM))
	if err != nil {
		log.Printf("Failed to submit CSR: %v", err)
		return
	}

	// Save private key to disk immediately
	certsDir := filepath.Join("certs", "client-"+cc.Organization)
	os.MkdirAll(certsDir, 0700)

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Printf("Warning: failed to marshal private key: %v", err)
	} else {
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
		keyPath := filepath.Join(certsDir, proposalID+".key.pem")
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			log.Printf("Warning: failed to save private key: %v", err)
		} else {
			log.Printf("Private key saved to: %s", keyPath)
		}
	}

	// Save CSR to disk
	csrPath := filepath.Join(certsDir, proposalID+".csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		log.Printf("Warning: failed to save CSR: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ CSR submitted successfully!")
	fmt.Printf("  Proposal ID: %s\n", proposalID)
	fmt.Printf("  Private key: %s\n", filepath.Join(certsDir, proposalID+".key.pem"))
	fmt.Println()
	fmt.Println("The TSS CA members will now vote on and sign your certificate.")
	fmt.Println("Use option 2 to check the status of your request.")
	fmt.Println()

	// Optionally wait for the certificate
	fmt.Print("Wait for certificate? (y/n): ")
	wait, _ := reader.ReadString('\n')
	wait = strings.TrimSpace(wait)
	if strings.ToLower(wait) == "y" {
		cc.waitForCertificate(proposalID, certsDir)
	}
}

func (cc *CertClient) waitForCertificate(proposalID string, certsDir string) {
	fmt.Println("Waiting for certificate (polling every 10s, press Ctrl+C to stop)...")

	for i := 0; i < 60; i++ { // Max 10 minutes
		time.Sleep(10 * time.Second)

		// Check CSR status
		result, err := cc.contract.EvaluateTransaction("GetCSRProposal", proposalID)
		if err != nil {
			log.Printf("  Polling... error: %v", err)
			continue
		}

		var proposal map[string]interface{}
		if err := json.Unmarshal(result, &proposal); err != nil {
			continue
		}

		status, _ := proposal["status"].(string)
		fmt.Printf("  [%s] CSR status: %s\n", time.Now().Format("15:04:05"), status)

		if status == "signed" || status == "completed" {
			// Try to find the certificate
			certID, _ := proposal["certificateId"].(string)
			if certID != "" {
				cc.downloadCertificate(certID, proposalID, certsDir)
				return
			}

			// Try to find certificate by looking at all certs
			if cc.findAndSaveCertByProposal(proposalID, certsDir) {
				return
			}
		}

		if status == "rejected" {
			fmt.Println("  ✗ CSR was rejected!")
			return
		}
	}

	fmt.Println("  Timeout waiting for certificate. Check status later with option 2.")
}

func (cc *CertClient) downloadCertificate(certID, proposalID, certsDir string) {
	result, err := cc.contract.EvaluateTransaction("GetCertificate", certID)
	if err != nil {
		log.Printf("Failed to get certificate: %v", err)
		return
	}

	var cert map[string]interface{}
	if err := json.Unmarshal(result, &cert); err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		return
	}

	certPEM, _ := cert["certPEM"].(string)
	if certPEM == "" {
		log.Printf("Certificate has no PEM data")
		return
	}

	certPath := filepath.Join(certsDir, proposalID+".cert.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		log.Printf("Warning: failed to save certificate: %v", err)
		return
	}

	fmt.Println()
	fmt.Println("✓ Certificate received and saved!")
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private key: %s\n", filepath.Join(certsDir, proposalID+".key.pem"))
	fmt.Println()

	// Also save a combined bundle
	bundlePath := filepath.Join(certsDir, proposalID+".bundle.pem")
	keyPEM, _ := os.ReadFile(filepath.Join(certsDir, proposalID+".key.pem"))
	bundle := append([]byte(certPEM+"\n"), keyPEM...)
	if err := os.WriteFile(bundlePath, bundle, 0600); err != nil {
		log.Printf("Warning: failed to save bundle: %v", err)
	} else {
		fmt.Printf("  Bundle:      %s\n", bundlePath)
	}
}

func (cc *CertClient) findAndSaveCertByProposal(proposalID, certsDir string) bool {
	result, err := cc.contract.EvaluateTransaction("GetAllCertificates")
	if err != nil {
		return false
	}

	var certs []map[string]interface{}
	if err := json.Unmarshal(result, &certs); err != nil {
		return false
	}

	// Look for a certificate whose subject hash matches our proposalID
	for _, cert := range certs {
		certPEM, _ := cert["certPEM"].(string)
		if certPEM == "" {
			continue
		}

		// Check if this cert was recently created (within the last few minutes)
		certHash := fmt.Sprintf("%x", sha256.Sum256([]byte(certPEM)))
		certPath := filepath.Join(certsDir, proposalID+".cert.pem")
		if err := os.WriteFile(certPath, []byte(certPEM), 0644); err == nil {
			fmt.Println()
			fmt.Println("✓ Certificate found and saved!")
			fmt.Printf("  Certificate: %s\n", certPath)
			fmt.Printf("  Cert hash:   %s\n", certHash[:16]+"...")
			return true
		}
	}
	return false
}

// ===================== STATUS & QUERIES =====================

func (cc *CertClient) checkCSRStatus(reader *bufio.Reader) {
	fmt.Print("Enter proposal ID (or press Enter to list all): ")
	proposalID, _ := reader.ReadString('\n')
	proposalID = strings.TrimSpace(proposalID)

	if proposalID == "" {
		cc.listPendingCSRs()
		return
	}

	result, err := cc.contract.EvaluateTransaction("GetCSRProposal", proposalID)
	if err != nil {
		log.Printf("Failed to get CSR proposal: %v", err)
		return
	}

	var proposal map[string]interface{}
	if err := json.Unmarshal(result, &proposal); err != nil {
		log.Printf("Failed to parse proposal: %v", err)
		return
	}

	fmt.Println()
	fmt.Printf("CSR Proposal: %s\n", proposalID)
	fmt.Printf("  Status:        %v\n", proposal["status"])
	fmt.Printf("  Submitter:     %v\n", proposal["submitter"])
	fmt.Printf("  Approvals:     %v\n", proposal["approvalCount"])
	fmt.Printf("  Certificate ID: %v\n", proposal["certificateId"])

	if status, _ := proposal["status"].(string); status == "signed" || status == "completed" {
		certID, _ := proposal["certificateId"].(string)
		if certID != "" {
			certsDir := filepath.Join("certs", "client-"+cc.Organization)
			os.MkdirAll(certsDir, 0700)
			cc.downloadCertificate(certID, proposalID, certsDir)
		}
	}
}

func (cc *CertClient) listPendingCSRs() {
	result, err := cc.contract.EvaluateTransaction("GetPendingCSRs")
	if err != nil {
		log.Printf("Failed to get pending CSRs: %v", err)
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		log.Printf("Failed to parse proposals: %v", err)
		return
	}

	if len(proposals) == 0 {
		fmt.Println("No pending CSR proposals.")
		return
	}

	fmt.Printf("\nPending CSR Proposals (%d):\n", len(proposals))
	for i, p := range proposals {
		id, _ := p["proposalId"].(string)
		status, _ := p["status"].(string)
		fmt.Printf("  %d. %s (status: %s)\n", i+1, id, status)
	}
}

func (cc *CertClient) listCertificates() {
	result, err := cc.contract.EvaluateTransaction("GetAllCertificates")
	if err != nil {
		log.Printf("Failed to get certificates: %v", err)
		return
	}

	var certs []map[string]interface{}
	if err := json.Unmarshal(result, &certs); err != nil {
		log.Printf("Failed to parse certificates: %v", err)
		return
	}

	if len(certs) == 0 {
		fmt.Println("No certificates issued yet.")
		return
	}

	fmt.Printf("\nIssued Certificates (%d):\n", len(certs))
	for i, c := range certs {
		certID, _ := c["certId"].(string)
		subject, _ := c["subject"].(string)
		status := "active"
		if s, ok := c["status"].(string); ok && s != "" {
			status = s
		} else if revoked, ok := c["isRevoked"].(bool); ok && revoked {
			status = "revoked"
		}

		displayID := certID
		if len(displayID) > 30 {
			displayID = displayID[:30] + "..."
		}

		fmt.Printf("  %d. [%s] %s (subject: %s)\n", i+1, status, displayID, subject)
	}
}

func (cc *CertClient) viewCertificateDetails(reader *bufio.Reader) {
	fmt.Print("Enter certificate ID: ")
	certID, _ := reader.ReadString('\n')
	certID = strings.TrimSpace(certID)

	if certID == "" {
		fmt.Println("No certificate ID provided")
		return
	}

	result, err := cc.contract.EvaluateTransaction("GetCertificate", certID)
	if err != nil {
		log.Printf("Failed to get certificate: %v", err)
		return
	}

	var cert map[string]interface{}
	if err := json.Unmarshal(result, &cert); err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		return
	}

	prettyJSON, _ := json.MarshalIndent(cert, "", "  ")
	fmt.Println(string(prettyJSON))
}

func (cc *CertClient) viewCAState() {
	result, err := cc.contract.EvaluateTransaction("GetCA")
	if err != nil {
		log.Printf("Failed to get CA state: %v", err)
		return
	}

	var ca map[string]interface{}
	if err := json.Unmarshal(result, &ca); err != nil {
		log.Printf("Failed to parse CA state: %v", err)
		return
	}

	prettyJSON, _ := json.MarshalIndent(ca, "", "  ")
	fmt.Println(string(prettyJSON))
}

// ===================== CONFIG =====================

type GatewayConfig struct {
	MSPID        string
	CryptoPath   string
	OrgDomain    string
	MSPUser      string
	PeerEndpoint string
	PeerHostname string
}

func getConfig(org string) *GatewayConfig {
	if envMSPID := os.Getenv("TSS_MSPID"); envMSPID != "" {
		orgDomain := envOrDefault("TSS_DOMAIN", org+".example.com")
		mspUser := envOrDefault("TSS_MSP_USER", envOrDefault("TSS_USER", fmt.Sprintf("Admin@%s", orgDomain)))
		return &GatewayConfig{
			MSPID:        envMSPID,
			CryptoPath:   os.Getenv("TSS_CRYPTO_PATH"),
			OrgDomain:    orgDomain,
			MSPUser:      mspUser,
			PeerEndpoint: envOrDefault("TSS_PEER_ENDPOINT", "localhost:7051"),
			PeerHostname: envOrDefault("TSS_PEER_HOSTNAME", "peer0."+org+".example.com"),
		}
	}
	if org == "org2" {
		return &GatewayConfig{
			MSPID:        "Org2MSP",
			CryptoPath:   "D:/fabric/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com",
			OrgDomain:    "org2.example.com",
			MSPUser:      "Admin@org2.example.com",
			PeerEndpoint: "localhost:9051",
			PeerHostname: "peer0.org2.example.com",
		}
	}
	return &GatewayConfig{
		MSPID:        "Org1MSP",
		CryptoPath:   "D:/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com",
		OrgDomain:    "org1.example.com",
		MSPUser:      "Admin@org1.example.com",
		PeerEndpoint: "localhost:7051",
		PeerHostname: "peer0.org1.example.com",
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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

func (cc *CertClient) viewCertificateMerkleTree() {
	result, err := cc.contract.EvaluateTransaction("GetCertificateMerkleRoot")
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
