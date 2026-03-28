// menu.go provides the interactive CLI menu used for manual operations and runtime inspection.
// Runtime flow: StartInteractiveMenu reads operator input, dispatches actions, and invokes peer workflow methods.
package main

import (
	"bufio"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// ===================== INTERACTIVE MENU =====================

// runs the interactive operator loop and dispatches menu actions.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: main.
// Triggered: startup goroutine when interactive mode is enabled.
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
		} else if p.webuiEnabled {
			fmt.Println("9. Start Web UI")
		} else {
			fmt.Println("9. Start Web UI (disabled)")
		}
		fmt.Println("0. Exit")
		fmt.Print("Select option: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log.Printf("[%s] Interactive menu stdin closed; exiting menu loop", p.NodeID)
				return
			}
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

// renders and handles the advanced operations submenu.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) advancedMenu(reader *bufio.Reader) {
	for {
		fmt.Println("\n--- Advanced Options ---")
		fmt.Println("1. View DKG Session")
		fmt.Println("2. View Pending CSR Proposals")
		fmt.Println("3. View Signing Sessions")
		fmt.Println("4. View Pending Revocations")
		fmt.Println("5. View Node Role")
		fmt.Println("6. Force Reshare (Manual)")
		fmt.Println("7. Request CA Membership (Self)")
		fmt.Println("8. List Pending Join Requests")
		fmt.Println("9. Propose Member Removal")
		fmt.Println("10. List Pending Member Removals")
		fmt.Println("11. Force Fresh DKG (Reset CA Key)")
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
			p.viewPendingCSRs()
		case "3":
			p.viewSigningSessions()
		case "4":
			p.viewPendingRevocations()
		case "5":
			p.viewNodeRole()
		case "6":
			p.forceReshareMenu(reader)
		case "7":
			p.requestJoinMenu(reader)
		case "8":
			p.listPendingJoinRequests()
		case "9":
			p.proposeRemoveMemberMenu(reader)
		case "10":
			p.listPendingRemoveMemberProposals()
		case "11":
			p.manualFreshDKG(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option")
		}
	}
}

// fetches and prints the current CA state snapshot.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) displayCAState() {
	ca, err := p.GetCA()
	if err != nil {
		fmt.Printf("Error getting CA state: %v\n", err)
		return
	}
	caJSON, _ := json.MarshalIndent(ca, "", "  ")
	fmt.Printf("\nCA State:\n%s\n", caJSON)
}

// fetches and prints the epoch-0 DKG session state.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) displayDKGSession() {
	dkg, err := p.GetDKGSession(0)
	if err != nil {
		fmt.Printf("Error getting DKG session: %v\n", err)
		return
	}
	dkgJSON, _ := json.MarshalIndent(dkg, "", "  ")
	fmt.Printf("\nDKG Session:\n%s\n", dkgJSON)
}

// collects input and submits a CA join request.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// submits a join request transaction with the provided proposal ID and reason.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).EnsureCAInitialized, (*TSSPeer).requestJoinMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) RequestJoinCA(proposalID, reason string) error {
	_, err := p.Execute("RequestJoinCA", DefaultCAID, proposalID, reason)
	if err != nil {
		return err
	}
	p.emitMetric("join_request_submitted", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   p.MemberID,
	})
	return nil
}

// submits a governance vote for a pending join request.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: runtime callback/entrypoint paths (see CALL_MAP.md).
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) VoteOnJoinRequest(proposalID, decision, rationale string) error {
	_, err := p.Execute("VoteOnJoinRequest", DefaultCAID, proposalID, decision, rationale)
	return err
}

// prints currently pending join requests.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// collects input and submits a member-removal proposal.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// submits a remove-member governance proposal.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).proposeRemoveMemberMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) ProposeRemoveMember(proposalID, memberID, reason string) error {
	_, err := p.Execute("ProposeRemoveMember", DefaultCAID, proposalID, memberID, reason)
	if err != nil {
		return err
	}
	p.emitMetric("member_removal_proposed", map[string]interface{}{
		"proposal_id": proposalID,
		"member_id":   memberID,
	})
	return nil
}

// submits a governance vote for a pending remove-member proposal.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: runtime callback/entrypoint paths (see CALL_MAP.md).
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) VoteOnRemoveMember(proposalID, decision, rationale string) error {
	_, err := p.Execute("VoteOnRemoveMember", DefaultCAID, proposalID, decision, rationale)
	return err
}

// prints currently pending remove-member proposals.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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
		fmt.Printf("   Target: %v\n", r["targetNodeId"])
		fmt.Printf("   Reason: %v\n", r["reason"])
		fmt.Println()
	}
}

// queries and prints this node's current chaincode role.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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
	default:
		fmt.Println("Role: NONE (not part of this CA)")
	}
}

// collects input and triggers a manual ForceReshare request.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) forceReshareMenu(reader *bufio.Reader) {
	fmt.Print("Enter reason for reshare (optional): ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)

	if reason == "" {
		reason = "manual_reshare"
	}

	_, err := p.Execute("ForceReshare", DefaultCAID, reason)
	if err != nil {
		fmt.Printf("Error forcing reshare: %v\n", err)
		return
	}

	fmt.Println("OK Reshare initiated")
}

// collects CSR subject fields and submits a CSR proposal.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// lists pending CSR proposals and their voting status.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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
		fmt.Printf("   Submitter: %v\n", p["submitterId"])
		fmt.Printf("   Status: %v\n", p["status"])
		fmt.Printf("   Votes For: %v\n", p["votesFor"])
		fmt.Printf("   Votes Against: %v\n", p["votesAgainst"])
		fmt.Println()
	}
}

// lists signing sessions and partial-signature progress.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// prints local key-share availability and cached committee context.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// prints the canonical member identity bound to this peer.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) showMyMemberID() {
	fmt.Println("\n=== My Member ID ===")
	fmt.Println("Full ID:")
	fmt.Println(p.MemberID)
	fmt.Println("")
	fmt.Println("Use this ID when voting on join requests or removals.")
}

// collects input and triggers a manual ForceFreshDKG action.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// collects input and submits a revocation proposal.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// lists pending revocation proposals and votes.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).advancedMenu.
// Triggered: menu action after operator input in the interactive CLI.
func (p *TSSPeer) viewPendingRevocations() {
	const noPendingMsg = "\nNo pending revocation proposals"

	result, err := p.Query("GetPendingRevocations")
	if err != nil {
		fmt.Printf("Error getting pending revocations: %v\n", err)
		return
	}

	if len(result) == 0 || string(result) == "null" {
		fmt.Println(noPendingMsg)
		return
	}

	var proposals []map[string]interface{}
	if err := json.Unmarshal(result, &proposals); err != nil {
		fmt.Println(noPendingMsg)
		return
	}
	if len(proposals) == 0 {
		fmt.Println(noPendingMsg)
		return
	}

	fmt.Println("\n=== Pending Revocation Proposals ===")
	for i, proposal := range proposals {
		fmt.Printf("%d. Proposal ID: %v\n", i+1, proposal["proposalId"])
		targetID := fmt.Sprintf("%v", proposal["targetNodeId"])
		if len(targetID) > 60 {
			targetID = targetID[:60] + "..."
		}
		fmt.Printf("   Target: %v\n", targetID)
		fmt.Printf("   Reason: %v\n", proposal["reason"])
		fmt.Printf("   Votes For: %v / Against: %v\n", proposal["votesFor"], proposal["votesAgainst"])
		fmt.Printf("   Status: %v\n", proposal["status"])
		fmt.Println()
	}
}

// prints issued certificate records from chaincode.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
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

// fetches and prints the certificate Merkle tree view.
// Lifecycle: Operator-driven interactive menu workflow.
// Called by: (*TSSPeer).StartInteractiveMenu.
// Triggered: menu action after operator input in the interactive CLI.
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
