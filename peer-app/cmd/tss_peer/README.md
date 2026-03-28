# TSS Peer - Autonomous Decentralized PKI Node

## Overview

The TSS Node participates in a Decentralized PKI system using Threshold Signatures on Hyperledger Fabric.

## Features

### Autonomous Operations (No Manual Intervention)
- **DKG Participation**: Automatically participates in Distributed Key Generation
- **CSR Auto-Voting**: Automatically votes on pending CSR proposals
- **TSS Signing**: Participates in threshold signing sessions
- **Resharing**: Handles key resharing when members join/leave
- **Certificate Registration**: Registers combined certificates after signing

### Manual Operations (Interactive Menu)
<<<<<<< Updated upstream
- **Peer Joining**: Bootstrap or sponsor-based CA membership
- **CSR Submission**: Submit certificate signing requests
- **Member Sponsoring**: Sponsor new members to join the CA
=======
- **Peer Joining**: Bootstrap or join-request-based CA membership
- **CSR Submission**: Submit certificate signing requests
>>>>>>> Stashed changes
- **Status Viewing**: View CA state, DKG sessions, key share info


## Interactive Menu Options

<<<<<<< Updated upstream
### Running a Peer

**Option 1: PowerShell Script**
```powershell
cd peer-app/scripts
.\run_tss_peer.ps1 -org org1  # In Terminal 1
.\run_tss_peer.ps1 -org org2  # In Terminal 2
=======
>>>>>>> Stashed changes
```
========== TSS Peer Menu ==========
1. View CA State
2. Submit CSR (Certificate Request)
3. List Issued Certificates
4. Propose Certificate Revocation
5. View Certificate Merkle Tree
6. View My Key Share Info
7. Show My Member ID
8. Advanced Options >>>
9. Start Web UI / Stop Web UI
0. Exit

<<<<<<< Updated upstream
**Option 2: Direct Go Run**
```powershell
cd peer-app/cmd/tss_peer
go run . org1  # In Terminal 1
go run . org2  # In Terminal 2
```

### Testing the Full Workflow
```powershell
cd peer-app/scripts
.\test_full_workflow.ps1
```

## Interactive Menu Options

```
========== TSS Peer Menu ==========
1.  View CA State
2.  View DKG Session
3.  Sponsor New Member
4.  Endorse Sponsored Member
5.  List Pending Sponsorships
6.  Sponsor External Identity
7.  View External Identity
8.  Trigger Manual DKG Acknowledge
9.  Submit CSR (Certificate Request)
10. View Pending CSR Proposals
11. View Signing Sessions
12. View My Key Share Info
0.  Exit
```

=======
Advanced Options include:
- Read-only diagnostics (DKG/session/revocation views)
- Join request submission + member removal proposal
- Force reshare / fresh DKG
```

>>>>>>> Stashed changes
## Workflow Sequence

### Initial Setup (Automatic)
1. Peer connects to Fabric via Gateway API
<<<<<<< Updated upstream
2. Pre-generates TSS safe primes (~30 seconds)
3. Registers P2P address on blockchain
4. Joins CA via bootstrap (if within bootstrap period)
=======
2. Loads persisted TSS pre-params if available
3. Registers P2P address on blockchain
4. Joins CA via bootstrap (if within bootstrap period and join_mode=member)
>>>>>>> Stashed changes

### DKG Process (Automatic)
1. Polling loop detects "initiated" DKG session → Acknowledges
2. When "ready" → Waits for all peers to be reachable
3. Executes TSS keygen with P2P message exchange
4. org1 submits completion with CA public key

### Certificate Issuance (Automatic after CSR)
1. User submits CSR 
2. Other peers auto-vote (polling)
3. When approved → Signing session created
4. Peers execute TSS signing protocol
5. Certificate registered on blockchain

<<<<<<< Updated upstream
### Member Addition (Sponsor Model)
1. Existing member sponsors new member (menu option 3)
2. Other members endorse (menu option 4)
3. When threshold endorsements reached → Member added
4. Reshare session initiated → Peers generate new shares

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      TSS Peer                            │
├──────────────────┬──────────────────┬──────────────────┤
│  Gateway API     │   P2P Network    │   TSS Engine     │
│  (Fabric)        │   (TCP)          │   (bnb-chain)    │
├──────────────────┼──────────────────┼──────────────────┤
│ - Query CA       │ - Listen port    │ - Keygen         │
│ - Submit TX      │ - Send messages  │ - Signing        │
│ - Register addr  │ - Retry w/backoff│ - Pre-params     │
└──────────────────┴──────────────────┴──────────────────┘

Polling Loop (5s interval):
  ├── checkPendingDKG()      → DKG/Keygen
  ├── checkPendingCSRs()     → Auto-voting
  ├── checkSigningSessions() → TSS Signing
  └── checkReshareSessions() → Resharing
```

## Port Configuration

| Organization | P2P Port | Fabric Peer |
|--------------|----------|-------------|
| org1         | 6001     | localhost:7051 |
| org2         | 6002     | localhost:9051 |

## Troubleshooting

### "Failed to connect to peer"
- Ensure other peer is running and reachable
- Check firewall settings for P2P ports (6001, 6002)

### "DKG timeout"
- Both peers must be running simultaneously
- Check that pre-params generation completed

### "Not a member of this DKG session"
- Peer needs to join CA first (bootstrap or sponsor)
- Check CA members with menu option 1

### "Signing session not found"
- CSR needs to be approved first
- Check voting status with menu option 10

## Technical Details

- **TSS Library**: github.com/bnb-chain/tss-lib v1.5.0
- **Curve**: secp256k1 (Bitcoin/Ethereum compatible)
- **Threshold**: Configurable (default: n-1 for n parties)
- **Pre-params**: Paillier keys with safe primes (generated once and persisted to disk, so no more "No pre-params")
=======
### Member Addition (Join Request Model)
1. Candidate submits a join request
2. Existing members vote on the request
3. When approved → Member added
4. Reshare session initiated → Peers generate new shares
>>>>>>> Stashed changes
