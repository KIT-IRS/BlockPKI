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
- **Peer Joining**: Bootstrap or sponsor-based CA membership
- **CSR Submission**: Submit certificate signing requests
- **Member Sponsoring**: Sponsor new members to join the CA
- **Status Viewing**: View CA state, DKG sessions, key share info

## Workflow Sequence

### Initial Setup (Automatic)
1. Peer connects to Fabric via Gateway API
2. Pre-generates TSS safe primes 
3. Registers P2P address on blockchain
4. Joins CA via bootstrap (if within bootstrap period)

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

### Member Addition (Sponsor Model)
1. Existing member sponsors new member
2. Other members endorse 
3. When threshold endorsements reached → Member added
4. Reshare session initiated → Peers generate new shares

