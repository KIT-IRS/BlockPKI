# Fabric Blockchain based PKI

###### General Information ######

All commands were run in an Ubuntu wsl subsystem.

so it's important to run:
```bash
wsl -d Ubuntu
```

I also ran everything from my `D:fabric` directory.
My custom code is run from the cloned `fabric-samples git`, my `cd` commmands follow this so adjust them for your system.
The fabric prerequisites are explaines later, the most essential are docker and go (the language this code is written in).
Some normal bash commands are thus also written in go (or python for benchmarking)

## 1. Concepts

### TSS Node Roles (Join Modes)

`TSS_JOIN_MODE` controls **auto-join behavior only**. You can still manually join via Web UI or API.

- `member`: Attempt `BootstrapJoinCA` (during bootstrap window) and then confirm membership.
- `request`: Submit a join request proposal only (no auto-join). Use this only for identities that are not already in `CA.members`.
- `none`: Do not join the CA at all (manual only).

**Role-based access (OU roles):** client certificates use `OU=member` or `OU=observer` to control
which proposals can be submitted. `OU=admin` is treated as `member` for chaincode role checks.

**Web UI:** disabled by default. Enable with `TSS_WEBUI_ENABLED=true` and optionally set
`TSS_WEBUI_BIND=127.0.0.1` (default) or `0.0.0.0` if you need remote access.

**Polling interval:** defaults to 10s. Override with `TSS_POLL_INTERVAL_SECONDS=<n>`.

**Observer-light runtime:** peers not currently in `CA.members` run a lightweight poll profile:
- membership heartbeat + own certificate sync
- no DKG/reshare/signing/proposal auto-vote scans

Cadence tuning:
- `TSS_HEAVY_POLL_EVERY` (default `2`): member-heavy checks cadence.
- `TSS_CERT_FULL_SCAN_EVERY` (default `6`): full `GetAllCertificates` scan cadence.
- `TSS_AUTOVOTE_JITTER_MS` (default `300`): deterministic per-proposal vote jitter cap.
- `TSS_MEASURE_POLL_FALLBACK` (default `true`): keep polling-derived markers active when event stream is intermittent.

### Resilience / Auto-Recovery Env Vars (Were turned off during benchmarking)

Use these on every TSS peer for resilient key-share recovery:
- `TSS_KEYSHARE_SNAPSHOT_KEY_B64`: base64-encoded 32-byte key for AES-GCM encrypted key-share snapshots.
- `TSS_KEYSHARE_SNAPSHOT_RETENTION`: snapshots kept per node (default `30`).
- `TSS_AUTO_RESTORE_SNAPSHOT_ENABLED`: auto-restore snapshots during explicit-salt reshare mismatch (default `true`).
  - Keep this enabled for operational recovery after restart; disabling it can leave explicit-salt resharing unrecoverable without fresh DKG.
- `TSS_AUTO_FRESH_DKG_ENABLED`: auto-trigger `ForceFreshDKG` when same-key reshare is mathematically impossible (default `true`).
- `TSS_AUTO_FRESH_DKG_COOLDOWN_SECONDS`: cooldown between auto fresh-DKG submissions from the coordinator (default `300`).
- `TSS_STUCK_SESSION_TIMEOUT_SECONDS`: inactivity timeout for stuck key sessions (DKG/reshare) before coordinator evaluates fresh-DKG recovery (default `180`).

### MVCC Retry Tuning (Prevents read-write conflicts)
- `TSS_EXECUTE_MAX_ATTEMPTS` (default `8`)
- `TSS_EXECUTE_BACKOFF_BASE_MS` (default `250`)
- `TSS_EXECUTE_BACKOFF_MAX_MS` (default `4000`)
- `TSS_EXECUTE_BACKOFF_JITTER_PCT` (default `20`)

### How Fabric Gossip Works Across Hosts

Fabric peers discover each other via **gossip protocol**. 
---

| Problem | Solution |
|---|---|
| **Addresses** | Real IPs via env vars (`TSS_P2P_ADVERTISE`), managed on chain |
| **Docker networking** | Network is connected with `extra_hosts` for hostname resolution (docker-compose.yaml)|
| **Gossip discovery** | `CORE_PEER_GOSSIP_EXTERNALENDPOINT` converted via `extra_hosts` to real IPs |
| **TLS certificates** | SANs include all host IPs (set during crypto generation) |
| **TSS P2P registration** | `RegisterPeerAddress("192.168.1.101", ...)` via `TSS_P2P_ADVERTISE` |
| **Config** | Environment variables (`tss-<org>.env`) |
| **Crypto material** | Distributed per-host bundles (each host gets only what it needs). This is the bootstrapping crypto needed|
---

**Hostname resolution** — Docker containers resolve cross-host peer names via
   `extra_hosts` entries in docker-compose.yaml. These map `peer0.irsN.kit.edu` → IP for anchoring peers

generate.sh reads network-config.yaml
  produces docker-compose.yaml with correct extra_hosts and gossip config
  produces tss-<org>.env with correct P2P advertise address
  produces crypto with correct SANs

## 2. File Structure

```text
D:/fabric/fabric-samples
├── test-network/             # Same as upstream fabric-samples; only use custom copy if needed
├── chaincode/                # Chaincode definition
├── peer-app/                 # Peer runtime logic
└── deployment/
    ├── network-config.yaml   # EDIT: define hosts, orgs, IPs
    ├── generate.sh           # RUN: generates deployment artifacts
    ├── setup-host.sh         # RUN on each Pi: installs Docker + Fabric images
    └── generated/            # Created by generate.sh
        ├── organizations/    # Crypto material
        ├── configtx/         # Channel config
        ├── channel-artifacts/# Genesis/channel artifacts
        └── hosts/
            ├── pc/           # Bundle for PC
            │   ├── docker-compose.yaml
            │   ├── organizations/
            │   ├── channel-artifacts/
            │   ├── peercfg/
            │   ├── tss-irs1.env / tss-irs1-<node>.env
            │   └── tss-irs2.env / tss-irs2-<node>.env
            └── pi1/          # Bundle for Pi 1
                ├── docker-compose.yaml
                ├── organizations/
                ├── channel-artifacts/
                ├── peercfg/
                └── tss-irs3.env / tss-irs3-<node>.env
```

## 3. Deployment Deployment

```bash
# Fabric binaries (configtxgen, peer, osnadmin)

# You'll need to get fabric-samples, follow instructions from https://hyperledger-fabric.readthedocs.io/en/release-2.5/getting_started.html

# May be useful to also run the test-network to check if everything works: https://hyperledger-fabric.readthedocs.io/en/release-2.5/test_network.html - just the main functions without any special arguments should work

# yq (YAML parser for generate.sh)
go install github.com/mikefarah/yq/v4@latest
# Or download from: https://github.com/mikefarah/yq/releases
```

### Step 1: Configure Network

Edit `deployment/network-config.yaml`:
```yaml
hosts:
  pc:  # If you want to include the pc
    ip: "192.168.1.180"     # Change to the local IP of the PC
    orderer: true
    orgs: [irs1, irs2]
  pi1:
    ip: "192.168.1.165"     # Change to the local IP of the PI
    orderer: false
    orgs: [irs3]
```

To support multiple TSS peers per org, set:

- `orgs.<org>.member_users` / `orgs.<org>.observer_users` to generate extra client identities.
- `orgs.<org>.tss_nodes` with per-node ports, `msp_user`, and `join_mode`.

To generate extra client identities, set `orgs.<org>.member_users` and `orgs.<org>.observer_users`. Example:
```yaml
orgs:
  irs1:
    member_users: 3
    observer_users: 2
    # subject:
    #   member_cn_template: "Member{{index}}@irs1.kit.edu"
    #   observer_cn_template: "Observer{{index}}@irs1.kit.edu"
```

### Subject Overrides (OpenSSL)
You can override subject fields per org:
  ```yaml
  orgs:
    irs1:
      subject:
        c: DE
        st: BW
        l: Karlsruhe
        o: IRS-1
        admin_cn: Member@irs1.kit.edu
        peer_cn_template: "member{{index}}.irs1.kit.edu"
  ```

  Client role defaults (OU roles) for OpenSSL:
  ```yaml
  orgs:
    irs1:
      client_role_default: observer
      client_roles:
        Member1@irs1.kit.edu: member
        Member2@irs1.kit.edu: observer
  ```

### Step 2: Generate Data

```bash
# Do this on an engineering PC

cd /mnt/d/fabric/fabric-samples/deployment
chmod +x generate.sh
CRYPTO_PROVIDER=openssl ./generate.sh
```

### Step 3: Set Up the Raspberry Pi
        
#### Transfer & setup:
```bash

# Connect to the PIs
ssh ilo@192.168.1.161 # Up to 165 for the five PIs

# If you connect to the same PIs, the username is "ilo"  and the password is "IRS1234"
# Time is not updated when not in the irs-vsa-wifi, leads to tls "certificate not yet valid" errors

# Connect to this first (no need to go onto the PI itself to accept the terms on the website)
sudo nmcli device wifi connect "KA-WLAN"
# Afterwards it should be possible to connect to this
sudo nmcli device wifi connect "IRS-VSA-WIFI6(2.4G)" password "30331120"

# Sync the time and check if its correct
sudo systemctl restart systemd-timesyncd
date

# Rescan when irs-vsa not found, the PIs sometimes caused problems here
sudo nmcli device wifi rescan
sudo nmcli device wifi list


# Copy everything to the Pi -- always
cd /mnt/d/fabric/fabric-samples/

# scp -r deployment/generated/hosts/pi1/* ilo@192.168.1.161:/opt/fabric/
scp -r deployment/generated/hosts/pi2/* ilo@192.168.1.162:/opt/fabric/
scp -r deployment/generated/hosts/pi3/* ilo@192.168.1.163:/opt/fabric/
scp -r deployment/generated/hosts/pi4/* ilo@192.168.1.164:/opt/fabric/
scp -r deployment/generated/hosts/pi5/* ilo@192.168.1.165:/opt/fabric/

# Optional to not only overwrite but remove old data 
# (not required definetly, the docker compose and every client should be updated from the generate scripts, 
# just dont connect to three members when only two new ones are generated etc. then the crypto will mismatch)
rsync -av --delete deployment/generated/hosts/pi1/ ilo@192.168.1.161:/opt/fabric/
# ... same for pi2..pi5

# Copy setup and run script -- first setup
scp deployment/setup-host.sh ilo@192.168.1.161:/opt/fabric/

ssh ilo@192.168.1.161
cd /opt/fabric
sudo ./setup-host.sh
```

### Step 5: Start Fabric Containers

```bash
# On Pis
cd /opt/fabric
docker compose down -v --remove-orphans # May need additional clearance to remove all containers and volumes from previous runs not in compose file

docker compose up -d
```

Verify (Optional, if something is configured/deployed wrong or missing the peers/orderer may crash. ChatGPT is quite helpful with error codes for this, but needs a few tries and good description of the setup so Copilot/Codex of the workspace is also useful if you wanna go down that route):
```bash
docker ps   # Should show peer0.irs3.kit.edu running
docker logs peer0.irs3.kit.edu  # Check for gossip connection
```

### Step 6: Create Channel & Join All Peers

This is done from the orderer host (PC) to not install cli on every device

```bash
# Set env for orderer admin, if you changed any filepaths alter them accordingly. The most important parts to check are the indivudual IP adresses and ports
export FABRIC_CFG_PATH=/mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi2/peercfg # This can be any PI, doesnt have to be specific per peer
export ORDERER_CA=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/ordererOrganizations/kit.edu/orderers/orderer.kit.edu/tls/ca.crt

# Create channel via osnadmin, has the IP adress of the third PI that hosts the orderer in the current config
osnadmin channel join \
  --channelID mychannel \
  --config-block /mnt/d/fabric/fabric-samples/deployment/generated/channel-artifacts/mychannel.block \
  -o 192.168.1.163:7053 \ 
  --ca-file $ORDERER_CA \
  --client-cert /mnt/d/fabric/fabric-samples/deployment/generated/organizations/ordererOrganizations/kit.edu/orderers/orderer.kit.edu/tls/server.crt \
  --client-key /mnt/d/fabric/fabric-samples/deployment/generated/organizations/ordererOrganizations/kit.edu/orderers/orderer.kit.edu/tls/server.key

#Join Channel

# Repeat this for each peer to join the new channel, the envvars control the contacted peer, the command stays the same
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=IRS1MSP  # With the individual MSP
export CORE_PEER_TLS_ROOTCERT_FILE=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/peers/peer0.irs1.kit.edu/tls/ca.crt # change irs1 to 2 etc. and peers
export CORE_PEER_MSPCONFIGPATH=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/users/Member1@irs1.kit.edu/msp # change irs1 to 2 etc. and peer0 to 1 etc.
export CORE_PEER_ADDRESS=192.168.1.161:7051 # IP adress of the peer (if config is same its +1000 for every new one)
peer channel join -b /mnt/d/fabric/fabric-samples/deployment/generated/channel-artifacts/mychannel.block
```

### Step 7: Deploy Chaincode

Standard Fabric lifecycle on all 3 orgs:

```bash
# Package chaincode - If chaincode is already running on the network increment Version 1.0 -> 1.1 and Sequence 1 -> 2 and so on to make it deployable

cd /mnt/d/fabric/fabric-samples/deployment
CC_VERSION=1.0
CC_LABEL=bpki_${CC_VERSION}

peer lifecycle chaincode package bpki_${CC_VERSION}.tar.gz \
  --path ../chaincode --lang golang --label ${CC_LABEL}

# Start from here if chaincode is already packaged 

CC_VERSION=1.0
CC_LABEL=bpki_${CC_VERSION}

# Repeat this for every peer that needs to have invocable functions and produces endorsments (ideally every one but at least one per org) 
export FABRIC_CFG_PATH=/mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi2/peercfg
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=IRS1MSP # Individual MSP
export CORE_PEER_TLS_ROOTCERT_FILE=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/peers/peer0.irs1.kit.edu/tls/ca.crt # Change peer and irs1
export CORE_PEER_MSPCONFIGPATH=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/users/Member1@irs1.kit.edu/msp # Change peer and irs1
export CORE_PEER_ADDRESS=192.168.1.161:7051  # IP adress of the peer (if config is same its +1000 for every new one)

peer lifecycle chaincode install /mnt/d/fabric/fabric-samples/deployment/bpki_${CC_VERSION}.tar.gz
peer lifecycle chaincode queryinstalled

######################################################################

# Approve and Submit chaincode
export FABRIC_CFG_PATH=/mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi2/peercfg
export ORDERER_CA=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/ordererOrganizations/kit.edu/orderers/orderer.kit.edu/tls/ca.crt
export ORDERER_ADDR=192.168.1.163:7050
export CHANNEL=mychannel

# Adapt package id (seen in the earlier command)
export CC_NAME=bpki
export CC_VERSION=1.0 # same as described before, when a new one needs to be installed on a running network increment 1.1 
export CC_SEQUENCE=1 # and 2
export CC_PACKAGE_ID=bpki_1.0:caeebf5f380c49887ec1b3ed2631dfef62eb7aa7bc1fbecdb13babaf3523f270 # change this seen from queryinstalled command

# Example endorsement policy (adjust if you want ALL  or other configs)
export CC_POLICY="OutOf(3, 'IRS1MSP.peer','IRS2MSP.peer','IRS3MSP.peer','IRS4MSP.peer','IRS5MSP.peer')"

# This only needs to be done once per organization
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=IRS1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/peers/peer0.irs1.kit.edu/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/users/Member1@irs1.kit.edu/msp
export CORE_PEER_ADDRESS=192.168.1.161:7051

peer lifecycle chaincode approveformyorg \
  -o $ORDERER_ADDR --tls --cafile $ORDERER_CA \
  --channelID $CHANNEL --name $CC_NAME --version $CC_VERSION --sequence $CC_SEQUENCE \
  --package-id $CC_PACKAGE_ID --signature-policy "$CC_POLICY"

# Checks if commit ready

peer lifecycle chaincode checkcommitreadiness \
  --channelID $CHANNEL --name $CC_NAME --version $CC_VERSION --sequence $CC_SEQUENCE \
  --signature-policy "$CC_POLICY" --output json


# Commit (from one org)
export CORE_PEER_LOCALMSPID=IRS1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/peers/peer0.irs1.kit.edu/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/users/Member1@irs1.kit.edu/msp
export CORE_PEER_ADDRESS=192.168.1.161:7051

peer lifecycle chaincode commit \
  -o $ORDERER_ADDR --tls --cafile $ORDERER_CA \
  --channelID $CHANNEL --name $CC_NAME --version $CC_VERSION --sequence $CC_SEQUENCE \
  --signature-policy "$CC_POLICY" \
  --peerAddresses 192.168.1.161:7051 \
  --tlsRootCertFiles /mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs1.kit.edu/peers/peer0.irs1.kit.edu/tls/ca.crt \
  --peerAddresses 192.168.1.162:7051 \
  --tlsRootCertFiles /mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs2.kit.edu/peers/peer0.irs2.kit.edu/tls/ca.crt \
  --peerAddresses 192.168.1.163:7051 \
  --tlsRootCertFiles /mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs3.kit.edu/peers/peer0.irs3.kit.edu/tls/ca.crt \
  --peerAddresses 192.168.1.164:7051 \
  --tlsRootCertFiles /mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs4.kit.edu/peers/peer0.irs4.kit.edu/tls/ca.crt \
  --peerAddresses 192.168.1.165:7051 \
  --tlsRootCertFiles /mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs5.kit.edu/peers/peer0.irs5.kit.edu/tls/ca.crt 

peer lifecycle chaincode querycommitted --channelID $CHANNEL --name $CC_NAME

# This step can sometimes be misleading. For instance if there is a typo in the package ID, it still shows some chaincode to be committed even though its then only an empty package while the actually 
# installed one isn't committed. This can then be seen if the node instances show errors like "chaincode not installed on enough peers" 
# The check for commit readiness is also sometimes misleading as it shows the perspective from the individual enviroment settings. This can be different and still not actually be a network wide readiness

```

### Step 8: Start TSS Peers

```bash
## Optional transfer of binaries if updated

# For the Pis
cd /mnt/d/fabric/fabric-samples/peer-app/cmd/tss_peer
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi1/tss_peer .

# Copy Peer Logic
scp /mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi1/tss_peer \
  ilo@192.168.1.163:/opt/fabric/tss_peer

# Optional, clean stale keys -- after runs
rm -f /mnt/d/fabric/fabric-samples/deployment/generated/hosts/pc/state/irs1/keyshare_*.gob
rm -f /opt/fabric/state/irs3/keyshare_*.gob


## IMPORTANT: You can only join three peers with the mode member, then the bootstrapping CA function is locked. For more than three nodes use join_mode=request. 
## Ideally wait for a node to start and be accepted into the CA with reshare until you start the next one
# If the DKG is still running and you want to join a new node with join_mode=request, it will and can not send the join request to not protect the dkg from disruption

# If you want to submit CSRs from a node you need a cl interface or a WebUi of this node. You can also start a node in cl mode, submit the csr manually, stop the process by ^C and restart it headless
# The key share and state is then just reloaded, if you put a join_mode, it may run a reshare process to resync the key.

# Blocking Terminal, basic node
cd /opt/fabric
source tss-irs1.env
export TSS_JOIN_MODE=member
export TSS_INTERACTIVE_MENU=true
export TSS_HEAVY_POLL_EVERY=1
export TSS_POLL_INTERVAL_SECONDS=3
export TSS_AUTOVOTE_JITTER_MS=0
./tss_peer irs1

# Node with WebUI that can also be used for benchmarking 
cd /opt/fabric
source tss-irs3.env
export TSS_INTERACTIVE_MENU=true
export TSS_WEBUI_AUTOSTART=true
export TSS_JOIN_MODE=member
export TSS_METRICS_ENABLED=true
export TSS_HEAVY_POLL_EVERY=1
export TSS_POLL_INTERVAL_SECONDS=3
export TSS_AUTOVOTE_JITTER_MS=0
export TSS_WEBUI_ENABLED=true
export TSS_WEBUI_BIND=0.0.0.0
export TSS_WEBUI_PORT=8083
./tss_peer irs3

## Headless without blocking the command line 
cd /opt/fabric
source tss-irs1.env
sudo mkdir -p /opt/fabric/logs /opt/fabric/run
sudo chown -R ilo:ilo /opt/fabric/logs /opt/fabric/run
chmod 775 /opt/fabric/logs /opt/fabric/run
source tss-irs1.env
export TSS_JOIN_MODE=member
export TSS_AUTO_FRESH_DKG_ENABLED=false
export TSS_EXECUTE_MAX_ATTEMPTS=100
export TSS_INTERACTIVE_MENU=false
export TSS_HEAVY_POLL_EVERY=1
export TSS_POLL_INTERVAL_SECONDS=3
export TSS_AUTOVOTE_JITTER_MS=100

nohup ./tss_peer irs1 > /opt/fabric/logs/tss-irs1.log 2>&1 < /dev/null &
echo $! > /opt/fabric/run/tss-irs1.pid

cd /opt/fabric
sudo mkdir -p /opt/fabric/logs /opt/fabric/run
sudo chown -R ilo:ilo /opt/fabric/logs /opt/fabric/run
chmod 775 /opt/fabric/logs /opt/fabric/run
source tss-irs3.env
export TSS_AUTO_FRESH_DKG_ENABLED=false
export TSS_EXECUTE_MAX_ATTEMPTS=100
export TSS_INTERACTIVE_MENU=false
export TSS_METRICS_ENABLED=true
export TSS_HEAVY_POLL_EVERY=1
export TSS_POLL_INTERVAL_SECONDS=3
export TSS_AUTOVOTE_JITTER_MS=100
export TSS_WEBUI_BIND=0.0.0.0
export TSS_WEBUI_PORT=8083
export TSS_WEBUI_AUTOSTART=true
export TSS_WEBUI_ENABLED=true
export TSS_MEASURE_POLL_FALLBACK=true
nohup ./tss_peer irs3 > /opt/fabric/logs/tss-irs3.log 2>&1 < /dev/null &
echo $! > /opt/fabric/run/tss-irs3.pid

# Debug functions for headless mode

## Logs
cat /opt/fabric/run/tss-irs5.pid
tail -n 100 /opt/fabric/logs/tss-irs5.log

## Processes
ps -ef
ps -fp "$(cat /opt/fabric/run/tss-irs5.pid)"
ps -eo pid,etime,cmd | egrep 'tss_peer|peer node start|chaincode' | grep -v grep # These are also peer and chaincode docker containers

## Kill
pgrep -fa "tss_peer irs5"
kill "$(cat /opt/fabric/run/tss-irs5.pid)"
```
To generate multiple peers per org change network config
Peers use an automatic port offset of +1000 from the initial one on all ports

---

## 6. Environment Variables Reference

| Variable | Description | Example |
|---|---|---|
| `TSS_ORG` | Organization name | `irs3` |
| `TSS_MSPID` | Fabric MSP ID | `IRS3MSP` |
| `TSS_MSP_USER` | MSP user folder (identity) | `Member1@irs3.kit.edu` |
| `TSS_DOMAIN` | Organization domain | `irs3.kit.edu` |
| `TSS_CRYPTO_PATH` | Path to org crypto material | `./organizations/peerOrganizations/irs3.kit.edu` |
| `TSS_PEER_ENDPOINT` | Fabric peer gRPC address (usually localhost) | `localhost:7051` |
| `TSS_PEER_HOSTNAME` | Fabric peer hostname (for TLS verification) | `peer0.irs3.kit.edu` |
| `TSS_P2P_TLS_SERVER_CERT_PATH` | P2P mTLS server certificate path | `./organizations/peerOrganizations/irs3.kit.edu/peers/peer0.irs3.kit.edu/tls/server.crt` |
| `TSS_P2P_TLS_SERVER_KEY_PATH` | P2P mTLS server private key path | `./organizations/peerOrganizations/irs3.kit.edu/peers/peer0.irs3.kit.edu/tls/server.key` |
| `TSS_P2P_TLS_CLIENT_CERT_PATH` | P2P mTLS client certificate path | `./organizations/peerOrganizations/irs3.kit.edu/users/Member1@irs3.kit.edu/msp/signcerts/Member1@irs3.kit.edu-cert.pem` |
| `TSS_P2P_TLS_CLIENT_KEY_PATH` | P2P mTLS client private key path | `./organizations/peerOrganizations/irs3.kit.edu/users/Member1@irs3.kit.edu/msp/keystore/priv_sk` |
| `TSS_P2P_PORT` | TSS P2P listen port | `6001` |
| `TSS_P2P_ADVERTISE` | TSS P2P address registered on-chain | `192.168.1.101:6001` |
| `TSS_WEBUI_PORT` | Web dashboard port | `8080` |
| `TSS_STATE_DIR` | Local state directory | `state/irs3/user1` |
| `TSS_NODE_ID` | Override node ID (must match identity-derived ID) | `irs3-user1` |
| `TSS_JOIN_MODE` | Auto-join mode | `none` |
| `TSS_HEAVY_POLL_EVERY` | Member heavy-check cadence in polling ticks | `2` |
| `TSS_CERT_FULL_SCAN_EVERY` | Full certificate scan cadence in polling ticks | `6` |
| `TSS_AUTOVOTE_JITTER_MS` | Max deterministic per-proposal auto-vote jitter | `300` |
| `TSS_EXECUTE_MAX_ATTEMPTS` | Max submit attempts for MVCC/phantom conflicts | `8` |
| `TSS_EXECUTE_BACKOFF_BASE_MS` | Base retry backoff in milliseconds | `250` |
| `TSS_EXECUTE_BACKOFF_MAX_MS` | Max retry backoff in milliseconds | `4000` |
| `TSS_EXECUTE_BACKOFF_JITTER_PCT` | Retry backoff jitter percentage | `20` |
| `TSS_WEBUI_AUTOSTART` | to start the Web UI automatically at process boot (including headless mode) | `true` |
---


### 5.1 Add a Peer to a Running Org

This adds peers to an existing org on a running network.
It uses the existing orgs MSP to issue new enrollment certs.
Be careful that no residual peer containers or volumes from previous runs are present, otherwise this will cause issues with crypto inconsistencies


```bash
cd /mnt/d/fabric/fabric-samples/deployment

./add-peer.sh --org irs3 --peer-index 1 --client-role member

# peer crypto
rsync -av generated/organizations/peerOrganizations/irs3.kit.edu/peers/peer1.irs3.kit.edu \
  ilo@192.168.1.163:/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/peers/

# user identity
rsync -av "generated/organizations/peerOrganizations/irs3.kit.edu/users/Member2@irs3.kit.edu" \
  ilo@192.168.1.163:/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/users/

# compose override
rsync -av generated/hosts/pi3/peer1-irs3-override.yaml \
  ilo@192.168.1.163:/opt/fabric/


# run this on the pi to start the additional docker container
cd /opt/fabric
docker compose -f docker-compose.yaml -f peer1-irs3-override.yaml up -d peer1.irs3.kit.edu

# run this on the pc
cd /mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi3
# join channel
export FABRIC_CFG_PATH=$PWD/peercfg
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=IRS3MSP
export CORE_PEER_TLS_ROOTCERT_FILE=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs3.kit.edu/peers/peer0.irs3.kit.edu/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs3.kit.edu/users/Member1@irs3.kit.edu/msp
export CORE_PEER_ADDRESS=192.168.1.163:8051 #incremented by 1000 with each peer (initial orgs peer is 7051)
peer channel join -b channel-artifacts/mychannel.block

# install chaincode
export FABRIC_CFG_PATH=$PWD/peercfg
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=IRS3MSP
export CORE_PEER_TLS_ROOTCERT_FILE=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs3.kit.edu/peers/peer0.irs3.kit.edu/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/mnt/d/fabric/fabric-samples/deployment/generated/organizations/peerOrganizations/irs3.kit.edu/users/Member1@irs3.kit.edu/msp
export CORE_PEER_ADDRESS=192.168.1.163:8051  #incremented by 1000 with each peer (initial orgs peer is 7051)

peer lifecycle chaincode install /mnt/d/fabric/fabric-samples/deployment/bpki_${CC_VERSION}.tar.gz
peer lifecycle chaincode queryinstalled

# check if user exists
ls /opt/fabric/organizations/peerOrganizations/irs3.kit.edu/users/

# Start user, same as normal user but the crytopaths and adresses need to be changed
cd /opt/fabric
source tss-irs3.env
export TSS_MSP_USER=Member2@irs3.kit.edu
export TSS_PEER_HOSTNAME=peer1.irs3.kit.edu
export TSS_PEER_ENDPOINT=localhost:8051
export TSS_INTERACTIVE_MENU=true
export TSS_P2P_TLS_SERVER_CERT_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/peers/peer1.irs3.kit.edu/tls/server.crt
export TSS_P2P_TLS_SERVER_KEY_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/peers/peer1.irs3.kit.edu/tls/server.key
export TSS_P2P_TLS_CLIENT_CERT_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/users/Member2@irs3.kit.edu/msp/signcerts/Member2@irs3.kit.edu-cert.pem
export TSS_P2P_TLS_CLIENT_KEY_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/users/Member2@irs3.kit.edu/msp/keystore/priv_sk

export TSS_P2P_PORT=6004
export TSS_P2P_ADVERTISE=192.168.1.163:6004   # use THIS host’s IP
export TSS_WEBUI_PORT=8084
export TSS_STATE_DIR=state/irs3-peer1
export TSS_JOIN_MODE=request
./tss_peer irs3

cd /opt/fabric
sudo mkdir -p /opt/fabric/logs /opt/fabric/run
sudo chown -R ilo:ilo /opt/fabric/logs /opt/fabric/run
chmod 775 /opt/fabric/logs /opt/fabric/run
source tss-irs3.env
export TSS_MSP_USER=Member2@irs3.kit.edu
export TSS_PEER_HOSTNAME=peer1.irs3.kit.edu
export TSS_PEER_ENDPOINT=localhost:8051
export TSS_INTERACTIVE_MENU=true
export TSS_P2P_TLS_SERVER_CERT_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/peers/peer1.irs3.kit.edu/tls/server.crt
export TSS_P2P_TLS_SERVER_KEY_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/peers/peer1.irs3.kit.edu/tls/server.key
export TSS_P2P_TLS_CLIENT_CERT_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/users/Member2@irs3.kit.edu/msp/signcerts/Member2@irs3.kit.edu-cert.pem
export TSS_P2P_TLS_CLIENT_KEY_PATH=/opt/fabric/organizations/peerOrganizations/irs3.kit.edu/users/Member2@irs3.kit.edu/msp/keystore/priv_sk

export TSS_P2P_PORT=6004
export TSS_P2P_ADVERTISE=192.168.1.163:6004   # use THIS host’s IP
export TSS_WEBUI_PORT=8084
export TSS_STATE_DIR=state/irs3-peer1
export TSS_JOIN_MODE=request
nohup ./tss_peer irs3 > /opt/fabric/logs/tss-irs3-member2.log 2>&1 < /dev/null &
echo $! > /opt/fabric/run/tss-irs3-member2.pid

```
### Add a new org to an existing network (not tested)

Adding an org requires a channel config update and new MSP crypto.
Note: `generate.sh` regenerates all crypto, so run it in a temp copy of `deployment/` and copy only the new org folder into the live network.

```bash
# 1) Generate org MSP (OpenSSL) for irs4
# Update network-config.yaml to include irs4, then:
CRYPTO_PROVIDER=openssl ./generate.sh
# Copy ONLY the new org folder into the running network (do not overwrite existing crypto):
#   organizations/peerOrganizations/irs4.kit.edu

# 2) Create org definition for channel update
configtxgen -printOrg IRS4MSP > irs4.json

# 3) Fetch current config, add irs4, compute update
peer channel fetch config config_block.pb -o orderer.kit.edu:7050 -c mychannel --tls --cafile $ORDERER_CA
configtxlator proto_decode --input config_block.pb --type common.Block | jq .data.data[0].payload.data.config > config.json
jq -s '.[0] * {"channel_group":{"groups":{"Application":{"groups":{"IRS4MSP":.[1]}}}}}' \
  config.json irs4.json > modified_config.json
configtxlator proto_encode --input config.json --type common.Config > config.pb
configtxlator proto_encode --input modified_config.json --type common.Config > modified_config.pb
configtxlator compute_update --channel_id mychannel --original config.pb --updated modified_config.pb > irs4_update.pb

# 4) Wrap + submit update
configtxlator proto_decode --input irs4_update.pb --type common.ConfigUpdate | jq . > irs4_update.json
echo '{"payload":{"header":{"channel_header":{"channel_id":"mychannel","type":2}},"data":{"config_update":'$(cat irs4_update.json)'}}}' \
  | jq . > irs4_update_envelope.json
configtxlator proto_encode --input irs4_update_envelope.json --type common.Envelope > irs4_update_envelope.pb
peer channel update -f irs4_update_envelope.pb -c mychannel -o orderer.kit.edu:7050 --tls --cafile $ORDERER_CA

# 5) Start irs4 peer, join channel, install chaincode
```
Ideally include irs4 into the endorsement policy, approve & commit a new chaincode definition with updated policy.


### Merkle trees

Merkle trees are an efficient storage structure for certificates with inclusion proofs

```bash
# deployment/network-config.yaml -> controls wether they are used
features:
  merkle_tree: false

# if change not made:
peer chaincode invoke -C mychannel -n bpki \
  -c '{"function":"SetMerkleEnabled","Args":["root-ca-001","false"]}'
```

### Explorer - Blockchain Dashboard

Important: As of the end of this project, explorer was archived and is no longer actively maintained

Explorer is available on `localhost:8080`. As default
Canonical profile path: `explorer/connection/test-network.json`, May need to be changed on different configs

```bash
cd /mnt/d/fabric/fabric-samples/explorer

# Sync generated crypto into Explorer (IRS3 profile)
cp -r /mnt/d/fabric/fabric-samples/deployment/generated/hosts/pi3/organizations .

# Verify expected files for IRS3 profile
ls organizations/peerOrganizations/irs3.kit.edu/users/Member1@irs3.kit.edu/msp/keystore/priv_sk
ls organizations/peerOrganizations/irs3.kit.edu/users/Member1@irs3.kit.edu/msp/signcerts/Member1@irs3.kit.edu-cert.pem
ls organizations/peerOrganizations/irs3.kit.edu/peers/peer0.irs3.kit.edu/tls/ca.crt

# Start Explorer
cd /mnt/d/fabric/fabric-samples/explorer

# If explorer is running on a different machine, the networks need to be linked
docker network create fabric_net || true

docker-compose up -d

# Credentials
# user: exploreradmin
# pw: exploreradminpw
```

#### Benchmarks ####

```bash

# from your machine

scp /mnt/d/fabric/fabric-samples/peer-app/benchmarks/{run_benchmark_suite.py,run_workflows.py,collect_resources.py,label_resources.py,idle_comm_baseline.py,benchmark_queries.py,analyze_suite.py,compute_durations.py,measure_storage.sh,analyze_common.py,analyze_storage.py,analyze_workflow.py,latency_model.py} ilo@192.168.1.163:/opt/fabric/benchmarks/

# Single command: run csr -> queries -> revocation -> removal -> join for N runs,
# Merkle tree and root querys only make sense with multiple active certificates, ideally manually submit CSR proposals form the other nodes
cd /opt/fabric/benchmarks

# Run benchmark (write csv's)
OUT=/opt/fabric/benchmarks/out/suite_$(date +%Y%m%d_%H%M%S)
DOCKER_ROOT="$(docker info --format '{{.DockerRootDir}}')"
STORAGE_PATH="${DOCKER_ROOT}/volumes"
echo "DockerRootDir=$DOCKER_ROOT"
echo "StoragePath=$STORAGE_PATH"
sudo test -d "$STORAGE_PATH" || { echo "invalid storage path"; exit 1; }
sudo mkdir -p "$OUT"
sudo chown -R ilo:ilo "$OUT"
sudo -E python3 /opt/fabric/benchmarks/run_benchmark_suite.py \
  --api http://127.0.0.1:8083 \
  --runs 4 \
  --member-id 'x509::CN=Member1@irs3.kit.edu,OU=member+OU=admin,O=irs3.kit.edu,L=Karlsruhe,ST=Baden-Wuerttemberg,C=DE::CN=ca.irs3.kit.edu,O=irs3.kit.edu,L=Karlsruhe,ST=Baden-Wuerttemberg,C=DE' \
  --artifact-profile full \
  --query-cert-source auto_csr \
  --tx-event-window-skew-sec 120 \
  --workflows csr,revocation,removal,join \
  --metrics /opt/fabric/state/irs3/metrics.jsonl \
  --measurement \
  --measure \
  --storage-path "$STORAGE_PATH" \
  --storage-component 'peer=peer0\.irs3\.kit\.edu' \
  --storage-component 'orderer=orderer\.kit\.edu' \
  --storage-slices \
  --storage-topk 5 \
  --proc-match 'orderer=(^|\\s)(/[^\\s]*/)?orderer(\\s|$)' \
  --collect-messages \
  --query-bench \
  --query-iters 30 \
  --query-warmup 5 \
  --query-timeout 10 \
  --phase-tags \
  --inter-workflow-sleep 15 \
  --continue-on-error \
  --peer-metrics-url http://localhost:9446/metrics \
  --peer-metrics-prefix gossip_ \
  --outroot "$OUT"


# Analyse the run (generates plots)
sudo mkdir -p "$OUT/analysis"
sudo chown -R  ilo:ilo "$OUT/analysis"

# Optional: My setting for a proper tikz export
#python3 -m pip install --upgrade \
#  "matplotlib==3.7.5" \
#  "tikzplotlib==0.10.1" \
#  "webcolors==1.13"

MPLBACKEND=Agg python3 /opt/fabric/benchmarks/analyze_suite.py \
  --suite-root "$OUT" \
  --outdir "$OUT/analysis" \
  --analysis-profile full

# Can be also run on already completed runs (if the exported csvs properly match the analysis scripts)

MPLBACKEND=Agg python3 /opt/fabric/benchmarks/analyze_suite.py \
  --suite-root /opt/fabric/benchmarks/out/suite_20260306_091845 \
  --outdir "/opt/fabric/benchmarks/out/suite_20260306_091845/analysis" \
  --analysis-profile full


# Idle benchmark
OUT=/opt/fabric/benchmarks/out/idle_$(date +%Y%m%d_%H%M%S)
sudo mkdir -p "$OUT"
sudo chown -R ilo:ilo "$OUT"
python3 idle_comm_baseline.py \
  --duration 600 \
  --interval 3 \
  --iface eth0 \
  --peer-port 7051 \
  --orderer-port 7050 \
  --peer-metrics-url http://localhost:9446/metrics \
  --peer-metrics-prefix gossip_ \
  --outdir "$OUT"

# Optional cleanup of old runs
find /opt/fabric/benchmarks/out -maxdepth 1 -type d -name 'suite_*' -mtime +7 -print
find /opt/fabric/benchmarks/out -maxdepth 1 -type d -name 'suite_*' -mtime +7 -exec rm -rf {} +

```


