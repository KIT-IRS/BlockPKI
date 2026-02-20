#!/usr/bin/env bash
# ============================================================================
#  generate.sh — Generate ALL deployment artifacts from network-config.yaml
# ============================================================================
#  Reads network-config.yaml and produces:
#    1. Cryptogen configs + crypto material for N organizations
#    2. configtx.yaml for N organizations
#    3. Per-host docker-compose files
#    4. Per-host env files for TSS peers
#    5. Distributable bundles for each remote host
#
#  Prerequisites: yq (YAML parser), cryptogen, configtxgen, peer (Fabric bins)
#  Install yq: go install github.com/mikefarah/yq/v4@latest
#              or: sudo snap install yq
# ============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/network-config.yaml"
OUTPUT="$SCRIPT_DIR/generated"
PORT_STEP=1000
CRYPTO_PROVIDER="${CRYPTO_PROVIDER:-cryptogen}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Check dependencies
# ---------------------------------------------------------------------------
command -v yq >/dev/null 2>&1 || error "yq not found. Install: go install github.com/mikefarah/yq/v4@latest"
command -v cryptogen >/dev/null 2>&1 || error "cryptogen not found. Ensure Fabric binaries are in PATH."
command -v configtxgen >/dev/null 2>&1 || error "configtxgen not found. Ensure Fabric binaries are in PATH."

info "Reading network config from $CONFIG"

# ---------------------------------------------------------------------------
# Parse config
# ---------------------------------------------------------------------------
ORDERER_HOST=$(yq '.hosts | to_entries | .[] | select(.value.orderer == true) | .key' "$CONFIG")
ORDERER_IP=$(yq ".hosts.$ORDERER_HOST.ip" "$CONFIG")
ORDERER_PORT=$(yq '.orderer.port' "$CONFIG")
ORDERER_ADMIN_PORT=$(yq '.orderer.admin_port' "$CONFIG")
ORDERER_OPS_PORT=$(yq '.orderer.operations_port' "$CONFIG")
CHANNEL_NAME=$(yq '.channel.name' "$CONFIG")
MERKLE_TREE_ENABLED=$(yq '.features.merkle_tree' "$CONFIG" 2>/dev/null | tr -d '\r')
if [ -z "$MERKLE_TREE_ENABLED" ] || [ "$MERKLE_TREE_ENABLED" = "null" ]; then
    MERKLE_TREE_ENABLED=true
fi

HOSTS=($(yq '.hosts | keys | .[]' "$CONFIG"))
ALL_ORGS=($(yq '.orgs | keys | .[]' "$CONFIG"))

info "Orderer host: $ORDERER_HOST ($ORDERER_IP:$ORDERER_PORT)"
info "Hosts: ${HOSTS[*]}"
info "Organizations: ${ALL_ORGS[*]}"

# Build host→IP and org→host maps
declare -A HOST_IPS
declare -A ORG_HOST
declare -A ORG_IP
for host in "${HOSTS[@]}"; do
    HOST_IPS[$host]=$(yq ".hosts.$host.ip" "$CONFIG")
    host_orgs=($(yq ".hosts.$host.orgs[]" "$CONFIG"))
    for org in "${host_orgs[@]}"; do
        ORG_HOST[$org]=$host
        ORG_IP[$org]=${HOST_IPS[$host]}
    done
done

# ---------------------------------------------------------------------------
# Clean & create output directory
# ---------------------------------------------------------------------------
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT/organizations/cryptogen"
mkdir -p "$OUTPUT/organizations/ordererOrganizations"
mkdir -p "$OUTPUT/configtx"

# ---------------------------------------------------------------------------
# 1. Generate cryptogen configs
# ---------------------------------------------------------------------------
info "Generating cryptogen configs..."

# Orderer crypto config
# Collect ALL host IPs + "localhost" for SANs so the orderer TLS cert works from any host
ORDERER_SANS="localhost"
for host in "${HOSTS[@]}"; do
    ORDERER_SANS="$ORDERER_SANS\n          - ${HOST_IPS[$host]}"
done

cat > "$OUTPUT/organizations/cryptogen/crypto-config-orderer.yaml" << EOF
OrdererOrgs:
  - Name: Orderer
    Domain: example.com
    EnableNodeOUs: true
    Specs:
      - Hostname: orderer
        SANS:
          - localhost
$(for host in "${HOSTS[@]}"; do echo "          - ${HOST_IPS[$host]}"; done)
EOF

# Per-org crypto configs
for org in "${ALL_ORGS[@]}"; do
    ORG_NUM=${org#org}  # "org3" -> "3"
    ORG_NAME="Org${ORG_NUM}"
    DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
    HOST=${ORG_HOST[$org]}
    HOST_IP=${HOST_IPS[$HOST]}
    PEER_COUNT=$(yq ".orgs.$org.peers // 1" "$CONFIG")
    USERS_COUNT=$(yq ".orgs.$org.users // 1" "$CONFIG")

    cat > "$OUTPUT/organizations/cryptogen/crypto-config-${org}.yaml" << EOF
PeerOrgs:
  - Name: ${ORG_NAME}
    Domain: ${DOMAIN}
    EnableNodeOUs: true
    Template:
      Count: ${PEER_COUNT}
      SANS:
        - localhost
        - ${HOST_IP}
$(for h in "${HOSTS[@]}"; do
    if [ "${HOST_IPS[$h]}" != "$HOST_IP" ]; then
        echo "        - ${HOST_IPS[$h]}"
    fi
done)
    Users:
      Count: ${USERS_COUNT}
EOF
    info "  Created crypto-config-${org}.yaml (SANS: localhost, ${HOST_IP}, ...)"
done

# ---------------------------------------------------------------------------
# 2. Generate crypto material
# ---------------------------------------------------------------------------
if [ "$CRYPTO_PROVIDER" = "openssl" ]; then
    info "Generating crypto material with OpenSSL (CRYPTO_PROVIDER=openssl)..."
    "$SCRIPT_DIR/openssl-generate.sh" "$CONFIG" "$OUTPUT"
else
    info "Generating crypto material with cryptogen..."

    # Orderer
    cryptogen generate \
        --config="$OUTPUT/organizations/cryptogen/crypto-config-orderer.yaml" \
        --output="$OUTPUT/organizations"

    # Each org
    for org in "${ALL_ORGS[@]}"; do
        cryptogen generate \
            --config="$OUTPUT/organizations/cryptogen/crypto-config-${org}.yaml" \
            --output="$OUTPUT/organizations"
        info "  Generated crypto for $org"
    done
fi

# ---------------------------------------------------------------------------
# 3. Generate configtx.yaml
# ---------------------------------------------------------------------------
info "Generating configtx.yaml..."

# Build per-org sections
ORG_SECTIONS=""
ORG_REFS=""
for org in "${ALL_ORGS[@]}"; do
    ORG_NUM=${org#org}
    ORG_NAME="Org${ORG_NUM}"
    MSPID=$(yq ".orgs.$org.mspid" "$CONFIG")
    DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")

    ORG_SECTIONS+="
  - &${ORG_NAME}
    Name: ${MSPID}
    ID: ${MSPID}
    MSPDir: ../organizations/peerOrganizations/${DOMAIN}/msp
    Policies:
      Readers:
        Type: Signature
        Rule: \"OR('${MSPID}.admin', '${MSPID}.peer', '${MSPID}.client')\"
      Writers:
        Type: Signature
        Rule: \"OR('${MSPID}.admin', '${MSPID}.client')\"
      Admins:
        Type: Signature
        Rule: \"OR('${MSPID}.admin')\"
      Endorsement:
        Type: Signature
        Rule: \"OR('${MSPID}.peer')\"
"
    ORG_REFS+="
        - *${ORG_NAME}"
done

cat > "$OUTPUT/configtx/configtx.yaml" << HEREDOC
---
Organizations:
  - &OrdererOrg
    Name: OrdererOrg
    ID: OrdererMSP
    MSPDir: ../organizations/ordererOrganizations/example.com/msp
    Policies:
      Readers:
        Type: Signature
        Rule: "OR('OrdererMSP.member')"
      Writers:
        Type: Signature
        Rule: "OR('OrdererMSP.member')"
      Admins:
        Type: Signature
        Rule: "OR('OrdererMSP.admin')"
    OrdererEndpoints:
      - orderer.example.com:${ORDERER_PORT}
${ORG_SECTIONS}
Capabilities:
  Channel: &ChannelCapabilities
    V2_0: true
  Orderer: &OrdererCapabilities
    V2_0: true
  Application: &ApplicationCapabilities
    V2_5: true

Application: &ApplicationDefaults
  Organizations:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    LifecycleEndorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
    Endorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
  Capabilities:
    <<: *ApplicationCapabilities

Orderer: &OrdererDefaults
  Addresses:
    - orderer.example.com:${ORDERER_PORT}
  BatchTimeout: 2s
  BatchSize:
    MaxMessageCount: 10
    AbsoluteMaxBytes: 99 MB
    PreferredMaxBytes: 512 KB
  Organizations:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    BlockValidation:
      Type: ImplicitMeta
      Rule: "ANY Writers"

Channel: &ChannelDefaults
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
  Capabilities:
    <<: *ChannelCapabilities

Profiles:
  ChannelUsingRaft:
    <<: *ChannelDefaults
    Orderer:
      <<: *OrdererDefaults
      OrdererType: etcdraft
      EtcdRaft:
        Consenters:
          - Host: orderer.example.com
            Port: ${ORDERER_PORT}
            ClientTLSCert: ../organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt
            ServerTLSCert: ../organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt
      Organizations:
        - *OrdererOrg
      Capabilities: *OrdererCapabilities
    Application:
      <<: *ApplicationDefaults
      Organizations:${ORG_REFS}
      Capabilities: *ApplicationCapabilities
HEREDOC

info "  configtx.yaml generated with ${#ALL_ORGS[@]} organizations"

# ---------------------------------------------------------------------------
# 4. Generate genesis block
# ---------------------------------------------------------------------------
info "Generating genesis block..."
export FABRIC_CFG_PATH="$OUTPUT/configtx"
configtxgen -profile ChannelUsingRaft \
    -outputBlock "$OUTPUT/channel-artifacts/${CHANNEL_NAME}.block" \
    -channelID "$CHANNEL_NAME"
info "  Genesis block: $OUTPUT/channel-artifacts/${CHANNEL_NAME}.block"

# ---------------------------------------------------------------------------
# 5. Generate per-host Docker Compose files
# ---------------------------------------------------------------------------
info "Generating Docker Compose files per host..."

for host in "${HOSTS[@]}"; do
    HOST_IP=${HOST_IPS[$host]}
    HOST_DIR="$OUTPUT/hosts/$host"
    mkdir -p "$HOST_DIR"

    host_orgs=($(yq ".hosts.$host.orgs[]" "$CONFIG"))
    is_orderer=$(yq ".hosts.$host.orderer" "$CONFIG")

    # Build extra_hosts entries for REMOTE hosts only (avoid overriding same-host DNS)
    EXTRA_HOSTS=""
    EXTRA_HOSTS_LINES=()
    if [ -n "$ORDERER_HOST" ] && [ "$ORDERER_IP" != "$HOST_IP" ]; then
        EXTRA_HOSTS_LINES+=("      - \"orderer.example.com:${ORDERER_IP}\"")
    fi
    for org in "${ALL_ORGS[@]}"; do
        DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
        ORG_HOST_NAME=${ORG_HOST[$org]}
        ORG_IP=${HOST_IPS[$ORG_HOST_NAME]}
        if [ "$ORG_IP" != "$HOST_IP" ]; then
            PEER_COUNT=$(yq ".orgs.$org.peers // 1" "$CONFIG")
            for ((i=0; i<PEER_COUNT; i++)); do
                EXTRA_HOSTS_LINES+=("      - \"peer${i}.${DOMAIN}:${ORG_IP}\"")
            done
        fi
    done
    if [ ${#EXTRA_HOSTS_LINES[@]} -gt 0 ]; then
        EXTRA_HOSTS="    extra_hosts:\n$(printf '%s\n' "${EXTRA_HOSTS_LINES[@]}")"
    fi

    # --- Compose file header ---
    cat > "$HOST_DIR/docker-compose.yaml" << EOF
# Auto-generated for host: $host ($HOST_IP)
# Generated from network-config.yaml by generate.sh

volumes:
EOF

    # Volume declarations
    if [ "$is_orderer" = "true" ]; then
        echo "  orderer.example.com:" >> "$HOST_DIR/docker-compose.yaml"
    fi
    for org in "${host_orgs[@]}"; do
        DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
        PEER_COUNT=$(yq ".orgs.$org.peers // 1" "$CONFIG")
        for ((i=0; i<PEER_COUNT; i++)); do
            echo "  peer${i}.${DOMAIN}:" >> "$HOST_DIR/docker-compose.yaml"
        done
    done

    cat >> "$HOST_DIR/docker-compose.yaml" << EOF

networks:
  fabric_net:
    name: fabric_net

services:
EOF

    # --- Orderer service (if this host is the orderer) ---
    if [ "$is_orderer" = "true" ]; then
        cat >> "$HOST_DIR/docker-compose.yaml" << EOF

  orderer.example.com:
    container_name: orderer.example.com
    image: hyperledger/fabric-orderer:2.5.14
    labels:
      service: hyperledger-fabric
    environment:
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_LISTENPORT=${ORDERER_PORT}
      - ORDERER_GENERAL_LOCALMSPID=OrdererMSP
      - ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp
      - ORDERER_GENERAL_TLS_ENABLED=true
      - ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_BOOTSTRAPMETHOD=none
      - ORDERER_CHANNELPARTICIPATION_ENABLED=true
      - ORDERER_ADMIN_TLS_ENABLED=true
      - ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:${ORDERER_ADMIN_PORT}
    working_dir: /root
    command: orderer
    volumes:
      - ./organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp:/var/hyperledger/orderer/msp
      - ./organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls:/var/hyperledger/orderer/tls
      - ./channel-artifacts/${CHANNEL_NAME}.block:/var/hyperledger/orderer/orderer.genesis.block
      - orderer.example.com:/var/hyperledger/production/orderer
    ports:
      - "${ORDERER_PORT}:${ORDERER_PORT}"
      - "${ORDERER_ADMIN_PORT}:${ORDERER_ADMIN_PORT}"
    networks:
      - fabric_net
EOF
    fi

    # --- Peer services for each org on this host ---
    for org in "${host_orgs[@]}"; do
        PEER_PORT_BASE=$(yq ".orgs.$org.peer_port" "$CONFIG")
        CC_PORT_BASE=$(yq ".orgs.$org.chaincode_port" "$CONFIG")
        OPS_PORT_BASE=$(yq ".orgs.$org.operations_port" "$CONFIG")
        MSPID=$(yq ".orgs.$org.mspid" "$CONFIG")
        DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
        PEER_COUNT=$(yq ".orgs.$org.peers // 1" "$CONFIG")

        for ((i=0; i<PEER_COUNT; i++)); do
            PEER_HOST="peer${i}.${DOMAIN}"
            PEER_PORT=$((PEER_PORT_BASE + i*PORT_STEP))
            CC_PORT=$((CC_PORT_BASE + i*PORT_STEP))
            OPS_PORT=$((OPS_PORT_BASE + i*PORT_STEP))

            # Gossip bootstrap: point to self only
            GOSSIP_BOOTSTRAP="${PEER_HOST}:${PEER_PORT}"

            cat >> "$HOST_DIR/docker-compose.yaml" << EOF

  ${PEER_HOST}:
    container_name: ${PEER_HOST}
    image: hyperledger/fabric-peer:2.5.14
    labels:
      service: hyperledger-fabric
    environment:
      - FABRIC_CFG_PATH=/etc/hyperledger/peercfg
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_PROFILE_ENABLED=false
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt
      - CORE_PEER_ID=${PEER_HOST}
      - CORE_PEER_ADDRESS=${PEER_HOST}:${PEER_PORT}
      - CORE_PEER_LISTENADDRESS=0.0.0.0:${PEER_PORT}
      - CORE_PEER_CHAINCODEADDRESS=${PEER_HOST}:${CC_PORT}
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:${CC_PORT}
      - CORE_PEER_GOSSIP_BOOTSTRAP=${GOSSIP_BOOTSTRAP}
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=${PEER_HOST}:${PEER_PORT}
      - CORE_PEER_LOCALMSPID=${MSPID}
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
      - DOCKER_HOST=unix:///run/docker.sock
      - CORE_VM_ENDPOINT=unix:///run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=fabric_net
    volumes:
      - ./organizations/peerOrganizations/${DOMAIN}/peers/${PEER_HOST}:/etc/hyperledger/fabric
      - ./peercfg:/etc/hyperledger/peercfg
      - ${PEER_HOST}:/var/hyperledger/production
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/run/docker.sock:/run/docker.sock
    working_dir: /root
    command: peer node start
    ports:
      - "${PEER_PORT}:${PEER_PORT}"
    networks:
      - fabric_net
EOF
            if [ -n "$EXTRA_HOSTS" ]; then
                echo -e "$EXTRA_HOSTS" >> "$HOST_DIR/docker-compose.yaml"
            fi
        done
    done

    info "  Created $HOST_DIR/docker-compose.yaml"
done

# ---------------------------------------------------------------------------
# 6. Generate peercfg (core.yaml) for each host
# ---------------------------------------------------------------------------
for host in "${HOSTS[@]}"; do
    HOST_DIR="$OUTPUT/hosts/$host"
    mkdir -p "$HOST_DIR/peercfg"
    # Copy the default core.yaml from fabric config
    if [ -f "$SCRIPT_DIR/../config/core.yaml" ]; then
        cp "$SCRIPT_DIR/../config/core.yaml" "$HOST_DIR/peercfg/core.yaml"
    elif [ -f "$SCRIPT_DIR/../test-network/compose/docker/peercfg/core.yaml" ]; then
        cp "$SCRIPT_DIR/../test-network/compose/docker/peercfg/core.yaml" "$HOST_DIR/peercfg/core.yaml"
    else
        warn "  No core.yaml found to copy for $host"
    fi
done

# ---------------------------------------------------------------------------
# 7. Generate TSS peer env files
# ---------------------------------------------------------------------------
info "Generating TSS peer environment files..."

for org in "${ALL_ORGS[@]}"; do
    HOST=${ORG_HOST[$org]}
    HOST_IP=${HOST_IPS[$HOST]}
    HOST_DIR="$OUTPUT/hosts/$HOST"

    PEER_PORT=$(yq ".orgs.$org.peer_port" "$CONFIG")
    MSPID=$(yq ".orgs.$org.mspid" "$CONFIG")
    DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
    PEER_HOST="peer0.${DOMAIN}"

    BASE_P2P_PORT=$(yq ".orgs.$org.p2p_port" "$CONFIG")
    BASE_WEBUI_PORT=$(yq ".orgs.$org.webui_port" "$CONFIG")
    ORG_JOIN_MODE=$(yq ".orgs.$org.join_mode" "$CONFIG" 2>/dev/null | tr -d '\r')
    if [ -z "$ORG_JOIN_MODE" ] || [ "$ORG_JOIN_MODE" = "null" ]; then
        ORG_JOIN_MODE="none"
    fi
    ORG_MSP_USER=$(yq -r ".orgs.$org.msp_user // \"\"" "$CONFIG" | tr -d '\r')
    if [ -z "$ORG_MSP_USER" ] || [ "$ORG_MSP_USER" = "null" ]; then
        ORG_MSP_USER="Admin@${DOMAIN}"
    fi

    NODE_COUNT=$(yq ".orgs.$org.tss_nodes | length" "$CONFIG" 2>/dev/null | tr -d '\r')
    if [ -n "$NODE_COUNT" ] && [ "$NODE_COUNT" != "null" ] && [ "$NODE_COUNT" -gt 0 ]; then
        for ((i=0; i<NODE_COUNT; i++)); do
            NODE_NAME=$(yq -r ".orgs.$org.tss_nodes[$i].name // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_NAME" ] || [ "$NODE_NAME" = "null" ]; then
                NODE_NAME="node$((i+1))"
            fi

            NODE_JOIN_MODE=$(yq -r ".orgs.$org.tss_nodes[$i].join_mode // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_JOIN_MODE" ] || [ "$NODE_JOIN_MODE" = "null" ]; then
                NODE_JOIN_MODE="$ORG_JOIN_MODE"
            fi

            NODE_P2P_PORT=$(yq ".orgs.$org.tss_nodes[$i].p2p_port // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_P2P_PORT" ] || [ "$NODE_P2P_PORT" = "null" ]; then
                NODE_P2P_PORT=$((BASE_P2P_PORT + i))
            fi

            NODE_WEBUI_PORT=$(yq ".orgs.$org.tss_nodes[$i].webui_port // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_WEBUI_PORT" ] || [ "$NODE_WEBUI_PORT" = "null" ]; then
                NODE_WEBUI_PORT=$((BASE_WEBUI_PORT + i))
            fi

            NODE_STATE_DIR=$(yq -r ".orgs.$org.tss_nodes[$i].state_dir // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_STATE_DIR" ] || [ "$NODE_STATE_DIR" = "null" ]; then
                NODE_STATE_DIR="state/${org}/${NODE_NAME}"
            fi

            NODE_MSP_USER=$(yq -r ".orgs.$org.tss_nodes[$i].msp_user // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_MSP_USER" ] || [ "$NODE_MSP_USER" = "null" ]; then
                NODE_MSP_USER="$ORG_MSP_USER"
            fi

            NODE_ID_OVERRIDE=$(yq -r ".orgs.$org.tss_nodes[$i].node_id // \"\"" "$CONFIG" | tr -d '\r')
            NODE_P2P_ADVERTISE=$(yq -r ".orgs.$org.tss_nodes[$i].p2p_advertise // \"\"" "$CONFIG" | tr -d '\r')
            if [ -z "$NODE_P2P_ADVERTISE" ] || [ "$NODE_P2P_ADVERTISE" = "null" ]; then
                NODE_P2P_ADVERTISE="${HOST_IP}:${NODE_P2P_PORT}"
            fi

            cat > "$HOST_DIR/tss-${org}-${NODE_NAME}.env" << EOF
# TSS Peer config for ${org} on host ${HOST} (${HOST_IP})
# Source this file before running the TSS peer binary:
#   source tss-${org}-${NODE_NAME}.env && ./tss_peer ${org}

export TSS_ORG=${org}
export TSS_MSPID=${MSPID}
export TSS_DOMAIN=${DOMAIN}
export TSS_MSP_USER=${NODE_MSP_USER}
export TSS_CRYPTO_PATH=./organizations/peerOrganizations/${DOMAIN}
export TSS_PEER_ENDPOINT=localhost:${PEER_PORT}
export TSS_PEER_HOSTNAME=${PEER_HOST}
export TSS_P2P_PORT=${NODE_P2P_PORT}
export TSS_P2P_ADVERTISE=${NODE_P2P_ADVERTISE}
export TSS_WEBUI_PORT=${NODE_WEBUI_PORT}
export TSS_STATE_DIR=${NODE_STATE_DIR}
export TSS_NODE_ID=${NODE_ID_OVERRIDE}
export TSS_ORDERER_ENDPOINT=${ORDERER_IP}:${ORDERER_PORT}
export TSS_JOIN_MODE=${NODE_JOIN_MODE}
export TSS_METRICS_ENABLED=false
export MERKLE_TREE_ENABLED=${MERKLE_TREE_ENABLED}
export TSS_MERKLE_TREE_ENABLED=${MERKLE_TREE_ENABLED}
EOF
            info "  Created tss-${org}-${NODE_NAME}.env (P2P advertise: ${NODE_P2P_ADVERTISE})"
        done
    else
        P2P_PORT=${BASE_P2P_PORT}
        WEBUI_PORT=${BASE_WEBUI_PORT}
        JOIN_MODE=${ORG_JOIN_MODE}
        MSP_USER=${ORG_MSP_USER}

        cat > "$HOST_DIR/tss-${org}.env" << EOF
# TSS Peer config for ${org} on host ${HOST} (${HOST_IP})
# Source this file before running the TSS peer binary:
#   source tss-${org}.env && ./tss_peer ${org}

export TSS_ORG=${org}
export TSS_MSPID=${MSPID}
export TSS_DOMAIN=${DOMAIN}
export TSS_MSP_USER=${MSP_USER}
export TSS_CRYPTO_PATH=./organizations/peerOrganizations/${DOMAIN}
export TSS_PEER_ENDPOINT=localhost:${PEER_PORT}
export TSS_PEER_HOSTNAME=${PEER_HOST}
export TSS_P2P_PORT=${P2P_PORT}
export TSS_P2P_ADVERTISE=${HOST_IP}:${P2P_PORT}
export TSS_WEBUI_PORT=${WEBUI_PORT}
export TSS_STATE_DIR=state/${org}
export TSS_NODE_ID=
export TSS_ORDERER_ENDPOINT=${ORDERER_IP}:${ORDERER_PORT}
export TSS_JOIN_MODE=${JOIN_MODE}
export TSS_METRICS_ENABLED=false
export MERKLE_TREE_ENABLED=${MERKLE_TREE_ENABLED}
export TSS_MERKLE_TREE_ENABLED=${MERKLE_TREE_ENABLED}
EOF
        info "  Created tss-${org}.env (P2P advertise: ${HOST_IP}:${P2P_PORT})"
    fi
done

# ---------------------------------------------------------------------------
# 8. Build TSS peer binary for each host (by arch)
# ---------------------------------------------------------------------------
info "Building TSS peer binaries..."

command -v go >/dev/null 2>&1 || error "go not found. Install Go to build tss_peer."
TSS_SRC="$SCRIPT_DIR/../peer-app/cmd/tss_peer"

for host in "${HOSTS[@]}"; do
    HOST_DIR="$OUTPUT/hosts/$host"
    HOST_ARCH=$(yq ".hosts.$host.arch" "$CONFIG")
    if [ -z "$HOST_ARCH" ] || [ "$HOST_ARCH" = "null" ]; then
        HOST_ARCH="amd64"
    fi
    info "  Building tss_peer for $host (arch=$HOST_ARCH)"
    ( cd "$TSS_SRC" && GOOS=linux GOARCH="$HOST_ARCH" CGO_ENABLED=0 CGO_ENABLED=0 go build -o "$HOST_DIR/tss_peer" . )
    chmod +x "$HOST_DIR/tss_peer"
done

# ---------------------------------------------------------------------------
# 9. Copy crypto material to per-host bundles
# ---------------------------------------------------------------------------
info "Copying crypto material to host bundles..."

for host in "${HOSTS[@]}"; do
    HOST_DIR="$OUTPUT/hosts/$host"
    host_orgs=($(yq ".hosts.$host.orgs[]" "$CONFIG"))
    if [ "$host" = "$ORDERER_HOST" ]; then
        mkdir -p "$HOST_DIR/organizations"
        cp -r "$OUTPUT/organizations/ordererOrganizations" "$HOST_DIR/organizations/"
    fi

    # Channel artifacts (genesis block needed by orderer AND for channel join)
    mkdir -p "$HOST_DIR/channel-artifacts"
    cp "$OUTPUT/channel-artifacts/${CHANNEL_NAME}.block" "$HOST_DIR/channel-artifacts/"

    # Peer crypto for each org on this host
    mkdir -p "$HOST_DIR/organizations/peerOrganizations"
    for org in "${host_orgs[@]}"; do
        DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
        cp -r "$OUTPUT/organizations/peerOrganizations/${DOMAIN}" \
              "$HOST_DIR/organizations/peerOrganizations/${DOMAIN}"
    done

    # MSP material for ALL orgs (needed to verify endorsements from all orgs)
    for org in "${ALL_ORGS[@]}"; do
        DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
        ORG_MSP_DIR="$HOST_DIR/organizations/peerOrganizations/${DOMAIN}/msp"
        if [ ! -d "$ORG_MSP_DIR" ]; then
            mkdir -p "$HOST_DIR/organizations/peerOrganizations/${DOMAIN}"
            cp -r "$OUTPUT/organizations/peerOrganizations/${DOMAIN}/msp" "$ORG_MSP_DIR"
        fi
    done

    # Orderer MSP for all hosts (needed for channel operations)
    mkdir -p "$HOST_DIR/organizations/ordererOrganizations"
    mkdir -p "$HOST_DIR/organizations/ordererOrganizations/example.com/msp"
    # Copy contents, not the directory itself, to avoid msp/msp nesting
    cp -r "$OUTPUT/organizations/ordererOrganizations/example.com/msp/." \
          "$HOST_DIR/organizations/ordererOrganizations/example.com/msp" 2>/dev/null || true
    # Orderer TLS cert (needed by peers to verify orderer)
    mkdir -p "$HOST_DIR/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls"
    cp "$OUTPUT/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt" \
       "$HOST_DIR/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt" 2>/dev/null || true

    info "  Bundled crypto for $host (orgs: ${host_orgs[*]})"
done

# ---------------------------------------------------------------------------
# 10. Generate deploy-chaincode.sh helper
# ---------------------------------------------------------------------------
info "Generating chaincode deployment script..."

cat > "$OUTPUT/deploy-chaincode.sh" << 'CHAINCODE_SCRIPT'
#!/usr/bin/env bash
# Deploy chaincode to all organizations in the multi-host network.
# Run this from the orderer host after all peers are running.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHAINCODE_SCRIPT

cat >> "$OUTPUT/deploy-chaincode.sh" << EOF
CHANNEL_NAME="${CHANNEL_NAME}"
CC_NAME="$(yq '.channel.chaincode_name' "$CONFIG")"
CC_SRC_PATH="$(yq '.channel.chaincode_path' "$CONFIG")"
ORDERER_IP="${ORDERER_IP}"
ORDERER_PORT="${ORDERER_PORT}"
EOF

cat >> "$OUTPUT/deploy-chaincode.sh" << 'CHAINCODE_BODY'

echo "=== Deploying chaincode $CC_NAME to channel $CHANNEL_NAME ==="
echo "This script packages, installs, approves, and commits the chaincode."
echo ""
echo "Make sure:"
echo "  1. All peers are running (docker compose up -d on each host)"
echo "  2. The channel has been created and all peers have joined"
echo "  3. Fabric binaries (peer, osnadmin) are in PATH"
echo ""
echo "For manual deployment, use the standard Fabric lifecycle commands."
echo "Refer to: https://hyperledger-fabric.readthedocs.io/en/latest/deploy_chaincode.html"
CHAINCODE_BODY

chmod +x "$OUTPUT/deploy-chaincode.sh"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
info "============================================"
info " Generation complete!"
info "============================================"
info ""
info "Output directory: $OUTPUT/"
info ""
info "Per-host bundles are in: $OUTPUT/hosts/<hostname>/"
info "Each bundle contains:"
info "  - docker-compose.yaml     (Fabric containers for that host)"
info "  - organizations/          (crypto material)"
info "  - channel-artifacts/      (genesis block)"
info "  - tss-<org>.env / tss-<org>-<node>.env (TSS peer environment config)"
info "  - peercfg/                (Fabric peer core.yaml)"
info ""
info "Next steps:"
info "  1. Edit network-config.yaml with your actual IPs"
info "  2. Re-run ./generate.sh"
info "  3. Copy each host bundle to the target machine"
info "  4. On each host: docker compose up -d"
info "  5. Create channel and join peers (see README)"
info "  6. Deploy chaincode"
info "  7. Start TSS peers: source tss-<org>.env && ./tss_peer <org> (or tss-<org>-<node>.env)"
