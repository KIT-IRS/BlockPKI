#!/usr/bin/env bash
# ============================================================================
#  create-channel.sh — Create channel and join all peers
# ============================================================================
#  Run this from the orderer host (PC) after 'docker compose up -d' on ALL hosts.
#
#  Usage: ./create-channel.sh <path-to-generated>
#  Example: ./create-channel.sh ./generated/hosts/pc
# ============================================================================

set -euo pipefail

DEPLOY_DIR="${1:-.}"
CHANNEL_NAME="${CHANNEL_NAME:-mychannel}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Fabric config path (core.yaml, etc.)
export FABRIC_CFG_PATH="${DEPLOY_DIR}/peercfg"

ORDERER_CA="${DEPLOY_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt"
ORDERER_ADMIN_TLS_CERT="${DEPLOY_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt"
ORDERER_ADMIN_TLS_KEY="${DEPLOY_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.key"

# ---------------------------------------------------------------------------
# 1. Create channel via osnadmin
# ---------------------------------------------------------------------------
info "Creating channel '$CHANNEL_NAME' via osnadmin..."
osnadmin channel join \
    --channelID "$CHANNEL_NAME" \
    --config-block "${DEPLOY_DIR}/channel-artifacts/${CHANNEL_NAME}.block" \
    -o localhost:7053 \
    --ca-file "$ORDERER_CA" \
    --client-cert "$ORDERER_ADMIN_TLS_CERT" \
    --client-key "$ORDERER_ADMIN_TLS_KEY"

info "Channel '$CHANNEL_NAME' created"

# ---------------------------------------------------------------------------
# 2. Join each org's peer
# ---------------------------------------------------------------------------
# Find all org directories in the crypto material
for ORG_DIR in "${DEPLOY_DIR}"/organizations/peerOrganizations/*/; do
    DOMAIN=$(basename "$ORG_DIR")

    # Extract org name and MSP ID
    # Domain format: orgN.example.com
    ORG_NAME=$(echo "$DOMAIN" | cut -d. -f1)
    ORG_NUM=${ORG_NAME#org}
    MSPID="Org${ORG_NUM}MSP"

    # Check if this org has a peer directory (not just MSP material)
    PEER_DIR="${ORG_DIR}peers/peer0.${DOMAIN}"
    if [ ! -d "$PEER_DIR" ]; then
        info "Skipping $DOMAIN (MSP only, no peer on this host)"
        continue
    fi

    # Check for admin user credentials
    ADMIN_MSP="${ORG_DIR}users/Admin@${DOMAIN}/msp"
    if [ ! -d "$ADMIN_MSP" ]; then
        info "Skipping $DOMAIN (no Admin user found)"
        continue
    fi

    info "Joining peer0.${DOMAIN} to channel '$CHANNEL_NAME'..."

    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_LOCALMSPID="$MSPID"
    export CORE_PEER_TLS_ROOTCERT_FILE="${PEER_DIR}/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP"

    # Determine the peer address — check if running locally or on remote host
    # Try localhost first (for peers on this machine)
    # Read peer port from docker-compose or use the standard port
    PEER_PORT=7051
    if grep -q "peer0.${DOMAIN}" "${DEPLOY_DIR}/docker-compose.yaml" 2>/dev/null; then
        PEER_PORT=$(grep -A1 "peer0.${DOMAIN}:" "${DEPLOY_DIR}/docker-compose.yaml" | \
                    grep -oP '(?<=CORE_PEER_LISTENADDRESS=0.0.0.0:)\d+' || echo "7051")
    fi

    export CORE_PEER_ADDRESS="localhost:${PEER_PORT}"

    peer channel join -b "${DEPLOY_DIR}/channel-artifacts/${CHANNEL_NAME}.block" && \
        info "  ✓ peer0.${DOMAIN} joined" || \
        info "  ✗ peer0.${DOMAIN} failed (may need to join from remote host)"
done

info ""
info "Channel setup complete!"
info ""
info "For peers on REMOTE hosts, run this from the remote host:"
info "  export CORE_PEER_ADDRESS=localhost:<port>"
info "  export CORE_PEER_LOCALMSPID=<OrgMSP>"
info "  export CORE_PEER_MSPCONFIGPATH=<admin-msp-path>"
info "  export CORE_PEER_TLS_ROOTCERT_FILE=<tls-ca-cert>"
info "  export CORE_PEER_TLS_ENABLED=true"
info "  export FABRIC_CFG_PATH=./peercfg"
info "  peer channel join -b channel-artifacts/${CHANNEL_NAME}.block"
