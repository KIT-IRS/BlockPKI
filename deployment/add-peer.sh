#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# add-peer.sh — Add a new peer to an existing org in a running network
# ----------------------------------------------------------------------------
# This script:
#  1) Generates MSP + TLS material for peerN using existing org CA/TLS CA
#  2) Creates a docker-compose override file for the new peer service
#  3) Prints the exact channel-join command
#
# Usage:
#   ./add-peer.sh --org irs3 --peer-index 1
#
# Optional:
#   --config /path/to/network-config.yaml
#   --output /path/to/generated
#   --host pi3
#   --client-user Member2@irs3.kit.edu
#   --client-role member|observer|client
#   --no-client-user
#
# NOTE: Requires openssl and yq. Uses existing OpenSSL-generated org CA/TLS CA keys.
# ----------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/network-config.yaml"
OUTPUT="$SCRIPT_DIR/generated"
PORT_STEP=1000

ORG=""
PEER_INDEX=""
HOST=""
CLIENT_USER=""
CREATE_CLIENT_USER="true"
CLIENT_ROLE="member"

COUNTRY="DE"
STATE="Baden-Wuerttemberg"
LOCALITY="Karlsruhe"

usage() {
  echo "Usage: $0 --org irs3 --peer-index 1 [--host pi3] [--config path] [--output path] [--client-user Member2@irs3.kit.edu] [--client-role member|observer|client] [--no-client-user]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --org) ORG="$2"; shift 2;;
    --peer-index) PEER_INDEX="$2"; shift 2;;
    --host) HOST="$2"; shift 2;;
    --config) CONFIG="$2"; shift 2;;
    --output) OUTPUT="$2"; shift 2;;
    --client-user) CLIENT_USER="$2"; shift 2;;
    --client-role) CLIENT_ROLE="$2"; shift 2;;
    --no-client-user) CREATE_CLIENT_USER="false"; shift 1;;
    *) usage;;
  esac
done

if [[ -z "$ORG" || -z "$PEER_INDEX" ]]; then
  usage
fi

command -v yq >/dev/null 2>&1 || { echo "ERROR: yq not found"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl not found"; exit 1; }

if [[ ! -f "$CONFIG" ]]; then
  echo "ERROR: config not found: $CONFIG"
  exit 1
fi

normalize_client_role() {
  local role="$1"
  role=$(echo "$role" | tr '[:upper:]' '[:lower:]' | tr -d '\r' | xargs)
  echo "$role"
}

validate_client_role() {
  local role="$1"
  if [[ "$role" != "member" && "$role" != "observer" && "$role" != "client" ]]; then
    echo "ERROR: invalid --client-role '$role' (expected member|observer|client)"
    exit 1
  fi
}

CLIENT_ROLE="$(normalize_client_role "$CLIENT_ROLE")"
validate_client_role "$CLIENT_ROLE"

if [[ -z "$HOST" ]]; then
  HOST=$(yq ".hosts | to_entries[] | select(.value.orgs[]==\"$ORG\") | .key" "$CONFIG")
fi

if [[ -z "$HOST" ]]; then
  echo "ERROR: Could not determine host for $ORG"
  exit 1
fi

get_org_subject() {
  local org="$1"
  local key="$2"
  local fallback="$3"
  local val
  val=$(yq -r ".orgs.${org}.subject.${key} // \"\"" "$CONFIG")
  if [[ -z "$val" || "$val" == "null" ]]; then
    echo "$fallback"
  else
    echo "$val"
  fi
}

HOST_IP=$(yq ".hosts.$HOST.ip" "$CONFIG")
DOMAIN=$(yq ".orgs.$ORG.domain" "$CONFIG")
MSPID=$(yq ".orgs.$ORG.mspid" "$CONFIG")
PEER_PORT_BASE=$(yq ".orgs.$ORG.peer_port" "$CONFIG")
CC_PORT_BASE=$(yq ".orgs.$ORG.chaincode_port" "$CONFIG")
OPS_PORT_BASE=$(yq ".orgs.$ORG.operations_port" "$CONFIG")

PEER_HOST="peer${PEER_INDEX}.${DOMAIN}"
PEER_PORT=$((PEER_PORT_BASE + PEER_INDEX*PORT_STEP))
CC_PORT=$((CC_PORT_BASE + PEER_INDEX*PORT_STEP))
OPS_PORT=$((OPS_PORT_BASE + PEER_INDEX*PORT_STEP))

ORG_PATH="$OUTPUT/organizations/peerOrganizations/$DOMAIN"
HOST_DIR="$OUTPUT/hosts/$HOST"

CA_KEY=$(ls "$ORG_PATH/ca/"*sk 2>/dev/null | head -n1 || true)
CA_CERT=$(ls "$ORG_PATH/ca/"*.pem 2>/dev/null | head -n1 || true)
TLSCA_KEY=$(ls "$ORG_PATH/tlsca/"*sk 2>/dev/null | head -n1 || true)
TLSCA_CERT=$(ls "$ORG_PATH/tlsca/"*.pem 2>/dev/null | head -n1 || true)

if [[ -z "$CA_KEY" || -z "$CA_CERT" ]]; then
  echo "ERROR: org CA not found in $ORG_PATH/ca"
  exit 1
fi
if [[ -z "$TLSCA_KEY" || -z "$TLSCA_CERT" ]]; then
  echo "ERROR: org TLS CA not found in $ORG_PATH/tlsca"
  exit 1
fi

PEER_DIR="$ORG_PATH/peers/$PEER_HOST"
MSP_DIR="$PEER_DIR/msp"
TLS_DIR="$PEER_DIR/tls"

mkdir -p "$MSP_DIR/cacerts" "$MSP_DIR/tlscacerts" "$MSP_DIR/signcerts" "$MSP_DIR/keystore" "$TLS_DIR"

# Subject defaults (aligned with openssl-generate.sh)
ORG_C="$(get_org_subject "$ORG" "c" "$COUNTRY")"
ORG_ST="$(get_org_subject "$ORG" "st" "$STATE")"
ORG_L="$(get_org_subject "$ORG" "l" "$LOCALITY")"
ORG_O="$(get_org_subject "$ORG" "o" "$DOMAIN")"

# Copy org MSP trust roots + config
cp "$ORG_PATH/msp/cacerts/"* "$MSP_DIR/cacerts/" || true
cp "$ORG_PATH/msp/tlscacerts/"* "$MSP_DIR/tlscacerts/" || true
if [[ -f "$ORG_PATH/msp/config.yaml" ]]; then
  cp "$ORG_PATH/msp/config.yaml" "$MSP_DIR/config.yaml"
fi

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# Peer MSP signing cert (OU=peer)
MSP_KEY="$MSP_DIR/keystore/priv_sk"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$MSP_KEY"
MSP_SUBJ="/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=peer/CN=$PEER_HOST"
openssl req -new -key "$MSP_KEY" -subj "$MSP_SUBJ" -out "$TMP_DIR/peer_msp.csr"
openssl x509 -req -in "$TMP_DIR/peer_msp.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$MSP_DIR/signcerts/${PEER_HOST}-cert.pem" -days 3650 -sha256

# Peer TLS cert
TLS_KEY="$TLS_DIR/server.key"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$TLS_KEY"
TLS_SUBJ="/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/CN=$PEER_HOST"
openssl req -new -key "$TLS_KEY" -subj "$TLS_SUBJ" -out "$TMP_DIR/peer_tls.csr"

cat > "$TMP_DIR/tls_ext.cnf" <<EOF
subjectAltName = DNS:${PEER_HOST},DNS:localhost,IP:${HOST_IP}
extendedKeyUsage = serverAuth, clientAuth
EOF

openssl x509 -req -in "$TMP_DIR/peer_tls.csr" -CA "$TLSCA_CERT" -CAkey "$TLSCA_KEY" -CAcreateserial \
  -out "$TLS_DIR/server.crt" -days 3650 -sha256 -extfile "$TMP_DIR/tls_ext.cnf"
cp "$TLSCA_CERT" "$TLS_DIR/ca.crt"

# Optional client identity for TSS/CLI usage (default role: member)
if [[ "$CREATE_CLIENT_USER" == "true" ]]; then
  if [[ -z "$CLIENT_USER" ]]; then
    CLIENT_USER="Member$((PEER_INDEX + 1))@${DOMAIN}"
  fi
  USER_DIR="$ORG_PATH/users/$CLIENT_USER"
  USER_MSP_DIR="$USER_DIR/msp"
  mkdir -p "$USER_MSP_DIR"/{cacerts,tlscacerts,signcerts,keystore}
  cp "$ORG_PATH/msp/cacerts/"* "$USER_MSP_DIR/cacerts/" || true
  cp "$ORG_PATH/msp/tlscacerts/"* "$USER_MSP_DIR/tlscacerts/" || true
  if [[ -f "$ORG_PATH/msp/config.yaml" ]]; then
    cp "$ORG_PATH/msp/config.yaml" "$USER_MSP_DIR/config.yaml"
  fi

  USER_KEY="$USER_MSP_DIR/keystore/priv_sk"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$USER_KEY"
  case "$CLIENT_ROLE" in
    member)
      USER_SUBJ="/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=member/OU=admin/CN=${CLIENT_USER}"
      ;;
    observer)
      USER_SUBJ="/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=observer/OU=client/CN=${CLIENT_USER}"
      ;;
    client)
      USER_SUBJ="/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=client/CN=${CLIENT_USER}"
      ;;
  esac
  openssl req -new -key "$USER_KEY" -subj "$USER_SUBJ" -out "$TMP_DIR/user_msp.csr"
  openssl x509 -req -in "$TMP_DIR/user_msp.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$USER_MSP_DIR/signcerts/${CLIENT_USER}-cert.pem" -days 3650 -sha256
fi

# Compose override
OVERRIDE="$HOST_DIR/peer${PEER_INDEX}-${ORG}-override.yaml"

EXTRA_HOSTS_LINES=()
ORDERER_HOST_KEY=$(yq ".hosts | to_entries[] | select(.value.orderer==true) | .key" "$CONFIG")
ORDERER_IP=$(yq ".hosts.$ORDERER_HOST_KEY.ip" "$CONFIG")
ORDERER_FQDN=$(yq -r ".orderer.hostname" "$CONFIG")
if [[ -z "$ORDERER_FQDN" || "$ORDERER_FQDN" == "null" ]]; then
  echo "ERROR: orderer.hostname missing in config"
  exit 1
fi
if [[ -n "$ORDERER_IP" && "$ORDERER_IP" != "$HOST_IP" ]]; then
  EXTRA_HOSTS_LINES+=("      - \"${ORDERER_FQDN}:${ORDERER_IP}\"")
fi
for o in $(yq ".orgs | keys | .[]" "$CONFIG"); do
  o_domain=$(yq ".orgs.$o.domain" "$CONFIG")
  o_host=$(yq ".hosts | to_entries[] | select(.value.orgs[]==\"$o\") | .key" "$CONFIG")
  o_ip=$(yq ".hosts.$o_host.ip" "$CONFIG")
  o_peers=$(yq ".orgs.$o.peers // 1" "$CONFIG")
  if [[ "$o_ip" != "$HOST_IP" ]]; then
    for ((i=0; i<o_peers; i++)); do
      EXTRA_HOSTS_LINES+=("      - \"peer${i}.${o_domain}:${o_ip}\"")
    done
  fi
done

EXTRA_HOSTS=""
if [[ ${#EXTRA_HOSTS_LINES[@]} -gt 0 ]]; then
  EXTRA_HOSTS="    extra_hosts:\n$(printf '%s\n' "${EXTRA_HOSTS_LINES[@]}")"
fi

cat > "$OVERRIDE" <<EOF
version: '2.1'

volumes:
  ${PEER_HOST}:

services:
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
      - CORE_PEER_GOSSIP_BOOTSTRAP=${PEER_HOST}:${PEER_PORT}
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

if [[ -n "$EXTRA_HOSTS" ]]; then
  echo -e "$EXTRA_HOSTS" >> "$OVERRIDE"
fi

echo "OK: Generated crypto for $PEER_HOST in $ORG_PATH/peers/"
echo "OK: Wrote compose override: $OVERRIDE"
echo
echo "Next steps on host ($HOST):"
echo "  1) Copy updated org crypto + override file to the host."
echo "     rsync -av $ORG_PATH/peers/$PEER_HOST $HOST:/opt/fabric/organizations/peerOrganizations/$DOMAIN/peers/"
if [[ "$CREATE_CLIENT_USER" == "true" ]]; then
  echo "     rsync -av $ORG_PATH/users/$CLIENT_USER $HOST:/opt/fabric/organizations/peerOrganizations/$DOMAIN/users/"
fi
echo "     rsync -av $OVERRIDE $HOST:/opt/fabric/"
echo "  2) Start the new peer:"
echo "     docker compose -f docker-compose.yaml -f peer${PEER_INDEX}-${ORG}-override.yaml up -d ${PEER_HOST}"
echo "  3) Join the channel:"
echo "     export FABRIC_CFG_PATH=/opt/fabric/peercfg"
echo "     export CORE_PEER_TLS_ENABLED=true"
echo "     export CORE_PEER_LOCALMSPID=${MSPID}"
echo "     export CORE_PEER_TLS_ROOTCERT_FILE=/opt/fabric/organizations/peerOrganizations/${DOMAIN}/peers/${PEER_HOST}/tls/ca.crt"
echo "     export CORE_PEER_MSPCONFIGPATH=/opt/fabric/organizations/peerOrganizations/${DOMAIN}/users/Admin@${DOMAIN}/msp"
echo "     export CORE_PEER_ADDRESS=localhost:${PEER_PORT}"
echo "     peer channel join -b channel-artifacts/mychannel.block"
echo
echo "Optional: install chaincode on the new peer if you want it to endorse/query."
