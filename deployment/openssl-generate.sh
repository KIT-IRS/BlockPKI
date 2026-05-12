#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# openssl-generate.sh — Generate Fabric MSP/TLS crypto using OpenSSL
# ----------------------------------------------------------------------------
# Usage:
#   ./openssl-generate.sh [config] [output]
#
# Generates the same folder structure as cryptogen under:
#   <output>/organizations/
#
# NOTE: This is a static generator (no CA server). Keys are stored on disk.
# ----------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${1:-$SCRIPT_DIR/network-config.yaml}"
OUTPUT="${2:-$SCRIPT_DIR/generated}"
ORG_OUT="$OUTPUT/organizations"

command -v yq >/dev/null 2>&1 || { echo "ERROR: yq not found"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl not found"; exit 1; }

mkdir -p "$ORG_OUT"

COUNTRY="DE"
STATE="Baden-Wuerttemberg"
LOCALITY="Karlsruhe"

normalize_role() {
  local role="$1"
  role=$(echo "$role" | tr '[:upper:]' '[:lower:]' | tr -d '\r' | xargs)
  echo "$role"
}

validate_role() {
  local role="$1"
  if [[ "$role" != "member" && "$role" != "observer" ]]; then
    echo "ERROR: invalid client role '$role' (expected member|observer)"
    exit 1
  fi
}

validate_nonneg_int() {
  local value="$1"
  local label="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "ERROR: ${label} must be a non-negative integer (got '${value}')"
    exit 1
  fi
}

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

expand_peer_cn_template() {
  local template="$1"
  local idx="$2"
  local domain="$3"
  local out
  out="${template//\{\{index\}\}/$idx}"
  out="${out//\{\{domain\}\}/$domain}"
  echo "$out"
}

all_host_ips=()
while read -r ip; do
  all_host_ips+=("$ip")
done < <(yq ".hosts.*.ip" "$CONFIG")

make_config_yaml() {
  local out_path="$1"
  local ca_cert_name="$2"
  cat > "$out_path" <<EOF
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/${ca_cert_name}
    OrganizationalUnitIdentifier: orderer
EOF
}

gen_ca() {
  local key_path="$1"
  local cert_path="$2"
  local cn="$3"
  local org="$4"
  # Use PKCS#8 keys (BEGIN PRIVATE KEY) for Fabric SDK compatibility
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key_path"
  openssl req -x509 -new -key "$key_path" -sha256 -days 3650 \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${org}/CN=${cn}" \
    -out "$cert_path"
}

issue_cert() {
  local ca_key="$1"
  local ca_cert="$2"
  local out_key="$3"
  local out_cert="$4"
  local subj="$5"
  local extfile="$6"
  # Use PKCS#8 keys (BEGIN PRIVATE KEY) for Fabric SDK compatibility
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$out_key"
  openssl req -new -key "$out_key" -subj "$subj" -out "${out_cert}.csr"
  if [[ -n "$extfile" ]]; then
    openssl x509 -req -in "${out_cert}.csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
      -out "$out_cert" -days 3650 -sha256 -extfile "$extfile"
  else
    openssl x509 -req -in "${out_cert}.csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
      -out "$out_cert" -days 3650 -sha256
  fi
  rm -f "${out_cert}.csr"
}

make_tls_ext() {
  local out="$1"
  local host="$2"
  local host_ip="$3"
  {
    printf "subjectAltName = DNS:%s,DNS:localhost,IP:%s" "$host" "$host_ip"
    for ip in "${all_host_ips[@]}"; do
      if [[ "$ip" != "$host_ip" ]]; then
        printf ",IP:%s" "$ip"
      fi
    done
    printf "\nextendedKeyUsage = serverAuth, clientAuth\n"
  } > "$out"
}

# ------------------------ Orderer Org --------------------------------------
ORDERER_HOST=$(yq ".orderer.hostname" "$CONFIG")
ORDERER_DOMAIN="${ORDERER_HOST#*.}"
if [[ -z "$ORDERER_DOMAIN" || "$ORDERER_DOMAIN" == "$ORDERER_HOST" ]]; then
  echo "ERROR: orderer.hostname must include a domain (for example orderer.kit.edu)"
  exit 1
fi

ORDERER_ORG="$ORG_OUT/ordererOrganizations/${ORDERER_DOMAIN}"
mkdir -p "$ORDERER_ORG/ca" "$ORDERER_ORG/tlsca" "$ORDERER_ORG/msp/cacerts" "$ORDERER_ORG/msp/tlscacerts"

ORDERER_CA_KEY="$ORDERER_ORG/ca/priv_sk"
ORDERER_CA_CERT="$ORDERER_ORG/ca/ca.${ORDERER_DOMAIN}-cert.pem"
ORDERER_TLSCA_KEY="$ORDERER_ORG/tlsca/priv_sk"
ORDERER_TLSCA_CERT="$ORDERER_ORG/tlsca/tlsca.${ORDERER_DOMAIN}-cert.pem"

gen_ca "$ORDERER_CA_KEY" "$ORDERER_CA_CERT" "ca.${ORDERER_DOMAIN}" "${ORDERER_DOMAIN}"
gen_ca "$ORDERER_TLSCA_KEY" "$ORDERER_TLSCA_CERT" "tlsca.${ORDERER_DOMAIN}" "${ORDERER_DOMAIN}"

cp "$ORDERER_CA_CERT" "$ORDERER_ORG/msp/cacerts/"
cp "$ORDERER_TLSCA_CERT" "$ORDERER_ORG/msp/tlscacerts/"
make_config_yaml "$ORDERER_ORG/msp/config.yaml" "ca.${ORDERER_DOMAIN}-cert.pem"

# Orderer node certs
ORDERER_NODE="$ORDERER_ORG/orderers/${ORDERER_HOST}"
mkdir -p "$ORDERER_NODE/msp/cacerts" "$ORDERER_NODE/msp/tlscacerts" "$ORDERER_NODE/msp/signcerts" "$ORDERER_NODE/msp/keystore" "$ORDERER_NODE/tls"
cp "$ORDERER_ORG/msp/cacerts/"* "$ORDERER_NODE/msp/cacerts/"
cp "$ORDERER_ORG/msp/tlscacerts/"* "$ORDERER_NODE/msp/tlscacerts/"
cp "$ORDERER_ORG/msp/config.yaml" "$ORDERER_NODE/msp/config.yaml"

issue_cert "$ORDERER_CA_KEY" "$ORDERER_CA_CERT" \
  "$ORDERER_NODE/msp/keystore/priv_sk" \
  "$ORDERER_NODE/msp/signcerts/${ORDERER_HOST}-cert.pem" \
  "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORDERER_DOMAIN}/OU=orderer/CN=${ORDERER_HOST}" \
  ""

TLS_EXT="$(mktemp)"
make_tls_ext "$TLS_EXT" "$ORDERER_HOST" "$(yq '.hosts | to_entries[] | select(.value.orderer==true) | .value.ip' "$CONFIG")"
issue_cert "$ORDERER_TLSCA_KEY" "$ORDERER_TLSCA_CERT" \
  "$ORDERER_NODE/tls/server.key" \
  "$ORDERER_NODE/tls/server.crt" \
  "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORDERER_DOMAIN}/CN=${ORDERER_HOST}" \
  "$TLS_EXT"
rm -f "$TLS_EXT"
cp "$ORDERER_TLSCA_CERT" "$ORDERER_NODE/tls/ca.crt"

# Orderer admin
ORDERER_ADMIN="$ORDERER_ORG/users/Admin@${ORDERER_DOMAIN}/msp"
mkdir -p "$ORDERER_ADMIN/cacerts" "$ORDERER_ADMIN/tlscacerts" "$ORDERER_ADMIN/signcerts" "$ORDERER_ADMIN/keystore"
cp "$ORDERER_ORG/msp/cacerts/"* "$ORDERER_ADMIN/cacerts/"
cp "$ORDERER_ORG/msp/tlscacerts/"* "$ORDERER_ADMIN/tlscacerts/"
cp "$ORDERER_ORG/msp/config.yaml" "$ORDERER_ADMIN/config.yaml"
issue_cert "$ORDERER_CA_KEY" "$ORDERER_CA_CERT" \
  "$ORDERER_ADMIN/keystore/priv_sk" \
  "$ORDERER_ADMIN/signcerts/Admin@${ORDERER_DOMAIN}-cert.pem" \
  "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORDERER_DOMAIN}/OU=admin/CN=Admin@${ORDERER_DOMAIN}" \
  ""

# ------------------------ Peer Orgs ----------------------------------------
for org in $(yq ".orgs | keys | .[]" "$CONFIG"); do
  DOMAIN=$(yq ".orgs.$org.domain" "$CONFIG")
  PEER_COUNT=$(yq ".orgs.$org.peers // 1" "$CONFIG")
  HOST=$(yq ".hosts | to_entries[] | select(.value.orgs[]==\"$org\") | .key" "$CONFIG")
  HOST_IP=$(yq ".hosts.$HOST.ip" "$CONFIG")
  ORG_C="$(get_org_subject "$org" "c" "$COUNTRY")"
  ORG_ST="$(get_org_subject "$org" "st" "$STATE")"
  ORG_L="$(get_org_subject "$org" "l" "$LOCALITY")"
  ORG_O="$(get_org_subject "$org" "o" "$DOMAIN")"
  ADMIN_CN="$(get_org_subject "$org" "admin_cn" "Admin@${DOMAIN}")"
  PEER_CN_TEMPLATE="$(get_org_subject "$org" "peer_cn_template" "peer{{index}}.${DOMAIN}")"
  MEMBER_CN_TEMPLATE="$(get_org_subject "$org" "member_cn_template" "Member{{index}}@${DOMAIN}")"
  OBSERVER_CN_TEMPLATE="$(get_org_subject "$org" "observer_cn_template" "Observer{{index}}@${DOMAIN}")"

  MEMBER_COUNT_RAW=$(yq -r ".orgs.${org}.member_users // \"\"" "$CONFIG" | tr -d '\r')
  OBSERVER_COUNT_RAW=$(yq -r ".orgs.${org}.observer_users // \"\"" "$CONFIG" | tr -d '\r')
  LEGACY_USERS_RAW=$(yq -r ".orgs.${org}.users // \"\"" "$CONFIG" | tr -d '\r')

  if [[ -n "$LEGACY_USERS_RAW" && "$LEGACY_USERS_RAW" != "null" ]] && \
     ([[ -n "$MEMBER_COUNT_RAW" && "$MEMBER_COUNT_RAW" != "null" ]] || [[ -n "$OBSERVER_COUNT_RAW" && "$OBSERVER_COUNT_RAW" != "null" ]]); then
    echo "ERROR: org ${org} mixes legacy users with member_users/observer_users"
    exit 1
  fi

  if [[ -n "$LEGACY_USERS_RAW" && "$LEGACY_USERS_RAW" != "null" ]]; then
    MEMBER_COUNT="$LEGACY_USERS_RAW"
    OBSERVER_COUNT=0
  else
    MEMBER_COUNT="${MEMBER_COUNT_RAW:-1}"
    OBSERVER_COUNT="${OBSERVER_COUNT_RAW:-1}"
    if [[ "$MEMBER_COUNT" == "null" || -z "$MEMBER_COUNT" ]]; then
      MEMBER_COUNT=1
    fi
    if [[ "$OBSERVER_COUNT" == "null" || -z "$OBSERVER_COUNT" ]]; then
      OBSERVER_COUNT=1
    fi
  fi

  validate_nonneg_int "$MEMBER_COUNT" "org ${org} member_users"
  validate_nonneg_int "$OBSERVER_COUNT" "org ${org} observer_users"

  ORG_PATH="$ORG_OUT/peerOrganizations/${DOMAIN}"
  mkdir -p "$ORG_PATH/ca" "$ORG_PATH/tlsca" "$ORG_PATH/msp/cacerts" "$ORG_PATH/msp/tlscacerts"

  CA_KEY="$ORG_PATH/ca/priv_sk"
  CA_CERT="$ORG_PATH/ca/ca.${DOMAIN}-cert.pem"
  TLSCA_KEY="$ORG_PATH/tlsca/priv_sk"
  TLSCA_CERT="$ORG_PATH/tlsca/tlsca.${DOMAIN}-cert.pem"

  gen_ca "$CA_KEY" "$CA_CERT" "ca.${DOMAIN}" "${ORG_O}"
  gen_ca "$TLSCA_KEY" "$TLSCA_CERT" "tlsca.${DOMAIN}" "${ORG_O}"

  cp "$CA_CERT" "$ORG_PATH/msp/cacerts/"
  cp "$TLSCA_CERT" "$ORG_PATH/msp/tlscacerts/"
  make_config_yaml "$ORG_PATH/msp/config.yaml" "ca.${DOMAIN}-cert.pem"

  # Admin user
  ADMIN_DIR="$ORG_PATH/users/Admin@${DOMAIN}/msp"
  mkdir -p "$ADMIN_DIR/cacerts" "$ADMIN_DIR/tlscacerts" "$ADMIN_DIR/signcerts" "$ADMIN_DIR/keystore"
  cp "$ORG_PATH/msp/cacerts/"* "$ADMIN_DIR/cacerts/"
  cp "$ORG_PATH/msp/tlscacerts/"* "$ADMIN_DIR/tlscacerts/"
  cp "$ORG_PATH/msp/config.yaml" "$ADMIN_DIR/config.yaml"
  issue_cert "$CA_KEY" "$CA_CERT" \
    "$ADMIN_DIR/keystore/priv_sk" \
    "$ADMIN_DIR/signcerts/Admin@${DOMAIN}-cert.pem" \
    "/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=admin/CN=${ADMIN_CN}" \
    ""

  # Member users (dual OU: member + admin)
  if [[ "$MEMBER_COUNT" -gt 0 ]]; then
    for ((u=1; u<=MEMBER_COUNT; u++)); do
      USER_NAME="Member${u}@${DOMAIN}"
      USER_CN="$(expand_peer_cn_template "$MEMBER_CN_TEMPLATE" "$u" "$DOMAIN")"
      USER_DIR="$ORG_PATH/users/${USER_NAME}/msp"
      mkdir -p "$USER_DIR/cacerts" "$USER_DIR/tlscacerts" "$USER_DIR/signcerts" "$USER_DIR/keystore"
      cp "$ORG_PATH/msp/cacerts/"* "$USER_DIR/cacerts/"
      cp "$ORG_PATH/msp/tlscacerts/"* "$USER_DIR/tlscacerts/"
      cp "$ORG_PATH/msp/config.yaml" "$USER_DIR/config.yaml"
      issue_cert "$CA_KEY" "$CA_CERT" \
        "$USER_DIR/keystore/priv_sk" \
        "$USER_DIR/signcerts/${USER_NAME}-cert.pem" \
        "/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=member/OU=admin/CN=${USER_CN}" \
        ""
    done
  fi

  # Observer users
  # Includes OU=client so the peers ACL treats observers as valid client identities
  # (required for query/invoke). Keep OU=observer so chaincode role checks can still
  if [[ "$OBSERVER_COUNT" -gt 0 ]]; then
    for ((u=1; u<=OBSERVER_COUNT; u++)); do
      USER_NAME="Observer${u}@${DOMAIN}"
      USER_CN="$(expand_peer_cn_template "$OBSERVER_CN_TEMPLATE" "$u" "$DOMAIN")"
      USER_DIR="$ORG_PATH/users/${USER_NAME}/msp"
      mkdir -p "$USER_DIR/cacerts" "$USER_DIR/tlscacerts" "$USER_DIR/signcerts" "$USER_DIR/keystore"
      cp "$ORG_PATH/msp/cacerts/"* "$USER_DIR/cacerts/"
      cp "$ORG_PATH/msp/tlscacerts/"* "$USER_DIR/tlscacerts/"
      cp "$ORG_PATH/msp/config.yaml" "$USER_DIR/config.yaml"
      issue_cert "$CA_KEY" "$CA_CERT" \
        "$USER_DIR/keystore/priv_sk" \
        "$USER_DIR/signcerts/${USER_NAME}-cert.pem" \
        "/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=observer/OU=client/CN=${USER_CN}" \
        ""
    done
  fi

  for ((i=0; i<PEER_COUNT; i++)); do
    PEER_HOST="peer${i}.${DOMAIN}"
    PEER_CN="$(expand_peer_cn_template "$PEER_CN_TEMPLATE" "$i" "$DOMAIN")"
    PEER_DIR="$ORG_PATH/peers/${PEER_HOST}"
    MSP_DIR="$PEER_DIR/msp"
    TLS_DIR="$PEER_DIR/tls"
    mkdir -p "$MSP_DIR/cacerts" "$MSP_DIR/tlscacerts" "$MSP_DIR/signcerts" "$MSP_DIR/keystore" "$TLS_DIR"
    cp "$ORG_PATH/msp/cacerts/"* "$MSP_DIR/cacerts/"
    cp "$ORG_PATH/msp/tlscacerts/"* "$MSP_DIR/tlscacerts/"
    cp "$ORG_PATH/msp/config.yaml" "$MSP_DIR/config.yaml"

    issue_cert "$CA_KEY" "$CA_CERT" \
      "$MSP_DIR/keystore/priv_sk" \
      "$MSP_DIR/signcerts/${PEER_HOST}-cert.pem" \
      "/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/OU=peer/CN=${PEER_CN}" \
      ""

    TLS_EXT="$(mktemp)"
    make_tls_ext "$TLS_EXT" "$PEER_HOST" "$HOST_IP"
    issue_cert "$TLSCA_KEY" "$TLSCA_CERT" \
      "$TLS_DIR/server.key" \
      "$TLS_DIR/server.crt" \
      "/C=${ORG_C}/ST=${ORG_ST}/L=${ORG_L}/O=${ORG_O}/CN=${PEER_HOST}" \
      "$TLS_EXT"
    rm -f "$TLS_EXT"
    cp "$TLSCA_CERT" "$TLS_DIR/ca.crt"
  done
done

echo "OK: OpenSSL crypto generated at $ORG_OUT"
