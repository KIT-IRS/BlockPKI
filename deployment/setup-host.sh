#!/usr/bin/env bash
# ============================================================================
#  setup-host.sh — Bootstrap a new host (Raspberry Pi / Ubuntu) for Fabric
# ============================================================================
#  Transfer this script + the host bundle to the target machine, then run:
#    chmod +x setup-host.sh && sudo ./setup-host.sh
#
#  This installs the MINIMUM software required:
#    1. Docker Engine (arm64 or amd64)
#    2. Docker Compose plugin
#    3. Pulls Fabric Docker images (peer, orderer, tools)
#
#  After running this, you only need to:
#    1. docker compose up -d          (start Fabric containers)
#    2. source tss-<org>.env          (load TSS config)
#    3. ./tss_peer <org>              (run TSS peer)
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Must run as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo ./setup-host.sh"
fi

ARCH=$(uname -m)
info "Architecture: $ARCH"

# Pinned Docker versions for arm64 (avoids Docker 29.x build issues on Pi)
CE_VER="5:24.0.9-1~ubuntu.22.04~jammy"
CLI_VER="5:24.0.9-1~ubuntu.22.04~jammy"
CTR_VER="1.6.33-1"

ensure_docker_repo() {
    # Install prerequisites
    apt-get update
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Add Docker GPG key
    install -m 0755 -d /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
            gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
    fi

    # Add repository
    if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/ubuntu \
            $(lsb_release -cs) stable" | \
            tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    apt-get update
}

install_pinned_docker_arm64() {
    info "Installing pinned Docker (24.0.9) + containerd (1.6.33) for arm64..."
    systemctl stop docker docker.socket 2>/dev/null || true
    apt-mark unhold docker-ce docker-ce-cli containerd.io || true
    apt-get install -y --allow-downgrades \
        docker-ce="$CE_VER" \
        docker-ce-cli="$CLI_VER" \
        containerd.io="$CTR_VER" \
        docker-buildx-plugin docker-compose-plugin
    apt-mark hold docker-ce docker-ce-cli containerd.io
    systemctl enable docker
    systemctl start docker
}

install_latest_docker() {
    info "Installing Docker (latest stable)..."
    # Remove old versions
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
}

# ---------------------------------------------------------------------------
# 1. Install Docker
# ---------------------------------------------------------------------------
if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
    if [ -z "$DOCKER_VER" ]; then
        DOCKER_VER=$(docker --version | awk '{print $3}' | tr -d ',')
    fi
    DOCKER_MAJOR=$(echo "$DOCKER_VER" | cut -d. -f1 | tr -dc '0-9')
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && [ -n "$DOCKER_MAJOR" ] && [ "$DOCKER_MAJOR" -ge 29 ]; then
        warn "Docker $DOCKER_VER detected on arm64; downgrading to 24.0.9 to avoid build issues."
        ensure_docker_repo
        install_pinned_docker_arm64
    else
        info "Docker already installed: $(docker --version)"
    fi
else
    ensure_docker_repo
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
        install_pinned_docker_arm64
    else
        install_latest_docker
    fi
    info "Docker installed: $(docker --version)"
fi

# Add current user to docker group (so they don't need sudo)
REAL_USER="${SUDO_USER:-$USER}"
if ! id -nG "$REAL_USER" | grep -qw docker; then
    usermod -aG docker "$REAL_USER"
    info "Added $REAL_USER to docker group (re-login required)"
fi

# ---------------------------------------------------------------------------
# 2. Pull Fabric Docker Images
# ---------------------------------------------------------------------------
FABRIC_VERSION="2.5"
FABRIC_CA_VERSION="1.5"

info "Pulling Hyperledger Fabric Docker images..."

# These are multi-arch images (amd64 + arm64)
docker pull hyperledger/fabric-peer:${FABRIC_VERSION}
docker pull hyperledger/fabric-orderer:${FABRIC_VERSION}
docker pull hyperledger/fabric-tools:${FABRIC_VERSION}
docker pull hyperledger/fabric-ccenv:${FABRIC_VERSION}
docker pull hyperledger/fabric-baseos:${FABRIC_VERSION}

# Tag as latest
docker tag hyperledger/fabric-peer:${FABRIC_VERSION} hyperledger/fabric-peer:latest
docker tag hyperledger/fabric-orderer:${FABRIC_VERSION} hyperledger/fabric-orderer:latest
docker tag hyperledger/fabric-tools:${FABRIC_VERSION} hyperledger/fabric-tools:latest
docker tag hyperledger/fabric-ccenv:${FABRIC_VERSION} hyperledger/fabric-ccenv:latest
docker tag hyperledger/fabric-baseos:${FABRIC_VERSION} hyperledger/fabric-baseos:latest

info "Fabric images pulled and tagged"

# ---------------------------------------------------------------------------
# 3. Create working directory
# ---------------------------------------------------------------------------
DEPLOY_DIR="/opt/fabric"
mkdir -p "$DEPLOY_DIR"
chown "$REAL_USER:$REAL_USER" "$DEPLOY_DIR"

info "Deployment directory: $DEPLOY_DIR"
info "Copy your host bundle contents here."

# ---------------------------------------------------------------------------
# 4. Configure firewall (if ufw is active)
# ---------------------------------------------------------------------------
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Configuring firewall rules..."
    # Fabric peer ports (commonly used range)
    ufw allow 7050/tcp comment "Fabric Orderer"
    ufw allow 7051/tcp comment "Fabric Peer"
    ufw allow 7053/tcp comment "Fabric Orderer Admin"
    ufw allow 9051/tcp comment "Fabric Peer (alt)"
    ufw allow 11051/tcp comment "Fabric Peer (alt)"
    # TSS P2P ports
    ufw allow 6001:6010/tcp comment "TSS P2P"
    # TSS Web UI
    ufw allow 8080:8090/tcp comment "TSS Web UI"
    info "Firewall rules added"
else
    info "No active firewall detected, skipping"
fi

# ---------------------------------------------------------------------------
# 5. Set /etc/hosts entries
# ---------------------------------------------------------------------------
info ""
info "============================================"
info " IMPORTANT: Add host entries"
info "============================================"
info ""
info "Add the following to /etc/hosts on this machine"
info "(replace IPs with your actual network IPs):"
info ""
info "  192.168.1.100  orderer.example.com"
info "  192.168.1.100  peer0.org1.example.com"
info "  192.168.1.100  peer0.org2.example.com"
info "  192.168.1.101  peer0.org3.example.com"
info ""
info "These entries are also set via extra_hosts in docker-compose.yaml"
info "for containers, but the TSS peer binary needs them on the host OS."
info ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
info "============================================"
info " Host setup complete!"
info "============================================"
info ""
info "Minimum software installed:"
info "  ✓ Docker Engine"
info "  ✓ Docker Compose plugin"
info "  ✓ Fabric Docker images (peer, orderer, tools, ccenv, baseos)"
info ""
info "Files needed on this host (copy from admin machine):"
info "  - docker-compose.yaml"
info "  - organizations/         (crypto material)"
info "  - channel-artifacts/     (genesis block)"
info "  - peercfg/core.yaml"
info "  - tss-<org>.env          (TSS peer config)"
info "  - tss_peer               (TSS peer binary, built for $ARCH)"
info ""
info "To start:"
info "  cd $DEPLOY_DIR"
info "  docker compose up -d"
info "  source tss-<org>.env"
info "  ./tss_peer <org>"
