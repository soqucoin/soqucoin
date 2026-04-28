#!/bin/bash
# deploy_soqucoind.sh — Soqucoin Node Deployment Script
# SOQ-INFRA-024: Automated binary deployment + service management
#
# Usage:
#   ./deploy_soqucoind.sh <vps-ip> [--rebuild] [--pool] [--systemd]
#
# Examples:
#   ./deploy_soqucoind.sh 64.23.197.144 --rebuild --systemd --pool   # Full upgrade
#   ./deploy_soqucoind.sh 143.110.229.69 --rebuild --systemd          # Node-only upgrade
#   ./deploy_soqucoind.sh 64.23.197.144                               # Status check only
#
# Prerequisites:
#   - SSH key-based access to root@<vps-ip>
#   - Source tree built locally (make -j already run)
#   - Pool binary built at /opt/merged-mining-pool/pool-server (if --pool)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARIES=("soqucoind" "soqucoin-cli" "soqucoin-tx")
VPS_BIN_DIR="/usr/local/bin"
VPS_SYSTEMD_DIR="/etc/systemd/system"
POOL_DIR="/opt/merged-mining-pool"
SYSTEMD_SRC="${SCRIPT_DIR}/contrib/systemd"

# ── Color output ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[DEPLOY]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }

# ── Parse arguments ────────────────────────────────────────────────
if [ $# -lt 1 ]; then
    echo "Usage: $0 <vps-ip> [--rebuild] [--pool] [--systemd]"
    echo ""
    echo "Options:"
    echo "  --rebuild    Build from source on VPS (git pull + make)"
    echo "  --pool       Also deploy/restart pool-server"
    echo "  --systemd    Install/update systemd service files"
    echo "  (no options) Status check only"
    exit 1
fi

VPS_IP="$1"
shift
DO_REBUILD=false
DO_POOL=false
DO_SYSTEMD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild)  DO_REBUILD=true ;;
        --pool)     DO_POOL=true ;;
        --systemd)  DO_SYSTEMD=true ;;
        *)          err "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ── Helper: run on VPS ─────────────────────────────────────────────
vssh() {
    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "root@${VPS_IP}" "$@"
}

# ── Step 0: Connectivity check ─────────────────────────────────────
log "Checking connectivity to ${VPS_IP}..."
if ! vssh "echo OK" >/dev/null 2>&1; then
    err "Cannot reach ${VPS_IP} via SSH"
    exit 1
fi
log "Connected ✅"

# ── Step 1: Current status ─────────────────────────────────────────
log "=== Current Status on ${VPS_IP} ==="
vssh "
    echo 'Uptime:' \$(uptime -p 2>/dev/null || uptime)
    echo ''
    echo '--- Processes ---'
    pgrep -a soqucoind 2>/dev/null || echo '  soqucoind: NOT RUNNING'
    pgrep -a pool-server 2>/dev/null || echo '  pool-server: NOT RUNNING'
    echo ''
    echo '--- Systemd Services ---'
    systemctl list-units --type=service --state=running 2>/dev/null | grep -iE 'soqu|pool' || echo '  None'
    echo ''
    echo '--- Binary Version ---'
    /usr/local/bin/soqucoind --version 2>/dev/null | head -1 || echo '  soqucoind not found'
    echo ''
    echo '--- Chain Info ---'
    /usr/local/bin/soqucoin-cli -stagenet getblockchaininfo 2>/dev/null | grep -E 'chain|blocks|headers' | head -3 || echo '  Cannot reach RPC'
    echo ''
    echo '--- Disk ---'
    df -h / | tail -1
"

# If no action flags, just show status and exit
if ! $DO_REBUILD && ! $DO_POOL && ! $DO_SYSTEMD; then
    info "Status check only. Use --rebuild/--pool/--systemd for actions."
    exit 0
fi

# ── Step 2: Rebuild from source ────────────────────────────────────
if $DO_REBUILD; then
    log "=== Rebuilding soqucoind from source on ${VPS_IP} ==="

    # Check if source exists
    if ! vssh "test -d /root/soqucoin-build"; then
        log "Cloning source tree..."
        vssh "cd /root && git clone https://github.com/soqucoin/soqucoin.git soqucoin-build"
    fi

    # Stop node gracefully
    log "Stopping soqucoind..."
    vssh "/usr/local/bin/soqucoin-cli -stagenet stop 2>/dev/null || true"
    sleep 5

    # Pull latest code and rebuild
    log "Pulling latest code and building..."
    vssh "
        cd /root/soqucoin-build
        git fetch origin
        git checkout main
        git reset --hard origin/main
        echo 'Building (this takes 5-15 minutes)...'

        # Check if configure has been run
        if [ ! -f Makefile ]; then
            echo 'Running autogen + configure...'
            ./autogen.sh
            ./configure --without-gui --without-miniupnpc --with-incompatible-bdb
        fi

        make -j\$(nproc) 2>&1 | tail -3
    "

    # Install new binaries
    log "Installing binaries..."
    for bin in "${BINARIES[@]}"; do
        vssh "cp /root/soqucoin-build/src/${bin} ${VPS_BIN_DIR}/${bin}"
        log "  Installed ${bin}"
    done

    # Verify version
    NEW_VERSION=$(vssh "${VPS_BIN_DIR}/soqucoind --version 2>/dev/null | head -1")
    log "New version: ${NEW_VERSION}"

    # Restart node
    log "Starting soqucoind..."
    if vssh "systemctl is-enabled soqucoind-stagenet 2>/dev/null | grep -q enabled"; then
        vssh "systemctl restart soqucoind-stagenet"
        log "Restarted via systemd ✅"
    else
        vssh "${VPS_BIN_DIR}/soqucoind -conf=/root/.soqucoin/soqucoin.conf -daemon -nodnsseed -prematurewitness"
        log "Started manually ✅"
    fi

    # Wait for RPC
    log "Waiting for RPC to become available..."
    for i in $(seq 1 30); do
        if vssh "${VPS_BIN_DIR}/soqucoin-cli -stagenet getblockchaininfo >/dev/null 2>&1"; then
            BLOCKS=$(vssh "${VPS_BIN_DIR}/soqucoin-cli -stagenet getblockchaininfo 2>/dev/null | grep '\"blocks\"' | grep -o '[0-9]*'")
            log "RPC ready — block height: ${BLOCKS} ✅"
            break
        fi
        sleep 2
    done
fi

# ── Step 3: Pool server ───────────────────────────────────────────
if $DO_POOL; then
    log "=== Deploying pool-server on ${VPS_IP} ==="

    # Check if pool binary exists on VPS
    if vssh "test -f ${POOL_DIR}/pool-server"; then
        log "Pool binary found at ${POOL_DIR}/pool-server"

        # Restart pool
        if vssh "systemctl is-enabled pool-server 2>/dev/null | grep -q enabled"; then
            vssh "systemctl restart pool-server"
            log "Pool restarted via systemd ✅"
        else
            vssh "pkill pool-server 2>/dev/null || true; sleep 2; cd ${POOL_DIR} && nohup ./pool-server > /var/log/pool-server.log 2>&1 &"
            log "Pool restarted manually ✅"
        fi
    else
        warn "Pool binary not found at ${POOL_DIR}/pool-server"
        warn "Build it first, then re-run with --pool"
    fi
fi

# ── Step 4: Systemd service installation ──────────────────────────
if $DO_SYSTEMD; then
    log "=== Installing systemd services on ${VPS_IP} ==="

    # Copy service files
    for svc in soqucoind.service pool-server.service; do
        if [ -f "${SYSTEMD_SRC}/${svc}" ]; then
            scp -o StrictHostKeyChecking=no "${SYSTEMD_SRC}/${svc}" "root@${VPS_IP}:${VPS_SYSTEMD_DIR}/${svc}"
            log "  Copied ${svc}"
        else
            warn "  ${svc} not found in ${SYSTEMD_SRC}"
        fi
    done

    # Reload systemd
    vssh "systemctl daemon-reload"
    log "  systemd daemon-reload ✅"

    # Enable services (don't start — that would interrupt running processes)
    vssh "systemctl enable soqucoind.service 2>/dev/null || true"
    vssh "systemctl enable pool-server.service 2>/dev/null || true"
    log "  Services enabled for auto-start on boot ✅"

    info "Services installed but NOT restarted (to avoid interrupting mining)."
    info "To switch from manual to systemd management:"
    info "  1. Kill the manual process: pkill soqucoind"
    info "  2. Start via systemd: systemctl start soqucoind"
    info "  3. Verify: systemctl status soqucoind"
fi

# ── Final status ───────────────────────────────────────────────────
log ""
log "=== Deployment Complete ==="
vssh "
    echo '--- Running Processes ---'
    pgrep -a soqucoind 2>/dev/null || echo '  soqucoind: NOT RUNNING'
    pgrep -a pool-server 2>/dev/null || echo '  pool-server: NOT RUNNING'
    echo ''
    echo '--- Chain Height ---'
    /usr/local/bin/soqucoin-cli -stagenet getblockchaininfo 2>/dev/null | grep '\"blocks\"' || echo '  RPC unavailable'
"
log "Done ✅"
