#!/bin/bash
# =============================================================================
# Stagenet Deployment Script
# Source of truth: soqucoin-genesis branch on GitHub
# Run this ON THE VPS, not on the Mac Mini
#
# Usage: ssh root@<stagenet-vps> 'bash -s' < contrib/stagenet-deploy.sh
#   OR:  scp this to VPS, then ssh in and run it
#
# Prerequisites on VPS:
#   apt install build-essential libtool autotools-dev automake pkg-config \
#     bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev \
#     libzmq3-dev libdb++-dev git
# =============================================================================

set -euo pipefail

REPO_URL="https://github.com/soqucoin/soqucoin.git"
BRANCH="soqucoin-genesis"
BUILD_DIR="/opt/soqucoin-build"
DATA_DIR="/root/.soqucoin"

echo "============================================="
echo "  Soqucoin Stagenet Deployment"
echo "  Branch: $BRANCH"
echo "============================================="

# Step 0: Install build dependencies
echo "[1/7] Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential libtool autotools-dev automake \
  pkg-config bsdmainutils python3 libssl-dev libevent-dev \
  libboost-all-dev libzmq3-dev libdb++-dev git

# Step 1: Clone or pull
if [ -d "$BUILD_DIR/.git" ]; then
    echo "[2/7] Updating existing repo..."
    cd "$BUILD_DIR"
    git fetch origin
    git checkout "$BRANCH"
    git reset --hard "origin/$BRANCH"
else
    echo "[2/7] Cloning fresh repo..."
    git clone -b "$BRANCH" "$REPO_URL" "$BUILD_DIR"
    cd "$BUILD_DIR"
fi

echo "  HEAD: $(git log --oneline -1)"

# Step 2: Build
echo "[3/7] Building soqucoind (this takes 5-10 minutes)..."
./autogen.sh
./configure --without-gui --disable-bench
make -j$(nproc)

echo "  Binary: $(file src/soqucoind)"
echo "  Size:   $(du -h src/soqucoind | cut -f1)"

# Step 3: Install
echo "[4/7] Installing binaries..."
cp src/soqucoind /usr/local/bin/soqucoind
cp src/soqucoin-cli /usr/local/bin/soqucoin-cli
cp src/soqucoin-tx /usr/local/bin/soqucoin-tx

# Step 4: Wipe old stagenet data (REQUIRED — difficulty rules changed)
echo "[5/7] Wiping old stagenet chain data..."
if [ -d "$DATA_DIR/stagenet" ]; then
    echo "  Removing: $DATA_DIR/stagenet/{blocks,chainstate,banlist.dat,peers.dat}"
    rm -rf "$DATA_DIR/stagenet/blocks" \
           "$DATA_DIR/stagenet/chainstate" \
           "$DATA_DIR/stagenet/banlist.dat" \
           "$DATA_DIR/stagenet/peers.dat"
    echo "  Wallet preserved (if present)"
else
    echo "  No existing stagenet data found — fresh start"
    mkdir -p "$DATA_DIR"
fi

# Step 5: Create stagenet config
echo "[6/7] Writing stagenet config..."
mkdir -p "$DATA_DIR"
cat > "$DATA_DIR/soqucoin.conf" << 'EOF'
# Soqucoin Stagenet Configuration
# Source: contrib/stagenet-deploy.sh
# Network
stagenet=1
listen=1
maxconnections=32
dnsseed=0

# RPC (for stratum pool)
server=1
rpcthreads=4
rpcworkqueue=16
rpcuser=stagenet_rpc_user
rpcpassword=CHANGE_ME_TO_STRONG_RANDOM
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# ZMQ (for pool notifications)
zmqpubhashblock=tcp://127.0.0.1:28332

# Performance
dbcache=512
par=2
maxmempool=100

# Logging
debug=net
debug=rpc
shrinkdebugfile=1
printtoconsole=0
EOF

echo "  ⚠️  CHANGE rpcpassword in $DATA_DIR/soqucoin.conf before starting!"

# Step 6: Build Lattice-BP++ standalone test harness
echo "[7/7] Building Lattice-BP++ benchmark harness..."
cd "$BUILD_DIR/src/crypto/latticebp"
c++ -std=c++17 -O2 -DLATTICEBP_STANDALONE -I. \
    test_latticebp.cpp commitment.cpp ring_signature.cpp range_proof.cpp \
    -o test_latticebp
echo "  Harness built: $(file test_latticebp)"

echo ""
echo "============================================="
echo "  Deployment Complete!"
echo "============================================="
echo ""
echo "Next steps:"
echo "  1. Edit rpcpassword: nano $DATA_DIR/soqucoin.conf"
echo "  2. Start node:       soqucoind -stagenet -daemon"
echo "  3. Check status:     soqucoin-cli -stagenet getblockchaininfo"
echo "  4. Run benchmarks:   cd $BUILD_DIR/src/crypto/latticebp && ./test_latticebp"
echo "  5. Point L3 miner to: stratum+tcp://<vps-ip>:28333"
echo ""
echo "Source of truth: $BRANCH @ $(git log --oneline -1)"
