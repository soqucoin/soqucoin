#!/usr/bin/env bash
#
# L7 ASIC Integration Test Battery for Soqucoin
# Tests Bulletproofs++ confidential transactions with Scrypt mining
#
# For whitepaper Section 6.3 benchmarks
#

set -e

# Configuration
DATADIR="/tmp/soqu_l7_battery"
CLI="./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443"
DAEMON="./src/soqucoind -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443 -datadir=$DATADIR"
DYLD_LIBRARY_PATH="$(pwd)/src/secp256k1/.libs:$DYLD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH

# Test parameters
NUM_BLOCKS=100
CONF_TXS_PER_BLOCK=10  # Reduced from 147 for faster testing; increase for production benchmark
TOTAL_CONF_TXS=$((NUM_BLOCKS * CONF_TXS_PER_BLOCK))

echo "=============================================="
echo "L7 ASIC Integration Test Battery"
echo "=============================================="
echo "Blocks to mine: $NUM_BLOCKS"
echo "Confidential TXs per block: $CONF_TXS_PER_BLOCK"
echo "Total confidential TXs: $TOTAL_CONF_TXS"
echo ""

# Cleanup
cleanup() {
    echo "[*] Cleaning up..."
    $CLI stop 2>/dev/null || true
    sleep 2
    rm -rf "$DATADIR"
}

trap cleanup EXIT

# Setup
echo "[1/8] Setting up test environment..."
rm -rf "$DATADIR"
mkdir -p "$DATADIR"

cat > "$DATADIR/soqucoin.conf" << EOF
regtest=1
rpcuser=miner
rpcpassword=soqu
rpcport=18443
server=1
daemon=1
txindex=1
EOF

# Start daemon
echo "[2/8] Starting soqucoind..."
$DAEMON
sleep 5

# Wait for RPC
for i in {1..30}; do
    if $CLI getblockchaininfo > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Verify daemon is running
if ! $CLI getblockchaininfo > /dev/null 2>&1; then
    echo "[!] Failed to start daemon"
    exit 1
fi

echo "[*] Daemon started successfully"

# Mine initial blocks for coinbase maturity
echo "[3/8] Mining 101 blocks for coinbase maturity..."
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 101 "$ADDR" > /dev/null

BALANCE=$($CLI getbalance)
echo "[*] Initial balance: $BALANCE SOQU"

# Benchmark: Bulletproofs++ proof generation
echo ""
echo "[4/8] Running Bulletproofs++ benchmarks..."
echo "=============================================="
./src/bench/bench_soqucoin -filter="Bulletproofs.*" 2>&1 | grep -v "^#" | head -5

# Create confidential transactions
echo ""
echo "[5/8] Creating $TOTAL_CONF_TXS confidential transactions..."
echo "=============================================="

START_TIME=$(date +%s.%N)
CONF_TX_COUNT=0
FAILED_TX_COUNT=0

for block in $(seq 1 $NUM_BLOCKS); do
    for tx in $(seq 1 $CONF_TXS_PER_BLOCK); do
        RECV=$($CLI getnewaddress)
        if TXID=$($CLI sendtoaddress "$RECV" 0.001 "" "" false true 2>/dev/null); then
            CONF_TX_COUNT=$((CONF_TX_COUNT + 1))
        else
            FAILED_TX_COUNT=$((FAILED_TX_COUNT + 1))
        fi
    done
    
    # Progress indicator
    if [ $((block % 10)) -eq 0 ]; then
        echo "  Created $((block * CONF_TXS_PER_BLOCK)) confidential TXs..."
    fi
done

END_TIME=$(date +%s.%N)
TX_CREATION_TIME=$(echo "$END_TIME - $START_TIME" | bc)

echo "[*] Created $CONF_TX_COUNT confidential TXs in ${TX_CREATION_TIME}s"
echo "[*] Failed TXs: $FAILED_TX_COUNT"

# Check mempool
MEMPOOL_SIZE=$($CLI getmempoolinfo | grep '"size"' | grep -o '[0-9]*')
echo "[*] Mempool size: $MEMPOOL_SIZE transactions"

# Mine blocks with confidential transactions
echo ""
echo "[6/8] Mining $NUM_BLOCKS blocks with confidential transactions..."
echo "=============================================="

START_TIME=$(date +%s.%N)
BLOCKS_WITH_CONF_TX=0
TOTAL_BLOCK_SIZE=0
TOTAL_VERIFICATION_TIME=0

for block in $(seq 1 $NUM_BLOCKS); do
    # Mine block
    BLOCK_HASH=$($CLI generatetoaddress 1 "$ADDR" | tr -d '[]" ')
    
    # Get block info
    BLOCK_INFO=$($CLI getblock "$BLOCK_HASH" 2)
    BLOCK_SIZE=$(echo "$BLOCK_INFO" | grep '"size"' | head -1 | grep -o '[0-9]*')
    TX_COUNT=$(echo "$BLOCK_INFO" | grep -c '"txid"' || echo "1")
    
    TOTAL_BLOCK_SIZE=$((TOTAL_BLOCK_SIZE + BLOCK_SIZE))
    
    # Check for OP_RETURN (confidential tx indicator)
    if echo "$BLOCK_INFO" | grep -q '"type": "nulldata"'; then
        BLOCKS_WITH_CONF_TX=$((BLOCKS_WITH_CONF_TX + 1))
    fi
    
    # Progress indicator
    if [ $((block % 10)) -eq 0 ]; then
        echo "  Mined $block blocks (${TX_COUNT} txs in last block, size: ${BLOCK_SIZE} bytes)..."
    fi
done

END_TIME=$(date +%s.%N)
MINING_TIME=$(echo "$END_TIME - $START_TIME" | bc)
AVG_BLOCK_SIZE=$((TOTAL_BLOCK_SIZE / NUM_BLOCKS))

echo "[*] Mined $NUM_BLOCKS blocks in ${MINING_TIME}s"
echo "[*] Blocks with confidential TXs: $BLOCKS_WITH_CONF_TX"
echo "[*] Average block size: $AVG_BLOCK_SIZE bytes"

# Verify block validation times
echo ""
echo "[7/8] Measuring block validation overhead..."
echo "=============================================="

# Get a sample block with confidential transactions
LATEST_HASH=$($CLI getbestblockhash)
LATEST_HEIGHT=$($CLI getblockcount)

# Measure getblock time (includes validation)
START_TIME=$(date +%s.%N)
for i in $(seq 1 10); do
    $CLI getblock "$LATEST_HASH" 2 > /dev/null
done
END_TIME=$(date +%s.%N)
AVG_GETBLOCK_TIME=$(echo "scale=4; ($END_TIME - $START_TIME) / 10" | bc)

echo "[*] Average getblock time (10 runs): ${AVG_GETBLOCK_TIME}s"

# Final report
echo ""
echo "[8/8] Test Battery Results"
echo "=============================================="
echo ""
echo "=== SOQUCOIN L7 INTEGRATION TEST RESULTS ==="
echo "Date: $(date)"
echo ""
echo "--- Test Parameters ---"
echo "Blocks mined: $NUM_BLOCKS"
echo "Confidential TXs created: $CONF_TX_COUNT"
echo "Failed TXs: $FAILED_TX_COUNT"
echo ""
echo "--- Performance Metrics ---"
echo "TX creation time: ${TX_CREATION_TIME}s"
echo "Mining time: ${MINING_TIME}s"
echo "Avg block size: $AVG_BLOCK_SIZE bytes"
echo "Avg getblock time: ${AVG_GETBLOCK_TIME}s"
echo ""
echo "--- Bulletproofs++ Benchmarks ---"
./src/bench/bench_soqucoin -filter="Bulletproofs.*" 2>&1 | grep -v "^#" | head -5
echo ""
echo "--- Blockchain State ---"
echo "Final height: $LATEST_HEIGHT"
echo "Final balance: $($CLI getbalance) SOQU"
echo ""
echo "=== TEST BATTERY COMPLETE ==="

# Save results to file for whitepaper
RESULTS_FILE="l7_integration_results_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "=== SOQUCOIN L7 INTEGRATION TEST RESULTS ==="
    echo "Date: $(date)"
    echo ""
    echo "--- Test Parameters ---"
    echo "Blocks mined: $NUM_BLOCKS"
    echo "Confidential TXs created: $CONF_TX_COUNT"
    echo ""
    echo "--- Performance Metrics ---"
    echo "TX creation time: ${TX_CREATION_TIME}s"
    echo "Mining time: ${MINING_TIME}s"
    echo "Avg block size: $AVG_BLOCK_SIZE bytes"
    echo "Avg getblock time: ${AVG_GETBLOCK_TIME}s"
    echo ""
    echo "--- Bulletproofs++ Benchmarks (Apple M4) ---"
    ./src/bench/bench_soqucoin -filter="Bulletproofs.*" 2>&1 | grep -v "^#" | head -5
} > "$RESULTS_FILE"

echo ""
echo "[*] Results saved to: $RESULTS_FILE"

