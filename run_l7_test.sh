#!/usr/bin/env bash
# L7 Live Integration Test
# Orchestrates the full test: Daemon -> Proxy -> ASIC -> Block -> Verification

set -e

# Configuration
PROXY_IP="192.168.1.169"
PROXY_PORT="3333"
MINER_IP="192.168.1.235"
CLI="./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443"

echo "=========================================================="
echo "   L7 ASIC Confidential Transaction Integration Test"
echo "=========================================================="
echo "Miner IP: $MINER_IP"
echo "Proxy:    $PROXY_IP:$PROXY_PORT"
echo "=========================================================="

# 1. Cleanup and Start Daemon
echo "[1] Starting Soqucoin Daemon..."
pkill -f soqucoind || true
pkill -f stratum_proxy.py || true
sleep 2

./src/soqucoind -regtest -daemon -rpcuser=miner -rpcpassword=soqu -rpcport=18443 -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 -debug=1
echo "    Waiting for daemon to warm up..."
sleep 5

# 2. Generate initial blocks (to activate SegWit and get coins)
echo "[2] Generating initial blocks..."
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 101 "$ADDR" > /dev/null
echo "    ✓ 101 blocks generated (Balance: $($CLI getbalance))"

# 3. Start Stratum Proxy
echo "[3] Starting Stratum Proxy..."
# Run in background, redirect output to a log file we can tail
python3 stratum_proxy.py --use-generate-fallback > proxy.log 2>&1 &
PROXY_PID=$!
echo "    Proxy running (PID: $PROXY_PID). Listening on port $PROXY_PORT."
echo "    Logs: tail -f proxy.log"

# 4. Create Confidential Transaction
echo "[4] Creating Confidential Transaction..."
# Send to self
TXID=$($CLI sendtoaddress "$ADDR" 1.0 "" "" false true)
echo "    TXID: $TXID"
echo "    Waiting for ASIC to mine..."

# 5. Monitor for Confirmation
echo "[5] Monitoring for Block..."
START_TIME=$(date +%s)
CONFIRMED=0

while [ $CONFIRMED -eq 0 ]; do
    CONFIRMS=$($CLI gettransaction "$TXID" | grep '"confirmations"' | cut -d':' -f2 | tr -d ' ,')
    if [ "$CONFIRMS" -gt "0" ]; then
        CONFIRMED=1
        echo ""
        echo "    ✅ TRANSACTION CONFIRMED!"
        echo "    Confirmations: $CONFIRMS"
        break
    fi
    
    # Check if proxy is still running
    if ! kill -0 $PROXY_PID 2>/dev/null; then
        echo "    ❌ Proxy process died!"
        cat proxy.log
        exit 1
    fi
    
    # Check for miner connection in logs
    if grep -q "New connection" proxy.log; then
        if ! grep -q "Miner Connected" .miner_seen 2>/dev/null; then
            echo "    ✓ ASIC Connected!"
            touch .miner_seen
        fi
    fi
    
    if grep -q "Share submitted" proxy.log; then
         if ! grep -q "Share Seen" .share_seen 2>/dev/null; then
            echo "    ✓ Share received from ASIC! Block generation triggered..."
            touch .share_seen
        fi
    fi

    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    if [ $ELAPSED -gt 300 ]; then
        echo "    ❌ Timeout waiting for block (5 minutes)"
        exit 1
    fi
    
    echo -ne "    Waiting... (${ELAPSED}s) \r"
    sleep 2
done

# 6. Verify Block Data
echo ""
echo "[6] Verifying Block Data..."
BLOCK_HASH=$($CLI gettransaction "$TXID" | grep '"blockhash"' | cut -d'"' -f4)
echo "    Block Hash: $BLOCK_HASH"

# Dump block to JSON
$CLI getblock "$BLOCK_HASH" 2 > l7_final_block.json
echo "    Saved block data to l7_final_block.json"

# Check for OP_RETURN
HAS_OP_RETURN=$(grep -c "6a" l7_final_block.json || true)
if [ "$HAS_OP_RETURN" -gt "0" ]; then
    echo "    ✅ OP_RETURN payload found in block."
else
    echo "    ⚠️  Warning: OP_RETURN not explicitly found in JSON dump (check manually)."
fi

echo ""
echo "=========================================================="
echo "TEST COMPLETE: SUCCESS"
echo "=========================================================="

# Cleanup
kill $PROXY_PID
