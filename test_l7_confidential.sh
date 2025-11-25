#!/bin/bash
set -e

echo "=== L7 Confidential Transaction Mining Test ==="
echo ""

# Cleanup
echo "Cleaning up previous test..."
killall soqucoind stratum_proxy_dilithium || true
rm -rf /tmp/soqu_l7_conf
sleep 2

# Setup datadir
echo "Setting up node..."
mkdir -p /tmp/soqu_l7_conf
cat > /tmp/soqu_l7_conf/soqucoin.conf <<EOF
regtest=1
rpcuser=user
rpcpassword=pass
rpcport=18443
server=1
daemon=1
rmode=dilithium
EOF

# Start node
echo "Starting soqucoind..."
src/soqucoind -datadir=/tmp/soqu_l7_conf

sleep 8

CLI="src/soqucoin-cli -datadir=/tmp/soqu_l7_conf"

# Mine initial blocks
echo "Mining 101 blocks to mature coinbase..."
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 101 $ADDR

echo "Balance: $($CLI getbalance)"

# Create 50 confidential transactions to mempool
echo ""
echo "Creating 50 confidential transactions..."
for i in {1..50}; do
    RECV=$($CLI getnewaddress)
    TXID=$($CLI sendtoaddress $RECV 0.1 "" "" false true)
    if [ $? -eq 0 ]; then
        echo "  ✓ Confidential tx $i: $TXID"
    else
        echo "  ✗ Failed to create tx $i"
        exit 1
    fi
done

echo ""
echo "Mempool size: $($CLI getmempoolinfo | grep size)"

# Start proxy for L7
echo ""
echo "Starting Stratum proxy..."
python3 stratum_proxy.py &
PROXY_PID=$!

sleep 3

# Get Mac's IP address
MAC_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)

echo ""
echo "=== PROXY READY FOR L7 ==="
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Connect your L7 ASIC to:"
echo ""
echo "  URL:      stratum+tcp://${MAC_IP}:3333"
echo "  Worker:   any username"
echo "  Password: any password"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Waiting for L7 to mine 10 blocks..."
echo "Press ENTER when mining is complete..."
read

# Capture data
echo ""
echo "Capturing block data for whitepaper..."

# Find a block with confidential tx
CURRENT_HEIGHT=$($CLI getblockcount)
echo "Current height: $CURRENT_HEIGHT"

# Check blocks 102-111 for confidential txs
for height in {102..111}; do
    if [ $height -le $CURRENT_HEIGHT ]; then
        HASH=$($CLI getblockhash $height)
        BLOCK=$($CLI getblock $HASH 2)
        
        # Check if block has confidential tx (OP_RETURN)
        if echo "$BLOCK" | grep -q "6a20"; then
            echo ""
            echo "=== FOUND CONFIDENTIAL BLOCK at height $height ==="
            echo "$BLOCK" > /tmp/block_${height}_confidential.json
            
            # Extract and display summary
            echo "$BLOCK" | grep -A 30 '"tx"' | head -50
            
            echo ""
            echo "Full block saved to: /tmp/block_${height}_confidential.json"
            break
        fi
    fi
done

# Stop
echo ""
echo "Stopping proxy..."
kill $PROXY_PID || true

echo "Stopping node..."
$CLI stop

echo ""
echo "=== Test Complete ==="
echo "Block data captured for whitepaper Figure 6"
