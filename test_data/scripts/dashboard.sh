#!/bin/bash
# Live Dashboard for L7 Testing
# Run this to see real-time stats

echo "=================================================="
echo "L7 Integration Test - Live Dashboard"
echo "=================================================="
echo ""

# Get current time
echo "Current Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Node status
echo "=== NODE STATUS ==="
HEIGHT=$(./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443 getblockcount 2>/dev/null)
MEMPOOL=$(./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443 getrawmempool 2>/dev/null | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
BALANCE=$(./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443 getbalance 2>/dev/null)

echo "Block Height: $HEIGHT"
echo "Mempool Size: $MEMPOOL txs"
echo "Balance: $BALANCE SOQU"
echo ""

# Process status
echo "=== SERVICES STATUS ==="
if pgrep -f "soqucoind.*regtest" > /dev/null; then
    echo "✓ Node: Running"
else
    echo "✗ Node: NOT RUNNING"
fi

if pgrep -f "stratum_proxy.py" > /dev/null; then
    echo "✓ Stratum Proxy: Running"
else
    echo "✗ Stratum Proxy: NOT RUNNING"
fi

if pgrep -f "tx_generator.py" > /dev/null; then
    echo "✓ TX Generator: Running"
else
    echo "✗ TX Generator: NOT RUNNING"
fi

if pgrep -f "l7_monitor.py" > /dev/null; then
    echo "✓ L7 Monitor: Running"
else
    echo "✗ L7 Monitor: NOT RUNNING"
fi
echo ""

# Transaction generator stats
if [ -f "tx_generator.log" ]; then
    echo "=== TX GENERATOR STATS ==="
    LAST_TX=$(grep "Created confidential tx" tx_generator.log | tail -1)
    if [ -n "$LAST_TX" ]; then
        echo "Last TX: $LAST_TX"
    fi
    TOTAL_CREATED=$(grep -c "✓ Created" tx_generator.log)
    TOTAL_FAILED=$(grep -c "ERROR: Failed to create" tx_generator.log)
    echo "Total Created: $TOTAL_CREATED"
    echo "Total Failed: $TOTAL_FAILED"
    echo ""
fi

# Monitor stats
if [ -f "data_capture/metrics.json" ]; then
    echo "=== CAPTURED DATA ==="
    python3 << 'EOF'
import json
try:
    with open('data_capture/metrics.json', 'r') as f:
        metrics = json.load(f)
    print(f"Blocks Captured: {metrics.get('total_blocks', 0)}")
    print(f"Confidential TXs: {metrics.get('total_confidential_txs', 0)}")
    print(f"Avg TXs/Block: {metrics.get('txs_per_block', 0):.2f}")
    print(f"Runtime: {metrics.get('runtime_minutes', 0):.1f} minutes")
    if metrics.get('blocks', []):
        last_block = metrics['blocks'][-1]
        print(f"Last Block: #{last_block['height']} - {last_block['confidential_tx_count']} conf txs")
except:
    print("No metrics data yet")
EOF
    echo ""
fi

# Data directory status
if [ -d "data_capture/blocks" ]; then
    BLOCK_FILES=$(ls data_capture/blocks/*.json 2>/dev/null | wc -l)
    TX_FILES=$(ls data_capture/transactions/*.json 2>/dev/null | wc -l)
    echo "=== DATA FILES ==="
    echo "Block Files: $BLOCK_FILES"
    echo "TX Files: $TX_FILES"
    echo ""
fi

echo "=================================================="
echo "Press Ctrl+C to exit"
echo "Run: watch -n 5 ./dashboard.sh for auto-refresh"
echo "=================================================="
