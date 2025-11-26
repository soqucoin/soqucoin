#!/bin/bash
# Quick Start Script for L7 Integration Testing

echo "=========================================="
echo "L7 Integration Test - Quick Start"
echo "=========================================="

# Check if node is running
if ! pgrep -f "soqucoind.*regtest" > /dev/null; then
    echo "ERROR: Soqucoin node is not running!"
    echo "Please start the node with:"
    echo "  ./src/soqucoind -regtest -daemon -rpcuser=miner -rpcpassword=soqu -rpcport=18443 -datadir=regtest_data -prematurewitness -blockmintxfee=0"
    exit 1
fi

echo "✓ Node is running"

# Check stratum proxy
if ! pgrep -f "stratum_proxy.py" > /dev/null; then
    echo "WARNING: Stratum proxy is not running"
    echo "Starting stratum proxy..."
    python3 stratum_proxy.py &
    sleep 2
fi

echo "✓ Stratum proxy is running"

# Check balance
BALANCE=$(./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443 getbalance)
echo "✓ Wallet balance: $BALANCE SOQU"

if (( $(echo "$BALANCE < 10" | bc -l) )); then
    echo "WARNING: Low balance. Consider generating more blocks."
fi

# Create data directory
mkdir -p data_capture/{blocks,transactions,logs}
echo "✓ Data directories created"

echo ""
echo "=========================================="
echo "Ready to start testing!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Start transaction generator:"
echo "   python3 tx_generator.py"
echo ""
echo "2. Start monitoring (in another terminal):"
echo "   python3 l7_monitor.py"
echo ""
echo "3. Configure L7 miner to connect to:"
echo "   stratum+tcp://$(ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | head -1):3333"
echo "   Pool URL: stratum+tcp://$(ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | head -1):3333"
echo "   Worker: test.worker"
echo "   Password: x"
echo ""
echo "4. Monitor progress in data_capture/logs/"
echo ""
echo "=========================================="
