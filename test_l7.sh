#!/bin/bash
# Antminer L7 Test Script for Soqucoin

echo "=== Soqucoin L7 Mining Test ==="
echo ""

# 1. Start L7 proxy
echo "[1/4] Starting L7 Stratum proxy on port 3333..."
python3 l7_proxy.py &
PROXY_PID=$!
sleep 3

# 2. Check node status
echo "[2/4] Checking Soqucoin node status..."
./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu getmininginfo

# 3. Instructions for L7 configuration
echo ""
echo "[3/4] Configure your Antminer L7:"
echo "  1. Access L7 web UI (find IP with: nmap -sn 192.168.1.0/24)"
echo "  2. Navigate to Miner Configuration"
echo "  3. Pool 1 URL:  stratum+tcp://192.168.1.121:3333"
echo "  4. Worker:      miner"
echo "  5. Password:    x"
echo "  6. Save & Apply"
echo ""
echo "Press ENTER once L7 is configured and mining..."
read

# 4. Monitor for 60 seconds
echo "[4/4] Monitoring for 60 seconds..."
for i in {1..12}; do
    sleep 5
    BLOCKS=$(./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu getblockcount)
    echo "  [${i}0s] Block height: $BLOCKS"
done

echo ""
echo "=== Test Complete ==="
echo "Check proxy logs above for L7 connection/share activity"
echo ""
echo "To stop proxy: kill $PROXY_PID"
