#!/bin/bash
set -e

# Clean up
DATA_DIR="/Users/caseymacmini/Library/Application Support/Soqucoin/regtest"
echo "Cleaning up $DATA_DIR..."
rm -rf "$DATA_DIR"

# Start daemon
echo "Starting soqucoind..."
./src/soqucoind -regtest -daemon
sleep 5

# Generate address (default wallet)
echo "Generating address..."
ADDR=$(./src/soqucoin-cli -regtest getnewaddress)
echo "Address: $ADDR"

# Mine blocks
echo "Mining 110 blocks..."
./src/soqucoin-cli -regtest generatetoaddress 110 $ADDR

# Send transaction
echo "Sending transaction..."
TXID=$(./src/soqucoin-cli -regtest sendtoaddress $ADDR 0.1)
echo "Sent 0.1 to $ADDR, TXID: $TXID"

# Mine block to confirm
echo "Mining confirmation block..."
./src/soqucoin-cli -regtest generatetoaddress 1 $ADDR

# Check balance
BAL=$(./src/soqucoin-cli -regtest getbalance)
echo "Balance: $BAL"

# Stop daemon
echo "Stopping daemon..."
./src/soqucoin-cli -regtest stop
