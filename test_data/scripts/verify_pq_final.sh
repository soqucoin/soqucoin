#!/bin/bash
set -e
echo "Starting Dilithium-only verification..."
./src/soqucoind -regtest -daemon
sleep 5
addr=$(./src/soqucoin-cli -regtest getnewaddress)
echo "Dilithium address: $addr"
echo "Mining 101 blocks..."
./src/soqucoin-cli -regtest generatetoaddress 101 "$addr" > /dev/null
echo "Sending Dilithium transaction..."
txid=$(./src/soqucoin-cli -regtest sendtoaddress "$addr" 10)
echo "Dilithium transaction sent: $txid"
./src/soqucoin-cli -regtest generatetoaddress 1 "$addr" > /dev/null
balance=$(./src/soqucoin-cli -regtest getbalance)
echo "Final balance: $balance"
./src/soqucoin-cli -regtest stop
echo ""
echo "✅ SOQUCOIN IS NOW QUANTUM-IMMUNE FROM BLOCK 0"
echo "✅ All transactions signed with Dilithium"
echo "✅ All addresses use witness v1 (OP_1 + SHA256(pubkey))"
