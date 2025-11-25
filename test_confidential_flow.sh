#!/bin/bash
set -e

# Setup
echo "Cleaning up..."
killall soqucoind || true
rm -rf /tmp/soqucoin_regtest_zk
sleep 2

echo "Starting regtest node..."
mkdir -p /tmp/soqucoin_regtest_zk
src/soqucoind -regtest -daemon -datadir=/tmp/soqucoin_regtest_zk -rmode=dilithium -rpcuser=user -rpcpassword=pass
sleep 10

# Alias
CLI="src/soqucoin-cli -regtest -datadir=/tmp/soqucoin_regtest_zk -rpcuser=user -rpcpassword=pass"

# Mine 101 blocks to mature coinbase
echo "Mining 101 blocks..."
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 101 $ADDR

# Check balance
BAL=$($CLI getbalance)
echo "Balance: $BAL"

# Send Confidential Transaction
# sendtoaddress "address" amount ... confidential=true
RECV_ADDR=$($CLI getnewaddress)
echo "Sending 10 SOQU confidentially to $RECV_ADDR..."

# Use 0 and 1 for booleans to avoid parsing issues
# sendtoaddress "address" amount "comment" "comment_to" subtractfeefromamount confidential
TXID=$($CLI sendtoaddress $RECV_ADDR 10 "" "" 0 1)
echo "TXID: $TXID"

if [[ -z "$TXID" ]]; then
    echo "FAILURE: Transaction failed."
    exit 1
fi

if [[ -z "$TXID" ]]; then
    echo "FAILURE: Transaction failed."
    exit 1
fi

# Mine 10 blocks to simulate L7 confirmation
echo "Mining 10 blocks (L7 simulation)..."
$CLI generatetoaddress 10 $ADDR

# Verify Transaction and Block
echo "Verifying transaction..."
RAW_TX=$($CLI getrawtransaction $TXID 1)
echo "$RAW_TX" > /tmp/tx.json

# Get the block containing the transaction
BLOCKHASH=$($CLI getblockhash 102) # 101 initial + 1 with tx (actually tx is in block 102 if we mined 101 first, then sent, then mined)
# Wait, we mined 101. Then sent tx. Then mined 10 blocks.
# The tx should be in block 102.
BLOCKHASH=$($CLI getbestblockhash)
# Actually, let's find which block the tx is in.
# The tx is in the mempool when we start mining.
# The first block mined after sending will contain it.
# We mined 10 blocks. It should be in the first of those 10.
# Current height is 101 + 10 = 111.
# The tx should be in block 102.
BLOCKHASH_102=$($CLI getblockhash 102)
BLOCK_102=$($CLI getblock $BLOCKHASH_102 2) # verbosity 2 for full tx details
echo "$BLOCK_102" > /tmp/block_102.json

echo "Captured Block 102 (L7 Confidential Block):"
# Extract relevant parts for screenshot (txid, vout with OP_RETURN)
cat /tmp/block_102.json | grep -A 20 "$TXID"
# Actually, grep might be too simple. Let's check scriptPubKey asm or hex.
SCRIPT_HEX=$(cat /tmp/tx.json | grep "hex" | grep "6a20")

if [[ -n "$SCRIPT_HEX" ]]; then
    echo "SUCCESS: Confidential output found (OP_RETURN detected)."
else
    echo "FAILURE: No OP_RETURN output found."
    exit 1
fi

# Stop node
$CLI stop
echo "Test Passed!"
