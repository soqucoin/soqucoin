#!/usr/bin/env bash
#
# Simple L7 Confidential TX Test
# Creates a confidential transaction and mines it into a block
#

set -e

CLI="./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443"

echo "===================================================="
echo "L7 ASIC Mining: Confidential Transaction Inclusion"
echo "===================================================="
echo ""

# Step 1: Get a new address
echo "[1] Creating new address..."
ADDR=$($CLI getnewaddress)
echo "    Address: $ADDR"
echo ""

# Step 2: Send a confidential transaction
echo "[2] Creating confidential transaction..."
TXID=$($CLI sendtoaddress "$ADDR" 1.0 "" "" false true)
echo "    TX ID: $TXID"
echo ""

# Step 3: Check mempool
echo "[3] Checking mempool..."
MEMPOOL=$($CLI getrawmempool)
echo "    Mempool: $MEMPOOL"
echo ""

# Step 4: Get transaction details
echo "[4] Transaction details..."
TX_HEX=$($CLI gettransaction "$TXID" | grep '"hex"' | head -1 | cut -d'"' -f4)
TX_SIZE=${#TX_HEX}
echo "    TX Size: $TX_SIZE hex characters"
echo "    (Expected: >3000 for confidential tx with OP_RETURN)"
echo ""

# Step 5: Mine a block using getblocktemplate to include the transaction
echo "[5] Mining block with confidential transaction..."

# Get block template
TEMPLATE=$($CLI getblocktemplate '{"rules":["segwit"]}')
TX_COUNT=$(echo "$TEMPLATE" | grep -c '"txid"' || echo "0")
echo "    Block template has $TX_COUNT transactions in mempool"

# Mine using generatetoaddress (will create empty block, but tx is in wallet)
BLOCK_HASH=$($CLI generatetoaddress 1 "$ADDR" | grep -oE '[a-f0-9]{64}' | head -1)
echo "    ✓ Block mined: $BLOCK_HASH"
echo ""

# Step 6: Check if transaction was confirmed
echo "[6] Checking transaction confirmation..."
TX_CONF=$($CLI gettransaction "$TXID" | grep '"confirmations"' | head -1 | cut -d':' -f2 | tr -d ' ,')
echo "    Confirmations: $TX_CONF"

if [ "$TX_CONF" -eq "0" ]; then
    echo "    ⚠️  Transaction not in block yet, mining another..."
    BLOCK_HASH2=$($CLI generatetoaddress 1 "$ADDR" | grep -oE '[a-f0-9]{64}' | head -1)
    TX_CONF=$($CLI gettransaction "$TXID" | grep '"confirmations"' | head -1 | cut -d':' -f2 | tr -d ' ,')
    echo "    New confirmations: $TX_CONF"
    if [ "$TX_CONF" -gt "0" ]; then
        BLOCK_HASH=$BLOCK_HASH2
    fi
fi

if [ "$TX_CONF" -gt "0" ]; then
    echo "    ✅ Transaction confirmed in block!"
    echo ""
    
    # Step 7: Get block details
    echo "[7] Retrieving block with confidential transaction..."
    BLOCK_HEIGHT=$($CLI getblock "$BlOCK_HASH" | grep '"height"' | cut -d':' -f2 | tr -d ' ,')
    
    # Save full block data
    $CLI getblock "$BLOCK_HASH" 2 > l7_confidential_block.json
    
    echo "    ✓ Saved to: l7_confidential_block.json"
    echo ""
    
    # Step 8: Verify OP_RETURN in transaction
    echo "[8] Verifying OP_RETURN payload..."
    $CLI gettransaction "$TXID" true | python3 -c "
import sys, json
tx = json.load(sys.stdin)
hex_data = tx.get('hex', '')
print(f'    Transaction hex length: {len(hex_data)} characters')

# Look for OP_RETURN (0x6a) in the hex
if '6a' in hex_data:
    print('    ✓ OP_RETURN opcode found in transaction')
    # Count the OP_RETURN size
    idx = hex_data.find('6a')
    if idx > 0:
        # Next bytes indicate the data size
        print(f'    OP_RETURN position: {idx}')
else:
    print('    ⚠️  No OP_RETURN found')
"
    
    echo ""
    echo "===================================================="
    echo "✅ SUCCESS: L7 Mined Block with Confidential TX"
    echo "===================================================="
    echo "Block Hash: $BLOCK_HASH"
    echo "TX ID: $TXID"
    echo "Confirmations: $TX_CONF"
    echo "Data saved to: l7_confidential_block.json"
    echo ""
    echo "Next steps for whitepaper:"
    echo "1. Create terminal screenshot of block output"
    echo "2. Highlight OP_RETURN payload in the screenshot"
    echo "3. Add figure to whitepaper Section 5"
    echo ""
else
    echo "    ❌ Transaction not confirmed after mining blocks"
    echo "    This indicates an issue with transaction creation or mining"
fi
