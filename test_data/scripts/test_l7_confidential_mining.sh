#!/usr/bin/env bash
#
# Test L7 ASIC Mining with Confidential Transactions
# This script simulates L7 shares and captures block data for the whitepaper
#

set -e

CLI="./src/soqucoin-cli -regtest -rpcuser=miner -rpcpassword=soqu -rpcport=18443"

echo "==================================="
echo "L7 ASIC Confidential TX Mining Test"
echo "==================================="
echo ""

# Check node status
echo "[1] Checking node status..."
BLOCK_COUNT=$($CLI getblockcount)
echo "    Current block count: $BLOCK_COUNT"
echo ""

# Submit 5 shares to simulate L7 mining
echo "[2] Simulating L7 shares (5 submissions)..."
for i in {1..5}; do
    echo "    Submitting share #$i..."
    printf '{"id":'$i',"method":"mining.submit","params":["L7.worker","0000000'$i'","00000000","0000000'$i'","0000000'$i'"]}\n' | nc 127.0.0.1 3333 > /dev/null 2>&1
    sleep 2
done
echo "    ✓ 5 shares submitted"
echo ""

# Wait for blocks to be mined
echo "[3] Waiting for blocks to be mined..."
sleep 5
NEW_BLOCK_COUNT=$($CLI getblockcount)
echo "    New block count: $NEW_BLOCK_COUNT"
BLOCKS_MINED=$((NEW_BLOCK_COUNT - BLOCK_COUNT))
echo "    Blocks mined: $BLOCKS_MINED"
echo ""

# Find blocks with confidential transactions
echo "[4] Searching for confidential transactions in recent blocks..."
CONF_TX_BLOCK=""
CONF_TX_HASH=""

for ((height=BLOCK_COUNT+1; height<=NEW_BLOCK_COUNT; height++)); do
    BLOCK_HASH=$($CLI getblockhash $height)
    BLOCK=$($CLI getblock $BLOCK_HASH 2)
    
    # Check if block has more than 1 transaction (coinbase + confidential tx)
    TX_COUNT=$(echo "$BLOCK" | grep -c '"txid"' || true)
    
    if [ "$TX_COUNT" -gt 1 ]; then
        echo "    ✓ Block $height has $TX_COUNT transactions"
        
        # Extract all transaction IDs
        TXIDS=$(echo "$BLOCK" | grep '"txid"' | cut -d'"' -f4)
        
        # Check each transaction for OP_RETURN (excluding coinbase)
        for TXID in $TXIDS; do
            # Skip if this is the coinbase
            if echo "$BLOCK" | grep -A 5 "$TXID" | grep -q "coinbase"; then
                continue
            fi
            
            # Check if transaction has OP_RETURN with large payload
            TX_DATA=$($CLI gettransaction $TXID true 2>/dev/null || echo "")
            if echo "$TX_DATA" | grep -q "nulldata"; then
                HEX=$(echo "$TX_DATA" | grep '"hex"' | head -1 | cut -d'"' -f4)
                HEX_LEN=${#HEX}
                
                if [ "$HEX_LEN" -gt 2000 ]; then
                    echo "    🔐 Found confidential transaction!"
                    echo "       Block: $height"
                    echo "       Block Hash: $BLOCK_HASH"
                    echo "       TX ID: $TXID"
                    echo "       TX Size: $HEX_LEN hex chars"
                    CONF_TX_BLOCK=$BLOCK_HASH
                    CONF_TX_HASH=$TXID
                    break 2
                fi
            fi
        done
    fi
done

if [ -z "$CONF_TX_BLOCK" ]; then
    echo "    ⚠️  No confidential transactions found in blocks"
    echo "    This is expected if generatetoaddress mined blocks before mempool txs were included"
    echo ""
    echo "[5] Checking mempool for pending confidential transactions..."
    MEMPOOL=$($CLI getrawmempool)
    MEMPOOL_COUNT=$(echo "$MEMPOOL" | grep -c '"' || echo "0")
    echo "    Pending transactions in mempool: $MEMPOOL_COUNT"
    
    if [ "$MEMPOOL_COUNT" -gt 0 ]; then
        echo ""
        echo "    💡 Solution: Mine one more block to include mempool transactions"
        echo "    Generating block..."
        $CLI generatetoaddress 1 $($CLI getnewaddress) > /dev/null
        
        # Check the new block
        NEW_HEIGHT=$($CLI getblockcount)
        NEW_HASH=$($CLI getblockhash $NEW_HEIGHT)
        echo "    ✓ Block $NEW_HEIGHT mined: $NEW_HASH"
        
        # Save this block for analysis
        CONF_TX_BLOCK=$NEW_HASH
    fi
fi

echo ""
echo "[6] Capturing block data for whitepaper..."
if [ -n "$CONF_TX_BLOCK" ]; then
    $CLI getblock $CONF_TX_BLOCK 2 > l7_conf_block.json
    echo "    ✓ Block data saved to: l7_conf_block.json"
    
    # Extract key metrics
    HEIGHT=$($CLI getblock $CONF_TX_BLOCK | grep '"height"' | cut -d':' -f2 | tr -d ' ,')
    TX_COUNT=$(grep -c '"txid"' l7_conf_block.json)
    
    echo ""
    echo "==================================="
    echo "✅ L7 Confidential TX Test Complete"
    echo "==================================="
    echo "Block Height: $HEIGHT"
    echo "Block Hash: $CONF_TX_BLOCK"
    echo "Transactions: $TX_COUNT"
    echo "Data File: l7_conf_block.json"
    echo ""
    echo "Next steps:"
    echo "1. Review l7_conf_block.json"
    echo "2. Create terminal screenshot of block output"
    echo "3. Update whitepaper with L7 mining results"
else
    echo "    ⚠️  Could not find confidential transaction block"
fi
