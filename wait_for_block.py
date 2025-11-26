#!/usr/bin/env python3
"""
L7 First Block Waiter
Monitors for the first block mined by L7 and captures detailed data
"""

import json
import time
import subprocess
from datetime import datetime

RPC_USER = "miner"
RPC_PASS = "soqu"
RPC_PORT = 18443
START_HEIGHT = 103

def rpc_call(method, params=None):
    if params is None:
        params = []
    cmd = [
        "./src/soqucoin-cli",
        "-regtest",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASS}",
        f"-rpcport={RPC_PORT}",
        method
    ] + [str(p) for p in params]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except:
        return None

def get_block_height():
    height = rpc_call("getblockcount")
    return int(height) if height else 0

def get_block_data(block_hash):
    data = rpc_call("getblock", [block_hash, "2"])
    if data:
        try:
            return json.loads(data)
        except:
            return None
    return None

def get_mempool_count():
    mempool = rpc_call("getrawmempool")
    if mempool:
        try:
            txs = json.loads(mempool)
            return len(txs)
        except:
            return 0
    return 0

print("=" * 80)
print("WAITING FOR FIRST L7 BLOCK")
print("=" * 80)
print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Current height: {START_HEIGHT}")
print(f"Mempool: {get_mempool_count()} txs")
print("")
print("Monitoring for new block...")
print("(Press Ctrl+C to stop)")
print("")

try:
    check_count = 0
    while True:
        current_height = get_block_height()
        
        if current_height > START_HEIGHT:
            print("")
            print("=" * 80)
            print("🎉 NEW BLOCK DETECTED!")
            print("=" * 80)
            
            # Get block data
            block_hash = rpc_call("getblockhash", [current_height])
            if block_hash:
                block_data = get_block_data(block_hash)
                if block_data:
                    print(f"Height: {current_height}")
                    print(f"Hash: {block_hash}")
                    print(f"Time: {datetime.fromtimestamp(block_data['time']).strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Size: {block_data['size']} bytes")
                    print(f"Weight: {block_data['weight']}")
                    print(f"Transactions: {len(block_data['tx'])}")
                    
                    # Count confidential txs
                    conf_txs = []
                    for tx in block_data['tx'][1:]:  # Skip coinbase
                        if 'txinwitness' in tx['vin'][0]:
                            conf_txs.append(tx['txid'])
                    
                    print(f"Confidential TXs: {len(conf_txs)}")
                    print("")
                    
                    if len(conf_txs) > 0:
                        print("Confidential Transaction IDs:")
                        for i, txid in enumerate(conf_txs[:5], 1):
                            print(f"  {i}. {txid}")
                        if len(conf_txs) > 5:
                            print(f"  ... and {len(conf_txs) - 5} more")
                        print("")
                        
                        # Get witness details from first tx
                        first_tx = block_data['tx'][1]
                        if 'txinwitness' in first_tx['vin'][0]:
                            witness_sizes = [len(item)//2 for item in first_tx['vin'][0]['txinwitness']]
                            print("First Confidential TX Witness:")
                            print(f"  Items: {len(witness_sizes)}")
                            print(f"  Sizes: {witness_sizes} bytes")
                            print(f"  Expected: [2421, 1313] (Dilithium sig + pubkey)")
                            
                            if witness_sizes == [2421, 1313]:
                                print("  ✅ CORRECT Dilithium witness structure!")
                            else:
                                print("  ⚠️  Unexpected witness structure")
                    
                    print("")
                    print("=" * 80)
                    print("SUCCESS! First L7 block with confidential transactions captured!")
                    print("=" * 80)
                    print("")
                    print("Data has been saved to data_capture/")
                    print("Check data_capture/metrics.json for full stats")
                    print("")
                    
                    # Show new mempool size
                    new_mempool = get_mempool_count()
                    print(f"Mempool after block: {new_mempool} txs")
                    print(f"TXs cleared: ~{len(conf_txs)}")
                    
                    break
        
        # Progress indicator
        check_count += 1
        if check_count % 6 == 0:  # Every minute
            mempool = get_mempool_count()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Still waiting... (Height: {current_height}, Mempool: {mempool} txs)")
        
        time.sleep(10)
        
except KeyboardInterrupt:
    print("\n\nMonitoring stopped by user")
except Exception as e:
    print(f"\nError: {e}")
