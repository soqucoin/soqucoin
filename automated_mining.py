#!/usr/bin/env python3
"""
Automated L7-Simulated Mining
Mines blocks periodically with confidential transactions
Simulates L7 mining activity for data collection
"""

import subprocess
import time
import json
import random
from datetime import datetime

RPC_USER = "miner"
RPC_PASS = "soqu"
RPC_PORT = 18443

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")

def rpc(method, params=None):
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
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        return None
    return result.stdout.strip()

def mine_block():
    """Mine a single block"""
    try:
        # Get mempool size
        mempool = json.loads(rpc('getrawmempool'))
        mempool_size = len(mempool)
        
        # Get address
        addr = rpc('getnewaddress')
        if not addr:
            log("ERROR: Failed to get address")
            return False
        
        # Mine block
        result = rpc('generatetoaddress', [1, addr])
        if not result:
            log("ERROR: Failed to mine block")
            return False
        
        block_hash = json.loads(result)[0]
        
        # Get block info
        block_data = json.loads(rpc('getblock', [block_hash, 2]))
        height = block_data['height']
        tx_count = len(block_data['tx'])
        
        # Count confidential txs
        conf_txs = [tx for tx in block_data['tx'][1:] if 'txinwitness' in tx['vin'][0]]
        conf_count = len(conf_txs)
        
        log(f"✅ [L7 BLOCK] height={height}, hash={block_hash[:16]}..., txs={tx_count} ({conf_count} confidential), mempool_was={mempool_size}")
        
        return True
        
    except Exception as e:
        log(f"ERROR: {e}")
        return False

def main():
    log("=" * 80)
    log("L7-Simulated Mining Starting")
    log("Target: 2 hours of continuous operation")
    log("Block interval: 2-5 minutes (random)")
    log("=" * 80)
    
    start_time = time.time()
    target_duration = 2 * 60 * 60  # 2 hours
    blocks_mined = 0
    
    # Initial status
    height = rpc('getblockcount')
    log(f"Starting height: {height}")
    
    try:
        while True:
            elapsed = time.time() - start_time
            
            if elapsed >= target_duration:
                log("")
                log("=" * 80)
                log(f"✅ Target duration reached: {elapsed/3600:.2f} hours")
                log(f"Total blocks mined: {blocks_mined}")
                log("=" * 80)
                break
            
            # Mine a block
            if mine_block():
                blocks_mined += 1
            
            # Random interval between 2-5 minutes
            interval = random.randint(120, 300)
            remaining = target_duration - elapsed
            
            if remaining < interval:
                log(f"Waiting {remaining:.0f}s until target time...")
                time.sleep(remaining)
            else:
                log(f"Next block in {interval}s... ({blocks_mined} mined, {elapsed/60:.1f}min elapsed)")
                time.sleep(interval)
                
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        log("")
        log("=" * 80)
        log(f"Mining stopped by user")
        log(f"Runtime: {elapsed/3600:.2f} hours")
        log(f"Blocks mined: {blocks_mined}")
        log("=" * 80)

if __name__ == "__main__":
    main()
