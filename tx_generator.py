#!/usr/bin/env python3
"""
Continuous Confidential Transaction Generator for L7 Stress Testing
Creates confidential transactions at a configurable rate to ensure
L7 miner always has confidential transactions to include in blocks.
"""

import json
import time
import subprocess
import sys
from datetime import datetime

# Configuration
RPC_USER = "miner"
RPC_PASS = "soqu"
RPC_PORT = 18443
TX_INTERVAL = 30  # seconds between transactions
TX_AMOUNT = 1.0   # amount per transaction
LOG_FILE = "tx_generator.log"

def log(message):
    """Log with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] {message}"
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def rpc_call(method, params=None):
    """Make RPC call to Soqucoin node"""
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
            log(f"ERROR: RPC call failed: {result.stderr}")
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        log(f"ERROR: RPC call timed out: {method}")
        return None
    except Exception as e:
        log(f"ERROR: Exception during RPC call: {e}")
        return None

def get_new_address():
    """Get a new address from the wallet"""
    return rpc_call("getnewaddress")

def get_balance():
    """Get wallet balance"""
    balance = rpc_call("getbalance")
    return float(balance) if balance else 0.0

def get_mempool_count():
    """Get number of transactions in mempool"""
    mempool = rpc_call("getrawmempool")
    if not mempool:
        return 0
    try:
        txs = json.loads(mempool)
        return len(txs)
    except:
        return 0

def create_confidential_transaction():
    """Create a confidential transaction"""
    # Get new address
    address = get_new_address()
    if not address:
        log("ERROR: Failed to get new address")
        return None
    
    # Create confidential transaction using JSON-RPC directly
    import urllib.request
    import base64
    
    auth_str = f"{RPC_USER}:{RPC_PASS}"
    auth_bytes = base64.b64encode(auth_str.encode()).decode()
    
    payload = {
        "jsonrpc": "1.0",
        "id": "txgen",
        "method": "sendtoaddress",
        "params": [address, TX_AMOUNT, "", "", False, True]
    }
    
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{RPC_PORT}",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth_bytes}"
            }
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode())
            
            if result.get('error'):
                log(f"ERROR: RPC error: {result['error']}")
                return None
            
            txid = result.get('result')
            if txid:
                log(f"✓ Created confidential tx: {txid}")
                return txid
            else:
                log("ERROR: No txid in response")
                return None
                
    except Exception as e:
        log(f"ERROR: Exception creating tx: {e}")
        return None

def check_node_health():
    """Check if node is healthy"""
    blockcount = rpc_call("getblockcount")
    if blockcount is None:
        return False
    log(f"Node health check OK - Block height: {blockcount}")
    return True

def main():
    log("=" * 60)
    log("Confidential Transaction Generator Starting")
    log(f"Transaction interval: {TX_INTERVAL} seconds")
    log(f"Transaction amount: {TX_AMOUNT} SOQU")
    log("=" * 60)
    
    # Initial health check
    if not check_node_health():
        log("FATAL: Node is not responding. Exiting.")
        sys.exit(1)
    
    # Check initial balance
    balance = get_balance()
    log(f"Initial balance: {balance:.2f} SOQU")
    
    if balance < TX_AMOUNT:
        log("WARNING: Insufficient balance for transactions")
        log("Please generate some blocks first:")
        log(f"  ./src/soqucoin-cli -regtest -rpcuser={RPC_USER} -rpcpassword={RPC_PASS} generatetoaddress 101 $(./src/soqucoin-cli -regtest -rpcuser={RPC_USER} -rpcpassword={RPC_PASS} getnewaddress)")
        sys.exit(1)
    
    # Stats
    txs_created = 0
    txs_failed = 0
    start_time = time.time()
    
    try:
        while True:
            # Create transaction
            txid = create_confidential_transaction()
            
            if txid:
                txs_created += 1
            else:
                txs_failed += 1
            
            # Get mempool stats
            mempool_count = get_mempool_count()
            
            # Calculate stats
            elapsed = time.time() - start_time
            rate = txs_created / (elapsed / 60) if elapsed > 0 else 0
            
            log(f"Stats - Created: {txs_created}, Failed: {txs_failed}, Mempool: {mempool_count}, Rate: {rate:.1f} tx/min")
            
            # Wait before next transaction
            time.sleep(TX_INTERVAL)
            
    except KeyboardInterrupt:
        log("\n" + "=" * 60)
        log("Transaction Generator Stopping")
        log(f"Total transactions created: {txs_created}")
        log(f"Total failures: {txs_failed}")
        log(f"Total runtime: {(time.time() - start_time) / 60:.1f} minutes")
        log("=" * 60)
        sys.exit(0)
    except Exception as e:
        log(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
