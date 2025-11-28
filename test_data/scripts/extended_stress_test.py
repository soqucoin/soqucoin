#!/usr/bin/env python3
"""
Extended stress test - sends 1000 transactions to validate sustained performance
"""
import subprocess
import time
import json

def run_cli(command):
    """Run soqucoin-cli command and return JSON result"""
    cmd = ['./src/soqucoin-cli', '-regtest', '-rpcuser=miner', '-rpcpassword=soqu'] + command
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout) if result.stdout.strip() and result.stdout.strip().startswith('{') else result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"CLI Error: {e.stderr}")
        raise
    except json.JSONDecodeError:
        return result.stdout.strip()

def main():
    print("Extended Stress Test (1000 transactions)...")
    print("=" * 60)
    
    # Test connection
    info = run_cli(['getblockchaininfo'])
    print(f"Connected to node")
    print(f"  Chain: {info['chain']}")
    print(f"  Current blocks: {info['blocks']}")
    
    # Generate addresses
    dest_address = run_cli(['getnewaddress'])
    mining_address = run_cli(['getnewaddress'])
    print(f"  Destination: {dest_address[:20]}...")
    print(f"  Mining addr: {mining_address[:20]}...")
    print()
    
    start_time = time.time()
    tx_sent = 0
    blocks_mined = 0
    
    try:
        for i in range(1, 1001):
            run_cli(['sendtoaddress', dest_address, '0.001'])
            tx_sent += 1
            
            if i % 100 == 0:
                elapsed = time.time() - start_time
                tps = tx_sent / elapsed
                print(f"Progress: {i}/1000 txs | {elapsed:.1f}s elapsed | {tps:.2f} TPS")
            
            if i % 200 == 0:
                run_cli(['generatetoaddress', '1', mining_address])
                blocks_mined += 1
                print(f"  ⛏ Mined block {blocks_mined}")
        
        # Mine final blocks to confirm all transactions
        print("\nMining final blocks...")
        run_cli(['generatetoaddress', '2', mining_address])
        blocks_mined += 2
        
    except Exception as e:
        print(f"\n❌ Error at transaction {tx_sent + 1}: {e}")
        return 1
    
    duration = time.time() - start_time
    
    print("\n" + "=" * 60)
    print("✓ Extended Stress Test COMPLETED")
    print(f"  Transactions sent: {tx_sent}")
    print(f"  Blocks mined: {blocks_mined}")
    print(f"  Total time: {duration:.2f}s")
    print(f"  Average TPS: {tx_sent / duration:.2f}")
    print("=" * 60)
    
    # Verify final state
    final_info = run_cli(['getblockchaininfo'])
    print(f"\nFinal block height: {final_info['blocks']}")
    print(f"Blocks added: {final_info['blocks'] - info['blocks']}")
    
    return 0

if __name__ == "__main__":
    exit(main())
