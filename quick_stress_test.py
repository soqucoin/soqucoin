#!/usr/bin/env python3
"""
Quick stress test - sends 100 transactions to verify functionality
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
    print("Quick Stress Test (100 transactions)...")
    
    # Test connection
    info = run_cli(['getblockchaininfo'])
    print(f"Connected. Blocks: {info['blocks']}")
    
    # Generate addresses
    dest_address = run_cli(['getnewaddress'])
    mining_address = run_cli(['getnewaddress'])
    print(f"Sending to: {dest_address}")
    
    start_time = time.time()
    
    for i in range(1, 101):
        run_cli(['sendtoaddress', dest_address, '0.01'])
        if i % 10 == 0:
            print(f"Sent {i} transactions...")
        if i % 50 == 0:
            print("Mining block...")
            run_cli(['generatetoaddress', '1', mining_address])
    
    # Mine final block
    run_cli(['generatetoaddress', '1', mining_address])
    
    duration = time.time() - start_time
    print(f"\nCompleted! Time: {duration:.2f}s, TPS: {100 / duration:.2f}")

if __name__ == "__main__":
    main()
