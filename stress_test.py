#!/usr/bin/env python3
import subprocess
import time
import json
from decimal import Decimal

def run_cli(command):
    """Run soqucoin-cli command and return JSON result"""
    cmd = ['./src/soqucoin-cli', '-regtest', '-rpcuser=miner', '-rpcpassword=soqu'] + command
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout) if result.stdout.strip() else None
    except subprocess.CalledProcessError as e:
        print(f"CLI Error: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        print("CLI command timed out")
        raise
    except json.JSONDecodeError:
        # Some commands don't return JSON (like sendtoaddress returning just a txid)
        return result.stdout.strip()

def main():
    print("Starting Soqucoin Stress Test...")
    
    # Configuration
    num_transactions = 10000
    mine_interval = 1000
    
    # Test connection
    try:
        info = run_cli(['getblockchaininfo'])
        print(f"Connected to node. Chain: {info['chain']}, Blocks: {info['blocks']}")
    except Exception as e:
        print(f"Error connecting to node: {e}")
        print("Please ensure soqucoind is running in regtest mode with rpcuser=miner and rpcpassword=soqu")
        return 1
    
    # Generate a new address for receiving transactions
    dest_address = run_cli(['getnewaddress'])
    # Get mining address for block generation
    mining_address = run_cli(['getnewaddress'])
    print(f"Sending transactions to: {dest_address}")
    print(f"Mining blocks to: {mining_address}")
    
    start_time = time.time()
    tx_count = 0
    
    try:
        for i in range(1, num_transactions + 1):
            try:
                # Send 0.01 SOQU to the destination address
                run_cli(['sendtoaddress', dest_address, '0.01'])
                tx_count += 1
                
                if i % 100 == 0:
                    print(f"Sent {i} transactions...")
                
                if i % mine_interval == 0:
                    print(f"Mining a block to clear mempool...")
                    run_cli(['generatetoaddress', '1', mining_address])
                    
            except Exception as e:
                print(f"Error on transaction {i}: {e}")
                # If mempool is full, try mining
                if "mempool full" in str(e).lower():
                    print("Mempool full, mining a block...")
                    run_cli(['generatetoaddress', '1', mining_address])
                else:
                    break
    
    except KeyboardInterrupt:
        print("\nStress test interrupted.")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print("\nStress Test Completed!")
    print(f"Total Transactions Sent: {tx_count}")
    print(f"Total Time: {duration:.2f} seconds")
    if duration > 0:
        print(f"TPS: {tx_count / duration:.2f}")
    
    return 0

if __name__ == "__main__":
    exit(main())
