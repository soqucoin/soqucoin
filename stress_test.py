#!/usr/bin/env python3
import sys
import os
import time
import random
import decimal
import concurrent.futures
import threading

# Add qa/rpc-tests to path to import test_framework
sys.path.append(os.path.join(os.getcwd(), "qa", "rpc-tests"))

try:
    from test_framework.authproxy import AuthServiceProxy, JSONRPCException
except ImportError:
    print("Error: Could not import AuthServiceProxy. Make sure you are running from the build root.")
    sys.exit(1)

def send_batch(rpc_url, dest_address, count):
    rpc = AuthServiceProxy(rpc_url)
    for _ in range(count):
        try:
            rpc.sendtoaddress(dest_address, 1.0)
        except Exception as e:
            print(f"Tx Error: {e}")

def main():
    print("Starting multi-threaded stress test...")
    
    rpc_user = "admin"
    rpc_password = "admin"
    rpc_port = 18350
    rpc_url = f"http://{rpc_user}:{rpc_password}@127.0.0.1:{rpc_port}"
    
    total_txs = 10000
    threads = 10
    txs_per_thread = total_txs // threads
    
    try:
        # Check connection
        rpc_main = AuthServiceProxy(rpc_url)
        info = rpc_main.getblockchaininfo()
        print(f"Connected to node at block {info['blocks']}")
        dest_address = rpc_main.getnewaddress()
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for _ in range(threads):
                futures.append(executor.submit(send_batch, rpc_url, dest_address, txs_per_thread))
            
            # Monitor and mine
            completed_txs = 0
            while any(f.running() for f in futures):
                mempool = rpc_main.getmempoolinfo()
                size = mempool['size']
                print(f"\rMempool: {size} txs", end="")
                
                if size > 1000:
                    print("\nMining block to clear mempool...")
                    rpc_main.generate(1)
                
                time.sleep(1)
            
            # Wait for all
            concurrent.futures.wait(futures)
            
    except Exception as e:
        print(f"\nFatal Error: {e}")
        sys.exit(1)

    end_time = time.time()
    duration = end_time - start_time
    print(f"\nStress test completed in {duration:.2f} seconds")
    print(f"Throughput: {total_txs / duration:.2f} tx/s")

if __name__ == "__main__":
    main()
