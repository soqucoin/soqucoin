#!/usr/bin/env python3
import time
import json
import sys
from decimal import Decimal

try:
    import requests
except ImportError:
    print("Error: requests library not found. Install with: pip3 install requests")
    exit(1)

class JSONRPCException(Exception):
    pass

class SimpleRPC:
    def __init__(self, url, user, password):
        self.url = url
        self.auth = (user, password)
        self.id = 0
    
    def _call(self, method, params=[]):
        self.id += 1
        payload = {
            "jsonrpc": "1.0",
            "id": self.id,
            "method": method,
            "params": params
        }
        try:
            response = requests.post(self.url, json=payload, auth=self.auth, timeout=30)
            response.raise_for_status()
            result = response.json()
            if result.get("error"):
                raise JSONRPCException(result["error"]["message"])
            return result.get("result")
        except requests.exceptions.RequestException as e:
            raise JSONRPCException(f"RPC connection error: {e}")
    
    def __getattr__(self, method):
        return lambda *params: self._call(method, list(params))

def main():
    print("Starting Soqucoin Stress Test...")

    # Configuration
    rpc_user = "miner"
    rpc_password = "soqu"
    rpc_port = 18444  # Regtest RPC port
    num_transactions = 10000
    mine_interval = 1000

    # Connect to local node
    rpc_url = f"http://127.0.0.1:{rpc_port}"
    try:
        rpc_connection = SimpleRPC(rpc_url, rpc_user, rpc_password)
        info = rpc_connection.getblockchaininfo()
        print(f"Connected to node. Chain: {info['chain']}, Blocks: {info['blocks']}")
    except Exception as e:
        print(f"Error connecting to node: {e}")
        print(f"Please ensure soqucoind is running in regtest mode with rpcuser={rpc_user} and rpcpassword={rpc_password}")
        sys.exit(1)

    # Generate a new address for receiving transactions
    dest_address = rpc_connection.getnewaddress()
    print(f"Sending transactions to: {dest_address}")

    start_time = time.time()
    tx_count = 0

    try:
        for i in range(1, num_transactions + 1):
            try:
                # Send 0.0001 SOQU to the destination address
                rpc_connection.sendtoaddress(dest_address, Decimal("0.0001"))
                tx_count += 1
                
                if i % 100 == 0:
                    print(f"Sent {i} transactions...")

                if i % mine_interval == 0:
                    print(f"Mining a block to clear mempool...")
                    rpc_connection.generate(1)
                    
            except JSONRPCException as e:
                print(f"RPC Error on transaction {i}: {e}")
                # If mempool is full, try mining
                if "mempool full" in str(e):
                    print("Mempool full, mining a block...")
                    rpc_connection.generate(1)
                else:
                    break

    except KeyboardInterrupt:
        print("\nStress test interrupted.")

    end_time = time.time()
    duration = end_time - start_time
    
    print("\nStress Test Completed!")
    print(f"Total Transactions Sent: {tx_count}")
    print(f"Total Time: {duration:.2f} seconds")
    print(f"TPS: {tx_count / duration:.2f}")

if __name__ == "__main__":
    main()
