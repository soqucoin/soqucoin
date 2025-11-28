#!/usr/bin/env python3
"""
L7 Mining Monitor and Data Capture
Monitors blocks mined by L7, captures data for whitepaper, and tracks metrics
"""

import json
import time
import subprocess
import os
from datetime import datetime
from pathlib import Path

# Configuration
RPC_USER = "miner"
RPC_PASS = "soqu"
RPC_PORT = 18443
DATA_DIR = "data_capture"
CHECK_INTERVAL = 10  # seconds

# Create data directories
Path(f"{DATA_DIR}/blocks").mkdir(parents=True, exist_ok=True)
Path(f"{DATA_DIR}/transactions").mkdir(parents=True, exist_ok=True)
Path(f"{DATA_DIR}/logs").mkdir(parents=True, exist_ok=True)

class L7Monitor:
    def __init__(self):
        self.last_block_height = 0
        self.blocks_captured = 0
        self.confidential_txs_found = 0
        self.start_time = time.time()
        self.metrics = {
            "start_time": datetime.now().isoformat(),
            "blocks": [],
            "total_confidential_txs": 0,
            "total_blocks": 0,
        }
        
    def log(self, message):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] {message}"
        print(msg)
        with open(f"{DATA_DIR}/logs/monitor.log", "a") as f:
            f.write(msg + "\n")
    
    def rpc_call(self, method, params=None):
        """Make RPC call"""
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
    
    def get_block_height(self):
        """Get current block height"""
        height = self.rpc_call("getblockcount")
        return int(height) if height else 0
    
    def get_block_hash(self, height):
        """Get block hash at height"""
        return self.rpc_call("getblockhash", [height])
    
    def get_block_data(self, block_hash):
        """Get full block data"""
        data = self.rpc_call("getblock", [block_hash, "2"])
        if data:
            try:
                return json.loads(data)
            except:
                return None
        return None
    
    def get_transaction_data(self, txid):
        """Get transaction data"""
        data = self.rpc_call("getrawtransaction", [txid, "true"])
        if data:
            try:
                return json.loads(data)
            except:
                return None
        return None
    
    def analyze_block(self, block_data):
        """Analyze block for confidential transactions"""
        block_hash = block_data["hash"]
        height = block_data["height"]
        tx_count = len(block_data["tx"])
        
        # Check for confidential transactions (non-coinbase with witness)
        confidential_txs = []
        for tx in block_data["tx"][1:]:  # Skip coinbase
            if "txinwitness" in tx["vin"][0]:
                witness_sizes = [len(item)//2 for item in tx["vin"][0]["txinwitness"]]
                confidential_txs.append({
                    "txid": tx["txid"],
                    "witness_items": len(witness_sizes),
                    "witness_sizes": witness_sizes,
                    "size": tx["size"],
                    "vsize": tx["vsize"]
                })
        
        block_info = {
            "height": height,
            "hash": block_hash,
            "time": block_data["time"],
            "size": block_data["size"],
            "weight": block_data["weight"],
            "tx_count": tx_count,
            "confidential_tx_count": len(confidential_txs),
            "confidential_txs": confidential_txs
        }
        
        return block_info
    
    def save_block_data(self, block_data, block_info):
        """Save block data to files"""
        height = block_info["height"]
        
        # Save full block JSON
        with open(f"{DATA_DIR}/blocks/block_{height}.json", "w") as f:
            json.dump(block_data, f, indent=2)
        
        # Save block summary
        with open(f"{DATA_DIR}/blocks/block_{height}_summary.json", "w") as f:
            json.dump(block_info, f, indent=2)
        
        # Save confidential transactions
        for tx_info in block_info["confidential_txs"]:
            txid = tx_info["txid"]
            tx_data = self.get_transaction_data(txid)
            if tx_data:
                with open(f"{DATA_DIR}/transactions/tx_{txid}.json", "w") as f:
                    json.dump(tx_data, f, indent=2)
    
    def update_metrics(self, block_info):
        """Update metrics"""
        self.metrics["blocks"].append(block_info)
        self.metrics["total_blocks"] += 1
        self.metrics["total_confidential_txs"] += block_info["confidential_tx_count"]
        
        # Calculate stats
        elapsed = time.time() - self.start_time
        self.metrics["runtime_minutes"] = elapsed / 60
        self.metrics["blocks_per_hour"] = self.metrics["total_blocks"] / (elapsed / 3600) if elapsed > 0 else 0
        self.metrics["txs_per_block"] = self.metrics["total_confidential_txs"] / self.metrics["total_blocks"] if self.metrics["total_blocks"] > 0 else 0
        
        # Save metrics
        with open(f"{DATA_DIR}/metrics.json", "w") as f:
            json.dump(self.metrics, f, indent=2)
    
    def display_summary(self, block_info):
        """Display block summary"""
        self.log("=" * 80)
        self.log(f"NEW BLOCK CAPTURED - Height: {block_info['height']}")
        self.log(f"Hash: {block_info['hash']}")
        self.log(f"Size: {block_info['size']} bytes, Weight: {block_info['weight']}")
        self.log(f"Transactions: {block_info['tx_count']} total, {block_info['confidential_tx_count']} confidential")
        
        for i, tx in enumerate(block_info["confidential_txs"], 1):
            self.log(f"  Confidential TX #{i}:")
            self.log(f"    TXID: {tx['txid']}")
            self.log(f"    Witness: {tx['witness_items']} items, sizes: {tx['witness_sizes']}")
            self.log(f"    Size: {tx['size']} bytes, vsize: {tx['vsize']}")
        
        # Overall stats
        elapsed = time.time() - self.start_time
        self.log(f"\nOverall Stats:")
        self.log(f"  Runtime: {elapsed/60:.1f} minutes")
        self.log(f"  Blocks captured: {self.metrics['total_blocks']}")
        self.log(f"  Confidential txs: {self.metrics['total_confidential_txs']}")
        self.log(f"  Avg txs/block: {self.metrics['txs_per_block']:.2f}")
        self.log(f"  Blocks/hour: {self.metrics['blocks_per_hour']:.2f}")
        self.log("=" * 80)
    
    def run(self):
        """Main monitoring loop"""
        self.log("L7 Monitor Starting")
        self.log(f"Data directory: {DATA_DIR}")
        self.log(f"Check interval: {CHECK_INTERVAL} seconds")
        
        # Get initial height
        self.last_block_height = self.get_block_height()
        self.log(f"Initial block height: {self.last_block_height}")
        
        try:
            while True:
                current_height = self.get_block_height()
                
                # Check for new blocks
                if current_height > self.last_block_height:
                    # Process all new blocks
                    for height in range(self.last_block_height + 1, current_height + 1):
                        block_hash = self.get_block_hash(height)
                        if not block_hash:
                            continue
                        
                        block_data = self.get_block_data(block_hash)
                        if not block_data:
                            continue
                        
                        # Analyze block
                        block_info = self.analyze_block(block_data)
                        
                        # Save data
                        self.save_block_data(block_data, block_info)
                        
                        # Update metrics
                        self.update_metrics(block_info)
                        
                        # Display summary
                        self.display_summary(block_info)
                    
                    self.last_block_height = current_height
                
                time.sleep(CHECK_INTERVAL)
                
        except KeyboardInterrupt:
            self.log("\nMonitor stopping...")
            self.log(f"Final stats saved to {DATA_DIR}/metrics.json")
            self.log(f"Total blocks captured: {self.metrics['total_blocks']}")
            self.log(f"Total confidential txs: {self.metrics['total_confidential_txs']}")

if __name__ == "__main__":
    monitor = L7Monitor()
    monitor.run()
