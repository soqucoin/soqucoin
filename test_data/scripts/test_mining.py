#!/usr/bin/env python3
"""
Test block generation to verify L7 mining will work
"""
import subprocess
import time
import json

def rpc(method, params=None):
    if params is None:
        params = []
    cmd = ["./src/soqucoin-cli", "-regtest", "-rpcuser=miner", "-rpcpassword=soqu", "-rpcport=18443", method] + [str(p) for p in params]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()

print("Testing block generation...")
print(f"Current height: {rpc('getblockcount')}")
print(f"Mempool: {len(json.loads(rpc('getrawmempool')))} txs")

print("\nMining 1 test block...")
addr = rpc('getnewaddress')
result = rpc('generatetoaddress', [1, addr])
block_hash = json.loads(result)[0]

print(f"Block mined: {block_hash[:16]}...")
print(f"New height: {rpc('getblockcount')}")

block_data = json.loads(rpc('getblock', [block_hash, 2]))
conf_txs = [tx for tx in block_data['tx'][1:] if 'txinwitness' in tx['vin'][0]]

print(f"Block contained {len(block_data['tx'])} txs ({len(conf_txs)} confidential)")
print(f"Mempool now: {len(json.loads(rpc('getrawmempool')))} txs")

if len(conf_txs) > 0:
    print(f"\n✅ SUCCESS! Block mining working with {len(conf_txs)} confidential txs")
    print(f"When L7 submits shares, proxy will mine blocks just like this.")
else:
    print(f"\n⚠️  Block mined but no confidential txs included")
