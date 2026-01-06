#!/usr/bin/env python3
"""
Soqucoin Stagenet Genesis Block Miner

⚠️ WARNING: DO NOT USE THIS SCRIPT TO MINE FINAL GENESIS BLOCKS!

This Python implementation produces different coinbase transaction serialization
than the C++ code in soqucoind. The resulting genesis hash will NOT match what
the node expects.

Instead, use the built-in C++ mining loop:
1. Set genesis nonce to 0 in chainparams.cpp
2. Build and run soqucoind
3. It will print the mined nonce and hashes
4. Hardcode those values in chainparams.cpp

This script is kept for reference/educational purposes only.

import hashlib
import struct
import time

try:
    import scrypt
except ImportError:
    print("Installing scrypt...")
    import subprocess
    subprocess.check_call(['pip3', 'install', 'scrypt'])
    import scrypt

def double_sha256(data):
    """Double SHA256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def scrypt_hash(header):
    """Scrypt hash for PoW (1024, 1, 1, 32)."""
    return scrypt.hash(header, header, N=1024, r=1, p=1, buflen=32)

def uint256_from_bytes(b):
    """Convert 32 bytes to integer (little-endian)."""
    return int.from_bytes(b, 'little')

def compact_to_target(nBits):
    """Convert compact target format to full 256-bit target."""
    size = nBits >> 24
    word = nBits & 0x007fffff
    if size <= 3:
        word >>= 8 * (3 - size)
    else:
        word <<= 8 * (size - 3)
    return word

def create_block_header(version, prev_hash, merkle_root, timestamp, bits, nonce):
    """Create 80-byte block header."""
    header = struct.pack('<I', version)          # Version (4 bytes)
    header += prev_hash                           # Previous hash (32 bytes)
    header += merkle_root                         # Merkle root (32 bytes)
    header += struct.pack('<I', timestamp)        # Timestamp (4 bytes)
    header += struct.pack('<I', bits)             # Bits (4 bytes)
    header += struct.pack('<I', nonce)            # Nonce (4 bytes)
    return header

def create_coinbase_tx(coinbase_msg, reward_satoshis, pubkey_script):
    """Create coinbase transaction."""
    # Version
    tx = struct.pack('<I', 1)
    
    # Input count
    tx += b'\x01'
    
    # Previous output hash (all zeros for coinbase)
    tx += b'\x00' * 32
    
    # Previous output index (0xffffffff for coinbase)
    tx += b'\xff\xff\xff\xff'
    
    # Script sig length + coinbase data
    coinbase_data = coinbase_msg.encode('utf-8')
    script_sig = bytes([len(coinbase_data)]) + coinbase_data
    tx += bytes([len(script_sig)]) + script_sig
    
    # Sequence
    tx += b'\xff\xff\xff\xff'
    
    # Output count
    tx += b'\x01'
    
    # Output value (reward)
    tx += struct.pack('<Q', reward_satoshis)
    
    # Output script
    tx += bytes([len(pubkey_script)]) + pubkey_script
    
    # Lock time
    tx += struct.pack('<I', 0)
    
    return tx

def get_merkle_root(coinbase_tx):
    """Get merkle root for single transaction."""
    return double_sha256(coinbase_tx)

def mine_genesis():
    """Mine the stagenet genesis block."""
    
    # Stagenet parameters
    COINBASE_MSG = "Soqucoin Stagenet - Mainnet rehearsal network Jan 2026"
    TIMESTAMP = 1736107200  # 2026-01-05 12:00:00 UTC
    NBITS = 0x1e0ffff0      # Same as testnet3
    REWARD = 500000 * 100000000  # 500000 coins in satoshis
    
    # Public key script (same as testnet3)
    PUBKEY_HEX = "040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"
    pubkey_bytes = bytes.fromhex(PUBKEY_HEX)
    pubkey_script = bytes([len(pubkey_bytes)]) + pubkey_bytes + bytes([0xac])  # OP_CHECKSIG
    
    # Calculate target
    target = compact_to_target(NBITS)
    print(f"Target: {target:064x}")
    print(f"Coinbase: {COINBASE_MSG}")
    print(f"Timestamp: {TIMESTAMP}")
    print()
    
    # Create coinbase transaction
    coinbase_tx = create_coinbase_tx(COINBASE_MSG, REWARD, pubkey_script)
    merkle_root = get_merkle_root(coinbase_tx)
    
    print(f"Merkle Root: {merkle_root[::-1].hex()}")
    print()
    
    # Previous hash (all zeros for genesis)
    prev_hash = b'\x00' * 32
    
    # Mine!
    print("Mining stagenet genesis block...")
    start_time = time.time()
    nonce = 0
    
    while True:
        header = create_block_header(1, prev_hash, merkle_root, TIMESTAMP, NBITS, nonce)
        pow_hash = scrypt_hash(header)
        hash_int = uint256_from_bytes(pow_hash)
        
        if hash_int < target:
            elapsed = time.time() - start_time
            block_hash = double_sha256(header)
            
            print()
            print("=" * 60)
            print("STAGENET GENESIS MINED!")
            print("=" * 60)
            print(f"  Nonce:       {nonce}")
            print(f"  Block Hash:  {block_hash[::-1].hex()}")
            print(f"  PoW Hash:    {pow_hash[::-1].hex()}")
            print(f"  Merkle Root: {merkle_root[::-1].hex()}")
            print(f"  Time:        {elapsed:.2f} seconds")
            print()
            print("Add to chainparams.cpp:")
            print(f'  genesis = CreateGenesisBlockStagenet({TIMESTAMP}, {nonce}, 0x{NBITS:08x}, 1, 500000 * COIN);')
            print(f'  assert(consensus.hashGenesisBlock == uint256S("0x{block_hash[::-1].hex()}"));')
            print(f'  assert(genesis.hashMerkleRoot == uint256S("0x{merkle_root[::-1].hex()}"));')
            return nonce, block_hash[::-1].hex(), merkle_root[::-1].hex()
        
        nonce += 1
        if nonce % 100000 == 0:
            elapsed = time.time() - start_time
            hashrate = nonce / elapsed if elapsed > 0 else 0
            print(f"  Nonce: {nonce:,} | Hashrate: {hashrate:,.0f} H/s")
        
        if nonce >= 0xffffffff:
            print("Nonce overflow! Need to change timestamp.")
            return None

if __name__ == "__main__":
    mine_genesis()
