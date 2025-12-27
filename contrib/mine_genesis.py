#!/usr/bin/env python3
"""
Soqucoin Genesis Block Miner
Mines a new genesis block for Testnet3 with unique Soqucoin parameters.
"""

import hashlib
import struct
import time

def sha256d(data):
    """Double SHA-256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def scrypt_hash(header):
    """
    Scrypt hash for PoW. Uses same parameters as Litecoin/Dogecoin:
    N=1024, r=1, p=1, dkLen=32
    """
    import hashlib
    try:
        # Try using hashlib's scrypt (Python 3.6+)
        return hashlib.scrypt(header, salt=header, n=1024, r=1, p=1, dklen=32)
    except AttributeError:
        # Fallback - requires pylibscrypt or similar
        raise ImportError("Python 3.6+ with scrypt support required")

def create_merkle_root(txid):
    """For genesis, merkle root = coinbase txid"""
    return txid

def serialize_coinbase_tx(timestamp_msg, reward_satoshis, pubkey_script):
    """Serialize genesis coinbase transaction"""
    tx = b''
    # Version (4 bytes, little-endian)
    tx += struct.pack('<I', 1)
    # Input count (1 byte)
    tx += b'\x01'
    # Previous output hash (32 bytes, all zeros for coinbase)
    tx += b'\x00' * 32
    # Previous output index (4 bytes, 0xffffffff for coinbase)
    tx += b'\xff\xff\xff\xff'
    # ScriptSig: height push (minimal) + timestamp message
    scriptsig = bytes([4, 0xff, 0xff, 0x00, 0x1d])  # nBits push
    scriptsig += bytes([1, 0x04])  # CScriptNum(4) push
    scriptsig += bytes([len(timestamp_msg)]) + timestamp_msg.encode('utf-8')
    tx += bytes([len(scriptsig)]) + scriptsig
    # Sequence (4 bytes)
    tx += b'\xff\xff\xff\xff'
    # Output count (1 byte)
    tx += b'\x01'
    # Value (8 bytes, little-endian)
    tx += struct.pack('<Q', reward_satoshis)
    # ScriptPubKey
    tx += bytes([len(pubkey_script)]) + pubkey_script
    # Locktime (4 bytes)
    tx += struct.pack('<I', 0)
    return tx

def serialize_block_header(version, prev_block, merkle_root, ntime, nbits, nonce):
    """Serialize 80-byte block header"""
    header = b''
    header += struct.pack('<I', version)
    header += prev_block[::-1]  # Little-endian
    header += merkle_root[::-1]  # Little-endian
    header += struct.pack('<I', ntime)
    header += struct.pack('<I', nbits)
    header += struct.pack('<I', nonce)
    return header

def check_pow(header_hash, nbits):
    """Check if hash meets difficulty target"""
    # Extract exponent and coefficient from nbits
    exp = nbits >> 24
    coef = nbits & 0x007fffff
    # Calculate target
    target = coef * (256 ** (exp - 3))
    # Compare hash (as little-endian integer) to target
    hash_int = int.from_bytes(header_hash, 'little')
    return hash_int < target

def mine_genesis():
    # ============================================
    # SOQUCOIN TESTNET3 GENESIS PARAMETERS
    # ============================================
    TIMESTAMP_MSG = "First quantum-resistant Scrypt chain - Soqucoin Testnet3 Dec 2025"
    GENESIS_TIME = int(time.time())  # Current time
    GENESIS_NBITS = 0x1e0ffff0  # Same difficulty as Dogecoin genesis
    GENESIS_VERSION = 1
    GENESIS_REWARD = 88 * 100000000  # 88 coins in satoshis
    
    # Genesis output script (P2PK to burn address - unspendable)
    # This is a standard P2PK script with a test pubkey
    PUBKEY_HEX = "040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"
    pubkey_script = bytes([len(bytes.fromhex(PUBKEY_HEX))]) + bytes.fromhex(PUBKEY_HEX) + bytes([0xac])  # OP_CHECKSIG
    
    print("=" * 60)
    print("SOQUCOIN TESTNET3 GENESIS BLOCK MINER")
    print("=" * 60)
    print(f"Timestamp: {TIMESTAMP_MSG}")
    print(f"Genesis Time: {GENESIS_TIME} ({time.ctime(GENESIS_TIME)})")
    print(f"nBits: 0x{GENESIS_NBITS:08x}")
    print(f"Reward: {GENESIS_REWARD // 100000000} SOQ")
    print()
    
    # Create coinbase transaction
    coinbase_tx = serialize_coinbase_tx(TIMESTAMP_MSG, GENESIS_REWARD, pubkey_script)
    coinbase_txid = sha256d(coinbase_tx)
    merkle_root = coinbase_txid
    
    print(f"Coinbase TXID: {coinbase_txid[::-1].hex()}")
    print(f"Merkle Root: {merkle_root[::-1].hex()}")
    print()
    print("Mining genesis block... (this may take a few minutes)")
    print()
    
    # Previous block is all zeros for genesis
    prev_block = bytes(32)
    
    # Mine!
    nonce = 0
    start_time = time.time()
    last_update = start_time
    
    while True:
        header = serialize_block_header(
            GENESIS_VERSION, prev_block, merkle_root,
            GENESIS_TIME, GENESIS_NBITS, nonce
        )
        
        header_hash = scrypt_hash(header)
        
        if check_pow(header_hash, GENESIS_NBITS):
            elapsed = time.time() - start_time
            print()
            print("=" * 60)
            print("GENESIS BLOCK FOUND!")
            print("=" * 60)
            print(f"Nonce: {nonce}")
            print(f"Block Hash: {header_hash[::-1].hex()}")
            print(f"Merkle Root: {merkle_root[::-1].hex()}")
            print(f"Time Elapsed: {elapsed:.2f} seconds")
            print()
            print("// Add to chainparams.cpp (CTestNetParams):")
            print(f'genesis = CreateGenesisBlock("{TIMESTAMP_MSG}", {GENESIS_TIME}, {nonce}, 0x1e0ffff0, 1, 88 * COIN);')
            print(f'assert(consensus.hashGenesisBlock == uint256S("0x{header_hash[::-1].hex()}"));')
            print(f'assert(genesis.hashMerkleRoot == uint256S("0x{merkle_root[::-1].hex()}"));')
            return
        
        nonce += 1
        
        # Progress update every 10 seconds
        if time.time() - last_update > 10:
            elapsed = time.time() - start_time
            rate = nonce / elapsed
            print(f"  Nonce: {nonce:,} | Rate: {rate:.0f} H/s | Elapsed: {elapsed:.0f}s")
            last_update = time.time()
        
        # Wrap nonce at 32-bit max
        if nonce >= 0xFFFFFFFF:
            print("Nonce exhausted, incrementing timestamp...")
            nonce = 0
            GENESIS_TIME += 1

if __name__ == "__main__":
    mine_genesis()
