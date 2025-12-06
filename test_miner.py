
import socket
import json
import struct
import hashlib
import binascii
import time

def hex_to_bytes(h):
    return binascii.unhexlify(h)

def bytes_to_hex(b):
    return binascii.hexlify(b).decode('utf-8')

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 3333))

# Subscribe
msg = {"id": 1, "method": "mining.subscribe", "params": []}
s.sendall((json.dumps(msg) + "\n").encode())
print("Sent Subscribe")
resp_str = s.recv(4096).decode()
print(f"Resp: {resp_str}")
resp = json.loads(resp_str)
extranonce1 = resp['result'][1]
en2_size = resp['result'][2]

# Authorize
msg = {"id": 2, "method": "mining.authorize", "params": ["user", "pass"]}
s.sendall((json.dumps(msg) + "\n").encode())
print("Sent Auth")
resp = s.recv(4096).decode()
print(f"Resp: {resp}")

# Wait for Job
while True:
    try:
        data = s.recv(4096).decode()
        for line in data.split('\n'):
            if not line: continue
            try:
                req = json.loads(line)
            except:
                continue
                
            if req.get('method') == 'mining.notify':
                print("Got Job!")
                job = req['params']
                # params: [job_id, prevhash_be, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean]
                job_id = job[0]
                prevhash_hex = job[1]
                coinb1 = job[2]
                coinb2 = job[3]
                merkle_branch = job[4]
                version = job[5]
                nbits = job[6]
                ntime = job[7]
                
                # Construct fake share
                en2 = "00000000"
                nonce = "00000001"
                
                # --- CALCULATE EXPECTED HASH ---
                coinbase_hex = coinb1 + extranonce1 + en2 + coinb2
                coinbase_bin = hex_to_bytes(coinbase_hex)
                coinbase_hash = sha256d(coinbase_bin)
                
                merkle_root = coinbase_hash
                for branch_hash_hex in merkle_branch:
                    branch_hash = hex_to_bytes(branch_hash_hex)
                    merkle_root = sha256d(merkle_root + branch_hash)
                    
                # Header Construction
                # Version (LE)
                version_bin = hex_to_bytes(version) # This was struct.pack(">I") from bridge
                # Bridge sends BE. L7 receives BE.
                # L7 treats as BE word? Serializes as LE? 
                # Standard Stratum: version is BE hex string. Miner byte-swaps to LE for hashing.
                version_le = version_bin[::-1]
                
                prevhash_bin = hex_to_bytes(prevhash_hex) # Bridge sends BE.
                prevhash_le = prevhash_bin[::-1]
                
                merkle_root_le = merkle_root # Already LE
                
                ntime_bin = hex_to_bytes(ntime) # Bridge sends BE.
                ntime_le = ntime_bin[::-1]
                
                nbits_bin = hex_to_bytes(nbits) # Bridge sends BE string.
                nbits_le = nbits_bin[::-1]
                
                nonce_bin = hex_to_bytes(nonce)
                nonce_le = nonce_bin[::-1]
                
                header = version_le + prevhash_le + merkle_root_le + ntime_le + nbits_le + nonce_le
                header_hash = sha256d(header)
                
                print(f"Calculated Header Hash (BE): {header_hash[::-1].hex()}")
                
                # Loop submit to trigger VarDiff
                for i in range(15):
                    # Construct fake share with unique nonce
                    en2 = "00000000"
                    nonce = hex(i)[2:].zfill(8)
                    
                    # Send submit.
                    msg = {"id": 4+i, "method": "mining.submit", "params": ["user", job_id, en2, ntime, nonce]}
                    s.sendall((json.dumps(msg) + "\n").encode())
                    print(f"Sent Submit {i}")
                    time.sleep(0.2) 
                    
                print("Sleeping 32s to close window...")
                time.sleep(32)
                
                # Final triggering submit
                msg = {"id": 99, "method": "mining.submit", "params": ["user", job_id, en2, ntime, "00000099"]}
                s.sendall((json.dumps(msg) + "\n").encode())
                print("Sent Final Submit")
                
                # Read responses loop
                while True:
                    resp = s.recv(4096).decode()
                    print(f"Resp Loop: {resp}")
                    if "mining.set_difficulty" in resp:
                         print("SUCCESS: VarDiff Triggered!")
                         break
                exit()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        break
