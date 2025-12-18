#!/usr/bin/env python3
"""
Soqucoin Testnet Stratum Bridge for L7 Antminer
Translates Stratum V1 <-> Soqucoin RPC (getblocktemplate + submitblock)
Preserves Dilithium Coinbase Outputs
Tracks miner statistics for leaderboard
"""

import asyncio
import json
import time
import binascii
import struct
import urllib.request
import base64
import logging
import hashlib
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# --- CONFIGURATION ---
# Default to Docker-friendly defaults or localhost fallback
RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:18332") 
RPC_USER = os.getenv("RPC_USER", "soqu")
RPC_PASS = os.getenv("RPC_PASS", "change_this_password_in_production")

STRATUM_HOST = "0.0.0.0"
STRATUM_PORT = 3333
STATS_PORT = 8080
STATS_FILE = os.getenv("STATS_FILE", "/data/miner_stats.json")

# VarDiff Configuration
INITIAL_DIFFICULTY = 32 # Start low for Goldshell stability. L7 will scale up.
MIN_VARDIFF = 64
MAX_VARDIFF = 65536
TARGET_SPM = 4       # Shares per minute
RETARGET_WINDOW = 30 # Seconds

LOG_LEVEL = logging.INFO

# ---------------------

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("Bridge")


class MinerStats:
    """Track per-worker mining statistics with JSON persistence"""
    
    def __init__(self, stats_file=STATS_FILE):
        self.stats_file = stats_file
        self.stats = {}
        self.block_height = 0
        self.network_hashrate = 0.0
        self.lock = threading.Lock()
        self._load()
    
    def _load(self):
        """Load existing stats from file"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    data = json.load(f)
                    # Handle both old format (miners as list) and new format (miners as dict)
                    miners_data = data.get('miners', {})
                    if isinstance(miners_data, list):
                        # Convert list format back to dict format
                        self.stats = {}
                        for miner in miners_data:
                            worker = miner.get('worker', 'unknown')
                            self.stats[worker] = {
                                "total_shares": miner.get('shares', 0),
                                "blocks_found": miner.get('blocks', 0),
                                "first_seen": miner.get('first_seen', ''),
                                "last_seen": miner.get('last_seen', ''),
                                "hashrate_mhs": miner.get('hashrate_mhs', 0.0)
                            }
                        logger.info(f"Converted stats for {len(self.stats)} miners from list format")
                    elif isinstance(miners_data, dict):
                        self.stats = miners_data
                        logger.info(f"Loaded stats for {len(self.stats)} miners")
                    else:
                        logger.warning(f"Unexpected miners format: {type(miners_data)}")
                        self.stats = {}
        except Exception as e:
            logger.warning(f"Could not load stats: {e}")
            self.stats = {}
    
    def _save(self):
        """Persist stats to JSON file (saves internal format for reload)"""
        try:
            os.makedirs(os.path.dirname(self.stats_file) or '.', exist_ok=True)
            # Save internal format (dict) for proper reloading
            save_data = {
                "block_height": self.block_height,
                "network_hashrate": self.network_hashrate,
                "miners": self.stats,  # Save as dict, not list!
                "updated": datetime.utcnow().isoformat() + "Z"
            }
            with open(self.stats_file, 'w') as f:
                json.dump(save_data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save stats: {e}")
    
    def record_share(self, worker_name, is_block=False):
        """Record a successful share submission"""
        with self.lock:
            now = datetime.utcnow().isoformat() + "Z"
            if worker_name not in self.stats:
                self.stats[worker_name] = {
                    "total_shares": 0,
                    "blocks_found": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "hashrate_mhs": 0.0
                }
            
            self.stats[worker_name]["total_shares"] += 1
            self.stats[worker_name]["last_seen"] = now
            
            if is_block:
                self.stats[worker_name]["blocks_found"] += 1
                logger.info(f"🏆 Block found by {worker_name}! Total: {self.stats[worker_name]['blocks_found']}")
            
            self._save()
    
    def update_hashrate(self, worker_name, hashrate_mhs):
        """Update estimated hashrate for a worker"""
        with self.lock:
            if worker_name in self.stats:
                self.stats[worker_name]["hashrate_mhs"] = round(hashrate_mhs, 2)
    
    def update_network_info(self, block_height, network_hashrate):
        """Update network-level info"""
        with self.lock:
            self.block_height = block_height
            self.network_hashrate = network_hashrate
    
    def _get_export_data(self):
        """Get data for JSON export"""
        miners_list = []
        for worker, data in self.stats.items():
            miners_list.append({
                "worker": worker,
                "shares": data["total_shares"],
                "blocks": data["blocks_found"],
                "hashrate_mhs": data["hashrate_mhs"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"]
            })
        
        # Sort by blocks found, then shares
        miners_list.sort(key=lambda x: (-x["blocks"], -x["shares"]))
        
        # Calculate pool hashrate as sum of all miners
        pool_hashrate_mhs = sum(data.get("hashrate_mhs", 0) for data in self.stats.values())
        
        return {
            "block_height": self.block_height,
            "network_hashrate_ths": round(self.network_hashrate / 1000, 2),
            "pool_hashrate_ths": round(pool_hashrate_mhs / 1000000, 4),  # MH/s to TH/s
            "total_miners": len(self.stats),
            "total_blocks": self.block_height,
            "miners": miners_list,
            "updated": datetime.utcnow().isoformat() + "Z"
        }
    
    def get_stats_json(self):
        """Get JSON string for HTTP response"""
        with self.lock:
            return json.dumps(self._get_export_data(), indent=2)


# Global miner stats instance
miner_stats = MinerStats()


class StatsRequestHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to serve stats.json"""
    
    def do_GET(self):
        if self.path == '/stats.json' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS for static site
            self.end_headers()
            self.wfile.write(miner_stats.get_stats_json().encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


def run_stats_server():
    """Run HTTP stats server in background thread"""
    server = HTTPServer(('0.0.0.0', STATS_PORT), StatsRequestHandler)
    logger.info(f"Stats HTTP server listening on port {STATS_PORT}")
    server.serve_forever()


def hex_to_bytes(h):
    return binascii.unhexlify(h)

def bytes_to_hex(b):
    return binascii.hexlify(b).decode('utf-8')

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def reverse_bytes(h):
    return h[::-1]

def swap_endian_words(h):
    """Reverse each 4-byte word in a 32-byte hash (Stratum prevhash encoding)"""
    result = b''
    for i in range(0, len(h), 4):
        result += h[i:i+4][::-1]
    return result

class Buffer:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n):
        if self.pos + n > len(self.data):
            raise IndexError("Read past end of buffer")
        res = self.data[self.pos:self.pos+n]
        self.pos += n
        return res

    def read_varint(self):
        n = 0
        while True:
            b = self.read(1)[0]
            if b < 0xfd:
                return b
            elif b == 0xfd:
                return struct.unpack("<H", self.read(2))[0]
            elif b == 0xfe:
                return struct.unpack("<I", self.read(4))[0]
            elif b == 0xff:
                return struct.unpack("<Q", self.read(8))[0]

class StratumBridge:
    def __init__(self):
        self.clients = {}
        self.job_counter = 0
        self.jobs = {} # Keep history for lookups
        self.current_template = None
        self.current_job = None  # Current job for mining.notify
        self.extranonce1_counter = 0

    async def rpc_request(self, method, params=[]):
        def do_request():
            payload = json.dumps({
                "jsonrpc": "1.0",
                "id": "bridge",
                "method": method,
                "params": params
            }).encode()
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Basic " + base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
            }
            
            req = urllib.request.Request(RPC_URL, data=payload, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    return json.loads(response.read().decode())
            except Exception as e:
                logger.error(f"RPC Connection Error: {e}")
                return None

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, do_request)

    def pack_varint(self, n):
        if n < 0xfd:
            return struct.pack("B", n)
        elif n <= 0xffff:
            return b'\xfd' + struct.pack("<H", n)
        elif n <= 0xffffffff:
            return b'\xfe' + struct.pack("<I", n)
        else:
            return b'\xff' + struct.pack("<Q", n)

    async def update_template(self):
        """Fetch gbt and update current job"""
        try:
            resp = await self.rpc_request("getblocktemplate", [{"rules": ["segwit", "csv", "segwit"], "capabilities": ["coinbasetxn", "workid", "coinbase/append"]}]) 
            if not resp or resp.get('error'):
                logger.warning(f"GetBlockTemplate failed: {resp.get('error') if resp else 'No response'}")
                return

            tpl = resp['result']
            
            # Update network stats - fetch network hashrate
            height = tpl.get('height', 0)
            try:
                mining_info = await self.rpc_request("getmininginfo", [])
                if mining_info and mining_info.get('result'):
                    # networkhashps is in H/s, convert to MH/s
                    net_hashrate_mhs = mining_info['result'].get('networkhashps', 0) / 1_000_000
                    miner_stats.update_network_info(height, net_hashrate_mhs)
                else:
                    miner_stats.update_network_info(height, 0)
            except:
                miner_stats.update_network_info(height, 0)
            
            # --- Transaction Parsing to preserve Outputs ---
            if 'coinbasetxn' not in tpl:
                logger.error("Template Update Error: 'coinbasetxn' missing.")
                return

            cbtxn_hex = tpl['coinbasetxn']['data']
            buf = Buffer(hex_to_bytes(cbtxn_hex))
            
            tx_version = buf.read(4)  # TX version (usually 01000000 or 02000000)
            
            # Check for SegWit marker (0x00 0x01) after version
            marker = buf.read(1)[0]
            if marker == 0x00:
                flag = buf.read(1)[0]  # Should be 0x01
                if flag != 0x01:
                    logger.warning(f"Unexpected SegWit flag: {flag}")
                vin_count = buf.read_varint()
                is_segwit = True
            else:
                # Not SegWit, marker byte was actually vin_count
                vin_count = marker if marker < 0xfd else buf.read_varint()
                is_segwit = False
            
            # Skip input (coinbase has 1 input)
            buf.read(32)  # PrevHash (all zeros for coinbase)
            buf.read(4)   # PrevIndex (0xffffffff for coinbase)
            orig_script_len = buf.read_varint()
            buf.read(orig_script_len)  # Original scriptSig
            buf.read(4)   # Sequence
            
            # Read outputs - capture the raw bytes
            vout_count = buf.read_varint()
            outputs_data = self.pack_varint(vout_count)
            for _ in range(vout_count):
                value = buf.read(8)
                spk_len = buf.read_varint()
                spk = buf.read(spk_len)
                outputs_data += value + self.pack_varint(spk_len) + spk
            
            # Skip witness data if SegWit
            if is_segwit:
                for _ in range(vin_count):
                    witness_count = buf.read_varint()
                    for _ in range(witness_count):
                        witness_len = buf.read_varint()
                        buf.read(witness_len)
            
            locktime = buf.read(4)
            
            # Construct vouts_and_locktime (outputs + locktime, no witness)
            vouts_and_locktime = outputs_data + locktime
            
            # --- Construct custom coinbases for Stratum ---
            height = tpl['height']
            height_bytes = b''
            temp_h = height
            while temp_h > 0:
                height_bytes += struct.pack("B", temp_h & 0xff)
                temp_h >>= 8
            if not height_bytes:  # Height 0 edge case
                height_bytes = b'\x00'
            
            height_push = struct.pack("B", len(height_bytes)) + height_bytes
            
            # CoinB1 = Version + VinCount + PrevHash + PrevIdx + ScriptLen + HeightPush
            # CoinB2 = Sequence + Outputs + Locktime
            # Script = HeightPush + EN1(4) + EN2(4)
            script_sig_len = len(height_push) + 8
            coinb1 = tx_version + self.pack_varint(vin_count) + (b'\x00'*32) + (b'\xff'*4) + self.pack_varint(script_sig_len) + height_push
            coinb2 = b'\xff\xff\xff\xff' + vouts_and_locktime

            # ---------------------------------------------

            job_id = hex(self.job_counter)[2:]
            self.job_counter += 1
            
            self.jobs[job_id] = {
                "job_id": job_id,
                "prevhash_be": bytes_to_hex(swap_endian_words(hex_to_bytes(tpl['previousblockhash'])[::-1])),  # Word-swapped LE for ASIC
                "coinb1": bytes_to_hex(coinb1),
                "coinb2": bytes_to_hex(coinb2),
                "merkle_branch": [], 
                "version": bytes_to_hex(struct.pack(">I", tpl['version'])),  # Standard Stratum: BE
                "nbits": tpl['bits'],  # RPC gives BE hex string
                "ntime": bytes_to_hex(struct.pack(">I", tpl['curtime'])),  # Standard Stratum: BE
                "clean": True,
                "tx_hashes": [t['hash'] for t in tpl['transactions']],
                "orig_txs": tpl['transactions']
            }
            
            self.jobs[job_id]['merkle_branch'] = self.build_merkle_branch(self.jobs[job_id]['tx_hashes'])
            self.current_job = self.jobs[job_id]
            
            logger.info(f"New Job {job_id}: Height {height}, Vouts preserved (Dilithium)")
            await self.broadcast_job(self.current_job)

        except Exception as e:
            logger.error(f"Template Update Error: {e}")

    def build_merkle_branch(self, tx_hashes):
        branch = []
        hashes = [hex_to_bytes(h) for h in tx_hashes]
        # We need to hash the coinbase placeholder?
        # Standard: the coinbase hash is NOT in tx_hashes here.
        # But for merkle branch construction, we assume coinbase is at index 0.
        # Stratum sends the branch (path) to root.
        # If no other txs, branch is empty.
        
        # If there are transactions:
        # The miner provides coinbase.
        # The bridge provides the hashes of the siblings on the path up.
        
        # We need a merkle tree calculator.
        return [bytes_to_hex(h) for h in self._calc_merkle_branch(hashes)]

    def _calc_merkle_branch(self, tx_hashes):
        # Classic bitcoin merkle branch (as needed by Stratum)
        # Input: list of REVERSED (internal LE) hashes of transactions (excluding coinbase)
        # Wait, getblocktemplate returns txid/hash in RPC byte order (Big Endian hex).
        # We need them in Little Endian (internal) for hashing.
        
        # Actually Stratum merkle branch entries are LE hex (double hash result).
        
        if not tx_hashes:
            return []
            
        # Recursive build? Or just path for index 0?
        # We just need the path for index 0 (Coinbase).
        branch = []
        current_level = [reverse_bytes(h) for h in tx_hashes] # Convert BE to LE
        
        # Insert placeholder for coinbase at start?
        # The caller (miner) starts with Hash(Coinbase).
        # Then pairs with Hash(Tx1).
        
        # So we need to compute the full tree but only keep the siblings of the path from 0.
        
        # Wait, getblocktemplate txs exclude coinbase.
        # So current_level is Tx1, Tx2, Tx3...
        # We are at leaf level.
        # We need to provide the sibling of Coinbase. That is Hash(Tx1).
        # Then Hash(Hash(Tx2) + Hash(Tx3)) ...
        
        # Correct algorithm:
        # Prepend Dummy to represent Coinbase? No, we don't know coinbase yet.
        # We calculate the branch relative to index 0.
        
        # Level 0 (Leaves): [Coinbase (Unknown), Tx1, Tx2, Tx3]
        # We need Tx1.
        # Then we hash pairwise.
        
        import math
        
        # We iterate up.
        # Current list is just Txs (excluding coinbase).
        # We keep track of the "match" index (initially 0).
        
        # Actually, let's treat the list as [Placeholder, Tx1, Tx2...]
        # But we don't know placeholder.
        # We just need the sibling hash at each step.
        
        hashes = [b'\x00'*32] + current_level # Placeholder at 0
        
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1]) # Duplicate last if odd
                
            # For the node at index 0 (our path), the sibling is index 1.
            branch.append(hashes[1])
            
            new_level = []
            for i in range(0, len(hashes), 2):
                # Hash(Left + Right)
                joined = hashes[i] + hashes[i+1]
                new_level.append(sha256d(joined))
            hashes = new_level
            
        return branch


    async def broadcast_job(self, job):
        params = [
            job["job_id"],
            job["prevhash_be"], 
            job["coinb1"],
            job["coinb2"],
            job["merkle_branch"],
            job["version"],
            job["nbits"],
            job["ntime"],
            job["clean"]
        ]
        msg = {"id": None, "method": "mining.notify", "params": params}
        serialized = json.dumps(msg) + "\n"
        for client in self.clients.values():
            writer = client['writer']
            try:
                writer.write(serialized.encode())
                await writer.drain()
            except:
                pass

    def adjust_difficulty(self, client_id):
        if client_id not in self.clients: return
        client = self.clients[client_id]
        
        client['shares_in_window'] += 1
        now = time.time()
        elapsed = now - client['window_start']
        
        if elapsed >= RETARGET_WINDOW:
            # Calculate SPM (Shares Per Minute)
            # Avoid division by zero
            if elapsed < 1: elapsed = 1
            spm = client['shares_in_window'] / (elapsed / 60.0)
            
            old_diff = client['difficulty']
            new_diff = old_diff
            
            if spm > (TARGET_SPM * 2): # > 8
                new_diff *= 2
            elif spm < (TARGET_SPM / 2): # < 2
                new_diff /= 2
                
            # Clamp
            new_diff = max(MIN_VARDIFF, min(MAX_VARDIFF, new_diff))
            
            if new_diff != old_diff:
                client['difficulty'] = int(new_diff)
                logger.info(f"VarDiff: Retargeting {client['addr']} to {new_diff} (SPM: {spm:.2f})")
                try:
                    msg = {"id": None, "method": "mining.set_difficulty", "params": [new_diff]}
                    client['writer'].write((json.dumps(msg) + "\n").encode())
                except:
                    pass
            
            # Reset window
            client['shares_in_window'] = 0
            client['window_start'] = now
            
            # Calculate and update hashrate for this worker
            # Standard formula: hashrate = difficulty * 2^32 / time_per_share
            # For Scrypt pools: difficulty is scaled by 2^16, so use 2^16 = 65536
            # hashrate_MH/s = difficulty * 65536 / seconds_per_share / 1,000,000
            #               = difficulty * 0.065536 / seconds_per_share
            worker_name = client.get('worker_name')
            if worker_name and spm > 0:
                seconds_per_share = 60.0 / spm
                hashrate_mhs = (client['difficulty'] * 0.065536) / seconds_per_share
                miner_stats.update_hashrate(worker_name, hashrate_mhs)

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"Client connected: {addr}")
        
        self.extranonce1_counter += 1
        client_id = self.extranonce1_counter
        self.clients[client_id] = {
            'writer': writer,
            'difficulty': INITIAL_DIFFICULTY,
            'window_start': time.time(),
            'shares_in_window': 0,
            'addr': addr,
            'worker_name': None  # Set on authorize
        }
        
        extranonce1 = struct.pack(">I", client_id).hex() 
        extranonce1_bin = struct.pack(">I", client_id)
        
        try:
            while True:
                data = await reader.readline()
                if not data: break
                
                req = json.loads(data.decode())
                mid = req.get('id')
                method = req.get('method')
                
                if method == "mining.subscribe":
                    # Standard Stratum response
                    res = [[["mining.set_difficulty", "1"], ["mining.notify", "1"]], extranonce1, 4]
                    resp = {"id": mid, "result": res, "error": None}
                    writer.write((json.dumps(resp) + "\n").encode())
                    await writer.drain()
                    
                    
                    # Send initial difficulty
                    diff_msg = {"id": None, "method": "mining.set_difficulty", "params": [float(self.clients[client_id]['difficulty'])]}
                    writer.write((json.dumps(diff_msg) + "\n").encode())
                    await writer.drain()
                    await asyncio.sleep(0.5)
                    
                    if self.current_job:
                        j = self.current_job
                        p = [j["job_id"], j["prevhash_be"], j["coinb1"], j["coinb2"], j["merkle_branch"], j["version"], j["nbits"], j["ntime"], j["clean"]]
                        n_msg = {"id": None, "method": "mining.notify", "params": p}
                        writer.write((json.dumps(n_msg) + "\n").encode())
                        await writer.drain()
                        
                elif method == "mining.authorize":
                    # Capture worker name for stats tracking
                    worker_name = req['params'][0] if req.get('params') else 'unknown'
                    self.clients[client_id]['worker_name'] = worker_name
                    logger.info(f"Authorized worker: {worker_name}")
                    resp = {"id": mid, "result": True, "error": None}
                    writer.write((json.dumps(resp) + "\n").encode())
                    await writer.drain()
                    
                elif method == "mining.submit":
                    logger.info(f"Received submit from {addr}")
                    # params: [worker_name, job_id, extranonce2, ntime, nonce]
                    worker = req['params'][0]
                    job_id = req['params'][1]
                    en2_hex = req['params'][2]
                    ntime_hex = req['params'][3]
                    nonce_hex = req['params'][4]
                    
                    if job_id not in self.jobs:
                        logger.warning(f"Share for unknown job {job_id}")
                        resp = {"id": mid, "result": False, "error": [21, "Job not found", None]}
                        writer.write((json.dumps(resp) + "\n").encode())
                        continue

                    job = self.jobs[job_id]
                    
                    # 1. Reconstruct Coinbase
                    # coinb1 (hex) + en1 (hex) + en2 (hex) + coinb2 (hex)

                    coinbase_hex = job['coinb1'] + extranonce1 + en2_hex + job['coinb2']
                    coinbase_bin = hex_to_bytes(coinbase_hex)
                    coinbase_hash = sha256d(coinbase_bin) # This is LE
                    
                    # 2. Calculate Merkle Root
                    merkle_root = coinbase_hash
                    for branch_hash_hex in job['merkle_branch']:
                        branch_hash = hex_to_bytes(branch_hash_hex)
                        # Hash(Root + Branch)
                        merkle_root = sha256d(merkle_root + branch_hash)
                        
                    # 3. Construct Block Header
                    # Version (4) + PrevHash (32) + MerkleRoot (32) + NTime (4) + NBits (4) + Nonce (4)
                    # Note: Stratum fields are usually Big Endian hex which need to be swapped?
                    # job['prevhash_be'] is BE. We need LE for hashing/serialization in block.
                    # Ntime/Nonce are provided as BE hex string effectively? 
                    # Usually Stratum sends them as big-endian hex strings but they represent numbers.
                    # Bitcoin headers Use Little Endian.
                    
                    version_bin = hex_to_bytes(job['version']) # Sent as BE
                    version_le = version_bin[::-1]  # Reverse to LE for header
                    
                    prevhash_bin = hex_to_bytes(job['prevhash_be']) # Sent as Word-Swapped LE
                    # Miner receives word-swapped LE, but soqucoind needs plain LE
                    # Un-swap the words to get back to plain LE format
                    prevhash_le = swap_endian_words(prevhash_bin)
                    
                    # Standard Stratum: Miner receives BE/WordSwap. We reconstruct LE/Plain.
                    
                    ntime_bin = hex_to_bytes(ntime_hex)
                    # Miner received BE. Returns BE. We reverse to LE.
                    ntime_le = ntime_bin[::-1]
                    
                    nonce_bin = hex_to_bytes(nonce_hex)
                    # Miner sent BE string. We reverse to LE.
                    nonce_le = nonce_bin[::-1]
                    
                    merkle_root_le = merkle_root # Already LE from sha256d
                    # Debug logging removed for cleanliness
                    # logger.info(f"debug: version_le=... prevhash_le=...")
                    
                    nbits_bin = hex_to_bytes(job['nbits']) # Sent as BE
                    nbits_le = nbits_bin[::-1] # Reverse to LE
                    
                    header = version_le + prevhash_le + merkle_root_le + ntime_le + nbits_le + nonce_le
                    header_hash = sha256d(header)
                    
                    # Log once
                    # logger.info(f"debug: Header Hash: {header_hash.hex()}")

                    submission_hex = (
                        bytes_to_hex(header) +
                        self.pack_varint(len(job['orig_txs']) + 1).hex() + 
                        coinbase_hex + 
                        "".join(tx['data'] for tx in job['orig_txs'])
                    )
                    
                    logger.info(f"Submitting Block: {submission_hex[:64]}...")
                    try:
                        res = await self.rpc_request("submitblock", [submission_hex])
                        
                        # Debug: Log the raw RPC response type and content
                        logger.debug(f"SubmitBlock RPC Response: type={type(res)}, value={res}")
                        
                        # Handle connection failures (None returned from rpc_request)
                        if res is None:
                            logger.error("SubmitBlock RPC Connection Failed")
                            writer.write((json.dumps({"id": mid, "result": False, "error": [20, "RPC Connection Failed", None]}) + "\n").encode())
                            await writer.drain()
                            continue
                        
                        # Defensive type check - res should be a dict
                        if not isinstance(res, dict):
                            logger.error(f"Unexpected RPC response type: {type(res)} - {res}")
                            writer.write((json.dumps({"id": mid, "result": False, "error": [20, f"Unexpected response: {res}", None]}) + "\n").encode())
                            await writer.drain()
                            continue
                        
                        # Check for RPC-level error
                        rpc_error = res.get('error')
                        if rpc_error:
                            error_msg = str(rpc_error.get('message', rpc_error)) if isinstance(rpc_error, dict) else str(rpc_error)
                            logger.info(f"Block Rejected (RPC error): {error_msg}")
                            writer.write((json.dumps({"id": mid, "result": False, "error": [20, error_msg, None]}) + "\n").encode())
                            await writer.drain()
                            continue
                        
                        # Get the result value
                        result_val = res.get('result')
                        success = False
                        
                        # submitblock returns NULL (None) on success
                        if result_val is None:
                            logger.info(f"🎉 Block Accepted! hash={sha256d(header).hex()}")
                            writer.write((json.dumps({"id": mid, "result": True, "error": None}) + "\n").encode())
                            success = True
                            miner_stats.record_share(worker, is_block=True)
                        elif result_val == 'inconclusive':
                            logger.info(f"Block Accepted (inconclusive)! hash={sha256d(header).hex()}")
                            writer.write((json.dumps({"id": mid, "result": True, "error": None}) + "\n").encode())
                            success = True
                            miner_stats.record_share(worker, is_block=True)
                        elif result_val == 'high-hash':
                            # Share meets pool difficulty but not network difficulty
                            # This is normal operation - these are valid shares
                            logger.info(f"Share Accepted (pool diff met, net diff not met)")
                            writer.write((json.dumps({"id": mid, "result": True, "error": None}) + "\n").encode())
                            success = True
                            miner_stats.record_share(worker, is_block=False)
                        elif isinstance(result_val, str):
                            # Other rejection reasons (duplicate, bad-*, etc.)
                            logger.warning(f"Block Rejected: {result_val}")
                            writer.write((json.dumps({"id": mid, "result": False, "error": [20, result_val, None]}) + "\n").encode())
                        else:
                            # Unexpected result type
                            logger.error(f"Unexpected result type: {type(result_val)} - {result_val}")
                            writer.write((json.dumps({"id": mid, "result": False, "error": [20, f"Unexpected: {result_val}", None]}) + "\n").encode())
                        
                        await writer.drain()
                        
                        if success:
                            self.adjust_difficulty(client_id)

                    except Exception as e:
                        logger.error(f"SubmitBlock Exception: {e}")
                        import traceback
                        traceback.print_exc()
                        try:
                            writer.write((json.dumps({"id": mid, "result": False, "error": [20, str(e), None]}) + "\n").encode())
                            await writer.drain()
                        except:
                            pass
                    
                else: 
                     logger.warning(f"Unknown method: {method}")

        except Exception as e:
            logger.error(f"Client error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            logger.info(f"Client disconnected: {addr}")

    async def poller(self):
        last_heartbeat = time.time()
        while True:
            await self.update_template()
            
            # Heatbeat every 60s
            now = time.time()
            if now - last_heartbeat > 60:
                client_count = len(self.clients)
                # Calculate average difficulty?
                # or just list active clients
                logger.info(f"❤️ Heartbeat: {client_count} Clients Connected. Job: {self.job_counter}")
                last_heartbeat = now
                
            await asyncio.sleep(1)

async def main():
    # Start HTTP stats server in background thread
    stats_thread = threading.Thread(target=run_stats_server, daemon=True)
    stats_thread.start()
    
    bridge = StratumBridge()
    server = await asyncio.start_server(bridge.handle_client, STRATUM_HOST, STRATUM_PORT)
    logger.info(f"Stratum Bridge listening on {STRATUM_HOST}:{STRATUM_PORT}")
    
    asyncio.create_task(bridge.poller())
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
