#!/usr/bin/env python3
"""
Stratum Mining Proxy for Soqucoin with Confidential Transactions
Bridges ASIC miners (Stratum) to Soqucoin Core RPC (getblocktemplate)
"""

import asyncio
import json
import hashlib
import struct
import time
import binascii
from http.client import HTTPConnection

# Configuration
STRATUM_HOST = '0.0.0.0'
STRATUM_PORT = 3333
RPC_HOST = '127.0.0.1'
RPC_PORT = 18443
RPC_USER = 'miner'
RPC_PASS = 'soqu'

class StratumProxy:
    def __init__(self):
        self.subscriptions = {}
        self.authorized_workers = set()
        self.current_job = None
        self.job_counter = 0
        self.clients = []
        self.jobs = {}  # Store job details for validation

    def rpc_call(self, method, params=None):
        """Simple RPC helper used throughout the proxy"""
        if params is None:
            params = []
        payload = json.dumps({"jsonrpc": "1.0", "id": "proxy", "method": method, "params": params})
        conn = HTTPConnection(RPC_HOST, RPC_PORT)
        auth = f"{RPC_USER}:{RPC_PASS}".encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + binascii.b2a_base64(auth).decode().strip()
        }
        try:
            conn.request('POST', '/', payload, headers)
            response = conn.getresponse()
            data = response.read().decode()
            conn.close()
            result = json.loads(data)
            if 'error' in result and result['error']:
                print(f"[!] RPC error {method}: {result['error']}")
                return None
            return result.get('result')
        except Exception as e:
            print(f"[!] RPC exception {method}: {e}")
            return None
        
    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"[+] New connection from {addr}")
        
        client_info = {'reader': reader, 'writer': writer, 'addr': addr, 'subscribed': False}
        self.clients.append(client_info)
        
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                    
                try:
                    message = json.loads(data.decode())
                except:
                    continue
                    
                method = message.get('method')
                params = message.get('params', [])
                req_id = message.get('id')
                
                response = None
                
                if method == 'mining.subscribe':
                    client_info['subscribed'] = True
                    
                    # Send initial mining job after subscription
                    asyncio.create_task(self.send_mining_job(client_info))
                    
                    response = {
                        'id': req_id,
                        'result': [
                            [["mining.set_difficulty", "1"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95c694"]],
                            "f8000000",  # extranonce1
                            4  # extranonce2_size
                        ],
                        'error': None
                    }
                    
                elif method == 'mining.authorize':
                    worker = params[0] if params else 'unknown'
                    self.authorized_workers.add(worker)
                    print(f"[+] ✅ Authorized worker: {worker}")
                    
                    response = {
                        'id': req_id,
                        'result': True,
                        'error': None
                    }
                    
                elif method == 'mining.submit':
                    # params: [worker_name, job_id, extranonce2, ntime, nonce]
                    if len(params) >= 5:
                        worker, job_id, extranonce2, ntime, nonce = params[:5]
                        print(f"[+] ✨ Share submitted by {worker}: job={job_id}, nonce={nonce}, ntime={ntime}")
                        
                        if getattr(self, 'use_generate', False):
                            # For regtest: use generate to mine a block instantly
                            # This simulates L7 finding blocks with confidential txs
                            
                            # Get an address
                            addr = self.rpc_call('getnewaddress')
                            if not addr:
                                print('[!] Failed to get address')
                                addr = "3QJmnh"  # fallback
                            
                            # Mine 1 block to this address (includes all pending confidential txs)
                            block_hashes = self.rpc_call('generatetoaddress', [1, addr])
                            
                            if not block_hashes:
                                print('[!] Block generation failed')
                                response = {'id': req_id, 'result': False, 'error': 'gen_failed'}
                            else:
                                block_hash = block_hashes[0] if isinstance(block_hashes, list) else block_hashes
                                
                                # Retrieve block details and verify OP_RETURN payload
                                block_info = self.rpc_call('getblock', [block_hash, 2])
                                if block_info:
                                    print(f"[+] 📦 Block {block_hash} mined (height {block_info.get('height')})")
                                    # Search for OP_RETURN in the block
                                    found_opreturn = False
                                    for tx in block_info.get('tx', []):
                                        for vout in tx.get('vout', []):
                                            if vout.get('scriptPubKey', {}).get('type') == 'nulldata':
                                                opreturn_hex = vout['scriptPubKey'].get('hex', '')
                                                print(f"[+] 🔐 OP_RETURN found ({len(opreturn_hex)} hex chars): {opreturn_hex[:64]}...")
                                                found_opreturn = True
                                                break
                                        if found_opreturn:
                                            break
                                    
                                    if not found_opreturn:
                                        print(f"[!] No OP_RETURN found in block {block_hash}")
                                
                                response = {'id': req_id, 'result': True, 'error': None}
                        else:
                            # Standard stratum behavior (placeholder)
                            response = {'id': req_id, 'result': True, 'error': None}
                    
                elif method == 'mining.get_transactions':
                    response = {
                        'id': req_id,
                        'result': [],
                        'error': None
                    }
                    
                if response:
                    writer.write((json.dumps(response) + '\n').encode())
                    await writer.drain()
                    
        except Exception as e:
            print(f"[-] Client error: {e}")
        finally:
            print(f"[-] Connection closed from {addr}")
            self.clients.remove(client_info)
            writer.close()
            
    async def send_json(self, writer, method, params):
        message = {'id': None, 'method': method, 'params': params}
        writer.write((json.dumps(message) + '\n').encode())
        await writer.drain()

    async def send_mining_job(self, client_info):
        """Send a mining job to the client"""
        # In a real pool, this would come from bitcoind getblocktemplate
        # For this test, we generate a static job that's valid for regtest
        
        job_id = hex(self.job_counter)[2:]
        self.job_counter += 1
        
        # Regtest difficulty 1 target
        # target = "000000000000000000000000000000000000000000000000000000000000ffff"
        
        # Job parameters
        prev_hash = "00" * 32
        coinbase1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
        coinbase2 = "ffffffff"
        merkle_branch = []
        version = "20000000"
        nbits = "207fffff"
        ntime = hex(int(time.time()))[2:]
        clean_jobs = True
        
        params = [
            job_id,
            prev_hash,
            coinbase1,
            coinbase2,
            merkle_branch,
            version,
            nbits,
            ntime,
            clean_jobs
        ]
        
        self.jobs[job_id] = params
        self.current_job = params
        
        await self.send_json(client_info['writer'], 'mining.notify', params)

    async def run(self):
        server = await asyncio.start_server(
            self.handle_client, STRATUM_HOST, STRATUM_PORT)
            
        print(f"[*] Stratum proxy listening on {STRATUM_HOST}:{STRATUM_PORT}")
        print(f"[*] Mode: {'Generate Fallback' if getattr(self, 'use_generate', False) else 'Standard Stratum'}")
        
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Soqucoin Stratum Proxy')
    parser.add_argument('--use-generate-fallback', action='store_true', help='Use generate RPC on share submit')
    args = parser.parse_args()
    
    proxy = StratumProxy()
    proxy.use_generate = args.use_generate_fallback
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        print("\n[*] Proxy stopped")
