#!/usr/bin/env python3
"""
Antminer L7 Stratum Proxy for Soqucoin
Optimized for cgminer/4.12.1 protocol with high-rate share handling
"""

import asyncio
import json
import hashlib
import struct
import time
import binascii
import base64
from http.client import HTTPConnection
from collections import deque

# Configuration
STRATUM_HOST = '0.0.0.0'
STRATUM_PORT = 3333
RPC_HOST = '127.0.0.1'
RPC_PORT = 18443  # Regtest default
RPC_USER = 'miner'
RPC_PASS = 'soqu'
DIFFICULTY = 16  # Low difficulty for regtest
WORK_PUSH_INTERVAL = 10  # seconds
SHARE_BATCH_INTERVAL = 0.1  # 100ms batch processing
DEBUG = True

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

class StratumL7Proxy:
    def __init__(self):
        self.clients = []
        self.job_counter = 0
        self.share_queue = deque()
        self.current_template = None
        
    def rpc_call(self, method, params=[]):
        """Make RPC call to Soqucoin node"""
        try:
            conn = HTTPConnection(RPC_HOST, RPC_PORT, timeout=30)
            
            auth = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
            
            payload = json.dumps({
                'jsonrpc': '1.0',
                'id': 'l7proxy',
                'method': method,
                'params': params
            })
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Basic {auth}'
            }
            
            conn.request('POST', '/', payload, headers)
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            conn.close()
            
            if 'result' in data:
                return data['result']
            else:
                if DEBUG:
                    log(f"[RPC ERROR] {data.get('error')}")
                return None
                
        except Exception as e:
            log(f"[RPC FAIL] {e}")
            return None
    
    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        log(f"[L7 CONNECT] {addr}")
        
        client = {
            'reader': reader,
            'writer': writer,
            'addr': addr,
            'subscribed': False,
            'authorized': False,
            'extranonce1': f"{len(self.clients):08x}",
            'worker': 'unknown'
        }
        self.clients.append(client)
        
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                
                try:
                    msg = data.decode().strip()
                    if not msg:
                        continue
                        
                    request = json.loads(msg)
                    response = await self.process_request(request, client)
                    
                    if response:
                        writer.write((json.dumps(response) + '\n').encode())
                        await writer.drain()
                        
                except json.JSONDecodeError as e:
                    if DEBUG:
                        log(f"[JSON ERR] {addr}: {e}")
                except Exception as e:
                    log(f"[REQ ERR] {addr}: {e}")
                    
        except Exception as e:
            log(f"[L7 DISCONNECT] {addr}: reason={e}")
        finally:
            self.clients.remove(client)
            writer.close()
            await writer.wait_closed()
            log(f"[L7 CLOSED] {addr}")
    
    async def process_request(self, req, client):
        method = req.get('method')
        params = req.get('params', [])
        req_id = req.get('id')
        
        if DEBUG:
            log(f"[<] {client['addr']}: {method}")
        
        if method == 'mining.subscribe':
            client['subscribed'] = True
            miner_ua = params[0] if params else 'cgminer/4.12.1'
            
            log(f"[L7 SUBSCRIBE] {client['addr']}: {miner_ua}")
            
            # Start pushing work to this client
            asyncio.create_task(self.work_pusher(client))
            
            return {
                'id': req_id,
                'result': [
                    [["mining.set_difficulty", "1"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95c694"]],
                    client['extranonce1'],
                    4  # extranonce2_size
                ],
                'error': None
            }
        
        elif method == 'mining.authorize':
            worker = params[0] if params else 'miner'
            client['worker'] = worker
            client['authorized'] = True
            
            log(f"[L7 AUTHORIZE] {client['addr']}: worker={worker}")
            
            return {
                'id': req_id,
                'result': True,
                'error': None
            }
        
        elif method == 'mining.submit':
            # params: [worker, job_id, extranonce2, ntime, nonce]
            if len(params) >= 5:
                worker, job_id, extranonce2, ntime, nonce = params[:5]
                
                log(f"[L7 SHARE] {worker}: job={job_id}, nonce={nonce}")
                
                # Queue for batch processing
                self.share_queue.append({
                    'worker': worker,
                    'job_id': job_id,
                    'extranonce2': extranonce2,
                    'ntime': ntime,
                    'nonce': nonce,
                    'client': client
                })
                
                # Accept immediately (simplified - real impl would validate)
                return {
                    'id': req_id,
                    'result': True,
                    'error': None
                }
        
        elif method == 'mining.configure':
            log(f"[L7 CONFIGURE] {client['addr']}: {params}")
            return {
                'id': req_id,
                'result': {},
                'error': None
            }
        
        return {'id': req_id, 'result': None, 'error': None}
    
    async def work_pusher(self, client):
        """Push work to L7 every WORK_PUSH_INTERVAL seconds"""
        await asyncio.sleep(1)  # Initial delay
        
        while client in self.clients:
            try:
                # Set difficulty
                diff_msg = {
                    'id': None,
                    'method': 'mining.set_difficulty',
                    'params': [DIFFICULTY]
                }
                client['writer'].write((json.dumps(diff_msg) + '\n').encode())
                await client['writer'].drain()
                
                # Send mining job
                job = self.create_mining_job()
                if job:
                    notify_msg = {
                        'id': None,
                        'method': 'mining.notify',
                        'params': job
                    }
                    client['writer'].write((json.dumps(notify_msg) + '\n').encode())
                    await client['writer'].drain()
                    
                    log(f"[L7 WORK PUSH] {client['addr']}: job={job[0]}, diff={DIFFICULTY}")
                
                await asyncio.sleep(WORK_PUSH_INTERVAL)
                
            except Exception as e:
                log(f"[WORK PUSH ERR] {client['addr']}: {e}")
                break
    
    def create_mining_job(self):
        """Create mining job from getblocktemplate"""
        try:
            # Get block template from node
            template = self.rpc_call('getblocktemplate', [{'rules': ['segwit']}])
            
            if not template:
                # Fallback: create dummy work
                log("[WARN] No template from node, using dummy work")
                job_id = f"{self.job_counter:08x}"
                self.job_counter += 1
                
                return [
                    job_id,  # job_id
                    "00" * 32,  # prevhash
                    "01000000" + "01" + "00" * 32 + "ffffffff" + "20" + "00" * 32,  # coinb1
                    "072f736c7573682f00000000",  # coinb2
                    [],  # merkle_branch
                    "20000002",  # version
                    "1e0ffff0",  # nbits
                    hex(int(time.time()))[2:],  # ntime
                    True  # clean_jobs
                ]
            
            # Construct proper job from template
            job_id = f"{self.job_counter:08x}"
            self.job_counter += 1
            self.current_template = template
            
            prevhash = template['previousblockhash'] if 'previousblockhash' in template else '00' * 32
            version = format(template['version'], '08x')
            nbits = template['bits']
            ntime = hex(template['curtime'])[2:]
            
            # Simplified coinbase (would need proper construction for production)
            coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20"
            coinb2 = "072f736c7573682f00000000"
            
            return [
                job_id,
                prevhash,
                coinb1,
                coinb2,
                [],  # merkle_branch
                version,
                nbits,
                ntime,
                True  # clean_jobs
            ]
            
        except Exception as e:
            log(f"[JOB CREATE ERR] {e}")
            return None
    
    async def share_processor(self):
        """Batch process shares every SHARE_BATCH_INTERVAL"""
        while True:
            await asyncio.sleep(SHARE_BATCH_INTERVAL)
            
            if self.share_queue:
                batch_size = len(self.share_queue)
                log(f"[SHARE BATCH] Processing {batch_size} shares")
                
                # Process up to 100 shares per batch
                for _ in range(min(100, batch_size)):
                    if self.share_queue:
                        share = self.share_queue.popleft()
                        # In production: validate and submit to node
                        # For now: just log acceptance
                        if DEBUG:
                            log(f"[SHARE OK] {share['worker']}: {share['nonce']}")

async def main():
    proxy = StratumL7Proxy()
    
    # Start share processor
    asyncio.create_task(proxy.share_processor())
    
    server = await asyncio.start_server(
        proxy.handle_client,
        STRATUM_HOST,
        STRATUM_PORT
    )
    
    addr = server.sockets[0].getsockname()
    log("=" * 60)
    log("  Soqucoin Antminer L7 Stratum Proxy")
    log("=" * 60)
    log(f"  Listening: {addr[0]}:{addr[1]}")
    log(f"  Backend: {RPC_HOST}:{RPC_PORT}")
    log(f"  Difficulty: {DIFFICULTY}")
    log(f"  Work interval: {WORK_PUSH_INTERVAL}s")
    log("=" * 60)
    log("")
    log("L7 Configuration:")
    log(f"  URL:  stratum+tcp://192.168.1.121:3333")
    log(f"  User: miner")
    log(f"  Pass: x")
    log("")
    log("[READY] Waiting for L7 connection...")
    log("=" * 60)
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("\n[SHUTDOWN] Proxy stopped")
