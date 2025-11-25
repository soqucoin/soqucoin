#!/usr/bin/env python3
"""
Minimal Stratum Mining Proxy for Soqucoin (Scrypt)
Bridges ASIC miners (Stratum) to Bitcoin Core RPC (getwork)
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
                    request = json.loads(data.decode().strip())
                    response = await self.process_request(request, client_info)
                    
                    if response:
                        writer.write((json.dumps(response) + '\n').encode())
                        await writer.drain()
                        
                except json.JSONDecodeError as e:
                    print(f"[!] Invalid JSON from {addr}: {e}")
                except Exception as e:
                    print(f"[!] Request processing error: {e}")
                    
        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
        finally:
            self.clients.remove(client_info)
            writer.close()
            await writer.wait_closed()
            print(f"[-] Connection closed: {addr}")
    
    async def process_request(self, request, client_info):
        method = request.get('method')
        params = request.get('params', [])
        req_id = request.get('id')
        
        print(f"[>] Stratum request: {method} from {client_info['addr']}")
        
        if method == 'mining.subscribe':
            client_info['subscribed'] = True
            
            # Send initial mining job after subscription
            asyncio.create_task(self.send_initial_job(client_info))
            
            return {
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
            print(f"[+] Authorized worker: {worker}")
            return {
                'id': req_id,
                'result': True,
                'error': None
            }
            
        elif method == 'mining.submit':
            # params: [worker_name, job_id, extranonce2, ntime, nonce]
            if len(params) >= 5:
                worker, job_id, extranonce2, ntime, nonce = params[:5]
                print(f"[+] ✨ Share submitted by {worker}: nonce={nonce}, ntime={ntime}")
                
                # Accept all shares for now (simplified)
                return {
                    'id': req_id,
                    'result': True,
                    'error': None
                }
            
        elif method == 'mining.get_transactions':
            return {
                'id': req_id,
                'result': [],
                'error': None
            }
            
        return {'id': req_id, 'result': None, 'error': None}
    
    async def send_initial_job(self, client_info):
        """Send initial mining job to newly subscribed client"""
        await asyncio.sleep(0.5)  # Brief delay after subscription
        
        try:
            job_id = f"{self.job_counter:08x}"
            self.job_counter += 1
            
            # Simplified: Send a basic mining.notify job
            # In production, this would fetch real work from getblocktemplate
            notify = {
                'id': None,
                'method': 'mining.notify',
                'params': [
                    job_id,                                          # job_id
                    "0000000000000000000000000000000000000000000000000000000000000000",  # prevhash
                    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008",  # coinb1
                    "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000",  # coinb2
                    [],                                              # merkle_branch
                    "20000002",                                      # version
                    "1c2ac4af",                                      # nbits
                    hex(int(time.time()))[2:],                       # ntime
                    False                                            # clean_jobs
                ]
            }
            
            client_info['writer'].write((json.dumps(notify) + '\n').encode())
            await client_info['writer'].drain()
            print(f"[*] Sent initial job {job_id} to {client_info['addr']}")
            
        except Exception as e:
            print(f"[!] Failed to send job: {e}")

async def main():
    proxy = StratumProxy()
    
    server = await asyncio.start_server(
        proxy.handle_client,
        STRATUM_HOST,
        STRATUM_PORT
    )
    
    addr = server.sockets[0].getsockname()
    print(f"""
╔══════════════════════════════════════════════════════╗
║   Soqucoin Stratum Mining Proxy v2                  ║
╚══════════════════════════════════════════════════════╝

[*] Listening on {addr[0]}:{addr[1]}
[*] Forwarding to RPC: {RPC_HOST}:{RPC_PORT}

[+] Ready for ASIC connections
[*] Configure your miner:
    URL:  stratum+tcp://192.168.1.121:3333
    User: miner
    Pass: soqu
    """)
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down proxy...")
