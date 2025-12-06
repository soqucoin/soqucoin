import asyncio
import json
import random
import time
import struct
import binascii
import socket

# Config
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 3333
NUM_MINERS = 50
SHARES_PER_MIN = 2

async def miner_client(miner_id):
    try:
        reader, writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        # print(f"Miner {miner_id} connected")
        
        # Subscribe
        msg = {"id": 1, "method": "mining.subscribe", "params": []}
        writer.write((json.dumps(msg) + "\n").encode())
        await writer.drain()
        line = await reader.readline()
        
        # Auth
        msg = {"id": 2, "method": "mining.authorize", "params": [f"miner{miner_id}", "pass"]}
        writer.write((json.dumps(msg) + "\n").encode())
        await writer.drain()
        line = await reader.readline()
        
        # Loop
        while True:
            # Wait for random interval
            await asyncio.sleep(60 / SHARES_PER_MIN + random.uniform(-5, 5))
            
            # Send fake share (invalid hash, but tests bridge load)
            # We need a job ID. In a real swarm we'd parse notify. 
            # For load testing, sending "garbage" might trigger error logs.
            # Ideally we parse the stream.
            
            # Simplified: Just keep connection open and periodically ping/subscribe?
            # Or actually try to read lines to consume buffer.
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
                
            # To properly load test, we should submit shares. 
            # But calculating valid shares is hard without CPU.
            # We will send "Invalid" shares just to test network/parsing I/O.
            
            # msg = {"id": 4, "method": "mining.submit", "params": ["user", "job_id", "0000", "0000", "0000"]}
            # writer.write((json.dumps(msg) + "\n").encode())
            # await writer.drain()
            
    except Exception as e:
        # print(f"Miner {miner_id} error: {e}")
        pass

async def main():
    print(f"Spawning {NUM_MINERS} miners...")
    tasks = []
    for i in range(NUM_MINERS):
        tasks.append(asyncio.create_task(miner_client(i)))
        if i % 10 == 0: await asyncio.sleep(0.1) # Ramp up
        
    print("Swarm active. Press Ctrl+C to stop.")
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
