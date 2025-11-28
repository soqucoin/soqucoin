#!/usr/bin/env python3
"""
Simple test to verify stratum proxy can start
"""
import asyncio
import sys

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connection from {addr}", flush=True)
    
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            print(f"Received: {data.decode().strip()}", flush=True)
            writer.write(b'{"id":1,"result":true,"error":null}\n')
            await writer.drain()
    except Exception as e:
        print(f"Error: {e}", flush=True)
    finally:
        writer.close()
        print(f"Closed connection from {addr}", flush=True)

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 3333)
    print(f"Test server listening on port 3333", flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped", flush=True)
        sys.exit(0)
