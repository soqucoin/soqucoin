import socket
import threading

# Configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 3333
TARGET_HOST = '127.0.0.1'
TARGET_PORT = 3334  # We'll run the proxy on this port

def handle_client(client_socket):
    # Connect to the actual proxy
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        proxy_socket.connect((TARGET_HOST, TARGET_PORT))
    except:
        print("[-] Failed to connect to proxy")
        client_socket.close()
        return

    # Start threads to forward data
    threading.Thread(target=forward, args=(client_socket, proxy_socket, "MINER -> PROXY")).start()
    threading.Thread(target=forward, args=(proxy_socket, client_socket, "PROXY -> MINER")).start()

def forward(source, destination, direction):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            print(f"[{direction}] {data.decode(errors='replace').strip()}", flush=True)
            destination.sendall(data)
    except:
        pass
    finally:
        source.close()
        destination.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)
    print(f"[*] Sniffer listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"[*] Forwarding to {TARGET_HOST}:{TARGET_PORT}", flush=True)

    while True:
        client, addr = server.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}", flush=True)
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == '__main__':
    main()
