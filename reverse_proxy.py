import ssl
import gzip
import signal
import socket
import argparse
import threading

from utilities import get_request_line, get_headers

parser = argparse.ArgumentParser(description="Configs for simple HTTP server")
parser.add_argument('--port', type=int, default=8443, help='Port for server to run on')
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose mode for workers')
parser.add_argument('-d', '--discover', action='store_true', default=False, help='Enable background thread to discover servers')
args = parser.parse_args()

HOST = '' # difference between windows and linux
PORT = args.port
DISCOVERY_PORT = 49152 if PORT != 49152 else 49153

VERBOSE = args.verbose

RUNNING = True

cached_requests = {} # important! figure out how to do this, store as (Method, Path)
servers = [] # important! figure out how to get a list of servers, store as (IP, PORT)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

def signal_shutdown(_sig, _frame) -> None:
    """Shut down server"""
    global RUNNING
    RUNNING = False

signal.signal(signal.SIGINT, signal_shutdown) # Catch CTRL+C
signal.signal(signal.SIGTERM, signal_shutdown) # Catch kill command

def handle_connection(connection: socket.socket, addr) -> None:
    print('thread started')
    try:
        with context.wrap_socket(connection, server_side=True) as s:
            print('connected')

            buffer = bytearray()
            header_delimiter = b'\r\n\r\n'

            while header_delimiter not in buffer:
                chunk = s.recv(1024)
                if not chunk:
                    if not buffer:
                        if VERBOSE: print('Connection closed cleanly by client')
                        return
                    else:
                        if VERBOSE: print('Connection closed before client sent full header')
                        return
                buffer.extend(chunk)
            
            head_raw, _, remaining_bytes = buffer.partition(header_delimiter) # partition returns (before, delimiter, after)
            head = head_raw.decode('utf-8')

            try:
                (method, path, protocol_version), remaining_head = get_request_line(head)
            except ValueError:
                if VERBOSE: print('Error parsing request line')
                # send back bad request 400
                return 
            
            try:
                headers = get_headers(remaining_head)
            except ValueError:
                if VERBOSE: print('Failed to parse headers')
                # send back bad request 400
                return

            if (method, path) in cached_requests:
                s.sendall(cached_requests[(method, path)]) # FIGURE THIS OUT !!!

            headers['X-Forwarded-For'] = f'{addr[0].replace("'", '')}'
            headers['X-Forwarded-Proto'] = 'https'

            print(addr)

    except Exception as e:
        print(f'SSL error: {e}')
    print('thread closed')

def discover_servers() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as discovery_sock:
        discovery_sock.bind((HOST, DISCOVERY_PORT))
        discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        discovery_sock.listen() 

        while True:
            _, addr = discovery_sock.accept() # make sure that i don't need to socket itself, just the information
            # addr is in the form ('IP', PORT, _, _)
            servers.append((addr[0], addr[1]))
            print(f'found server {addr}')

def main() -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        server_sock.bind((HOST, PORT))
        server_sock.listen()
        server_sock.settimeout(1.0)

        while RUNNING:
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue
            connection_worker = threading.Thread(target=handle_connection, args=(client_sock, addr,), daemon=True)
            connection_worker.start()

if __name__ == '__main__':
    if args.discover:
        print(f'Starting discovery thread listening to port {DISCOVERY_PORT}')
        discovery_thread = threading.Thread(target=discover_servers, daemon=True)
        discovery_thread.start()
        
    print(f'Starting reverse proxy server listening to port {PORT}')

    main()

    print('Reverse proxy server closed')