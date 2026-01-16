import ssl
import gzip
import signal
import socket
import argparse
import threading

from utilities import get_request_line, get_headers
from handlers import ip_hash, least_connections, random, round_robin

parser = argparse.ArgumentParser(description="Configs for simple HTTP server")
parser.add_argument('--port', type=int, default=8443, help='Port for server to run on')
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose mode for workers')
parser.add_argument('-d', '--discover', action='store_true', default=False, help='Enable background thread to discover servers')
parser.add_argument('-l', '--load', type=str, default='LEAST_CONNECTIONS', help='Choose a method of load balancing')

args = parser.parse_args()

HOST = '' # difference between windows and linux
PORT = args.port
DISCOVERY_PORT = 49152 if PORT != 49152 else 49153

VERBOSE = args.verbose

RUNNING = True

DISPATCH_DICTIONARY = {'IP_HASH': ip_hash, 'LEAST_CONNECTIONS': least_connections, 'RANDOM': random, 'ROUND_ROBIN': round_robin}

LOAD_BALANCING_ALGORITHM = args.load.upper() if args.load.upper() in DISPATCH_DICTIONARY else 'LEAST_CONNECTIONS'

ROUND_ROBIN_COUNTER = 0

cached_requests = {} # important! figure out how to do this, store as (Method, Path): (message, timeout)
servers = {} # store dict as (IP, Port): # connections
server_lock = threading.Lock()

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
                # validate time !!!
                s.sendall(cached_requests[(method, path)][0]) # FIGURE THIS OUT !!!

            headers['X-Forwarded-For'] = f'{addr[0].replace("'", '')}'
            headers['X-Forwarded-Proto'] = 'https'

            try:
                content_length = int(headers.get('content-length', 0)) # important, read this from the headers
            except ValueError:
                if VERBOSE: print('Failed to fetch content length')
                # send back bad request

            body = bytearray(remaining_bytes)

            while len(body) < content_length:
                bytes_to_read = content_length - len(body)
                chunk = s.recv(min(bytes_to_read, 4096))
                if not chunk:
                    if VERBOSE: print('Failed reading request body')
                    # send back internal server error
                    return
                body.extend(chunk)
            
            body = body[:content_length]

            new_request = (f'{method} {path} {protocol_version}\r\n').encode('utf-8')
            for header in headers:
                new_request += (f'{header}: {headers[header]}\r\n').encode('utf-8')
            new_request += b'\r\n' + body

            with server_lock:
                if LOAD_BALANCING_ALGORITHM == 'ROUND_ROBIN':
                    global ROUND_ROBIN_COUNTER
                    ROUND_ROBIN_COUNTER += 1
                
                targeted_ip, targeted_port = DISPATCH_DICTIONARY[LOAD_BALANCING_ALGORITHM](servers, addr[0], ROUND_ROBIN_COUNTER) # remember addr is a tuple (host, port, flow info, scope id)
                servers[(targeted_ip, targeted_port)] += 1

            print(f'chose server ({targeted_ip}, {targeted_port})')
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                    try:
                        s2.connect((targeted_ip, targeted_port))
                        print(f'connected to chosen server ({targeted_ip}, {targeted_port})')
                    except ConnectionRefusedError:
                        print(f'CRITICAL: Could not connect to server ({targeted_ip}, {targeted_port}), removing from servers list')
                        with server_lock:
                            servers.pop((targeted_ip, targeted_port))
                        return # return here ????? or try another server ????

                    print('sending message to selected server')

                    s2.sendall(new_request)
                    print('found response')


                    # everything below this is cooked ....
                    server_buffer = bytearray()

                    while header_delimiter not in server_buffer:
                        chunk = s2.recv(1024)
                        # wtf is this figure it out
                        # if not chunk:
                        #     if not buffer:
                        #         if VERBOSE: print('Connection closed cleanly by client')
                        #         return
                        #     else:
                        #         if VERBOSE: print('Connection closed before client sent full header')
                        #         return
                        server_buffer.extend(chunk)

                    response_head_raw, _, response_remaining_bytes = server_buffer.partition(header_delimiter) # partition returns (before, delimiter, after)
                    
                    response_headers_raw = response_head_raw.decode('utf-8').split('\r\n')[1:]

                    try:
                        response_headers = get_headers(response_headers_raw)
                    except ValueError:
                        if VERBOSE: print('Failed to parse headers from server response')
                        # send back bad request 400
                        return

                    #print(response_headers)

                    try:
                        response_content_length = int(response_headers.get('content-length', 0)) # important, read this from the headers
                    except ValueError:
                        if VERBOSE: print('Failed to fetch content length from server response')
                        # send back bad request

                    response_body = bytearray(response_remaining_bytes)

                    while len(response_body) < response_content_length:
                        bytes_to_read = response_content_length - len(body)
                        chunk = s.recv(min(bytes_to_read, 4096))
                        if not chunk:
                            if VERBOSE: print('Failed reading request body')
                            # send back internal server error
                            return
                        response_body.extend(chunk)
                    
                response_body = response_body[:response_content_length]

                response_message = response_head_raw + header_delimiter + response_body if response_body else response_head_raw + b'\r\n'
                
                


            # catch exceptions too
            finally:
                with server_lock:
                    servers[(targeted_ip, targeted_port)] -= 1
                    if servers[(targeted_ip, targeted_port)] < 0: # the # of connections can never be negative
                        print('CRITICAL: # connetions fell below 0. Forcefully resetting back to 0')
                        servers[(targeted_ip, targeted_port)] = 0


    except OSError as e:
        print(f'SSL error: {e}')
    except Exception as e:
        ... # some other error happened !!!
    print('thread closed')

def discover_servers() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as discovery_sock:
        discovery_sock.bind((HOST, DISCOVERY_PORT))
        discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        discovery_sock.listen() 

        while True:
            conn, addr = discovery_sock.accept() # make sure that i don't need to socket itself, just the information
            # addr is in the form ('IP', PORT, _, _)
            with conn:
                data = conn.recv(1024)
                ip, port = data.decode('utf-8').split(',')
            with server_lock:
                servers[(ip, int(port))] = 0
                print(f'Found server ({ip}, {port})')

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