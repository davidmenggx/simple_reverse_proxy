import hashlib

def ip_hash(servers: dict, client_ip: str, _round_robin_counter: int) -> tuple[str, int]:
    hash_object = hashlib.md5(client_ip.encode())
    hash_hex = hash_object.hexdigest()
    
    index = int(hash_hex, 16) % len(servers)
    return list(servers.keys())[index]