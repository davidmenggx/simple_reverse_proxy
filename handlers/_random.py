import random

def _random(servers: dict, _client_ip: str, _round_robin_counter: int) -> tuple[str, int]:
    return random.choice(list(servers.keys()))