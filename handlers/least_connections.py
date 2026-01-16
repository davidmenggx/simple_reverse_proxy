def least_connections(servers: dict, _client_ip: str, _round_robin_counter: int) -> tuple[str, int]:
    return min(servers, key=servers.get) # type: ignore