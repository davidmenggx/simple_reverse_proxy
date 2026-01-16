def round_robin(servers: dict, _client_ip: str, round_robin_counter: int) -> tuple[str, int]:
    servers_list = list(servers.keys())
    return servers_list[round_robin_counter%len(servers_list)]