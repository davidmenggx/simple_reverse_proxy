import re

def get_cache_control(directives: str) -> int:
    if match := re.search(r'\bmax-age="(\d+)', directives):
        return max(0, int(match.group(1)))
    return 0