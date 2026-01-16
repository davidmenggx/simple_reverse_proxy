def get_headers(headers: list[str]) -> dict[str, str]:
    """
    Returns HTTP headers in dictionary mapping

    All values in lowercase
    """
    res = {}
    
    for h in headers:
        header = h.split(': ')

        if len(header) != 2:
            raise ValueError('Parse Error - Headers')
        
        res[header[0].lower()] = header[1].lower()
    
    return res