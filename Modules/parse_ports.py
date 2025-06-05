def parse_ports(port_arg: str) -> list[int]:
    """
    Input: String of port numbers.
    Returns: A list of ints used to represent individual port numbers or ranges of portnumbers
    """
    ports = set()
    for part in port_arg.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)