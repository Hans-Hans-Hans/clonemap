from typing import List
import ipaddress


def get_hosts_from_cidr(host_arg: str) -> list[str]:
    """
    Converts a CIDR block into a list of usable host IP addresses (excluding network and broadcast).

    Args:
        host_arg (str): A string containing an IPv4 address with CIDR notation (e.g., "192.168.1.0/24").

    Returns:
        list[str]: A list of host IP addresses as strings.

    Raises:
        ValueError: If the CIDR block is invalid. An error message is printed instead.
    """
    try:
        # Parse the input as a network, allowing non-strict format like 192.168.1.10/24
        network = ipaddress.ip_network(host_arg, strict=False)
        # Convert the generator to a list of strings for usable host addresses
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        print(f"[!] Invalid CIDR Block: {e}")

def parse_host_ips(host_arg: str) -> list[str] | bool:
    """
    Parses and validates an IP address or CIDR block. Returns a list of IPs or False on failure.

    Args:
        host_arg (str): Input string containing either:
                        - A single IPv4 address (e.g., "192.168.1.1")
                        - A CIDR block (e.g., "192.168.1.0/24")
                        - A comma-separated list of IPs (e.g., "192.168.1.1,192.168.1.2")

    Returns:
        list[str]: A list of IP addresses.
        bool: False if the input is not a valid IP format.
    """

    # If CIDR notation is used, expand it into host IPs
    if "/" in host_arg:
        return get_hosts_from_cidr(host_arg)
    else:
        # Return a list of IPs split by comma
        return host_arg.split(",")
