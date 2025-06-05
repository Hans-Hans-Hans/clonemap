def parse_protocol(proto_arg: str) -> str:
    """
    Validates the protocol input and returns it in lowercase.

    Args:
        proto_arg (str): The protocol provided by the user.

    Returns:
        str: 'tcp' or 'udp', normalized to lowercase.

    Raises:
        ValueError: If the protocol is not 'tcp' or 'udp'.
    """
    # Normalize input to lowercase for consistent checking
    p = proto_arg.lower()

    # Validate protocol is one of the allowed values
    if p not in ("tcp", "udp"):
        raise ValueError("Protocol must be 'tcp' or 'udp'")

    return p