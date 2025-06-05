import json
import os

def load_service_map(path: str = "Modules/common_ports.json") -> dict:
    """
    Loads a JSON mapping of port numbers to service names.
    """
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as file:
        return json.load(file)