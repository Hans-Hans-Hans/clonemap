import argparse
from datetime import datetime
from Modules.parse_host_ips import parse_host_ips
from Modules.parse_ports import parse_ports
from Modules.parse_protocol import parse_protocol
from Modules.create_socket import connection, thread_spawn
import pyfiglet

if __name__ == "__main__":
    # Create Parser
    parser = argparse.ArgumentParser(description="CloneMap 1.1")

    # Add parser arguments (switches)
    parser.add_argument("--host", "-ip", type=str, help="Enter 1 or more IP addresses or range of IP Addresses.", required=True)
    parser.add_argument("--ports", '-p', type=str, help="Comma-serparated list or a range of ports.", required=False, nargs="?", const="")
    parser.add_argument("--proto", "-pT", "-pU", type=str, choices=["tcp", "udp"], default="tcp", help="Choose transport, layer 4, protocol. Either tcp or udp.", required=False)
    parser.add_argument("--debug", action="store_true", help="Enables the debug logs.", required=False)
    parser.add_argument("--banner","-sB", action="store_true", help="Enables banner retrieval for TCP.", required=False)
    parser.add_argument("--stealth", "-sS", action="store_true", help="Enables a stealth or half-open TCP scan.", required=False)
    # Add arguments to the parser
    args = parser.parse_args()

    # Takes args.host and determines if the IP is a network with a CIDR code or if its individual ips ands enters it as a list
    host_ips: list[str] = parse_host_ips(args.host)
    
    # Takes args.ports and adds them to a list or gets a range and add the ports within to the list
    if args.ports == "":
        with open("default_target_ports.txt", "r") as file:
            ports: list[str] = file.read().replace(" ", "").split(",")
    else:
        ports: list[str] = parse_ports(args.ports)
    
    # Takes args.proto and determines if the user wants to use TCP or UDP transport protocol
    if args.proto: protocol: str = parse_protocol(args.proto)
  
    # Flag to determine if the user wants all debug logs
    debug: bool = False
    if args.debug: debug = True

    # Flag to determine if the user wants TCP banner/service retrieval
    banner: bool = False
    if args.banner: banner = True
    
    # Flag to run a 'stealth' scan or 'half-open' SYN scan: Requires root/admin access.
    stealth: bool = False 
    if args.stealth: stealth = True
    
    app_banner = pyfiglet.figlet_format("CloneMap v1.1")
    print(app_banner)
    print(f'Starting CloneMap 1.1 (https://gitbub.com/Hans-Hans-Hans/clonemap) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n') 
    thread_spawn(host_ips, ports, protocol, debug, banner)