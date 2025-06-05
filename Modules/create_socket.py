import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from Modules.print_lock import print_lock  # Used to ensure thread-safe printing
from colorama import init, Fore, Style
from Modules.spinner import Spinner

def log_debug(message: str, debug: bool):
    if debug: 
        with print_lock: print(message + Style.RESET_ALL)
def log_error(message: str, debug: bool):
    if debug:
        with print_lock: print(Fore.RED + message + Style.RESET_ALL)
def log_success(message: str, debug: bool):
    if debug:
        with print_lock: print(Fore.GREEN + message + Style.RESET_ALL)


def print_host_report(ip: str, ip_address: str, results: list[tuple[int, str, str, str]], banner_enabled: bool):
    print(f"\nScan report for {ip} ({ip_address})")
    print(f"Host is up.\n")
    
    # Print header
    if banner_enabled:
        print(Fore.CYAN + f"{'PORT':<9} {'STATE':<8} {'SERVICE':<13} BANNER" + Style.RESET_ALL)
    else:
        print(Fore.CYAN + f"{'PORT':<9} {'STATE':<8} {'SERVICE':<13}" + Style.RESET_ALL)
    
    # Print each result
    for port, state, service, banner in results:
        # Color the state
        if state == "open":
            state_colored = Fore.GREEN + state + Style.RESET_ALL
        elif state == "closed":
            state_colored = Fore.RED + state + Style.RESET_ALL
        else:
            state_colored = state
        line = f"{port}/tcp  {state_colored:<8} {service:<13}"
        if banner_enabled and banner:
            line += f"{banner}"
        print(line)

def resolve_hostname(ip: str, debug: bool) -> str:
    try:
        ip_address = socket.gethostbyname(ip)
        log_success(f"[+] Resolved {ip} to {ip_address}", debug)
        return ip_address
    except socket.gaierror as e:
        log_error(f"[ERROR] Failed to resolve hostname {ip} - {e}", debug)
        
def grab_banner(sock: socket.socket, timeout: int, debug) -> str:
    try:
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        if banner:
            #with print_lock: print(f"[+] Banner: {banner}")
            return banner
        else:
            log_debug("[*] No banner received.", debug)
            return None
    except socket.timeout:
        log_debug("[*] Banner recv timed out.", debug)
        return None
    except Exception as e:
        log_error(f"[ERROR] Failed to grab banner: {e}", debug)
        return None

def create_socket(ip: str, port: str, protocol: str, debug: bool, banner: bool) -> socket:
    timeout = 1
    try:
        if protocol.lower() == "tcp":
            sock = socket.create_connection((ip, port), timeout=timeout)
            log_success(f'[+] Successfully connected to {ip}:{port} via TCP', debug)
        elif protocol.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b'ping', (ip,port))
                data, addr = sock.recvfrom(1024)
                log_success(f"[+] Got UDP response from {addr}", debug)
            except socket.timeout:
                log_error(f"[-] No UDP responsed from {ip}:{port} (might be filtered or closed)", debug)
            except Exception as e:
                log_error(f"[ERROR] UDP communication error with {ip}:{port} - {e}", debug)
        else:
            log_error(f"[ERROR] Unsupported protocol: {protocol}", debug)
            return None
        return sock
    except socket.error as e:
        log_error(f"[ERROR] Failed to create/connect socket to {ip}:{port} - {e}", debug)
        
def connection(ip: str, port_list: str, protocol: str, debug: bool, banner: bool):
    ip_address = resolve_hostname(ip, debug)
    results = []

    for port in port_list:
            state = "closed"
            banner_text = ""
            service = "WIP"


            sock = create_socket(ip_address, port, protocol, debug, banner)
            if sock: 
                state = "open"
                if banner and protocol == "tcp": 
                    banner_text = grab_banner(sock, 1, debug) or ""
                    sock.close()
            results.append((port, state, service, banner_text))
    
    if any(state == "open" for _, state, _, _ in results):
        with print_lock: print_host_report(ip, ip_address, results, banner)

def thread_spawn(ip_list: str, port_list: str, protocol: str, debug: bool, banner: bool):
    spinner = Spinner("Scanning...")
    spinner.start()
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(connection, ip, port_list, protocol, debug, banner) for ip in ip_list]
            for future in as_completed(futures):
                result = future.result() 
                if result:
                    print(result)
    finally:
        spinner.stop()