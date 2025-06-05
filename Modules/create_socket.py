import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from Modules.print_lock import print_lock  # Used to ensure thread-safe printing
from colorama import init, Fore, Style
from Modules.spinner import Spinner
from Modules.service_lookup import load_service_map

service_map = load_service_map()

def log_debug(message: str, debug: bool):
    """
    Log a debug message in plain text if debug mode is enabled.
    """
    if debug: 
        with print_lock:
            print(message + Style.RESET_ALL)

def log_error(message: str, debug: bool):
    """
    Log an error message in red if debug mode is enabled.
    """
    if debug:
        with print_lock:
            print(Fore.RED + message + Style.RESET_ALL)

def log_success(message: str, debug: bool):
    """
    Log a success message in green if debug mode is enabled.
    """
    if debug:
        with print_lock:
            print(Fore.GREEN + message + Style.RESET_ALL)

def print_host_report(ip: str, ip_address: str, results: list[tuple[int, str, str, str]], banner_enabled: bool):
    """
    Prints a formatted scan report for a single host.
    Includes port, state, service, and optionally banner.
    """
    print(f"\nScan report for {ip} ({ip_address})")
    print(f"Host is up.\n")
    
    # Print header
    if banner_enabled:
        print(Fore.CYAN + f"{'PORT':<9} {'STATE':<8} {'SERVICE':<15} BANNER" + Style.RESET_ALL)
    else:
        print(Fore.CYAN + f"{'PORT':<9} {'STATE':<8} {'SERVICE':<15}" + Style.RESET_ALL)
    
    # Print each result
    for port, state, service, banner in results:
        # Color the state
        state_padded = f"{state:<8}"  # pad before coloring

        if state == "open":
            state_colored = Fore.GREEN + state_padded + Style.RESET_ALL
        elif state == "closed":
            state_colored = Fore.RED + state_padded + Style.RESET_ALL
        else:
            state_colored = state_padded

        # Add padding to each column; add a space before banner if banner exists
        line = f"{str(port) + '/tcp':<9} {state_colored:<8} {service:<15}"
        if banner_enabled and banner:
            line += f" {banner}"
        print(line)

def resolve_hostname(ip: str, debug: bool) -> str:
    """
    Resolves a hostname to its corresponding IP address.
    Logs success or failure if debug is enabled.
    """
    try:
        ip_address = socket.gethostbyname(ip)
        log_success(f"[+] Resolved {ip} to {ip_address}", debug)
        return ip_address
    except socket.gaierror as e:
        log_error(f"[ERROR] Failed to resolve hostname {ip} - {e}", debug)

def grab_banner(sock: socket.socket, timeout: int, debug) -> str:
    """
    Attempts to receive a banner from an open TCP socket.
    Logs result if debug is enabled.
    """
    try:
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        if banner:
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
    """
    Creates and connects a socket to the target IP and port.
    Handles both TCP and UDP protocols.
    Logs connection status if debug is enabled.
    """
    timeout = 1
    try:
        if protocol.lower() == "tcp":
            sock = socket.create_connection((ip, port), timeout=timeout)
            log_success(f'[+] Successfully connected to {ip}:{port} via TCP', debug)
        elif protocol.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b'ping', (ip, port))
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
    """
    Attempts to connect to a list of ports on the given IP address.
    Logs and stores results for each port.
    Displays a report if any port is open.
    """
    ip_address = resolve_hostname(ip, debug)
    results = []

    for port in port_list:
        state = "closed"
        banner_text = ""
        service = service_map.get(str(port), "unknown")
        sock = create_socket(ip_address, port, protocol, debug, banner)
        if sock: 
            state = "open"
            if banner and protocol == "tcp": 
                banner_text = grab_banner(sock, 1, debug) or ""
                sock.close()
        results.append((port, state, service, banner_text))
    
    # Only print report if at least one port is open
    if any(state == "open" for _, state, _, _ in results):
        with print_lock:
            print_host_report(ip, ip_address, results, banner)

def thread_spawn(ip_list: str, port_list: str, protocol: str, debug: bool, banner: bool):
    """
    Starts multithreaded scanning of IPs and ports.
    Uses a thread pool and a spinner animation during execution.
    """
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