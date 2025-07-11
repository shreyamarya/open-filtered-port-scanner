import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- Constants ---
DEFAULT_TCP_TIMEOUT = 1.0
DEFAULT_UDP_TIMEOUT = 1.0
MAX_PORT_NUMBER = 65535
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

# --- Helper Functions ---
def parse_ports(port_input):
    ports = set()
    if port_input.lower() == 'all':
        return list(range(1, MAX_PORT_NUMBER + 1))
    parts = port_input.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def grab_banner(target_ip, port, timeout):
    banner = "N/A"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        try:
            http_request = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nConnection: close\r\n\r\n"
            sock.sendall(http_request)
        except socket.error:
            pass
        received_data = b""
        start_time = datetime.now()
        while (datetime.now() - start_time).total_seconds() < timeout:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received_data += chunk
                if b"\r\r" in received_data or b"\n\n" in received_data:
                    break
            except socket.timeout:
                break
        if received_data:
            banner = received_data.decode('utf-8', errors='ignore').strip()
            if len(banner) > 200:
                banner = banner[:200] + "..."
        else:
            banner = "No banner received."
    except Exception:
        banner = "No banner or connection refused."
    finally:
        sock.close()
    return banner

def scan_tcp_port(target_ip, port, timeout=DEFAULT_TCP_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = grab_banner(target_ip, port, timeout)
            return port, "Open", banner
        elif result == 111:
            return port, "Closed", ""
        else:
            return port, "Filtered", "Filtered (no TCP response)."
    except Exception as e:
        return port, "Error", str(e)
    finally:
        sock.close()

def scan_udp_port(target_ip, port, timeout=DEFAULT_UDP_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (target_ip, port))
        data, addr = sock.recvfrom(4096)
        return port, "Open", f"Received: {data[:100].decode('utf-8', errors='ignore')}"
    except socket.timeout:
        return port, "Open|Filtered", "No response."
    except ConnectionRefusedError:
        return port, "Closed", "Connection refused."
    except Exception as e:
        return port, "Error", str(e)
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description='Python Port Scanner (Open & Filtered Only)')
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--ports', default='1-1024', help='Ports to scan: "1-1024", "80,443", or "all"')
    parser.add_argument('--workers', type=int, default=50, help='Number of concurrent threads')
    parser.add_argument('--udp', action='store_true', help='Use UDP scan')
    parser.add_argument('--save', help='Save output to a file')
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve hostname: {args.target}")
        sys.exit(1)

    ports_to_scan = parse_ports(args.ports)
    print(f"Scanning {target_ip} ({'UDP' if args.udp else 'TCP'})...")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        if args.udp:
            futures = [executor.submit(scan_udp_port, target_ip, port) for port in ports_to_scan]
        else:
            futures = [executor.submit(scan_tcp_port, target_ip, port) for port in ports_to_scan]

        for i, future in enumerate(futures):
            try:
                port, status, info = future.result()
                if status in ["Open", "Open|Filtered"]:
                    results.append((port, status, info))
                sys.stdout.write(f"\rProgress: {i+1}/{len(ports_to_scan)}")
                sys.stdout.flush()
            except Exception as e:
                print(f"\nError scanning port: {e}")

    print("\n\nScan Complete.")
    output_lines = []
    for port, status, info in sorted(results):
        service = COMMON_PORTS.get(port, "Unknown")
        output_lines.append(f"[+] Port {port} ({service}) is {status}\n    Banner: {info}")

    for line in output_lines:
        print(line)

    if args.save:
        with open(args.save, 'w') as f:
            f.write("\n".join(output_lines))
        print(f"\nResults saved to {args.save}")

    # --- Summary Output ---
    print("\n--- Scan Summary ---")
    print(f"Total ports scanned: {len(ports_to_scan)}")
    print(f"Ports shown (Open / Open|Filtered): {len(results)}")
    for port, status, banner in results:
        service = COMMON_PORTS.get(port, "Unknown")
        print(f" - Port {port} ({service}): {status}, Banner: {banner}")

if __name__ == '__main__':
    main()
