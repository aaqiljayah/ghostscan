#!/usr/bin/env python3
"""
portscanner — TCP connect port scanner
github.com/aaqiljayah
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Common ports + service names ──────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 587, 993, 995, 1433, 1521, 3306,
    3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017
]

SERVICES = {
    21:    'FTP',
    22:    'SSH',
    23:    'Telnet',
    25:    'SMTP',
    53:    'DNS',
    80:    'HTTP',
    110:   'POP3',
    111:   'RPC',
    135:   'MSRPC',
    139:   'NetBIOS',
    143:   'IMAP',
    443:   'HTTPS',
    445:   'SMB',
    587:   'SMTP/TLS',
    993:   'IMAPS',
    995:   'POP3S',
    1433:  'MSSQL',
    1521:  'Oracle',
    3306:  'MySQL',
    3389:  'RDP',
    5432:  'PostgreSQL',
    5900:  'VNC',
    6379:  'Redis',
    8080:  'HTTP-Alt',
    8443:  'HTTPS-Alt',
    8888:  'HTTP-Alt',
    27017: 'MongoDB',
}

# ── ANSI colours ───────────────────────────────────────────────────────────────
GREEN  = '\033[92m'
RED    = '\033[91m'
CYAN   = '\033[96m'
YELLOW = '\033[93m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'


def banner():
    print(f"""
{CYAN}{BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{DIM}  TCP Connect Port Scanner · github.com/aaqiljayah{RESET}
""")


def resolve_target(target: str) -> str:
    """Resolve hostname to IP, return IP string."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"  {RED}[✗] Could not resolve host: {target}{RESET}")
        sys.exit(1)


def scan_port(ip: str, port: int, timeout: float) -> tuple[int, bool]:
    """Attempt TCP connect to ip:port. Returns (port, is_open)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port, result == 0
    except Exception:
        return port, False


def parse_ports(port_arg: str) -> list[int]:
    """
    Parse port argument into a list of ints.
    Accepts:
      - 'common'       → COMMON_PORTS
      - '80'           → [80]
      - '80,443,8080'  → [80, 443, 8080]
      - '1-1024'       → [1, 2, ..., 1024]
    """
    if port_arg == 'common':
        return COMMON_PORTS

    ports = set()
    for part in port_arg.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


def run_scan(target: str, ports: list[int], timeout: float, threads: int):
    ip = resolve_target(target)

    print(f"  {DIM}Target   :{RESET}  {BOLD}{target}{RESET}" + (f"  {DIM}({ip}){RESET}" if target != ip else ''))
    print(f"  {DIM}IP       :{RESET}  {ip}")
    print(f"  {DIM}Ports    :{RESET}  {len(ports)} to scan")
    print(f"  {DIM}Started  :{RESET}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print(f"  {DIM}{'PORT':<10}{'STATE':<12}{'SERVICE'}{RESET}")
    print(f"  {'─' * 40}")

    open_ports = []
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = SERVICES.get(port, 'unknown')
                print(f"  {GREEN}{port:<10}{'open':<12}{service}{RESET}")
                open_ports.append(port)

    elapsed = (datetime.now() - start_time).total_seconds()

    print(f"  {'─' * 40}")
    print()

    if open_ports:
        print(f"  {GREEN}[✓] {len(open_ports)} open port(s) found{RESET}  {DIM}in {elapsed:.2f}s{RESET}")
    else:
        print(f"  {YELLOW}[!] No open ports found{RESET}  {DIM}in {elapsed:.2f}s{RESET}")

    print()


def main():
    banner()

    parser = argparse.ArgumentParser(
        description='TCP connect port scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        'target',
        help='Target hostname or IP  (e.g. scanme.nmap.org)',
    )
    parser.add_argument(
        '-p', '--ports',
        default='common',
        metavar='PORTS',
        help=(
            'Ports to scan (default: common)\n'
            '  common       — 27 well-known ports\n'
            '  80           — single port\n'
            '  80,443,8080  — list\n'
            '  1-1024       — range'
        ),
    )
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=1.0,
        metavar='SEC',
        help='Timeout per port in seconds (default: 1.0)',
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        metavar='N',
        help='Number of threads (default: 100)',
    )
    parser.add_argument(
        '-h', '--help',
        action='help',
        help='Show this message and exit',
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"  {RED}[✗] Invalid port format: {args.ports}{RESET}")
        sys.exit(1)

    if not ports:
        print(f"  {RED}[✗] No ports to scan.{RESET}")
        sys.exit(1)

    run_scan(args.target, ports, args.timeout, args.threads)


if __name__ == '__main__':
    main()
