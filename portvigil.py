#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════════════════════
    PORTVIGIL v1.0 - Professional Network Port Scanner
══════════════════════════════════════════════════════════════════════════════
Author: Bacem El Manai (@becem69)
Purpose: Advanced port scanning for authorized penetration testing & CTF

FOR AUTHORIZED SECURITY TESTING ONLY
══════════════════════════════════════════════════════════════════════════════
"""

import socket
import sys
import threading
import argparse
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Optional
import json

class PortVigil:
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0):
        self.original_target = target
        self.target_ip = socket.gethostbyname(target)
        self.ports = sorted(ports)
        self.timeout = timeout
        self.open_ports: Set[int] = set()
        self.services: Dict[int, str] = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        
    def banner(self) -> None:
        """Display professional banner"""
        print("=" * 80)
        print(f"  PORTVIGIL v1.0 - Advanced Port Scanner by Bacem El Manai (@becem69)")
        print(f"  Target: {self.original_target} ({self.target_ip})")
        print(f"  Ports: {len(self.ports)} | Threads: {self.threads} | Timeout: {self.timeout}s")
        print("=" * 80)
    
    def get_service(self, port: int) -> str:
        """Comprehensive service detection"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis"
        }
        return services.get(port, f"Port-{port}")
    
    def scan_port(self, port: int) -> bool:
        """Thread-safe port scanning with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                service = self.get_service(port)
                with self.lock:
                    self.open_ports.add(port)
                    self.services[port] = service
                print(f"[+] {self.original_target}:{port:5d}/tcp  OPEN  {service:<12} | {datetime.now().strftime('%H:%M:%S')}")
                return True
        except:
            pass
        return False
    
    def scan(self, threads: int = 200) -> None:
        """Execute multi-threaded port scan"""
        self.threads = threads
        self.banner()
        
        print(f"[*] Initiating scan with {threads} threads...")
        print("-" * 80)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                pass  # Real-time output handled in scan_port
        
        self.print_results()
    
    def print_results(self) -> None:
        """Professional results summary"""
        scan_time = time.time() - self.start_time
        open_count = len(self.open_ports)
        
        print("\n" + "=" * 80)
        print(f"                    PORTVIGIL SCAN COMPLETE")
        print(f"══════════════════════════════════════════════════════════════════════════════")
        print(f"Target: {self.original_target} ({self.target_ip})")
        print(f"Ports scanned: {len(self.ports):,} | Open: {open_count} | Time: {scan_time:.2f}s")
        print(f"Scan rate: {len(self.ports)/scan_time:.0f} ports/sec")
        print("=" * 80)
        
        if open_count > 0:
            print("\nOPEN PORTS SUMMARY:")
            print("PORT     STATE  SERVICE        RECOMMENDATION")
            print("-" * 50)
            for port in sorted(self.open_ports):
                service = self.services[port]
                rec = self.get_recommendation(port, service)
                print(f"{port:6d}  OPEN   {service:<12} {rec}")
        else:
            print("\nNo open ports found - Target appears secure!")
        
        print("\n" + "=" * 80)
    
    def get_recommendation(self, port: int, service: str) -> str:
        """Security recommendations for open ports"""
        recs = {
            21: "Disable FTP", 22: "SSH (harden)", 23: "Disable Telnet",
            80: "Web (check vulns)", 443: "HTTPS (check certs)",
            3306: "MySQL (restrict access)", 3389: "RDP (2FA recommended)"
        }
        return recs.get(port, "Investigate")
    
    def export_json(self, filename: str) -> None:
        """Export results to JSON"""
        results = {
            "scan_info": {
                "target": self.original_target,
                "ip": self.target_ip,
                "total_ports": len(self.ports),
                "open_ports": len(self.open_ports),
                "scan_time": time.time() - self.start_time,
                "timestamp": datetime.now().isoformat()
            },
            "open_ports": [
                {"port": port, "service": self.services[port]}
                for port in sorted(self.open_ports)
            ]
        }
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to {filename}")

def parse_ports(port_str: str) -> List[int]:
    """Parse flexible port specifications"""
    ports = set()
    presets = {
        'top': list(range(1, 1001)),
        'common': [21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080],
        'web': [80,443,8080,8443,3000,5000,8000],
        'db': [3306,5432,1433,27017,6379,11211]
    }
    
    if port_str.lower() in presets:
        return presets[port_str.lower()]
    
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(max(1, start), min(65536, end + 1)))
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(
        description="PORTVIGIL - Professional Port Scanner by Bacem El Manai (@becem69)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
QUICK START EXAMPLES:
  %(prog)s scanme.nmap.org                    # Top 1000 ports
  %(prog)s -p common 192.168.1.1             # Common ports only
  %(prog)s -p 1-10000 -T 500 target.com      # Fast full scan
  %(prog)s -p web,db example.com             # Web + Database ports
  %(prog)s -p 80,443,22 -o results.json      # Specific ports + JSON export

PRESETS: top, common, web, db
        """
    )
    
    parser.add_argument('target', help="Target IP/hostname")
    parser.add_argument('-p', '--ports', default='top',
                       help="Ports: range(1-1000), comma-list, or preset(top,common,web,db)")
    parser.add_argument('-T', '--threads', type=int, default=200,
                       help="Threads (50-1000, default: 200)")
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help="Timeout seconds (0.1-5.0, default: 1.0)")
    parser.add_argument('-o', '--output', help="Export JSON results")
    
    args = parser.parse_args()
    
    # Validation
    args.threads = max(50, min(args.threads, 1000))
    args.timeout = max(0.1, min(args.timeout, 5.0))
    
    # Parse ports
    try:
        ports = parse_ports(args.ports)
        if not ports:
            print("No valid ports specified!")
            sys.exit(1)
    except Exception as e:
        print(f"Port parsing error: {e}")
        sys.exit(1)
    
    # Run scan
    try:
        scanner = PortVigil(args.target, ports, args.timeout)
        scanner.scan(args.threads)
        
        if args.output:
            scanner.export_json(args.output)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except socket.gaierror:
        print(f"Cannot resolve {args.target}")
    except Exception as e:
        print(f"Scan failed: {e}")

if __name__ == "__main__":
    print(f"PORTVIGIL v1.0 by Bacem El Manai (@becem69)")
    main()