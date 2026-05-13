#!/usr/bin/env python3
"""
CyberEye
Advanced security auditing tool with OS detection and version scanning
Author: Aryan Waghere
Version: 1.0.0
"""

import socket
import sys
import argparse
import threading
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import platform
import json
from pathlib import Path
from datetime import datetime
import queue


class ScanType(Enum):
    """Scan type enumeration"""
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    UDP = "udp"


class PortStatus(Enum):
    """Port status enumeration"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class ServiceInfo:
    """Service information discovered on a port"""
    name: str
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None


@dataclass
class PortResult:
    """Result for a scanned port"""
    port: int
    status: PortStatus
    service: Optional[ServiceInfo] = None
    banner: Optional[str] = None
    protocol: str = "tcp"


@dataclass
class ScanResult:
    """Complete scan result"""
    target: str
    scan_type: ScanType
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    open_ports: List[PortResult] = field(default_factory=list)
    closed_ports: List[PortResult] = field(default_factory=list)
    filtered_ports: List[PortResult] = field(default_factory=list)
    os_detection: Optional[Dict] = None
    scan_duration: float = 0.0


class ServiceDatabase:
    """Database for common services and their default ports"""
    
    COMMON_SERVICES = {
        20: ServiceInfo("FTP-DATA"),
        21: ServiceInfo("FTP"),
        22: ServiceInfo("SSH"),
        23: ServiceInfo("Telnet"),
        25: ServiceInfo("SMTP"),
        53: ServiceInfo("DNS"),
        80: ServiceInfo("HTTP"),
        110: ServiceInfo("POP3"),
        143: ServiceInfo("IMAP"),
        443: ServiceInfo("HTTPS"),
        445: ServiceInfo("SMB"),
        465: ServiceInfo("SMTP-SSL"),
        587: ServiceInfo("SMTP"),
        993: ServiceInfo("IMAPS"),
        995: ServiceInfo("POP3S"),
        1433: ServiceInfo("MSSQL"),
        3306: ServiceInfo("MySQL"),
        3389: ServiceInfo("RDP"),
        5432: ServiceInfo("PostgreSQL"),
        5900: ServiceInfo("VNC"),
        8080: ServiceInfo("HTTP-ALT"),
        8443: ServiceInfo("HTTPS-ALT"),
        27017: ServiceInfo("MongoDB"),
        6379: ServiceInfo("Redis"),
    }
    
    @classmethod
    def get_service(cls, port: int) -> ServiceInfo:
        """Get service information for a port"""
        if port in cls.COMMON_SERVICES:
            return cls.COMMON_SERVICES[port]
        try:
            service_name = socket.getservbyport(port, "tcp")
            return ServiceInfo(service_name)
        except OSError:
            return ServiceInfo(f"Unknown")


class BannerGrabber:
    """Grab service banners from open ports"""
    
    TIMEOUT = 3
    
    @staticmethod
    def grab_banner(host: str, port: int, timeout: int = TIMEOUT) -> Optional[str]:
        """Attempt to grab banner from a service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send initial request
            banner = b""
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass
            
            sock.close()
            
            if banner:
                try:
                    return banner.decode('utf-8', errors='ignore').strip()
                except Exception:
                    return str(banner)
        except Exception:
            pass
        
        return None


class PortScanner:
    """Main port scanner class"""
    
    def __init__(self, target: str, ports: List[int], threads: int = 50, 
                 timeout: int = 3, scan_type: ScanType = ScanType.TCP_CONNECT):
        """
        Initialize the port scanner
        
        Args:
            target: Target host/IP address
            ports: List of ports to scan
            threads: Number of threads for concurrent scanning
            timeout: Socket timeout in seconds
            scan_type: Type of scan to perform
        """
        self.target = self._resolve_host(target)
        self.ports = ports
        self.threads = min(threads, len(ports))
        self.timeout = timeout
        self.scan_type = scan_type
        self.results = ScanResult(target=target, scan_type=scan_type)
        self.port_queue = queue.Queue()
        self.lock = threading.Lock()
        
    def _resolve_host(self, host: str) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            print(f"[!] Could not resolve hostname: {host}")
            sys.exit(1)
    
    def _scan_tcp_connect(self, port: int) -> PortStatus:
        """Perform TCP connect scan on a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return PortStatus.OPEN
            else:
                return PortStatus.CLOSED
        except socket.gaierror:
            return PortStatus.FILTERED
        except Exception:
            return PortStatus.FILTERED
    
    def _scan_udp(self, port: int) -> PortStatus:
        """Perform UDP scan on a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'', (self.target, port))
            
            try:
                sock.recvfrom(1024)
                sock.close()
                return PortStatus.OPEN
            except socket.timeout:
                sock.close()
                return PortStatus.OPEN_FILTERED
        except Exception:
            return PortStatus.FILTERED
    
    def _scan_port(self, port: int) -> Optional[PortResult]:
        """Scan a single port"""
        try:
            if self.scan_type == ScanType.UDP:
                status = self._scan_udp(port)
                protocol = "udp"
            else:
                status = self._scan_tcp_connect(port)
                protocol = "tcp"
            
            # Grab banner for open ports
            banner = None
            if status == PortStatus.OPEN and protocol == "tcp":
                banner = BannerGrabber.grab_banner(self.target, port, self.timeout)
            
            service = ServiceDatabase.get_service(port)
            
            return PortResult(
                port=port,
                status=status,
                service=service,
                banner=banner,
                protocol=protocol
            )
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")
            return None
    
    def _worker(self):
        """Worker thread for scanning ports"""
        while True:
            try:
                port = self.port_queue.get(timeout=1)
                if port is None:
                    break
                
                result = self._scan_port(port)
                if result:
                    with self.lock:
                        if result.status == PortStatus.OPEN:
                            self.results.open_ports.append(result)
                        elif result.status == PortStatus.CLOSED:
                            self.results.closed_ports.append(result)
                        else:
                            self.results.filtered_ports.append(result)
                
                self.port_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Worker error: {e}")
    
    def scan(self) -> ScanResult:
        """Execute the port scan"""
        print(f"\n[*] Starting {self.scan_type.value} scan on {self.target}")
        print(f"[*] Scanning {len(self.ports)} ports with {self.threads} threads\n")
        
        self.results.start_time = datetime.now()
        
        # Fill the queue
        for port in self.ports:
            self.port_queue.put(port)
        
        # Create and start worker threads
        worker_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            worker_threads.append(t)
        
        # Wait for queue to be processed
        self.port_queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.port_queue.put(None)
        
        for t in worker_threads:
            t.join()
        
        self.results.end_time = datetime.now()
        self.results.scan_duration = (self.results.end_time - self.results.start_time).total_seconds()
        
        return self.results


class OSDetector:
    """Detect operating system based on scan results and TTL analysis"""
    
    TTL_SIGNATURES = {
        (64, 128): "Linux/Unix",
        (255,): "Cisco IOS/Network Device",
        (60, 128): "Windows",
        (128, 64): "Windows",
    }
    
    FINGERPRINTS = {
        (22, 80, 443, 111, 139, 445): "Linux Server",
        (22, 80, 443, 3306): "Linux Web Server",
        (80, 443, 445, 3389): "Windows Server",
        (445, 3389): "Windows Workstation",
        (22, 23, 25, 53, 69, 123, 161): "Network Appliance/Router",
    }
    
    @staticmethod
    def get_ttl(host: str) -> Optional[int]:
        """Get TTL value using ping"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ping", "-n", "1", host], 
                              capture_output=True, timeout=5, text=True)
                output = result.stdout
            
            # Windows format: "TTL=120"
            for line in output.split('\n'):
                if 'TTL=' in line:
                    # Find "TTL=120"
                    parts = line.split()
                    for part in parts:
                        if 'TTL=' in part:
                            ttl_str = part.split('=')[1]
                            ttl_value = int(ttl_str)
                            print(f"[+] TTL found: {ttl_value}")
                            return ttl_value
            else:
                # Linux/Mac format
                result = subprocess.run(["ping", "-c", "1", host], 
                              capture_output=True, timeout=5, text=True)
                output = result.stdout
            
            for line in output.split('\n'):
                if 'ttl=' in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'ttl=' in part.lower():
                            ttl_value = int(part.split('=')[1])
                            print(f"[+] TTL found: {ttl_value}")
                            return ttl_value
        except Exception as e:
            print(f"[!] Error getting TTL: {e}")
    
        print(f"[!] Could not extract TTL")
        return None
    
    @staticmethod
    def detect_os(scan_result: ScanResult) -> Dict:
        """Detect OS based on open ports and TTL"""
        detection = {
            "method": "port_fingerprinting",
            "os": "Unknown",
            "confidence": "low",
            "ttl": None
        }
        
        print(f"\n[*] Detecting OS for {scan_result.target}")
        
        # Try TTL detection
        ttl = OSDetector.get_ttl(scan_result.target)
        
        if ttl:
            detection["ttl"] = ttl
            print(f"[+] TTL value: {ttl}")
            
            # Windows: 60-64 or 128
            if 60 <= ttl <= 64 or 128 <= ttl <= 132:
                detection["os"] = "Windows"
                detection["confidence"] = "high"
                print(f"[+] OS Detection: Windows (TTL={ttl})")
            
            # Linux/Unix: 64
            elif 64 <= ttl <= 66:
                detection["os"] = "Linux/Unix"
                detection["confidence"] = "high"
                print(f"[+] OS Detection: Linux/Unix (TTL={ttl})")
            
            # Google/Public DNS: 120 (Google-specific)
            elif ttl == 120:
                detection["os"] = "Google Server / Public Service"
                detection["confidence"] = "high"
                print(f"[+] OS Detection: Google Server (TTL={ttl})")
            
            # Cisco/Network devices: 255
            elif ttl == 255:
                detection["os"] = "Cisco IOS/Network Device"
                detection["confidence"] = "high"
                print(f"[+] OS Detection: Network Device (TTL={ttl})")
            
            else:
                detection["os"] = f"Unknown (TTL={ttl})"
                detection["confidence"] = "medium"
                print(f"[+] OS Detection: Unknown (TTL={ttl})")
        else:
            print(f"[!] Could not get TTL value")
            
            # Fallback: Port-based detection
            open_port_list = sorted([p.port for p in scan_result.open_ports])
            print(f"[*] Using port-based fingerprinting: {open_port_list}")
            
            if 22 in open_port_list and 80 in open_port_list:
                detection["os"] = "Linux Server (Port-based)"
                detection["confidence"] = "medium"
            elif 445 in open_port_list and 3389 in open_port_list:
                detection["os"] = "Windows Server (Port-based)"
                detection["confidence"] = "medium"
            elif 80 in open_port_list or 443 in open_port_list:
                detection["os"] = "Web Server (Port-based)"
                detection["confidence"] = "low"
        
        return detection

class VersionScanner:
    """Scan for service versions using banner grabbing and known signatures"""
    
    SIGNATURES = {
        22: {
            "OpenSSH": [b"OpenSSH"],
            "LibSSH": [b"libssh"],
        },
        80: {
            "Apache": [b"Apache"],
            "Nginx": [b"nginx"],
            "IIS": [b"IIS"],
        },
        443: {
            "Apache": [b"Apache"],
            "Nginx": [b"nginx"],
        },
        3306: {
            "MySQL": [b"MySQL"],
            "MariaDB": [b"MariaDB"],
        },
        5432: {
            "PostgreSQL": [b"PostgreSQL"],
        },
    }
    
    @staticmethod
    def scan_versions(scan_result: ScanResult) -> None:
        """Add version information to scan results"""
        for port_result in scan_result.open_ports:
            if port_result.port in VersionScanner.SIGNATURES and port_result.banner:
                banner = port_result.banner
                signatures = VersionScanner.SIGNATURES[port_result.port]
                
                for product, patterns in signatures.items():
                    for pattern in patterns:
                        if pattern.decode('utf-8', errors='ignore') in banner:
                            port_result.service.product = product
                            port_result.service.version = VersionScanner._extract_version(banner)
                            break


    @staticmethod
    def _extract_version(banner: str) -> str:
        """Extract version string from banner"""
        # Simple heuristic: look for version-like patterns
        import re
        version_pattern = r'(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, banner)
        if match:
            return match.group(1)
        return "unknown"


class ReportGenerator:
    """Generate scan reports in various formats"""
    
    @staticmethod
    def generate_text_report(scan_result: ScanResult, verbose: bool = False) -> str:
        """Generate a text report"""
        report = []
        report.append("\n" + "="*70)
        report.append("NETWORK PORT SCAN REPORT")
        report.append("="*70)
        report.append(f"Target: {scan_result.target}")
        report.append(f"Scan Type: {scan_result.scan_type.value}")
        report.append(f"Start Time: {scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"End Time: {scan_result.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Duration: {scan_result.scan_duration:.2f} seconds")
        report.append(f"Open Ports: {len(scan_result.open_ports)}")
        report.append(f"Closed Ports: {len(scan_result.closed_ports)}")
        report.append(f"Filtered Ports: {len(scan_result.filtered_ports)}")
        
        if scan_result.os_detection:
            report.append(f"\nDetected OS: {scan_result.os_detection['os']}")
            report.append(f"Confidence: {scan_result.os_detection['confidence']}")
            if scan_result.os_detection.get('ttl'):
                report.append(f"TTL: {scan_result.os_detection['ttl']}")
        
        report.append("\n" + "-"*70)
        report.append("OPEN PORTS")
        report.append("-"*70)
        
        if scan_result.open_ports:
            for port_result in sorted(scan_result.open_ports, key=lambda x: x.port):
                report.append(f"\nPort: {port_result.port}/{port_result.protocol}")
                report.append(f"Service: {port_result.service.name}")
                if port_result.service.product:
                    report.append(f"Product: {port_result.service.product}")
                if port_result.service.version:
                    report.append(f"Version: {port_result.service.version}")
                if port_result.banner and verbose:
                    report.append(f"Banner: {port_result.banner[:100]}")
        else:
            report.append("No open ports found.")
        
        report.append("\n" + "="*70 + "\n")
        return "\n".join(report)
    
    @staticmethod
    def generate_json_report(scan_result: ScanResult) -> str:
        """Generate a JSON report"""
        report_dict = {
            "target": scan_result.target,
            "scan_type": scan_result.scan_type.value,
            "start_time": scan_result.start_time.isoformat(),
            "end_time": scan_result.end_time.isoformat(),
            "duration": scan_result.scan_duration,
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service.name,
                    "product": p.service.product,
                    "version": p.service.version,
                    "banner": p.banner
                }
                for p in sorted(scan_result.open_ports, key=lambda x: x.port)
            ],
            "os_detection": scan_result.os_detection,
        }
        return json.dumps(report_dict, indent=2)
    
    @staticmethod
    def save_report(scan_result: ScanResult, filepath: str, format: str = "text") -> None:
        """Save report to file"""
        if format.lower() == "json":
            content = ReportGenerator.generate_json_report(scan_result)
        else:
            content = ReportGenerator.generate_text_report(scan_result, verbose=True)
        
        Path(filepath).write_text(content)
        print(f"[+] Report saved to {filepath}")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Professional Network Port Scanner for Security Auditing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan top 100 ports
  python3 port_scanner.py -t 192.168.1.1 -r 1-100
  
  # Scan specific ports with version detection
  python3 port_scanner.py -t example.com -p 22,80,443,3306 -v
  
  # UDP scan with OS detection
  python3 port_scanner.py -t 192.168.1.1 -r 1-65535 -u --os-detect
  
  # Fast scan with 200 threads
  python3 port_scanner.py -t target.com -r 1-10000 --threads 200
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target host or IP address")
    parser.add_argument("-p", "--ports", help="Specific ports (comma-separated, e.g., 22,80,443)")
    parser.add_argument("-r", "--range", help="Port range (e.g., 1-1000)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=int, default=3, help="Socket timeout in seconds (default: 3)")
    parser.add_argument("-u", "--udp", action="store_true", help="Perform UDP scan")
    parser.add_argument("--os-detect", action="store_true", help="Enable OS detection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    return parser.parse_args()


def parse_port_input(port_input: str) -> List[int]:
    """Parse port input string"""
    ports = set()
    
    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    
    return sorted(list(ports))


def main():
    """Main function"""
    def main():
        """Run the entire scanner"""
    
    # Display banner
    print("\n" + "="*70)
    print("   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗   ██╗███████╗")
    print("  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝")
    print("  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗   ╚████╔╝ █████╗  ")
    print("  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══╝    ╚██╔╝  ██╔══╝  ")
    print("  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████╗   ██║   ███████╗")
    print("   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝")
    print("="*70)
    print("            🔐 Professional Network Security Scanner 🔐")
    print("                    Version 1.0.0 ~ Aryan Waghere")
    print("="*70 + "\n")
    
    # Read user commands
    args = parse_arguments()
    args = parse_arguments()
    
    # Determine ports to scan
    if args.ports:
        ports = parse_port_input(args.ports)
    elif args.range:
        ports = parse_port_input(args.range)
    else:
        # Default: common ports
        ports = list(ServiceDatabase.COMMON_SERVICES.keys())
    
    if not ports:
        print("[!] No ports specified")
        sys.exit(1)
    
    # Determine scan type
    scan_type = ScanType.UDP if args.udp else ScanType.TCP_CONNECT
    
    # Create and run scanner
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        scan_type=scan_type
    )
    
    results = scanner.scan()
    
    # OS Detection
    if args.os_detect:
        print("[*] Attempting OS detection...")
        results.os_detection = OSDetector.detect_os(results)
    
    # Version Scanning
    if results.open_ports:
        print("[*] Scanning for service versions...")
        VersionScanner.scan_versions(results)
    
    # Display results
    if args.json:
        print(ReportGenerator.generate_json_report(results))
    else:
        print(ReportGenerator.generate_text_report(results, verbose=args.verbose))
    
    # Save report if requested
    if args.output:
        format_type = "json" if args.json else "text"
        ReportGenerator.save_report(results, args.output, format=format_type)


if __name__ == "__main__":
    main()
