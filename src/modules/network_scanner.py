"""
Network scanning module for port scanning and service detection
"""

import asyncio
import socket
import subprocess
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import ipaddress

from src.core.logger import get_logger


class NetworkScanner:
    """Network scanner for port and service detection"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.timeout = config.get('scanning.network.timeout', 30)
        self.max_ports = config.get('scanning.network.max_ports', 1000)
        self.common_ports = config.get('scanning.network.common_ports', [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443
        ])

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform network scan on target

        Args:
            target: IP address, domain, or CIDR range

        Returns:
            Scan results
        """
        results = {
            'target': target,
            'scan_type': 'network',
            'success': True,
            'hosts': []
        }

        try:
            # Determine if target is CIDR range or single host
            if '/' in target:
                hosts = self._expand_cidr(target)
            else:
                # Resolve hostname if needed
                ip = self._resolve_host(target)
                if ip:
                    hosts = [ip]
                else:
                    results['success'] = False
                    results['error'] = f"Could not resolve host: {target}"
                    return results

            self.logger.info(f"Scanning {len(hosts)} host(s)")

            # Scan hosts concurrently
            with ThreadPoolExecutor(max_workers=10) as executor:
                scan_tasks = [
                    asyncio.get_event_loop().run_in_executor(
                        executor, self._scan_host, host
                    )
                    for host in hosts[:50]  # Limit to 50 hosts for safety
                ]
                host_results = await asyncio.gather(*scan_tasks)

            # Filter out hosts with no open ports
            results['hosts'] = [h for h in host_results if h['open_ports']]
            results['total_hosts_scanned'] = len(hosts)
            results['hosts_with_open_ports'] = len(results['hosts'])

        except Exception as e:
            self.logger.error(f"Network scan failed: {e}", exc_info=True)
            results['success'] = False
            results['error'] = str(e)

        return results

    def _expand_cidr(self, cidr: str) -> List[str]:
        """Expand CIDR notation to list of IP addresses"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Limit number of hosts
            hosts = list(network.hosts())[:self.max_ports]
            return [str(ip) for ip in hosts]
        except ValueError as e:
            self.logger.error(f"Invalid CIDR notation: {cidr}")
            return []

    def _resolve_host(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            self.logger.warning(f"Could not resolve hostname: {hostname}")
            return None

    def _scan_host(self, host: str) -> Dict[str, Any]:
        """Scan a single host for open ports"""
        self.logger.debug(f"Scanning host: {host}")

        result = {
            'host': host,
            'hostname': self._reverse_dns(host),
            'open_ports': [],
            'os_guess': None
        }

        # Scan common ports
        for port in self.common_ports:
            if self._is_port_open(host, port):
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': self._get_service_name(port),
                    'banner': self._grab_banner(host, port)
                }
                result['open_ports'].append(port_info)
                self.logger.debug(f"Found open port {port} on {host}")

        # Try to detect OS
        result['os_guess'] = self._detect_os(host)

        return result

    def _is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def _grab_banner(self, host: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send a generic request
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except:
                pass

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            if banner:
                return banner[:200]  # Limit banner length
        except:
            pass

        return None

    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        return service_map.get(port, 'Unknown')

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None

    def _detect_os(self, host: str) -> Optional[str]:
        """Attempt to detect operating system (basic)"""
        # This is a very basic OS detection
        # In production, you'd use nmap or similar tools

        # Check for common Windows ports
        if self._is_port_open(host, 3389, timeout=0.5) or self._is_port_open(host, 445, timeout=0.5):
            return "Windows"

        # Check for common Linux/Unix services
        if self._is_port_open(host, 22, timeout=0.5):
            return "Linux/Unix"

        return "Unknown"

    async def traceroute(self, target: str) -> Dict[str, Any]:
        """Perform traceroute to target"""
        result = {
            'target': target,
            'hops': []
        }

        try:
            # Use system traceroute command
            process = await asyncio.create_subprocess_exec(
                'traceroute', '-m', '15', '-w', '2', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                lines = stdout.decode('utf-8').split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        result['hops'].append(line.strip())

        except Exception as e:
            result['error'] = str(e)

        return result
