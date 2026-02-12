"""
Port scanning module for VIPRecon.
Identifies open ports and services using asynchronous connection attempts.
"""

import asyncio
import socket
from typing import List, Dict, Any, Optional
from src.core.models import ScanTarget, ScanResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PortScanner:
    """Asynchronous port scanner."""
    
    # Common ports to scan if none specified
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
        1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000, 27017
    ]
    
    def __init__(self, concurrency: int = 100, timeout: float = 2.0):
        """
        Initialize port scanner.
        
        Args:
            concurrency: Number of concurrent connection attempts.
            timeout: Connection timeout in seconds.
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        
    async def scan(self, domain: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """
        Scan specified ports for a domain.
        
        Args:
            domain: Target domain or IP.
            ports: List of ports to scan. Defaults to COMMON_PORTS.
            
        Returns:
            List of dictionaries containing open port information.
        """
        if not ports:
            ports = self.COMMON_PORTS
            
        logger.info(f"Starting port scan for {domain} ({len(ports)} ports)")
        
        tasks = [self._check_port(domain, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        
        logger.info(f"Port scan completed. Found {len(open_ports)} open ports.")
        return open_ports

    async def _check_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Check if a single port is open.
        """
        async with self.semaphore:
            try:
                # Use asyncio.open_connection for async socket connection
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                # Port is open
                service = self._guess_service(port)
                
                # Cleanup connection
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                
                return {
                    'port': port,
                    'status': 'open',
                    'service': service
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
                # Port is closed or unreachable
                return None
            except Exception as e:
                logger.debug(f"Error scanning port {port} on {host}: {str(e)}")
                return None

    def _guess_service(self, port: int) -> str:
        """
        Guess the service name based on well-known ports.
        """
        well_known = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8000: 'HTTP-Alt',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            9000: 'FastCGI',
            27017: 'MongoDB'
        }
        return well_known.get(port, 'Unknown')
