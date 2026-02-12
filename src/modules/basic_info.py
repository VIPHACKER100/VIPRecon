"""
Basic information gathering module for VIPRecon.
Collects HTTP headers, WHOIS data, DNS records, and SSL certificate information.
"""

import asyncio
import ssl
import socket
from typing import Dict, Any, Optional, List
from datetime import datetime
import dns.resolver
import whois
from src.core.http_client import AsyncHTTPClient
from src.core.models import ScanTarget
from src.core.exceptions import ModuleException, NetworkException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class BasicInfoGatherer:
    """Gathers basic reconnaissance information about a target."""
    
    def __init__(self, http_client: AsyncHTTPClient):
        """
        Initialize basic info gatherer.
        
        Args:
            http_client: HTTP client instance for making requests.
        """
        self.http_client = http_client
    
    async def gather(self, target: ScanTarget) -> Dict[str, Any]:
        """
        Gather all basic information about the target.
        
        Args:
            target: Target to gather information about.
        
        Returns:
            Dictionary containing all gathered information.
        
        Raises:
            ModuleException: If gathering fails critically.
        """
        logger.info(f"Gathering basic information for {target.domain}")
        
        results = {
            'domain': target.domain,
            'url': target.url,
            'timestamp': datetime.utcnow().isoformat(),
        }
        
        # Gather information concurrently
        tasks = [
            self._get_http_headers(target.url),
            self._get_dns_records(target.domain),
            self._get_whois_info(target.domain),
            self._get_ssl_info(target.domain, target.port),
        ]
        
        try:
            http_info, dns_info, whois_info, ssl_info = await asyncio.gather(
                *tasks, return_exceptions=True
            )
            
            # Process results (handle exceptions)
            results['http_headers'] = http_info if not isinstance(http_info, Exception) else {}
            results['dns_records'] = dns_info if not isinstance(dns_info, Exception) else {}
            results['whois'] = whois_info if not isinstance(whois_info, Exception) else {}
            results['ssl_certificate'] = ssl_info if not isinstance(ssl_info, Exception) else {}
            
            # Log any errors
            for name, result in [('HTTP', http_info), ('DNS', dns_info), 
                                  ('WHOIS', whois_info), ('SSL', ssl_info)]:
                if isinstance(result, Exception):
                    logger.warning(f"{name} info gathering failed: {str(result)}")
            
            logger.info(f"Basic info gathering completed for {target.domain}")
            return results
            
        except Exception as e:
            logger.error(f"Basic info gathering failed: {str(e)}")
            raise ModuleException("basic_info", f"Failed to gather basic information: {str(e)}")
    
    async def _get_http_headers(self, url: str) -> Dict[str, Any]:
        """
        Fetch and parse HTTP headers from the target.
        
        Args:
            url: Target URL.
        
        Returns:
            Dictionary containing HTTP header information.
        """
        try:
            response = await self.http_client.get(url)
            
            # Extract server information
            server_info = self._get_server_info(response.headers)
            
            return {
                'status_code': response.status_code,
                'headers': response.headers,
                'server': server_info.get('server'),
                'powered_by': server_info.get('powered_by'),
                'response_time': response.response_time,
                'content_length': response.headers.get('content-length', 'unknown'),
                'content_type': response.headers.get('content-type', 'unknown'),
            }
        except Exception as e:
            logger.warning(f"Failed to fetch HTTP headers: {str(e)}")
            raise
    
    def _get_server_info(self, headers: Dict[str, str]) -> Dict[str, Optional[str]]:
        """
        Extract server information from HTTP headers.
        
        Args:
            headers: HTTP headers dictionary.
        
        Returns:
            Dictionary with server and powered_by information.
        """
        return {
            'server': headers.get('server'),
            'powered_by': headers.get('x-powered-by'),
            'aspnet_version': headers.get('x-aspnet-version'),
            'framework': headers.get('x-framework'),
        }
    
    async def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Query DNS records for the domain.
        
        Args:
            domain: Domain to query.
        
        Returns:
            Dictionary containing DNS records by type.
        """
        logger.debug(f"Querying DNS records for {domain}")
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
                logger.debug(f"Found {len(records[record_type])} {record_type} records")
            except dns.resolver.NoAnswer:
                records[record_type] = []
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain} does not exist")
                break
            except Exception as e:
                logger.debug(f"Failed to query {record_type} records: {str(e)}")
                records[record_type] = []
        
        return records
    
    async def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for the domain.
        
        Args:
            domain: Domain to lookup.
        
        Returns:
            Dictionary containing WHOIS information.
        """
        logger.debug(f"Performing WHOIS lookup for {domain}")
        
        try:
            # Run WHOIS in thread pool (it's blocking)
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            
            # Extract relevant information
            whois_data = {
                'domain_name': w.domain_name if hasattr(w, 'domain_name') else None,
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else [],
                'org': w.org if hasattr(w, 'org') else None,
            }
            
            logger.debug(f"WHOIS lookup completed for {domain}")
            return whois_data
            
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            raise
    
    async def _get_ssl_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Retrieve SSL certificate information.
        
        Args:
            domain: Domain to check.
            port: Port to connect to (default: 443).
        
        Returns:
            Dictionary containing SSL certificate information.
        """
        logger.debug(f"Retrieving SSL certificate for {domain}:{port}")
        
        try:
            # Run SSL connection in thread pool (it's blocking)
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(
                None, self._get_ssl_cert_sync, domain, port
            )
            
            return cert_info
            
        except Exception as e:
            logger.warning(f"SSL certificate retrieval failed: {str(e)}")
            raise
    
    def _get_ssl_cert_sync(self, domain: str, port: int) -> Dict[str, Any]:
        """
        Synchronous SSL certificate retrieval.
        
        Args:
            domain: Domain to check.
            port: Port to connect to.
        
        Returns:
            Dictionary containing certificate information.
        """
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract relevant information
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                    'cipher': ssock.cipher(),
                    'tls_version': ssock.version(),
                }
                
                return cert_info
