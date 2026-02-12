"""
Subdomain enumeration module for VIPRecon.
Discovers subdomains using DNS brute-force and certificate transparency.
"""

import asyncio
import aiohttp
from pathlib import Path
from typing import List, Set, Optional
import dns.resolver
from src.core.models import Subdomain, ScanTarget
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SubdomainEnumerator:
    """Enumerates subdomains for a target domain."""
    
    def __init__(self, http_client: AsyncHTTPClient, max_subdomains: int = 1000):
        """
        Initialize subdomain enumerator.
        
        Args:
            http_client: HTTP client for checking subdomain availability.
            max_subdomains: Maximum number of subdomains to discover.
        """
        self.http_client = http_client
        self.max_subdomains = max_subdomains
        self.wordlist = self._load_wordlist()
    
    def _load_wordlist(self) -> List[str]:
        """
        Load subdomain wordlist from file.
        
        Returns:
            List of subdomain names to try.
        """
        try:
            wordlist_path = Path(__file__).parent.parent.parent / "config" / "wordlists" / "subdomains.txt"
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            logger.debug(f"Loaded {len(wordlist)} subdomain names from wordlist")
            return wordlist
        except Exception as e:
            logger.warning(f"Failed to load wordlist: {str(e)}, using defaults")
            return ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test']
    
    async def enumerate(self, domain: str) -> List[Subdomain]:
        """
        Enumerate subdomains for the target domain.
        
        Args:
            domain: Target domain to enumerate.
        
        Returns:
            List of discovered subdomains.
        """
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        discovered: Set[str] = set()
        
        try:
            # Run enumeration methods concurrently
            tasks = [
                self._brute_force_dns(domain, self.wordlist),
                self._certificate_transparency(domain),
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            for result in results:
                if isinstance(result, list):
                    discovered.update(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Enumeration method failed: {str(result)}")
            
            # Deduplicate and limit
            discovered = self._deduplicate_results(list(discovered))
            if len(discovered) > self.max_subdomains:
                logger.warning(f"Found {len(discovered)} subdomains, limiting to {self.max_subdomains}")
                discovered = discovered[:self.max_subdomains]
            
            logger.info(f"Found {len(discovered)} unique subdomains")
            
            # Resolve and check each subdomain
            subdomains = await self._resolve_subdomains(discovered)
            
            logger.info(f"Successfully resolved {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {str(e)}")
            raise ModuleException("subdomain_enum", f"Failed to enumerate subdomains: {str(e)}")
    
    async def _brute_force_dns(self, domain: str, wordlist: List[str]) -> List[str]:
        """
        Brute-force DNS queries to find subdomains.
        
        Args:
            domain: Target domain.
            wordlist: List of subdomain names to try.
        
        Returns:
            List of discovered subdomain names.
        """
        logger.debug(f"Starting DNS brute-force for {domain}")
        
        discovered = []
        
        # Create tasks for DNS resolution
        tasks = []
        for subdomain_name in wordlist:
            full_domain = f"{subdomain_name}.{domain}"
            tasks.append(self._check_dns_exists(full_domain))
        
        # Execute in batches to avoid overwhelming DNS server
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for subdomain in results:
                if subdomain and not isinstance(subdomain, Exception):
                    discovered.append(subdomain)
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        logger.debug(f"DNS brute-force found {len(discovered)} subdomains")
        return discovered
    
    async def _check_dns_exists(self, subdomain: str) -> Optional[str]:
        """
        Check if a subdomain exists via DNS query.
        
        Args:
            subdomain: Full subdomain to check.
        
        Returns:
            Subdomain name if it exists, None otherwise.
        """
        try:
            loop = asyncio.get_event_loop()
            # Run DNS query in thread pool
            await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(subdomain, 'A')
            )
            return subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None
        except Exception:
            return None
    
    async def _certificate_transparency(self, domain: str) -> List[str]:
        """
        Query certificate transparency logs for subdomains.
        
        Args:
            domain: Target domain.
        
        Returns:
            List of discovered subdomains.
        """
        logger.debug(f"Querying certificate transparency for {domain}")
        
        discovered = set()
        
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Split by newlines (crt.sh returns multiple names)
                            names = name_value.split('\n')
                            
                            for name in names:
                                name = name.strip()
                                # Only include subdomains of target domain
                                if name.endswith(f'.{domain}') and '*' not in name:
                                    discovered.add(name)
            
            logger.debug(f"Certificate transparency found {len(discovered)} subdomains")
            return list(discovered)
            
        except Exception as e:
            logger.warning(f"Certificate transparency query failed: {str(e)}")
            return []
    
    def _deduplicate_results(self, subdomains: List[str]) -> List[str]:
        """
        Remove duplicate subdomains.
        
        Args:
            subdomains: List of subdomain names.
        
        Returns:
            Deduplicated list.
        """
        # Convert to set and back to list
        unique = list(set(subdomains))
        # Sort for consistent output
        unique.sort()
        return unique
    
    async def _resolve_subdomains(self, subdomain_names: List[str]) -> List[Subdomain]:
        """
        Resolve IP addresses and check HTTP status for subdomains.
        
        Args:
            subdomain_names: List of subdomain names to resolve.
        
        Returns:
            List of Subdomain objects with resolution info.
        """
        logger.debug(f"Resolving {len(subdomain_names)} subdomains")
        
        tasks = [self._resolve_subdomain(name) for name in subdomain_names]
        
        # Execute in batches
        batch_size = 20
        subdomains = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    subdomains.append(result)
        
        return subdomains
    
    async def _resolve_subdomain(self, subdomain: str) -> Optional[Subdomain]:
        """
        Resolve a single subdomain and check if it's alive.
        
        Args:
            subdomain: Subdomain name to resolve.
        
        Returns:
            Subdomain object if successful, None otherwise.
        """
        try:
            # Resolve IP addresses
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(subdomain, 'A')
            )
            
            ip_addresses = [str(rdata) for rdata in answers]
            
            # Try to check HTTP status
            status_code = None
            is_alive = False
            
            try:
                url = f"https://{subdomain}"
                response = await self.http_client.head(url, allow_redirects=True)
                status_code = response.status_code
                is_alive = True
            except Exception:
                # Try HTTP if HTTPS fails
                try:
                    url = f"http://{subdomain}"
                    response = await self.http_client.head(url, allow_redirects=True)
                    status_code = response.status_code
                    is_alive = True
                except Exception:
                    pass
            
            return Subdomain(
                name=subdomain,
                ip_addresses=ip_addresses,
                status_code=status_code,
                is_alive=is_alive
            )
            
        except Exception as e:
            logger.debug(f"Failed to resolve {subdomain}: {str(e)}")
            return None
