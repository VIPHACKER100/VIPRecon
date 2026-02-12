"""
Directory brute-forcer module for VIPRecon.
Discovers hidden directories and files using wordlists.
"""

import asyncio
from typing import List, Dict, Any, Optional
from src.core.http_client import AsyncHTTPClient
from src.core.models import ScanTarget
from src.utils.logger import get_logger
from pathlib import Path

logger = get_logger(__name__)


class DirectoryBruteForcer:
    """Discovers directories and files using brute-force."""
    
    def __init__(self, http_client: AsyncHTTPClient, wordlist_path: Optional[str] = None):
        """
        Initialize directory brute-forcer.
        
        Args:
            http_client: HTTP client instance.
            wordlist_path: Path to the directory wordlist.
        """
        self.http_client = http_client
        self.wordlist_path = wordlist_path or str(Path(__file__).parent.parent.parent / "config" / "wordlists" / "common_dirs.txt")
        
    async def brute_force(self, target: ScanTarget) -> List[Dict[str, Any]]:
        """
        Perform directory/file brute-force.
        
        Args:
            target: Target to scan.
            
        Returns:
            List of discovered items with status codes.
        """
        wordlist = self._load_wordlist()
        if not wordlist:
            logger.warning("Directory wordlist is empty or not found.")
            return []
            
        logger.info(f"Starting directory brute-force for {target.url} ({len(wordlist)} items)")
        
        base_url = target.url.rstrip('/')
        results = []
        
        # Process in batches to control concurrency and manage memory
        batch_size = 20
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            tasks = []
            for item in batch:
                url = f"{base_url}/{item.lstrip('/')}"
                tasks.append(self._check_url(url))
            
            batch_results = await asyncio.gather(*tasks)
            results.extend([r for r in batch_results if r])
            
        logger.info(f"Directory brute-force completed. Found {len(results)} items.")
        return results

    async def _check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check if a URL exists and is interesting.
        """
        try:
            # We use HEAD first to save bandwidth
            response = await self.http_client.head(url, allow_redirects=False)
            
            # Interesting status codes: 200, 204, 301, 302, 307, 401, 403
            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', 'unknown')
                }
        except Exception:
            pass
        return None

    def _load_wordlist(self) -> List[str]:
        """
        Load directory wordlist from file.
        """
        path = Path(self.wordlist_path)
        if not path.exists():
            # Create a minimal default wordlist if it doesn't exist
            self._create_default_wordlist(path)
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            logger.error(f"Failed to load directory wordlist: {str(e)}")
            return []

    def _create_default_wordlist(self, path: Path) -> None:
        """
        Create a minimal default wordlist.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        default_items = [
            'admin', 'administrator', 'login', 'wp-admin', 'api', 'v1', 'v2', 
            'config', 'backup', 'backups', 'uploads', 'images', 'assets', 
            '.env', '.git', '.htaccess', 'server-status', 'phpinfo.php', 
            'robots.txt', 'sitemap.xml', 'test', 'dev', 'staging'
        ]
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(default_items))
            logger.info(f"Created default directory wordlist at {path}")
        except Exception as e:
            logger.error(f"Failed to create default wordlist: {str(e)}")
