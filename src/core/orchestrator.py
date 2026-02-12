"""
Scan orchestrator for VIPRecon.
Coordinates the execution of all scanning modules.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from src.core.models import ScanTarget, ScanResult, ScanMetadata
from src.core.http_client import AsyncHTTPClient
from src.core.rate_limiter import RateLimiter
from src.core.exceptions import ReconException
from src.utils.logger import get_logger
from src.utils.validators import TargetValidator

# Import all modules
from src.modules.basic_info import BasicInfoGatherer
from src.modules.fingerprinting import TechnologyFingerprinter
from src.modules.subdomain_enum import SubdomainEnumerator
from src.modules.waf_detector import WAFDetector
from src.modules.api_discovery import APIDiscoverer
from src.modules.vuln_scanner import VulnerabilityScanner
from src.modules.cors_checker import CORSChecker
from src.modules.js_analyzer import JavaScriptAnalyzer
from src.modules.security_headers import SecurityHeaderChecker
from src.modules.port_scanner import PortScanner
from src.modules.directory_brute import DirectoryBruteForcer

logger = get_logger(__name__)


class ScanOrchestrator:
    """Orchestrates the execution of scanning modules."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize scan orchestrator.
        
        Args:
            config: Configuration dictionary.
        """
        self.config = config
        self.http_client: Optional[AsyncHTTPClient] = None
        self.rate_limiter: Optional[RateLimiter] = None
        
        # Module registry
        self.available_modules = {
            'basic_info': self._run_basic_info,
            'fingerprint': self._run_fingerprinting,
            'subdomain_enum': self._run_subdomain_enum,
            'waf_detect': self._run_waf_detection,
            'api_discovery': self._run_api_discovery,
            'vuln_scan': self._run_vulnerability_scan,
            'cors_check': self._run_cors_check,
            'js_analysis': self._run_js_analysis,
            'security_headers': self._run_security_headers,
            'port_scan': self._run_port_scan,
            'dir_brute': self._run_dir_brute
        }
    
    async def scan(
        self,
        target_url: str,
        modules: List[str] = None,
        progress_callback: callable = None,
        resume_from: Optional[str] = None
    ) -> ScanResult:
        """
        Execute scan on target.
        
        Args:
            target_url: Target URL to scan.
            modules: List of module names to run. If None, runs all.
            progress_callback: Optional callback for progress updates.
        
        Returns:
            ScanResult object with all findings.
        """
        start_time = datetime.now()
        
        logger.info(f"Starting scan of {target_url}")
        
        # Validate and parse target
        target = self._prepare_target(target_url)
        
        # Initialize HTTP client and rate limiter
        await self._initialize_clients()
        
        # Determine which modules to run
        if modules is None:
            modules = list(self.available_modules.keys())
        
        # Initialize scan result
        scan_result = ScanResult(
            metadata=ScanMetadata(
                target=target_url,
                start_time=start_time,
                modules_run=[],
                modules_failed=[]
            )
        )
        
        # Load from checkpoint if resuming
        if resume_from:
            scan_result = self._load_checkpoint(resume_from, scan_result)
            logger.info(f"Resuming scan from checkpoint. Already completed: {scan_result.metadata.modules_run}")
        
        # Run modules
        for module_name in modules:
            if module_name not in self.available_modules:
                logger.warning(f"Unknown module: {module_name}")
                continue
            
            # Skip if already completed (for resume)
            if module_name in scan_result.metadata.modules_run:
                logger.info(f"Skipping module {module_name} (already completed in checkpoint)")
                continue
            
            try:
                # Notify progress
                if progress_callback:
                    progress_callback('start', module_name)
                
                logger.info(f"Running module: {module_name}")
                
                # Execute module
                module_func = self.available_modules[module_name]
                await module_func(target, scan_result)
                
                scan_result.metadata.modules_run.append(module_name)
                
                # Notify completion
                if progress_callback:
                    progress_callback('complete', module_name, True)
                
                logger.info(f"Module {module_name} completed successfully")
                
                # Save checkpoint
                await self._save_checkpoint(scan_result)
                
            except Exception as e:
                logger.error(f"Module {module_name} failed: {str(e)}", exc_info=True)
                scan_result.metadata.modules_failed.append(module_name)
                
                if progress_callback:
                    progress_callback('complete', module_name, False)
        
        # Finalize scan
        scan_result.metadata.end_time = datetime.now()
        scan_result.metadata.duration_seconds = (
            scan_result.metadata.end_time - scan_result.metadata.start_time
        ).total_seconds()
        
        # Cleanup
        await self._cleanup_clients()
        
        logger.info(f"Scan completed in {scan_result.metadata.duration_seconds:.2f}s")
        
        # Clean up checkpoint on successful completion
        if self.config.get('save_checkpoints', True):
            self._cleanup_checkpoint(target_url)

        return scan_result

    def _load_checkpoint(self, checkpoint_id: str, current_result: ScanResult) -> ScanResult:
        """Load scan results from a checkpoint file."""
        output_config = self.config.get('output', {})
        if isinstance(output_config, str):
            output_dir = Path(output_config)
        else:
            output_dir = Path(output_config.get('directory', './output'))
        
        # If checkpoint_id is just a scan name or slug, try to find the file
        checkpoint_path = Path(checkpoint_id)
        if not checkpoint_path.exists():
            target_slug = checkpoint_id.replace('://', '_').replace('/', '_').replace(':', '_')
            checkpoint_path = output_dir / f"checkpoint_{target_slug}.json"
            
        if not checkpoint_path.exists():
            logger.warning(f"Checkpoint file not found: {checkpoint_path}")
            return current_result
            
        try:
            with open(checkpoint_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Merge data into current_result
            if 'metadata' in data:
                current_result.metadata.modules_run = data['metadata'].get('modules_run', [])
                current_result.metadata.modules_failed = data['metadata'].get('modules_failed', [])
            
            current_result.target_info = data.get('target_info', {})
            
            # Map dictionaries back to dataclasses
            from src.core.models import Technology, Vulnerability, Subdomain, Endpoint, JavaScriptFinding, SecurityHeader, SeverityLevel
            
            current_result.technologies = [Technology(**t) for t in data.get('technologies', [])]
            
            vulnerabilities = []
            for v_data in data.get('vulnerabilities', []):
                if 'severity' in v_data:
                    v_data['severity'] = SeverityLevel(v_data['severity'])
                vulnerabilities.append(Vulnerability(**v_data))
            current_result.vulnerabilities = vulnerabilities
            
            current_result.subdomains = [Subdomain(**s) for s in data.get('subdomains', [])]
            current_result.endpoints = [Endpoint(**e) for e in data.get('endpoints', [])]
            current_result.javascript_findings = [JavaScriptFinding(**j) for j in data.get('javascript_findings', [])]
            current_result.security_headers = [SecurityHeader(**h) for h in data.get('security_headers', [])]
            current_result.open_ports = data.get('open_ports', [])
            current_result.directory_items = data.get('directory_items', [])
            current_result.waf_detected = data.get('waf_detected')
            
            return current_result
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {str(e)}")
            return current_result

    def _cleanup_checkpoint(self, target_url: str) -> None:
        """Remove checkpoint file after successful scan."""
        output_config = self.config.get('output', {})
        if isinstance(output_config, str):
            output_dir = Path(output_config)
        else:
            output_dir = Path(output_config.get('directory', './output'))
        
        target_slug = target_url.replace('://', '_').replace('/', '_').replace(':', '_')
        checkpoint_path = output_dir / f"checkpoint_{target_slug}.json"
        
        if checkpoint_path.exists():
            try:
                checkpoint_path.unlink()
                logger.debug(f"Checkpoint file removed: {checkpoint_path}")
            except Exception as e:
                logger.warning(f"Failed to remove checkpoint file: {str(e)}")

    async def _save_checkpoint(self, result: ScanResult) -> None:
        """Save scan progress to a checkpoint file."""
        if not self.config.get('save_checkpoints', True):
            return
            
        output_config = self.config.get('output', {})
        if isinstance(output_config, str):
            output_dir = Path(output_config)
        else:
            output_dir = Path(output_config.get('directory', './output'))
            
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use a consistent filename for the current scan's checkpoint
        target_slug = result.metadata.target.replace('://', '_').replace('/', '_').replace(':', '_')
        checkpoint_path = output_dir / f"checkpoint_{target_slug}.json"
        
        try:
            # We need a custom encoder for datetime and other types
            def serializer(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                if hasattr(obj, '__dict__'):
                    return obj.__dict__
                return str(obj)
                
            checkpoint_data = {
                'metadata': result.metadata.__dict__,
                'target_info': result.target_info,
                'technologies': [t.__dict__ for t in result.technologies],
                'vulnerabilities': [v.__dict__ for v in result.vulnerabilities],
                'subdomains': [s.__dict__ for s in result.subdomains],
                'endpoints': [e.__dict__ for e in result.endpoints],
                'javascript_findings': [j.__dict__ for j in result.javascript_findings],
                'security_headers': [h.__dict__ for h in result.security_headers],
                'open_ports': result.open_ports,
                'directory_items': result.directory_items,
                'waf_detected': result.waf_detected
            }
            
            # Additional processing for enums in vulnerabilities
            for v in checkpoint_data['vulnerabilities']:
                if 'severity' in v and hasattr(v['severity'], 'value'):
                    v['severity'] = v['severity'].value

            with open(checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(checkpoint_data, f, indent=2, default=serializer)
                
            logger.debug(f"Checkpoint saved: {checkpoint_path}")
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {str(e)}")

    async def _run_port_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """Run port scanning."""
        scanner = PortScanner()
        ports = await scanner.scan(target.domain)
        result.open_ports = ports

    async def _run_dir_brute(self, target: ScanTarget, result: ScanResult) -> None:
        """Run directory brute-force."""
        forcer = DirectoryBruteForcer(self.http_client)
        items = await forcer.brute_force(target)
        result.directory_items = items
    
    def _prepare_target(self, target_url: str) -> ScanTarget:
        """
        Validate and prepare target.
        
        Args:
            target_url: Target URL or domain.
        
        Returns:
            ScanTarget object.
        """
        validator = TargetValidator()
        return validator.parse_target(target_url)
    
    async def _initialize_clients(self) -> None:
        """Initialize HTTP client and rate limiter."""
        # Create rate limiter
        rate_limit = self.config.get('rate_limit', 1.0)
        self.rate_limiter = RateLimiter(requests_per_second=rate_limit)
        
        # Prepare proxy URL
        proxy_config = self.config.get('proxy')
        proxy_url = None
        if isinstance(proxy_config, dict) and proxy_config.get('enabled'):
            proxy_url = proxy_config.get('url')
        elif isinstance(proxy_config, str):
            proxy_url = proxy_config

        # Create HTTP client
        http_config = self.config.get('http', {})
        self.http_client = AsyncHTTPClient(
            rate_limiter=self.rate_limiter,
            timeout=http_config.get('timeout', 30),
            max_retries=http_config.get('max_retries', 3),
            proxy=proxy_url,
            verify_ssl=not self.config.get('no_verify_ssl', False),
            user_agent=self.config.get('user_agent', 'VIPRecon/1.0')
        )
    
    async def _cleanup_clients(self) -> None:
        """Cleanup HTTP client."""
        if self.http_client:
            await self.http_client.close()
    
    # Module execution methods
    
    async def _run_basic_info(self, target: ScanTarget, result: ScanResult) -> None:
        """Run basic information gathering."""
        gatherer = BasicInfoGatherer(self.http_client)
        info = await gatherer.gather(target)
        result.target_info = info
    
    async def _run_fingerprinting(self, target: ScanTarget, result: ScanResult) -> None:
        """Run technology fingerprinting."""
        # First get the main page
        response = await self.http_client.get(target.url)
        
        fingerprinter = TechnologyFingerprinter()
        technologies = await fingerprinter.fingerprint(target, response)
        result.technologies = technologies
    
    async def _run_subdomain_enum(self, target: ScanTarget, result: ScanResult) -> None:
        """Run subdomain enumeration."""
        enumerator = SubdomainEnumerator(self.http_client)
        subdomains = await enumerator.enumerate(target.domain)
        result.subdomains = subdomains
    
    async def _run_waf_detection(self, target: ScanTarget, result: ScanResult) -> None:
        """Run WAF detection."""
        detector = WAFDetector(self.http_client)
        waf_info = await detector.detect(target)
        result.waf_detected = waf_info
    
    async def _run_api_discovery(self, target: ScanTarget, result: ScanResult) -> None:
        """Run API endpoint discovery."""
        # Get main page HTML
        response = await self.http_client.get(target.url)
        
        discoverer = APIDiscoverer(self.http_client)
        endpoints = await discoverer.discover(target, response.body)
        result.endpoints = endpoints
    
    async def _run_vulnerability_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """Run vulnerability scanning."""
        scanner = VulnerabilityScanner(self.http_client)
        vulnerabilities = await scanner.scan(target, result.endpoints)
        result.vulnerabilities = vulnerabilities
    
    async def _run_cors_check(self, target: ScanTarget, result: ScanResult) -> None:
        """Run CORS misconfiguration check."""
        checker = CORSChecker(self.http_client)
        cors_vulns = await checker.check(target)
        
        # Add CORS vulnerabilities to main vulnerability list
        result.vulnerabilities.extend(cors_vulns)
    
    async def _run_js_analysis(self, target: ScanTarget, result: ScanResult) -> None:
        """Run JavaScript analysis."""
        # Get main page HTML
        response = await self.http_client.get(target.url)
        
        analyzer = JavaScriptAnalyzer(self.http_client)
        js_findings = await analyzer.analyze(target, response.body)
        result.javascript_findings = js_findings
    
    async def _run_security_headers(self, target: ScanTarget, result: ScanResult) -> None:
        """Run security headers check."""
        checker = SecurityHeaderChecker(self.http_client)
        headers = await checker.check(target)
        result.security_headers = headers
