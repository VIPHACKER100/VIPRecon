"""
JSON report generator for VIPRecon.
Generates machine-readable JSON reports from scan results.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from src.core.models import ScanResult, Vulnerability, Technology, Subdomain, SecurityHeader, JavaScriptFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


class JSONReportGenerator:
    """Generates JSON reports from scan results."""
    
    def __init__(self, output_dir: str = "./output"):
        """
        Initialize JSON report generator.
        
        Args:
            output_dir: Directory to save reports.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, scan_result: ScanResult, filename: str = None) -> str:
        """
        Generate JSON report from scan results.
        
        Args:
            scan_result: Scan results to report.
            filename: Optional custom filename.
        
        Returns:
            Path to generated report file.
        """
        logger.info("Generating JSON report")
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self._sanitize_filename(scan_result.metadata.target)
            filename = f"viprecon_{target_name}_{timestamp}.json"
        
        # Ensure .json extension
        if not filename.endswith('.json'):
            filename += '.json'
        
        # Build report data
        report_data = self._build_report_data(scan_result)
        
        # Write to file
        report_path = self.output_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"JSON report saved to: {report_path}")
        return str(report_path)
    
    def _build_report_data(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Build report data dictionary.
        
        Args:
            scan_result: Scan results.
        
        Returns:
            Report data dictionary.
        """
        metadata = scan_result.metadata
        
        report = {
            "report_metadata": {
                "tool": "VIPRecon",
                "version": metadata.tool_version,
                "generated_at": datetime.now().isoformat(),
                "report_format": "json",
                "report_version": "1.0"
            },
            "scan_metadata": {
                "target": metadata.target,
                "start_time": metadata.start_time.isoformat(),
                "end_time": metadata.end_time.isoformat() if metadata.end_time else None,
                "duration_seconds": metadata.duration_seconds,
                "modules_run": metadata.modules_run,
                "modules_failed": metadata.modules_failed
            },
            "summary": {
                "technologies_count": len(scan_result.technologies),
                "subdomains_count": len(scan_result.subdomains),
                "endpoints_count": len(scan_result.endpoints),
                "vulnerabilities_count": len(scan_result.vulnerabilities),
                "critical_vulnerabilities": scan_result.get_critical_count(),
                "high_vulnerabilities": scan_result.get_high_count(),
                "medium_vulnerabilities": scan_result.get_medium_count(),
                "low_vulnerabilities": scan_result.get_low_count()
            },
            "target_information": scan_result.target_info,
            "technologies": [self._serialize_technology(t) for t in scan_result.technologies],
            "subdomains": [self._serialize_subdomain(s) for s in scan_result.subdomains],
            "endpoints": [self._serialize_endpoint(e) for e in scan_result.endpoints],
            "vulnerabilities": [self._serialize_vulnerability(v) for v in scan_result.vulnerabilities],
            "security_headers": [self._serialize_security_header(h) for h in scan_result.security_headers],
            "javascript_findings": [self._serialize_js_finding(j) for j in scan_result.javascript_findings],
            "open_ports": scan_result.open_ports,
            "directory_items": scan_result.directory_items,
            "waf_detection": scan_result.waf_detected
        }
        
        return report
    
    def _serialize_technology(self, tech: Technology) -> Dict[str, Any]:
        """Serialize Technology object."""
        return {
            "name": tech.name,
            "version": tech.version,
            "category": tech.category,
            "confidence": tech.confidence,
            "indicators": tech.indicators
        }
    
    def _serialize_subdomain(self, subdomain: Subdomain) -> Dict[str, Any]:
        """Serialize Subdomain object."""
        return {
            "name": subdomain.name,
            "ip_addresses": subdomain.ip_addresses,
            "status_code": subdomain.status_code,
            "is_alive": subdomain.is_alive,
            "technologies": [self._serialize_technology(t) for t in subdomain.technologies]
        }
    
    def _serialize_endpoint(self, endpoint) -> Dict[str, Any]:
        """Serialize Endpoint object."""
        return {
            "path": endpoint.path,
            "method": endpoint.method,
            "parameters": endpoint.parameters,
            "source": endpoint.source,
            "status_code": endpoint.status_code,
            "requires_auth": endpoint.requires_auth
        }
    
    def _serialize_vulnerability(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Serialize Vulnerability object."""
        return {
            "type": vuln.type,
            "severity": vuln.severity.value,
            "description": vuln.description,
            "url": vuln.url,
            "parameter": vuln.parameter,
            "payload": vuln.payload,
            "proof": vuln.proof,
            "remediation": vuln.remediation,
            "cve": vuln.cve
        }
    
    def _serialize_security_header(self, header: SecurityHeader) -> Dict[str, Any]:
        """Serialize SecurityHeader object."""
        return {
            "header_name": header.header_name,
            "present": header.present,
            "value": header.value,
            "severity": header.severity.value,
            "recommendation": header.recommendation
        }
    
    def _serialize_js_finding(self, finding: JavaScriptFinding) -> Dict[str, Any]:
        """Serialize JavaScriptFinding object."""
        return {
            "file_url": finding.file_url,
            "endpoints": finding.endpoints,
            "api_keys": finding.api_keys,
            "subdomains": finding.subdomains,
            "comments_count": len(finding.comments),
            "sensitive_data": finding.sensitive_data
        }
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename by removing invalid characters.
        
        Args:
            filename: Original filename.
        
        Returns:
            Sanitized filename.
        """
        # Remove protocol and special characters
        sanitized = filename.replace('https://', '').replace('http://', '')
        sanitized = sanitized.replace('/', '_').replace(':', '_')
        sanitized = ''.join(c for c in sanitized if c.isalnum() or c in ('_', '-', '.'))
        return sanitized[:50]  # Limit length
