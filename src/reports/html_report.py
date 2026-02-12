"""
HTML report generator for VIPRecon.
Generates beautiful, interactive HTML reports from scan results.
"""

from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from src.core.models import ScanResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HTMLReportGenerator:
    """Generates HTML reports from scan results."""
    
    def __init__(self, output_dir: str = "./output"):
        """
        Initialize HTML report generator.
        
        Args:
            output_dir: Directory to save reports.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
    
    def generate(self, scan_result: ScanResult, filename: str = None) -> str:
        """
        Generate HTML report from scan results.
        
        Args:
            scan_result: Scan results to report.
            filename: Optional custom filename.
        
        Returns:
            Path to generated report file.
        """
        logger.info("Generating HTML report")
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self._sanitize_filename(scan_result.metadata.target)
            filename = f"viprecon_{target_name}_{timestamp}.html"
        
        # Ensure .html extension
        if not filename.endswith('.html'):
            filename += '.html'
        
        # Load template
        template = self.env.get_template('report_template.html')
        
        # Prepare template data
        template_data = self._prepare_template_data(scan_result)
        
        # Render template
        html_content = template.render(**template_data)
        
        # Write to file
        report_path = self.output_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to: {report_path}")
        return str(report_path)
    
    def _prepare_template_data(self, scan_result: ScanResult) -> dict:
        """
        Prepare data for template rendering.
        
        Args:
            scan_result: Scan results.
        
        Returns:
            Dictionary of template variables.
        """
        metadata = scan_result.metadata
        
        # Sort vulnerabilities by severity
        vulnerabilities_sorted = sorted(
            scan_result.vulnerabilities,
            key=lambda v: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(v.severity.value)
        )
        
        # Sort technologies by confidence
        technologies_sorted = sorted(
            scan_result.technologies,
            key=lambda t: t.confidence,
            reverse=True
        )
        
        # Sort subdomains (alive first)
        subdomains_sorted = sorted(
            scan_result.subdomains,
            key=lambda s: (not s.is_alive, s.name)
        )
        
        return {
            # Metadata
            'target': metadata.target,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration': f"{metadata.duration_seconds:.2f}",
            'version': metadata.tool_version,
            
            # Summary counts
            'technologies_count': len(scan_result.technologies),
            'subdomains_count': len(scan_result.subdomains),
            'endpoints_count': len(scan_result.endpoints),
            'vulnerabilities_count': len(scan_result.vulnerabilities),
            
            # Vulnerability breakdown
            'critical_count': scan_result.get_critical_count(),
            'high_count': scan_result.get_high_count(),
            'medium_count': scan_result.get_medium_count(),
            'low_count': scan_result.get_low_count(),
            
            # Detailed data
            'vulnerabilities': [self._format_vulnerability(v) for v in vulnerabilities_sorted],
            'technologies': [self._format_technology(t) for t in technologies_sorted],
            'subdomains': [self._format_subdomain(s) for s in subdomains_sorted],
            'endpoints': [self._format_endpoint(e) for e in scan_result.endpoints],
            'security_headers': [self._format_security_header(h) for h in scan_result.security_headers],
            'waf_detected': scan_result.waf_detected,
            'javascript_findings': scan_result.javascript_findings,
            'open_ports': scan_result.open_ports,
            'directory_items': scan_result.directory_items
        }
    
    def _format_vulnerability(self, vuln) -> dict:
        """Format vulnerability for template."""
        return {
            'type': vuln.type,
            'severity': vuln.severity.value,
            'description': vuln.description,
            'url': vuln.url,
            'parameter': vuln.parameter,
            'payload': vuln.payload,
            'proof': vuln.proof,
            'remediation': vuln.remediation,
            'cve': vuln.cve
        }
    
    def _format_technology(self, tech) -> dict:
        """Format technology for template."""
        return {
            'name': tech.name,
            'version': tech.version or 'Unknown',
            'category': tech.category or 'Unknown',
            'confidence': f"{tech.confidence:.0f}"
        }
    
    def _format_subdomain(self, subdomain) -> dict:
        """Format subdomain for template."""
        return {
            'name': subdomain.name,
            'ip_addresses': subdomain.ip_addresses,
            'status_code': subdomain.status_code,
            'is_alive': subdomain.is_alive
        }
    
    def _format_endpoint(self, endpoint) -> dict:
        """Format endpoint for template."""
        return {
            'path': endpoint.path,
            'method': endpoint.method,
            'source': endpoint.source,
            'status_code': endpoint.status_code
        }
    
    def _format_security_header(self, header) -> dict:
        """Format security header for template."""
        return {
            'header_name': header.header_name,
            'present': header.present,
            'value': header.value,
            'severity': header.severity.value,
            'recommendation': header.recommendation
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
