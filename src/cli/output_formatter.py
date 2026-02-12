"""
Output formatter for VIPRecon.
Formats scan results for console display.
"""

from typing import List, Dict, Any
from colorama import Fore, Style, init
from src.core.models import (
    Vulnerability, SeverityLevel, Technology, Subdomain,
    SecurityHeader, Endpoint, JavaScriptFinding
)

# Initialize colorama
init(autoreset=True)


class OutputFormatter:
    """Formats scan results for console output."""
    
    def __init__(self, use_color: bool = True):
        """
        Initialize output formatter.
        
        Args:
            use_color: Whether to use colored output.
        """
        self.use_color = use_color
    
    def format_basic_info(self, info: Dict[str, Any]) -> str:
        """
        Format basic information results.
        
        Args:
            info: Basic information dictionary.
        
        Returns:
            Formatted string.
        """
        output = []
        
        output.append(self._section_header("Basic Information"))
        
        # HTTP Headers
        if 'http_headers' in info and info['http_headers']:
            output.append(self._subsection_header("HTTP Information"))
            http_info = info['http_headers']
            output.append(f"  Status Code: {http_info.get('status_code', 'N/A')}")
            output.append(f"  Server: {http_info.get('server', 'Not disclosed')}")
            output.append(f"  Powered By: {http_info.get('powered_by', 'Not disclosed')}")
            output.append(f"  Response Time: {http_info.get('response_time', 'N/A')}s")
            output.append("")
        
        # DNS Records
        if 'dns_records' in info and info['dns_records']:
            output.append(self._subsection_header("DNS Records"))
            dns = info['dns_records']
            for record_type, records in dns.items():
                if records:
                    output.append(f"  {record_type}:")
                    for record in records[:5]:  # Limit to 5
                        output.append(f"    • {record}")
            output.append("")
        
        # WHOIS
        if 'whois' in info and info['whois']:
            output.append(self._subsection_header("WHOIS Information"))
            whois = info['whois']
            output.append(f"  Registrar: {whois.get('registrar', 'N/A')}")
            output.append(f"  Creation Date: {whois.get('creation_date', 'N/A')}")
            output.append(f"  Expiration Date: {whois.get('expiration_date', 'N/A')}")
            output.append("")
        
        # SSL Certificate
        if 'ssl_certificate' in info and info['ssl_certificate']:
            output.append(self._subsection_header("SSL Certificate"))
            ssl = info['ssl_certificate']
            if 'subject' in ssl:
                output.append(f"  Subject: {ssl['subject'].get('commonName', 'N/A')}")
            if 'issuer' in ssl:
                output.append(f"  Issuer: {ssl['issuer'].get('organizationName', 'N/A')}")
            output.append(f"  Valid Until: {ssl.get('not_after', 'N/A')}")
            output.append("")
        
        return "\n".join(output)
    
    def format_technologies(self, technologies: List[Technology]) -> str:
        """
        Format technology fingerprinting results.
        
        Args:
            technologies: List of detected technologies.
        
        Returns:
            Formatted string.
        """
        output = []
        
        output.append(self._section_header(f"Detected Technologies ({len(technologies)})"))
        
        if not technologies:
            output.append("  No technologies detected.")
            return "\n".join(output)
        
        # Group by category
        by_category: Dict[str, List[Technology]] = {}
        for tech in technologies:
            category = tech.category or "Unknown"
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(tech)
        
        # Display by category
        for category, techs in sorted(by_category.items()):
            output.append(self._subsection_header(category))
            for tech in sorted(techs, key=lambda t: t.confidence, reverse=True):
                confidence_color = self._get_confidence_color(tech.confidence)
                confidence_str = self._colored(f"{tech.confidence:.0f}%", confidence_color)
                output.append(f"  • {tech.name} ({confidence_str})")
            output.append("")
        
        return "\n".join(output)
    
    def format_subdomains(self, subdomains: List[Subdomain]) -> str:
        """
        Format subdomain enumeration results.
        
        Args:
            subdomains: List of discovered subdomains.
        
        Returns:
            Formatted string.
        """
        output = []
        
        output.append(self._section_header(f"Discovered Subdomains ({len(subdomains)})"))
        
        if not subdomains:
            output.append("  No subdomains discovered.")
            return "\n".join(output)
        
        # Separate alive and dead subdomains
        alive = [s for s in subdomains if s.is_alive]
        dead = [s for s in subdomains if not s.is_alive]
        
        if alive:
            output.append(self._subsection_header(f"Alive ({len(alive)})"))
            for subdomain in alive[:20]:  # Limit to 20
                status = f"[{subdomain.status_code}]" if subdomain.status_code else "[???]"
                ips = ", ".join(subdomain.ip_addresses[:2]) if subdomain.ip_addresses else "N/A"
                output.append(f"  {self._colored('✓', Fore.GREEN)} {subdomain.name} {status} - {ips}")
            
            if len(alive) > 20:
                output.append(f"  ... and {len(alive) - 20} more")
            output.append("")
        
        if dead and len(dead) <= 10:
            output.append(self._subsection_header(f"Not Responding ({len(dead)})"))
            for subdomain in dead[:10]:
                output.append(f"  {self._colored('✗', Fore.RED)} {subdomain.name}")
            output.append("")
        
        return "\n".join(output)
    
    def format_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> str:
        """
        Format vulnerability scan results.
        
        Args:
            vulnerabilities: List of discovered vulnerabilities.
        
        Returns:
            Formatted string.
        """
        output = []
        
        output.append(self._section_header(f"Vulnerabilities ({len(vulnerabilities)})"))
        
        if not vulnerabilities:
            output.append(self._colored("  ✓ No vulnerabilities detected!", Fore.GREEN))
            return "\n".join(output)
        
        # Group by severity
        by_severity: Dict[SeverityLevel, List[Vulnerability]] = {}
        for vuln in vulnerabilities:
            if vuln.severity not in by_severity:
                by_severity[vuln.severity] = []
            by_severity[vuln.severity].append(vuln)
        
        # Display in severity order
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO
        ]
        
        for severity in severity_order:
            if severity not in by_severity:
                continue
            
            vulns = by_severity[severity]
            severity_color = self._get_severity_color(severity)
            
            output.append(self._subsection_header(
                f"{severity.value.upper()} ({len(vulns)})",
                severity_color
            ))
            
            for vuln in vulns:
                output.append(f"\n  {self._colored('⚠', severity_color)} {vuln.type}")
                output.append(f"     URL: {vuln.url}")
                if vuln.parameter:
                    output.append(f"     Parameter: {vuln.parameter}")
                output.append(f"     Description: {vuln.description}")
                if vuln.proof:
                    output.append(f"     Proof: {vuln.proof}")
            
            output.append("")
        
        return "\n".join(output)
    
    def format_security_headers(self, headers: List[SecurityHeader]) -> str:
        """
        Format security headers check results.
        
        Args:
            headers: List of security header check results.
        
        Returns:
            Formatted string.
        """
        output = []
        
        output.append(self._section_header("Security Headers"))
        
        present = [h for h in headers if h.present]
        missing = [h for h in headers if not h.present]
        
        if present:
            output.append(self._subsection_header(f"Present ({len(present)})"))
            for header in present:
                symbol = self._colored('✓', Fore.GREEN)
                output.append(f"  {symbol} {header.header_name}")
                if header.value:
                    output.append(f"     Value: {header.value[:80]}...")
                if header.recommendation:
                    output.append(f"     {self._colored('Note:', Fore.YELLOW)} {header.recommendation}")
            output.append("")
        
        if missing:
            output.append(self._subsection_header(f"Missing ({len(missing)})"))
            for header in missing:
                symbol = self._colored('✗', Fore.RED)
                severity_color = self._get_severity_color(header.severity)
                severity_str = self._colored(f"[{header.severity.value.upper()}]", severity_color)
                output.append(f"  {symbol} {header.header_name} {severity_str}")
                if header.recommendation:
                    output.append(f"     {header.recommendation}")
            output.append("")
        
        return "\n".join(output)
    
    def format_js_findings(self, findings: List[JavaScriptFinding]) -> str:
        """
        Format JavaScript analysis results.
        
        Args:
            findings: List of JavaScript findings.
        
        Returns:
            Formatted string.
        """
        output = []
        
        output.append(self._section_header(f"JavaScript Analysis ({len(findings)} files)"))
        
        if not findings:
            output.append("  No JavaScript files analyzed.")
            return "\n".join(output)
        
        # Count total findings
        total_endpoints = sum(len(f.endpoints) for f in findings)
        total_api_keys = sum(len(f.api_keys) for f in findings)
        total_subdomains = sum(len(f.subdomains) for f in findings)
        
        output.append(f"\nSummary:")
        output.append(f"  • Endpoints found: {total_endpoints}")
        output.append(f"  • Potential API keys: {total_api_keys}")
        output.append(f"  • Subdomains discovered: {total_subdomains}")
        
        # Show files with sensitive findings
        sensitive_files = [f for f in findings if f.api_keys or f.sensitive_data]
        
        if sensitive_files:
            output.append(self._subsection_header("Files with Sensitive Data", Fore.YELLOW))
            for finding in sensitive_files[:10]:
                output.append(f"\n  {finding.file_url}")
                if finding.api_keys:
                    output.append(f"    {self._colored('⚠ API Keys:', Fore.YELLOW)} {len(finding.api_keys)} found")
                if finding.sensitive_data:
                    output.append(f"    {self._colored('⚠ Sensitive Data:', Fore.YELLOW)} {len(finding.sensitive_data)} items")
        
        output.append("")
        return "\n".join(output)
    
    def _section_header(self, title: str) -> str:
        """Create a section header."""
        line = "=" * 60
        return f"\n{line}\n{self._colored(title, Fore.CYAN, bold=True)}\n{line}"
    
    def _subsection_header(self, title: str, color: str = Fore.YELLOW) -> str:
        """Create a subsection header."""
        return f"\n{self._colored(title, color, bold=True)}"
    
    def _colored(self, text: str, color: str, bold: bool = False) -> str:
        """
        Apply color to text.
        
        Args:
            text: Text to color.
            color: Color to apply.
            bold: Whether to make text bold.
        
        Returns:
            Colored text if color is enabled, otherwise plain text.
        """
        if not self.use_color:
            return text
        
        style = Style.BRIGHT if bold else ""
        return f"{style}{color}{text}{Style.RESET_ALL}"
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity level."""
        color_map = {
            SeverityLevel.CRITICAL: Fore.RED,
            SeverityLevel.HIGH: Fore.RED,
            SeverityLevel.MEDIUM: Fore.YELLOW,
            SeverityLevel.LOW: Fore.CYAN,
            SeverityLevel.INFO: Fore.WHITE,
        }
        return color_map.get(severity, Fore.WHITE)
    
    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for confidence level."""
        if confidence >= 80:
            return Fore.GREEN
        elif confidence >= 60:
            return Fore.YELLOW
        else:
            return Fore.RED
