"""
Interactive shell for VIPRecon.
Provides an interactive mode for exploring scan results.
"""

import cmd
from typing import Optional, Dict, Any
from colorama import Fore, Style, init
from src.core.models import ScanResult, SeverityLevel

# Initialize colorama
init(autoreset=True)


class InteractiveShell(cmd.Cmd):
    """Interactive shell for exploring scan results."""
    
    intro = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗
║              VIPRecon Interactive Shell                       ║
╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

Type 'help' or '?' to list available commands.
Type 'exit' or 'quit' to exit the interactive shell.
    """
    
    prompt = f"{Fore.GREEN}viprecon>{Style.RESET_ALL} "
    
    def __init__(self, scan_result: ScanResult):
        """
        Initialize interactive shell.
        
        Args:
            scan_result: Scan results to explore.
        """
        super().__init__()
        self.scan_result = scan_result
        self.use_color = True
    
    def do_summary(self, arg):
        """Display scan summary."""
        print(f"\n{Fore.CYAN}Scan Summary{Style.RESET_ALL}")
        print("=" * 60)
        
        metadata = self.scan_result.metadata
        print(f"Target: {metadata.target}")
        print(f"Duration: {metadata.duration_seconds:.2f}s")
        print(f"Modules Run: {len(metadata.modules_run)}")
        
        print(f"\n{Fore.YELLOW}Findings:{Style.RESET_ALL}")
        print(f"  Technologies: {len(self.scan_result.technologies)}")
        print(f"  Subdomains: {len(self.scan_result.subdomains)}")
        print(f"  Endpoints: {len(self.scan_result.endpoints)}")
        print(f"  Vulnerabilities: {len(self.scan_result.vulnerabilities)}")
        
        if self.scan_result.vulnerabilities:
            print(f"\n{Fore.RED}Vulnerability Breakdown:{Style.RESET_ALL}")
            print(f"  Critical: {self.scan_result.get_critical_count()}")
            print(f"  High: {self.scan_result.get_high_count()}")
            print(f"  Medium: {self.scan_result.get_medium_count()}")
            print(f"  Low: {self.scan_result.get_low_count()}")
        
        print()
    
    def do_technologies(self, arg):
        """List detected technologies. Usage: technologies [category]"""
        techs = self.scan_result.technologies
        
        if not techs:
            print("No technologies detected.")
            return
        
        if arg:
            # Filter by category
            techs = [t for t in techs if t.category and arg.lower() in t.category.lower()]
            print(f"\n{Fore.CYAN}Technologies in category '{arg}':{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.CYAN}Detected Technologies:{Style.RESET_ALL}")
        
        for tech in sorted(techs, key=lambda t: t.confidence, reverse=True):
            confidence_color = Fore.GREEN if tech.confidence >= 80 else Fore.YELLOW
            print(f"  • {tech.name} ({confidence_color}{tech.confidence:.0f}%{Style.RESET_ALL}) - {tech.category}")
        
        print()
    
    def do_vulnerabilities(self, arg):
        """List vulnerabilities. Usage: vulnerabilities [severity]"""
        vulns = self.scan_result.vulnerabilities
        
        if not vulns:
            print(f"{Fore.GREEN}No vulnerabilities detected!{Style.RESET_ALL}")
            return
        
        if arg:
            # Filter by severity
            try:
                severity = SeverityLevel[arg.upper()]
                vulns = self.scan_result.get_vulnerabilities_by_severity(severity)
                print(f"\n{Fore.CYAN}{severity.value} Severity Vulnerabilities:{Style.RESET_ALL}")
            except KeyError:
                print(f"Invalid severity: {arg}. Use: critical, high, medium, low, info")
                return
        else:
            print(f"\n{Fore.CYAN}All Vulnerabilities:{Style.RESET_ALL}")
        
        for i, vuln in enumerate(vulns, 1):
            severity_color = self._get_severity_color(vuln.severity)
            print(f"\n{i}. {severity_color}[{vuln.severity.value}]{Style.RESET_ALL} {vuln.type}")
            print(f"   URL: {vuln.url}")
            if vuln.parameter:
                print(f"   Parameter: {vuln.parameter}")
            print(f"   {vuln.description}")
        
        print()
    
    def do_subdomains(self, arg):
        """List discovered subdomains. Usage: subdomains [alive|dead]"""
        subdomains = self.scan_result.subdomains
        
        if not subdomains:
            print("No subdomains discovered.")
            return
        
        if arg == "alive":
            subdomains = [s for s in subdomains if s.is_alive]
            print(f"\n{Fore.CYAN}Alive Subdomains:{Style.RESET_ALL}")
        elif arg == "dead":
            subdomains = [s for s in subdomains if not s.is_alive]
            print(f"\n{Fore.CYAN}Dead Subdomains:{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.CYAN}All Subdomains:{Style.RESET_ALL}")
        
        for subdomain in subdomains:
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if subdomain.is_alive else f"{Fore.RED}✗{Style.RESET_ALL}"
            ips = ", ".join(subdomain.ip_addresses[:2]) if subdomain.ip_addresses else "N/A"
            print(f"  {status} {subdomain.name} - {ips}")
        
        print()
    
    def do_endpoints(self, arg):
        """List discovered endpoints."""
        endpoints = self.scan_result.endpoints
        
        if not endpoints:
            print("No endpoints discovered.")
            return
        
        print(f"\n{Fore.CYAN}Discovered Endpoints:{Style.RESET_ALL}")
        
        for endpoint in endpoints[:50]:  # Limit to 50
            print(f"  • {endpoint.method} {endpoint.path}")
        
        if len(endpoints) > 50:
            print(f"\n  ... and {len(endpoints) - 50} more")
        
        print()
    
    def do_headers(self, arg):
        """Show security headers status."""
        headers = self.scan_result.security_headers
        
        if not headers:
            print("No security headers information available.")
            return
        
        present = [h for h in headers if h.present]
        missing = [h for h in headers if not h.present]
        
        print(f"\n{Fore.CYAN}Security Headers:{Style.RESET_ALL}")
        
        if present:
            print(f"\n{Fore.GREEN}Present:{Style.RESET_ALL}")
            for header in present:
                print(f"  ✓ {header.header_name}")
        
        if missing:
            print(f"\n{Fore.RED}Missing:{Style.RESET_ALL}")
            for header in missing:
                severity_color = self._get_severity_color(header.severity)
                print(f"  ✗ {header.header_name} {severity_color}[{header.severity.value}]{Style.RESET_ALL}")
        
        print()
    
    def do_waf(self, arg):
        """Show WAF detection results."""
        waf = self.scan_result.waf_detected
        
        if not waf:
            print("No WAF information available.")
            return
        
        print(f"\n{Fore.CYAN}WAF Detection:{Style.RESET_ALL}")
        
        if waf.get('detected'):
            print(f"  {Fore.YELLOW}WAF Detected:{Style.RESET_ALL} {waf.get('name', 'Unknown')}")
            print(f"  Confidence: {waf.get('confidence', 'unknown')}")
            if waf.get('evidence'):
                print(f"  Evidence: {waf.get('evidence')}")
        else:
            print(f"  {Fore.GREEN}No WAF detected{Style.RESET_ALL}")
        
        print()
    
    def do_export(self, arg):
        """Export results to file. Usage: export <filename>"""
        if not arg:
            print("Usage: export <filename>")
            return
        
        print(f"Exporting results to {arg}...")
        print("(Export functionality would be implemented here)")
        print()
    
    def do_search(self, arg):
        """Search in scan results. Usage: search <term>"""
        if not arg:
            print("Usage: search <term>")
            return
        
        term = arg.lower()
        results = []
        
        # Search in technologies
        for tech in self.scan_result.technologies:
            if term in tech.name.lower():
                results.append(f"Technology: {tech.name}")
        
        # Search in subdomains
        for subdomain in self.scan_result.subdomains:
            if term in subdomain.name.lower():
                results.append(f"Subdomain: {subdomain.name}")
        
        # Search in vulnerabilities
        for vuln in self.scan_result.vulnerabilities:
            if term in vuln.type.lower() or term in vuln.description.lower():
                results.append(f"Vulnerability: {vuln.type}")
        
        if results:
            print(f"\n{Fore.CYAN}Search results for '{arg}':{Style.RESET_ALL}")
            for result in results[:20]:
                print(f"  • {result}")
            if len(results) > 20:
                print(f"\n  ... and {len(results) - 20} more")
        else:
            print(f"No results found for '{arg}'")
        
        print()
    
    def do_exit(self, arg):
        """Exit the interactive shell."""
        print("Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit the interactive shell."""
        return self.do_exit(arg)
    
    def do_clear(self, arg):
        """Clear the screen."""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
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
    
    def emptyline(self):
        """Do nothing on empty line."""
        pass
    
    def default(self, line):
        """Handle unknown commands."""
        print(f"Unknown command: {line}. Type 'help' for available commands.")
