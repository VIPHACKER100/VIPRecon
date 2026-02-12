"""
Diff engine for VIPRecon.
Compares two scan results to identify changes.
"""

from typing import Dict, List, Any, Set
from src.core.models import ScanResult

class DiffEngine:
    """Compares two scan results to find additions, removals, or changes."""

    @staticmethod
    def compare(old_result: ScanResult, new_result: ScanResult) -> Dict[str, Any]:
        """
        Compare two scan results.
        
        Args:
            old_result: The previous scan result.
            new_result: The current scan result.
            
        Returns:
            A dictionary containing the differences.
        """
        diff = {
            "target": new_result.metadata.target,
            "new_vulnerabilities": [],
            "resolved_vulnerabilities": [],
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_technologies": [],
            "removed_technologies": []
        }

        # Compare Subdomains
        old_subs = {s.name for s in old_result.subdomains}
        new_subs = {s.name for s in new_result.subdomains}
        diff["new_subdomains"] = list(new_subs - old_subs)
        diff["removed_subdomains"] = list(old_subs - new_subs)

        # Compare Technologies
        old_techs = {t.name for t in old_result.technologies}
        new_techs = {t.name for t in new_result.technologies}
        diff["new_technologies"] = list(new_techs - old_techs)
        diff["removed_technologies"] = list(old_techs - new_techs)

        # Compare Vulnerabilities (by type and payload)
        old_vulns = {(v.type, v.url, v.payload) for v in old_result.vulnerabilities}
        new_vulns = {(v.type, v.url, v.payload) for v in new_result.vulnerabilities}
        
        added_vulns = new_vulns - old_vulns
        removed_vulns = old_vulns - new_vulns

        # Map back to objects for better reporting
        for v in new_result.vulnerabilities:
            if (v.type, v.url, v.payload) in added_vulns:
                diff["new_vulnerabilities"].append(v)
        
        for v in old_result.vulnerabilities:
            if (v.type, v.url, v.payload) in removed_vulns:
                diff["resolved_vulnerabilities"].append(v)

        return diff

    @staticmethod
    def format_diff_console(diff: Dict[str, Any]) -> str:
        """Format the diff for console output."""
        output = [f"\n--- Scan Diff for {diff['target']} ---"]
        
        if diff["new_vulnerabilities"]:
            output.append(f"🔴 NEW VULNERABILITIES: {len(diff['new_vulnerabilities'])}")
            for v in diff["new_vulnerabilities"]:
                output.append(f"  - {v.type} on {v.url}")
        
        if diff["resolved_vulnerabilities"]:
            output.append(f"🟢 RESOLVED: {len(diff['resolved_vulnerabilities'])}")
            
        if diff["new_subdomains"]:
            output.append(f"🌐 NEW SUBDOMAINS: {', '.join(diff['new_subdomains'])}")
            
        if not any([diff["new_vulnerabilities"], diff["new_subdomains"], diff["new_technologies"]]):
            output.append("✨ No significant changes detected since last scan.")
            
        return "\n".join(output)
