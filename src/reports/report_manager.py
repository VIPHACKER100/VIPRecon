"""
Report manager for VIPRecon.
Coordinates report generation in multiple formats.
"""

from pathlib import Path
from typing import List, Optional
from src.core.models import ScanResult
from src.reports.json_report import JSONReportGenerator
from src.reports.html_report import HTMLReportGenerator
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ReportManager:
    """Manages report generation in multiple formats."""
    
    def __init__(self, output_dir: str = "./output"):
        """
        Initialize report manager.
        
        Args:
            output_dir: Directory to save reports.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize generators
        self.json_generator = JSONReportGenerator(output_dir)
        self.html_generator = HTMLReportGenerator(output_dir)
    
    def generate_reports(
        self,
        scan_result: ScanResult,
        formats: List[str] = None,
        filename_base: str = None
    ) -> dict:
        """
        Generate reports in specified formats.
        
        Args:
            scan_result: Scan results to report.
            formats: List of formats to generate ('json', 'html'). Default: both.
            filename_base: Base filename (without extension).
        
        Returns:
            Dictionary mapping format to file path.
        """
        if formats is None:
            formats = ['json', 'html']
        
        logger.info(f"Generating reports in formats: {', '.join(formats)}")
        
        generated_reports = {}
        
        # Generate JSON report
        if 'json' in formats:
            try:
                json_filename = f"{filename_base}.json" if filename_base else None
                json_path = self.json_generator.generate(scan_result, json_filename)
                generated_reports['json'] = json_path
                logger.info(f"JSON report generated: {json_path}")
            except Exception as e:
                logger.error(f"Failed to generate JSON report: {str(e)}")
        
        # Generate HTML report
        if 'html' in formats:
            try:
                html_filename = f"{filename_base}.html" if filename_base else None
                html_path = self.html_generator.generate(scan_result, html_filename)
                generated_reports['html'] = html_path
                logger.info(f"HTML report generated: {html_path}")
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {str(e)}")
        
        return generated_reports
    
    def generate_json(self, scan_result: ScanResult, filename: str = None) -> str:
        """
        Generate JSON report only.
        
        Args:
            scan_result: Scan results.
            filename: Optional filename.
        
        Returns:
            Path to generated report.
        """
        return self.json_generator.generate(scan_result, filename)
    
    def generate_html(self, scan_result: ScanResult, filename: str = None) -> str:
        """
        Generate HTML report only.
        
        Args:
            scan_result: Scan results.
            filename: Optional filename.
        
        Returns:
            Path to generated report.
        """
        return self.html_generator.generate(scan_result, filename)
    
    def list_reports(self) -> dict:
        """
        List all generated reports in the output directory.
        
        Returns:
            Dictionary with lists of JSON and HTML reports.
        """
        json_reports = list(self.output_dir.glob("*.json"))
        html_reports = list(self.output_dir.glob("*.html"))
        
        return {
            'json': [str(r) for r in sorted(json_reports, key=lambda x: x.stat().st_mtime, reverse=True)],
            'html': [str(r) for r in sorted(html_reports, key=lambda x: x.stat().st_mtime, reverse=True)]
        }
    
    def get_latest_report(self, format_type: str = 'html') -> Optional[str]:
        """
        Get path to the most recent report of specified format.
        
        Args:
            format_type: Report format ('json' or 'html').
        
        Returns:
            Path to latest report or None if no reports exist.
        """
        reports = self.list_reports()
        
        if format_type in reports and reports[format_type]:
            return reports[format_type][0]
        
        return None
    
    def cleanup_old_reports(self, keep_count: int = 10) -> int:
        """
        Remove old reports, keeping only the most recent ones.
        
        Args:
            keep_count: Number of reports to keep per format.
        
        Returns:
            Number of reports deleted.
        """
        logger.info(f"Cleaning up old reports, keeping {keep_count} most recent")
        
        deleted_count = 0
        reports = self.list_reports()
        
        for format_type, report_list in reports.items():
            if len(report_list) > keep_count:
                to_delete = report_list[keep_count:]
                
                for report_path in to_delete:
                    try:
                        Path(report_path).unlink()
                        deleted_count += 1
                        logger.debug(f"Deleted old report: {report_path}")
                    except Exception as e:
                        logger.warning(f"Failed to delete {report_path}: {str(e)}")
        
        logger.info(f"Cleanup complete: {deleted_count} reports deleted")
        return deleted_count
