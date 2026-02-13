"""
VIPRecon - Web Application Reconnaissance and Security Testing Tool
Developed by viphacker100 (Aryan Ahirwar)
Version: 1.1.0
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.cli.argument_parser import parse_arguments, get_module_list
from src.cli.progress import ProgressTracker
from src.cli.output_formatter import OutputFormatter
from src.cli.interactive import InteractiveShell
from src.core.orchestrator import ScanOrchestrator
from src.core.models import (
    ScanResult, ScanMetadata, Technology, Vulnerability, 
    Subdomain, Endpoint, JavaScriptFinding, SecurityHeader, SeverityLevel
)
from src.reports.report_manager import ReportManager
from src.utils.config_loader import ConfigLoader
from src.utils.logger import setup_logging, get_logger
from src.utils.notifications import NotificationManager
from src.utils.diff_engine import DiffEngine
import json

# Fix Windows encoding issues
if sys.platform == 'win32':
    # Force UTF-8 encoding for stdout/stderr
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
    else:
        # For older python versions that don't have reconfigure
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')


def main():
    """Main entry point."""
    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Setup logging
        log_level = 'DEBUG' if args.verbose else 'INFO'
        setup_logging(log_level=log_level, use_color=not args.no_color)
        
        logger = get_logger(__name__)

        # Handle Diff Mode
        if args.diff:
            _handle_diff_mode(args)
            sys.exit(0)

        # Standard Scan Mode (requires target)
        if not args.target:
            print("Error: The following arguments are required: -t/--target (or use --diff)")
            sys.exit(1)

        # Load configuration
        config_loader = ConfigLoader()
        if args.config:
            config = config_loader.load_config(args.config)
        else:
            config = config_loader.load_default_config()
        
        # Override config with CLI arguments
        config = _apply_cli_overrides(config, args)
        
        # Get module list
        modules = get_module_list(args.modules)
        
        # Initialize progress tracker
        progress = ProgressTracker(
            total_modules=len(modules),
            use_color=not args.no_color
        )
        
        # Print banner and legal notice
        progress.print_banner()
        progress.print_legal_notice()
        
        # Print scan info
        progress.print_scan_info(args.target, modules)
        
        # Run scan
        scan_result = asyncio.run(_run_scan(
            args.target,
            modules,
            config,
            progress,
            args
        ))
        
        # Print summary
        progress.print_summary()
        
        # Display results
        formatter = OutputFormatter(use_color=not args.no_color)
        _display_results(scan_result, formatter)
        
        # Generate reports
        if args.format in ['json', 'html', 'both']:
            _generate_reports(scan_result, args, progress)
        
        # Send notifications
        if args.webhook:
            asyncio.run(_send_notification(scan_result, args, progress))
        
        # Launch interactive mode if requested
        if args.interactive:
            progress.update_status("\nLaunching interactive shell...", 'info')
            shell = InteractiveShell(scan_result)
            shell.cmdloop()
        
        logger.info("VIPRecon completed successfully")
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        # Try to save checkpoint if scan_result exists
        if 'scan_result' in locals() and scan_result:
            print("Saving checkpoint before exit...")
            try:
                _save_checkpoint_on_interrupt(scan_result, args)
                print(f"Checkpoint saved. Resume with: python main.py -t {args.target} --resume {args.target}")
            except Exception as checkpoint_error:
                print(f"Warning: Could not save checkpoint: {checkpoint_error}")
        sys.exit(1)
    except Exception as e:
        error_msg = str(e)
        print(f"\n\nError: {error_msg}")
        
        # Provide helpful suggestions for common errors
        if "Module" in error_msg and "failed" in error_msg:
            print("\n💡 Tip: You can resume this scan using: --resume <target>")
        elif "Connection" in error_msg or "Timeout" in error_msg:
            print("\n💡 Tip: Try increasing --timeout or check your network connection")
        elif "SSL" in error_msg or "certificate" in error_msg:
            print("\n💡 Tip: Use --no-verify-ssl to bypass certificate verification (not recommended for production)")
        elif "Permission" in error_msg:
            print("\n💡 Tip: Check file permissions or run with appropriate privileges")
        elif "not found" in error_msg.lower():
            print("\n💡 Tip: Verify the file path exists and is accessible")
        
        # Show traceback in verbose mode
        try:
            verbose = args.verbose if 'args' in locals() else False
        except:
            verbose = False
        if verbose:
            import traceback
            print("\n--- Full Traceback ---")
            traceback.print_exc()
        
        sys.exit(1)


async def _run_scan(target: str, modules: list, config: dict, progress: ProgressTracker, args):
    """
    Run the scan asynchronously.
    """
    # Create orchestrator
    orchestrator = ScanOrchestrator(config)
    
    # Run scan
    scan_result = await orchestrator.scan(
        target_url=target,
        modules=modules,
        progress_callback=progress.update,
        resume_from=args.resume
    )
    
    return scan_result


def _apply_cli_overrides(config, args):
    """
    Apply CLI argument overrides to configuration.
    
    Args:
        config: Base configuration.
        args: Parsed CLI arguments.
    
    Returns:
        Updated configuration.
    """
    # Webhooks
    if hasattr(args, 'webhook') and args.webhook:
        config['webhook'] = args.webhook
    if hasattr(args, 'webhook_service') and args.webhook_service:
        config['webhook_service'] = args.webhook_service

    # Rate limiting
    if args.rate_limit:
        config['rate_limit'] = args.rate_limit
    
    # HTTP settings
    if args.timeout:
        config['http'] = config.get('http', {})
        config['http']['timeout'] = args.timeout
    
    if args.max_retries:
        config['http'] = config.get('http', {})
        config['http']['max_retries'] = args.max_retries
    
    if args.user_agent:
        config['user_agent'] = args.user_agent
    
    # Network settings
    if args.proxy:
        config['proxy'] = args.proxy
    
    if args.no_verify_ssl:
        config['no_verify_ssl'] = True
    
    # Output settings
    config['output_dir'] = args.output
    config['report_format'] = args.format
    
    return config


def _display_results(scan_result, formatter):
    """
    Display scan results to console.
    
    Args:
        scan_result: ScanResult object.
        formatter: OutputFormatter instance.
    """
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    
    # Display basic information
    if scan_result.target_info:
        print(formatter.format_basic_info(scan_result.target_info))
    
    # Display technologies
    if scan_result.technologies:
        print(formatter.format_technologies(scan_result.technologies))
    
    # Display vulnerabilities
    if scan_result.vulnerabilities is not None:
        print(formatter.format_vulnerabilities(scan_result.vulnerabilities))
    
    # Display subdomains
    if scan_result.subdomains:
        print(formatter.format_subdomains(scan_result.subdomains))
    
    # Display security headers
    if scan_result.security_headers:
        print(formatter.format_security_headers(scan_result.security_headers))
    
    # Display JavaScript findings
    if scan_result.javascript_findings:
        print(formatter.format_js_findings(scan_result.javascript_findings))
    
    # Display WAF detection
    if scan_result.waf_detected:
        print("\n" + "-" * 60)
        print("WAF DETECTION")
        print("-" * 60)
        waf = scan_result.waf_detected
        print(f"  Detected: {waf.get('detected', False)}")
        if waf.get('name'):
            print(f"  Name: {waf.get('name')}")
        if waf.get('confidence'):
            print(f"  Confidence: {waf.get('confidence')}")
    
    # Display open ports
    if scan_result.open_ports:
        print("\n" + "-" * 60)
        print(f"OPEN PORTS ({len(scan_result.open_ports)})")
        print("-" * 60)
        for port in scan_result.open_ports[:20]:  # Limit to 20
            port_num = port.get('port', 'N/A')
            service = port.get('service', 'unknown')
            print(f"  Port {port_num}: {service}")
        if len(scan_result.open_ports) > 20:
            print(f"  ... and {len(scan_result.open_ports) - 20} more")
    
    # Display directory items
    if scan_result.directory_items:
        print("\n" + "-" * 60)
        print(f"DIRECTORY ITEMS ({len(scan_result.directory_items)})")
        print("-" * 60)
        for item in scan_result.directory_items[:20]:  # Limit to 20
            url = item.get('url', 'N/A')
            status = item.get('status_code', 'N/A')
            print(f"  [{status}] {url}")
        if len(scan_result.directory_items) > 20:
            print(f"  ... and {len(scan_result.directory_items) - 20} more")
    
    # Display summary statistics
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Target: {scan_result.metadata.target}")
    print(f"  Duration: {scan_result.metadata.duration_seconds:.2f} seconds")
    print(f"  Modules Run: {len(scan_result.metadata.modules_run)}")
    if scan_result.metadata.modules_failed:
        print(f"  Modules Failed: {len(scan_result.metadata.modules_failed)}")
    
    # Vulnerability summary
    if scan_result.vulnerabilities:
        critical = scan_result.get_critical_count()
        high = scan_result.get_high_count()
        medium = scan_result.get_medium_count()
        low = scan_result.get_low_count()
        
        print(f"\n  Vulnerabilities Found: {len(scan_result.vulnerabilities)}")
        if critical > 0:
            print(f"    CRITICAL: {critical}")
        if high > 0:
            print(f"    HIGH: {high}")
        if medium > 0:
            print(f"    MEDIUM: {medium}")
        if low > 0:
            print(f"    LOW: {low}")

def _handle_diff_mode(args):
    """Handle the comparison of two JSON reports."""
    files = args.diff.split(',')
    if len(files) != 2:
        print("Error: --diff requires exactly two comma-separated files.")
        print("Example: python main.py --diff report1.json,report2.json")
        sys.exit(1)

    try:
        print(f"Loading reports...")
        print(f"  Old: {files[0]}")
        print(f"  New: {files[1]}")
        
        # Load JSON reports
        with open(files[0], 'r') as f:
            data1 = json.load(f)
        with open(files[1], 'r') as f:
            data2 = json.load(f)
        
        # Convert to ScanResult objects
        scan_result1 = _json_to_scan_result(data1)
        scan_result2 = _json_to_scan_result(data2)
        
        # Compare using DiffEngine
        diff = DiffEngine.compare(scan_result1, scan_result2)
        
        # Display results
        print(DiffEngine.format_diff_console(diff))
        
    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error comparing reports: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _json_to_scan_result(data: dict) -> 'ScanResult':
    """
    Convert JSON data to ScanResult object.
    
    Args:
        data: Dictionary containing scan result data.
        
    Returns:
        ScanResult object.
    """
    from datetime import datetime
    
    # Parse metadata
    metadata_data = data.get('metadata', {})
    metadata = ScanMetadata(
        target=metadata_data.get('target', 'unknown'),
        start_time=datetime.fromisoformat(metadata_data.get('start_time')) if metadata_data.get('start_time') else datetime.now(),
        end_time=datetime.fromisoformat(metadata_data.get('end_time')) if metadata_data.get('end_time') else None,
        duration_seconds=metadata_data.get('duration_seconds', 0.0),
        modules_run=metadata_data.get('modules_run', []),
        modules_failed=metadata_data.get('modules_failed', []),
        tool_version=metadata_data.get('tool_version', '1.1.0')
    )
    
    # Create ScanResult
    result = ScanResult(metadata=metadata)
    
    # Parse technologies
    for tech_data in data.get('technologies', []):
        result.technologies.append(Technology(**tech_data))
    
    # Parse vulnerabilities
    for vuln_data in data.get('vulnerabilities', []):
        if 'severity' in vuln_data and isinstance(vuln_data['severity'], str):
            vuln_data['severity'] = SeverityLevel(vuln_data['severity'])
        result.vulnerabilities.append(Vulnerability(**vuln_data))
    
    # Parse subdomains
    for sub_data in data.get('subdomains', []):
        result.subdomains.append(Subdomain(**sub_data))
    
    # Parse endpoints
    for ep_data in data.get('endpoints', []):
        result.endpoints.append(Endpoint(**ep_data))
    
    # Parse JavaScript findings
    for js_data in data.get('javascript_findings', []):
        result.javascript_findings.append(JavaScriptFinding(**js_data))
    
    # Parse security headers
    for header_data in data.get('security_headers', []):
        if 'severity' in header_data and isinstance(header_data['severity'], str):
            header_data['severity'] = SeverityLevel(header_data['severity'])
        result.security_headers.append(SecurityHeader(**header_data))
    
    # Parse other fields
    result.target_info = data.get('target_info', {})
    result.open_ports = data.get('open_ports', [])
    result.directory_items = data.get('directory_items', [])
    result.waf_detected = data.get('waf_detected')
    
    return result


def _generate_reports(scan_result, args, progress):
    """
    Generate scan reports.
    
    Args:
        scan_result: ScanResult object.
        args: CLI arguments.
        progress: Progress tracker.
    """
    progress.update_status("\nGenerating reports...", 'info')
    
    report_manager = ReportManager(args.output)
    
    # Determine formats
    if args.format == 'both':
        formats = ['json', 'html']
    else:
        formats = [args.format]
    
    # Generate reports
    reports = report_manager.generate_reports(scan_result, formats=formats)
    
    # Display report paths
    for format_type, path in reports.items():
        progress.update_status(f"{format_type.upper()} report: {path}", 'success')


async def _send_notification(scan_result, args, progress):
    """Send scan completion notification."""
    progress.update_status("\nSending notification...", 'info')
    
    service = getattr(args, 'webhook_service', 'generic')
    manager = NotificationManager(webhook_url=args.webhook, service=service)
    await manager.notify_scan_complete(scan_result)


def _save_checkpoint_on_interrupt(scan_result, args):
    """
    Save checkpoint when scan is interrupted.
    
    Args:
        scan_result: Current ScanResult object.
        args: CLI arguments.
    """
    from pathlib import Path
    from datetime import datetime
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    target_slug = args.target.replace('://', '_').replace('/', '_').replace(':', '_')
    checkpoint_path = output_dir / f"checkpoint_{target_slug}.json"
    
    def serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)
    
    checkpoint_data = {
        'metadata': scan_result.metadata.__dict__,
        'target_info': scan_result.target_info,
        'technologies': [t.__dict__ for t in scan_result.technologies],
        'vulnerabilities': [v.__dict__ for v in scan_result.vulnerabilities],
        'subdomains': [s.__dict__ for s in scan_result.subdomains],
        'endpoints': [e.__dict__ for e in scan_result.endpoints],
        'javascript_findings': [j.__dict__ for j in scan_result.javascript_findings],
        'security_headers': [h.__dict__ for h in scan_result.security_headers],
        'open_ports': scan_result.open_ports,
        'directory_items': scan_result.directory_items,
        'waf_detected': scan_result.waf_detected
    }
    
    # Process enums in vulnerabilities
    for v in checkpoint_data['vulnerabilities']:
        if 'severity' in v and hasattr(v['severity'], 'value'):
            v['severity'] = v['severity'].value
    
    with open(checkpoint_path, 'w', encoding='utf-8') as f:
        json.dump(checkpoint_data, f, indent=2, default=serializer)


if __name__ == '__main__':
    main()
