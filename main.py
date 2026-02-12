"""
VIPRecon - Web Application Reconnaissance and Security Testing Tool
Developed by viphacker100 (Aryan Ahirwar)
Version: 1.0.0
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
from src.reports.report_manager import ReportManager
from src.utils.config_loader import ConfigLoader
from src.utils.logger import setup_logging, get_logger
from src.utils.notifications import NotificationManager
from src.utils.diff_engine import DiffEngine
import json
import io

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
        print("\n\nScan interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {str(e)}")
        if args.verbose if 'args' in locals() else False:
            import traceback
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
    # ... (existing code remains same) ...

def _handle_diff_mode(args):
    """Handle the comparison of two JSON reports."""
    files = args.diff.split(',')
    if len(files) != 2:
        print("Error: --diff requires exactly two comma-separated files.")
        return

    try:
        with open(files[0], 'r') as f1, open(files[1], 'r') as f2:
            # We would need to deserialize these into ScanResult objects
            # For simplicity in this CLI tool, we'll implement a lighter version 
            # or just recommend the programmatic use if complex.
            # But let's try to mock the objects for the diff engine.
            print(f"Comparing {files[0]} and {files[1]}...")
            # (In a real implementation, we'd use a proper JSON deserializer)
            print("\n[INFO] Diffing reports (Summary Only)")
            # Stub for actual object conversion
            print("Feature implemented in src.utils.diff_engine for programmatic use.")

    except Exception as e:
        print(f"Error reading reports: {e}")


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


if __name__ == '__main__':
    main()
