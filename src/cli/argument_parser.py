"""
Command-line argument parser for VIPRecon.
Handles all CLI arguments and options.
"""

import argparse
from typing import Optional
from pathlib import Path


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description='VIPRecon - Web Application Reconnaissance and Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python main.py -t https://example.com
  
  # Scan specific modules
  python main.py -t example.com -m fingerprint,subdomain_enum,vuln_scan
  
  # Custom rate limit and output
  python main.py -t example.com --rate-limit 0.5 -o ./my_scans
  
  # Generate reports
  python main.py -t example.com -o ./my_scans -f both
  
  # Send notification to Slack
  python main.py -t example.com --webhook https://hooks.slack.com/... --webhook-service slack
  
  # Compare two scans
  python main.py --diff report1.json,report2.json

Legal Notice:
  This tool is for authorized security testing only. Unauthorized access
  to computer systems is illegal. Always obtain proper authorization before
  testing any system you do not own.
        """
    )
    
    # Required arguments
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '-t', '--target',
        type=str,
        help='Target URL or domain (e.g., https://example.com or example.com)'
    )
    
    # Tool modes
    mode_group = parser.add_argument_group('tool modes')
    mode_group.add_argument(
        '--diff',
        type=str,
        help='Compare two JSON reports (comma-separated, e.g., result1.json,result2.json)'
    )
    
    # Module selection
    module_group = parser.add_argument_group('module selection')
    module_group.add_argument(
        '-m', '--modules',
        type=str,
        default='all',
        help='Comma-separated list of modules to run. Available: basic_info, fingerprint, '
             'subdomain_enum, waf_detect, api_discovery, vuln_scan, cors_check, '
             'js_analysis, security_headers, port_scan, dir_brute. Default: all'
    )
    
    # Output options
    output_group = parser.add_argument_group('output options')
    output_group.add_argument(
        '-o', '--output',
        type=str,
        default='./output',
        help='Output directory for reports and logs (default: ./output)'
    )
    output_group.add_argument(
        '-f', '--format',
        type=str,
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format (default: both)'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging (DEBUG level)'
    )
    
    # Scan configuration
    scan_group = parser.add_argument_group('scan configuration')
    scan_group.add_argument(
        '--rate-limit',
        type=float,
        default=1.0,
        help='Requests per second (default: 1.0)'
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    scan_group.add_argument(
        '--max-retries',
        type=int,
        default=3,
        help='Maximum number of retry attempts (default: 3)'
    )
    scan_group.add_argument(
        '--user-agent',
        type=str,
        default='VIPRecon/1.0 (Security Scanner)',
        help='Custom User-Agent string'
    )
    
    # Network options
    network_group = parser.add_argument_group('network options')
    network_group.add_argument(
        '--proxy',
        type=str,
        help='Proxy URL (e.g., http://127.0.0.1:8080)'
    )
    network_group.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification (not recommended)'
    )
    
    # Notification options
    notify_group = parser.add_argument_group('notification options')
    notify_group.add_argument(
        '--webhook',
        type=str,
        help='Webhook URL for scan completion notifications'
    )
    notify_group.add_argument(
        '--webhook-service',
        type=str,
        choices=['slack', 'discord', 'generic'],
        default='generic',
        help='Type of webhook service (default: generic)'
    )
    
    # Authentication options
    auth_group = parser.add_argument_group('authentication options')
    auth_group.add_argument(
        '--auth-type',
        type=str,
        choices=['basic', 'bearer', 'cookie'],
        help='Authentication type'
    )
    auth_group.add_argument(
        '--auth-username',
        type=str,
        help='Username for basic authentication'
    )
    auth_group.add_argument(
        '--auth-password',
        type=str,
        help='Password for basic authentication'
    )
    auth_group.add_argument(
        '--auth-token',
        type=str,
        help='Token for bearer authentication'
    )
    auth_group.add_argument(
        '--auth-cookie',
        type=str,
        help='Cookie string for cookie authentication'
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group('advanced options')
    advanced_group.add_argument(
        '--config',
        type=str,
        help='Path to custom configuration file (YAML)'
    )
    advanced_group.add_argument(
        '--wordlist',
        type=str,
        help='Path to custom wordlist for subdomain enumeration'
    )
    advanced_group.add_argument(
        '--interactive',
        action='store_true',
        help='Launch interactive mode after scan completion'
    )
    advanced_group.add_argument(
        '--resume',
        type=str,
        help='Resume scan from checkpoint (provide scan ID)'
    )
    advanced_group.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Version
    parser.add_argument(
        '--version',
        action='version',
        version='VIPRecon 1.1.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    _validate_arguments(args)
    
    return args


def _validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate parsed arguments.
    
    Args:
        args: Parsed arguments.
    
    Raises:
        argparse.ArgumentTypeError: If validation fails.
    """
    # Validate rate limit
    if args.rate_limit <= 0:
        raise argparse.ArgumentTypeError("Rate limit must be greater than 0")
    
    # Validate timeout
    if args.timeout <= 0:
        raise argparse.ArgumentTypeError("Timeout must be greater than 0")
    
    # Validate max retries
    if args.max_retries < 0:
        raise argparse.ArgumentTypeError("Max retries cannot be negative")
    
    # Validate output directory
    output_path = Path(args.output)
    if output_path.exists() and not output_path.is_dir():
        raise argparse.ArgumentTypeError(f"Output path exists but is not a directory: {args.output}")
    
    # Validate config file if provided
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            raise argparse.ArgumentTypeError(f"Config file not found: {args.config}")
        if not config_path.is_file():
            raise argparse.ArgumentTypeError(f"Config path is not a file: {args.config}")
    
    # Validate wordlist if provided
    if args.wordlist:
        wordlist_path = Path(args.wordlist)
        if not wordlist_path.exists():
            raise argparse.ArgumentTypeError(f"Wordlist file not found: {args.wordlist}")
        if not wordlist_path.is_file():
            raise argparse.ArgumentTypeError(f"Wordlist path is not a file: {args.wordlist}")
    
    # Validate authentication options
    if args.auth_type == 'basic':
        if not args.auth_username or not args.auth_password:
            raise argparse.ArgumentTypeError("Basic auth requires --auth-username and --auth-password")
    elif args.auth_type == 'bearer':
        if not args.auth_token:
            raise argparse.ArgumentTypeError("Bearer auth requires --auth-token")
    elif args.auth_type == 'cookie':
        if not args.auth_cookie:
            raise argparse.ArgumentTypeError("Cookie auth requires --auth-cookie")
    
    # Validate modules
    if args.modules != 'all':
        valid_modules = {
            'basic_info', 'fingerprint', 'subdomain_enum', 'waf_detect',
            'api_discovery', 'vuln_scan', 'cors_check', 'js_analysis',
            'security_headers', 'port_scan', 'dir_brute'
        }
        
        requested_modules = [m.strip() for m in args.modules.split(',')]
        invalid_modules = set(requested_modules) - valid_modules
        
        if invalid_modules:
            raise argparse.ArgumentTypeError(
                f"Invalid modules: {', '.join(invalid_modules)}. "
                f"Valid modules: {', '.join(sorted(valid_modules))}"
            )


def get_module_list(modules_arg: str) -> list:
    """
    Parse modules argument into list.
    
    Args:
        modules_arg: Modules argument string.
    
    Returns:
        List of module names.
    """
    if modules_arg == 'all':
        return [
            'basic_info',
            'fingerprint',
            'subdomain_enum',
            'waf_detect',
            'api_discovery',
            'vuln_scan',
            'cors_check',
            'js_analysis',
            'security_headers',
            'port_scan',
            'dir_brute'
        ]
    else:
        return [m.strip() for m in modules_arg.split(',')]
