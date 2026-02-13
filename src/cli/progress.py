"""
Progress tracker for VIPRecon scans.
Displays real-time progress information during scanning.
"""

import sys
from typing import Optional, Dict
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for Windows support
init(autoreset=True)


class ProgressTracker:
    """Tracks and displays scan progress."""
    
    def __init__(self, total_modules: int, use_color: bool = True):
        """
        Initialize progress tracker.
        
        Args:
            total_modules: Total number of modules to run.
            use_color: Whether to use colored output.
        """
        self.total_modules = total_modules
        self.completed_modules = 0
        self.current_module = None
        self.start_time = datetime.now()
        self.use_color = use_color
        self.module_status: Dict[str, str] = {}
    
    def start_module(self, module_name: str) -> None:
        """
        Mark a module as started.
        
        Args:
            module_name: Name of the module.
        """
        self.current_module = module_name
        self.module_status[module_name] = 'running'
        self._print_status(f"Starting {module_name}...", Fore.CYAN)
    
    def complete_module(self, module_name: str, success: bool = True) -> None:
        """
        Mark a module as completed.
        
        Args:
            module_name: Name of the module.
            success: Whether the module completed successfully.
        """
        self.completed_modules += 1
        self.module_status[module_name] = 'success' if success else 'failed'
        
        status_text = "✓" if success else "✗"
        color = Fore.GREEN if success else Fore.RED
        
        self._print_status(
            f"{status_text} {module_name} completed ({self.completed_modules}/{self.total_modules})",
            color
        )
        
        self.current_module = None
    
    def update(self, event: str, module_name: str, success: Optional[bool] = None) -> None:
        """
        Unified update method for callbacks.
        
        Args:
            event: Event type ('start' or 'complete').
            module_name: Name of the module.
            success: Whether the module completed successfully (for 'complete' event).
        """
        if event == 'start':
            self.start_module(module_name)
        elif event == 'complete':
            self.complete_module(module_name, success if success is not None else True)
    
    def update_status(self, message: str, level: str = 'info') -> None:
        """
        Update status with a message.
        
        Args:
            message: Status message.
            level: Message level (info, warning, error, success).
        """
        color_map = {
            'info': Fore.CYAN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'success': Fore.GREEN,
        }
        
        color = color_map.get(level, Fore.WHITE)
        self._print_status(message, color)
    
    def print_summary(self) -> None:
        """Print scan completion summary."""
        elapsed_time = datetime.now() - self.start_time
        
        success_count = sum(1 for status in self.module_status.values() if status == 'success')
        failed_count = sum(1 for status in self.module_status.values() if status == 'failed')
        
        print("\n" + "=" * 60)
        self._print_colored("Scan Complete!", Fore.GREEN, bold=True)
        print("=" * 60)
        
        print(f"\nElapsed Time: {elapsed_time}")
        print(f"Total Modules: {self.total_modules}")
        
        self._print_colored(f"✓ Successful: {success_count}", Fore.GREEN)
        
        if failed_count > 0:
            self._print_colored(f"✗ Failed: {failed_count}", Fore.RED)
        
        print("\nModule Status:")
        for module_name, status in self.module_status.items():
            if status == 'success':
                self._print_colored(f"  ✓ {module_name}", Fore.GREEN)
            elif status == 'failed':
                self._print_colored(f"  ✗ {module_name}", Fore.RED)
            else:
                self._print_colored(f"  ⊙ {module_name}", Fore.YELLOW)
        
        print()
    
    def print_banner(self) -> None:
        """Print VIPRecon banner."""
        banner = r"""
 _    _____ _____  ____                      
| |  / /  _/ __ \/ __ \___  _________  ____  
| | / // // /_/ / /_/ / _ \/ ___/ __ \/ __ \ 
| |/ // // ____/ _, _/  __/ /__/ /_/ / / / / 
|___/___/_/   /_/ |_|\___/\___/\____/_/ /_/  
                                              
Web Application Reconnaissance & Security Testing Tool
Version 1.1.0 | Developed by viphacker100 (Aryan Ahirwar)
        """
        
        self._print_colored(banner, Fore.CYAN, bold=True)
        print()
    
    def print_legal_notice(self) -> None:
        """Print legal notice."""
        notice = """
╔════════════════════════════════════════════════════════════════╗
║                         LEGAL NOTICE                           ║
╚════════════════════════════════════════════════════════════════╝

This tool is designed for authorized security testing and research
purposes only. Unauthorized access to computer systems is illegal.

By using this tool, you agree to:
  • Only test systems you own or have explicit permission to test
  • Comply with all applicable laws and regulations
  • Use the tool responsibly and ethically

The developers assume no liability for misuse of this tool.
        """
        
        self._print_colored(notice, Fore.YELLOW)
        print()
    
    def print_scan_info(self, target: str, modules: list) -> None:
        """
        Print scan information.
        
        Args:
            target: Target URL/domain.
            modules: List of modules to run.
        """
        print("=" * 60)
        self._print_colored("Scan Configuration", Fore.CYAN, bold=True)
        print("=" * 60)
        
        print(f"\nTarget: {target}")
        print(f"Modules: {len(modules)}")
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\nModules to run:")
        for module in modules:
            print(f"  • {module}")
        
        print("\n" + "=" * 60 + "\n")
    
    def _print_status(self, message: str, color: str) -> None:
        """
        Print status message with timestamp.
        
        Args:
            message: Message to print.
            color: Color to use.
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if self.use_color:
            print(f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL} {color}{message}{Style.RESET_ALL}")
        else:
            print(f"[{timestamp}] {message}")
    
    def _print_colored(self, text: str, color: str, bold: bool = False) -> None:
        """
        Print colored text.
        
        Args:
            text: Text to print.
            color: Color to use.
            bold: Whether to make text bold.
        """
        if self.use_color:
            style = Style.BRIGHT if bold else ""
            print(f"{style}{color}{text}{Style.RESET_ALL}")
        else:
            print(text)
    
    def get_progress_percentage(self) -> float:
        """
        Get current progress percentage.
        
        Returns:
            Progress percentage (0-100).
        """
        if self.total_modules == 0:
            return 0.0
        return (self.completed_modules / self.total_modules) * 100
    
    def get_elapsed_time(self) -> str:
        """
        Get elapsed time as formatted string.
        
        Returns:
            Formatted elapsed time.
        """
        elapsed = datetime.now() - self.start_time
        total_seconds = int(elapsed.total_seconds())
        
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


class SpinnerProgress:
    """Simple spinner for long-running operations."""
    
    SPINNER_CHARS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    
    def __init__(self, message: str = "Processing", use_color: bool = True):
        """
        Initialize spinner.
        
        Args:
            message: Message to display.
            use_color: Whether to use colored output.
        """
        self.message = message
        self.use_color = use_color
        self.index = 0
        self.running = False
    
    def spin(self) -> None:
        """Display next spinner frame."""
        if not self.running:
            return
        
        char = self.SPINNER_CHARS[self.index % len(self.SPINNER_CHARS)]
        
        if self.use_color:
            sys.stdout.write(f'\r{Fore.CYAN}{char}{Style.RESET_ALL} {self.message}')
        else:
            sys.stdout.write(f'\r{char} {self.message}')
        
        sys.stdout.flush()
        self.index += 1
    
    def start(self) -> None:
        """Start spinner."""
        self.running = True
    
    def stop(self, final_message: Optional[str] = None) -> None:
        """
        Stop spinner.
        
        Args:
            final_message: Optional final message to display.
        """
        self.running = False
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        
        if final_message:
            if self.use_color:
                print(f"{Fore.GREEN}✓{Style.RESET_ALL} {final_message}")
            else:
                print(f"✓ {final_message}")
        
        sys.stdout.flush()
