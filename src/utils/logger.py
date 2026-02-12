"""
Logging configuration for VIPRecon tool.
Provides structured logging with file and console output.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
try:
    init(autoreset=True)
except Exception:
    pass


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to console output."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def format(self, record):
        # Create a copy of the record to avoid altering the original in all handlers
        orig_levelname = record.levelname
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        
        result = super().format(record)
        # Restore original levelname
        record.levelname = orig_levelname
        return result


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    console_output: bool = True,
    file_output: bool = True,
    use_color: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5
) -> None:
    """
    Set up logging configuration for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to log file. If None, uses default location.
        console_output: Whether to output logs to console.
        file_output: Whether to output logs to file.
        use_color: Whether to use colored output in console.
        max_bytes: Maximum size of log file before rotation.
        backup_count: Number of backup log files to keep.
    """
    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        
        console_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        if use_color:
            # Use colored formatter for console
            console_formatter = ColoredFormatter(
                console_format,
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        else:
            console_formatter = logging.Formatter(
                console_format,
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if file_output:
        if log_file is None:
            # Use default log file location
            log_dir = Path("output/logs")
            log_dir.mkdir(parents=True, exist_ok=True)
            final_log_file = log_dir / "viprecon.log"
        else:
            final_log_file = Path(log_file)
            final_log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            str(final_log_file),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        
        # Use standard formatter for file (no colors)
        file_format = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        file_formatter = logging.Formatter(
            file_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def get_logger(module_name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    """
    return logging.getLogger(module_name)


def log_exception(logger: logging.Logger, message: str, exc: Exception) -> None:
    """
    Log an exception with full traceback.
    """
    logger.error(f"{message}: {str(exc)}", exc_info=True)
