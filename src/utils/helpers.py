"""
Helper utilities for Email Security Analyzer.

This module contains utility functions used throughout the application.
"""

import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import json
from datetime import datetime


def generate_test_id(identifier: str) -> str:
    """Generate a consistent test ID from an identifier."""
    return hashlib.md5(identifier.encode()).hexdigest()[:8]


def setup_logging(log_level: str = "INFO", log_file: Optional[Path] = None) -> None:
    """
    Set up logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
    """
    # Configure logging format
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Set up basic configuration
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=[]
    )

    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)


def save_json_report(data: Dict[Any, Any], output_path: Path) -> None:
    """
    Save data as JSON report.

    Args:
        data: Data to save
        output_path: Path to save the JSON file
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert datetime objects to ISO format strings
    def json_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=json_serializer, ensure_ascii=False)


def load_json_report(input_path: Path) -> Dict[Any, Any]:
    """
    Load JSON report from file.

    Args:
        input_path: Path to the JSON file

    Returns:
        Loaded data dictionary
    """
    if not input_path.exists():
        raise FileNotFoundError(f"JSON report not found: {input_path}")

    with open(input_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def sanitize_filename(filename: str, max_length: int = 100) -> str:
    """
    Sanitize a filename for safe file system usage.

    Args:
        filename: Original filename
        max_length: Maximum length for the filename

    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')

    # Remove multiple consecutive underscores
    while '__' in filename:
        filename = filename.replace('__', '_')

    # Remove leading/trailing underscores and whitespace
    filename = filename.strip('_ ')

    # Truncate if too long
    if len(filename) > max_length:
        # Try to keep the extension
        if '.' in filename:
            name, ext = filename.rsplit('.', 1)
            max_name_length = max_length - len(ext) - 1
            filename = f"{name[:max_name_length]}.{ext}"
        else:
            filename = filename[:max_length]

    return filename or "unnamed"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in bytes to human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.1f} GB"


def validate_email_address(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid, False otherwise
    """
    import re

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def extract_email_domain(email: str) -> Optional[str]:
    """
    Extract domain from email address.

    Args:
        email: Email address

    Returns:
        Domain part of the email, or None if invalid
    """
    if not validate_email_address(email):
        return None

    return email.split('@')[1]


def create_directory_structure(base_path: Path, subdirs: list) -> None:
    """
    Create directory structure.

    Args:
        base_path: Base directory path
        subdirs: List of subdirectories to create
    """
    base_path.mkdir(parents=True, exist_ok=True)

    for subdir in subdirs:
        (base_path / subdir).mkdir(parents=True, exist_ok=True)


def get_file_hash(file_path: Path, algorithm: str = 'md5') -> str:
    """
    Calculate file hash.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hexadecimal hash string
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    hash_obj = hashlib.new(algorithm)

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def merge_dicts(dict1: dict, dict2: dict) -> dict:
    """
    Merge two dictionaries recursively.

    Args:
        dict1: First dictionary
        dict2: Second dictionary

    Returns:
        Merged dictionary
    """
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncating

    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix


class ProgressTracker:
    """Simple progress tracker for long-running operations."""

    def __init__(self, total_items: int, description: str = "Processing"):
        """
        Initialize progress tracker.

        Args:
            total_items: Total number of items to process
            description: Description of the operation
        """
        self.total_items = total_items
        self.description = description
        self.current_item = 0
        self.start_time = datetime.now()
        self.logger = logging.getLogger(__name__)

    def update(self, increment: int = 1):
        """Update progress by increment."""
        self.current_item += increment

        if self.current_item % max(1, self.total_items // 10) == 0 or self.current_item == self.total_items:
            percentage = (self.current_item / self.total_items) * 100
            elapsed = datetime.now() - self.start_time

            if self.current_item > 0:
                avg_time_per_item = elapsed.total_seconds() / self.current_item
                remaining_items = self.total_items - self.current_item
                eta = remaining_items * avg_time_per_item

                self.logger.info(
                    f"{self.description}: {self.current_item}/{self.total_items} "
                    f"({percentage:.1f}%) - ETA: {format_duration(eta)}"
                )
            else:
                self.logger.info(f"{self.description}: {self.current_item}/{self.total_items} ({percentage:.1f}%)")

    def finish(self):
        """Mark progress as finished."""
        elapsed = datetime.now() - self.start_time
        self.logger.info(f"{self.description} completed in {format_duration(elapsed.total_seconds())}")


def retry_on_exception(max_retries: int = 3, delay: float = 1.0):
    """
    Decorator to retry function on exception.

    Args:
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
    """
    import time
    import functools

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        logging.getLogger(__name__).warning(
                            f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                    else:
                        logging.getLogger(__name__).error(
                            f"All {max_retries + 1} attempts failed for {func.__name__}"
                        )

            raise last_exception

        return wrapper

    return decorator