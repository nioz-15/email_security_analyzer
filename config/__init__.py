# config/__init__.py
"""
Configuration management for Email Security Analyzer.

This module handles application settings and environment configuration.
"""

from .settings import (

    settings,
    get_settings,
    validate_environment
)

__all__ = [
    "settings",
    "get_settings",
    "validate_environment"
]