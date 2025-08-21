# src/reporters/__init__.py
"""
Report generation modules for Email Security Analyzer.

This module contains reporters that generate various output formats.
"""

from .html_reporter import HTMLReporter

__all__ = ["HTMLReporter"]