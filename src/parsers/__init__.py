# src/parsers/__init__.py
"""
Report parsers for Email Security Analyzer.

This module contains parsers for different test report formats.
"""

from .allure_parser import AllureParser

__all__ = ["AllureParser"]