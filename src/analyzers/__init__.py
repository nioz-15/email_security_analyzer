# src/analyzers/__init__.py
"""
Analysis modules for Email Security Analyzer.

This module contains analyzers that classify and interpret test failures.
"""

from .ai_analyzer import AIAnalyzer

__all__ = ["AIAnalyzer"]