# src/core/__init__.py
"""
Core modules for Email Security Analyzer.

This module contains the main orchestration logic.
"""

from .mail_verifier import CompleteMailVerifier

__all__ = ["CompleteMailVerifier"]