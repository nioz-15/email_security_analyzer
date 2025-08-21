# src/verifiers/__init__.py
"""
Email verification modules for Email Security Analyzer.

This module contains verifiers that check email delivery and security actions.
"""

from .mailbox_verifier import PlaywrightMailboxVerifier

__all__ = ["PlaywrightMailboxVerifier"]