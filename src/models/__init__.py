# src/models/__init__.py
"""
Data models for Email Security Analyzer.

This module contains all data structures used throughout the application.
"""

from .data_models import (
    FailedTest,
    MailVerificationResult,
    AIAnalysisResult,
    CompleteTestReport,
    TestSummary,
    MailType,
    ClassificationType
)

__all__ = [
    "FailedTest",
    "MailVerificationResult",
    "AIAnalysisResult",
    "CompleteTestReport",
    "TestSummary",
    "MailType",
    "ClassificationType"
]