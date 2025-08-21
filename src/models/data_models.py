"""
Data models for Email Security Analyzer.

This module contains all the data structures used throughout the application.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional, Dict
from enum import Enum


class MailType(Enum):
    """Email types for testing."""
    CLEAN = "clean"
    PHISHING = "phishing"
    EICAR = "eicar"
    MALWARE = "malware"


class ClassificationType(Enum):
    """AI classification types."""
    REAL_ISSUE = "REAL_ISSUE"
    DELAY_ISSUE = "DELAY_ISSUE"
    CODE_ISSUE = "CODE_ISSUE"


@dataclass
class FailedTest:
    """Failed test data structure with complete parameters."""
    test_name: str
    mail_address: str
    mail_subject: str
    expected_behavior: str
    mail_type: str
    failure_message: str
    test_duration: float
    timestamp: datetime
    test_id: str = ""
    parameters: dict = None
    sent_timestamp: Optional[datetime] = None

    def __post_init__(self):
        """Initialize default values after object creation."""
        if self.parameters is None:
            self.parameters = {}

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


@dataclass
class MailVerificationResult:
    """Result of mailbox verification."""
    mail_found: bool
    mail_subject_found: str = ""
    original_subject_found: bool = False
    quarantined_subject_found: bool = False
    phishing_alert_found: bool = False
    action_applied: bool = False
    expected_action: str = ""
    actual_action: str = ""
    screenshot_path: str = ""
    verification_timestamp: datetime = None
    delivery_delay_minutes: Optional[float] = None
    error_message: str = ""
    mailbox_html_content: str = ""

    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.verification_timestamp is None:
            self.verification_timestamp = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


@dataclass
class AIAnalysisResult:
    """AI analysis result."""
    classification: str
    confidence: float
    explanation: str
    recommended_action: str
    analysis_successful: bool = True

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


@dataclass
class CompleteTestReport:
    """Complete test analysis report."""
    failed_test: FailedTest
    mailbox_verification: MailVerificationResult
    ai_analysis: AIAnalysisResult
    final_classification: str
    report_timestamp: datetime

    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.report_timestamp is None:
            self.report_timestamp = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'failed_test': self.failed_test.to_dict(),
            'mailbox_verification': self.mailbox_verification.to_dict(),
            'ai_analysis': self.ai_analysis.to_dict(),
            'final_classification': self.final_classification,
            'report_timestamp': self.report_timestamp.isoformat()
        }


@dataclass
class TestSummary:
    """Summary statistics for test results."""
    total_tests: int
    real_issues: int
    delay_issues: int
    code_issues: int
    security_success_rate: float

    @classmethod
    def from_reports(cls, reports: List[CompleteTestReport]) -> 'TestSummary':
        """Create summary from list of reports."""
        total_tests = len(reports)
        real_issues = sum(1 for r in reports if r.final_classification == ClassificationType.REAL_ISSUE.value)
        delay_issues = sum(1 for r in reports if r.final_classification == ClassificationType.DELAY_ISSUE.value)
        code_issues = sum(1 for r in reports if r.final_classification == ClassificationType.CODE_ISSUE.value)

        total_security_tests = real_issues + delay_issues
        security_success_rate = (delay_issues / total_security_tests * 100) if total_security_tests > 0 else 100

        return cls(
            total_tests=total_tests,
            real_issues=real_issues,
            delay_issues=delay_issues,
            code_issues=code_issues,
            security_success_rate=security_success_rate
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)