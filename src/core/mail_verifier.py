"""
Core Mail Verifier for Email Security Analyzer.

This module orchestrates the complete email verification and analysis process.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import List

from ..models.data_models import FailedTest, CompleteTestReport, ClassificationType
from ..parsers.allure_parser import AllureParser
from ..verifiers.mailbox_verifier import PlaywrightMailboxVerifier
from ..analyzers.ai_analyzer import AIAnalyzer
from ..reporters.html_reporter import HTMLReporter
from config.settings import settings

logger = logging.getLogger(__name__)


class CompleteMailVerifier:
    """Complete mail verifier with enhanced professional reporting."""

    def __init__(self, reports_folder: str, password: str = None, openai_api_key: str = None):
        """Initialize the complete mail verifier."""
        self.reports_folder = reports_folder
        self.password = password or settings.MAILBOX_PASSWORD
        self.openai_api_key = openai_api_key or settings.OPENAI_API_KEY

        # Initialize components
        self.parser = AllureParser(reports_folder)
        self.ai_analyzer = AIAnalyzer(self.openai_api_key)
        self.html_reporter = HTMLReporter()

        self.complete_reports: List[CompleteTestReport] = []

        # Clean up old files at startup
        self._cleanup_old_files()

    async def run_complete_analysis(self) -> List[CompleteTestReport]:
        """Run complete analysis with enhanced reporting."""

        logger.info("Starting Complete Mail Verification Analysis")
        logger.info("=" * 70)

        # Extract AssertionError failures with email-based deduplication
        failed_tests = self.parser.extract_failed_mail_tests()

        if not failed_tests:
            logger.warning("No AssertionError failures found")
            return []

        logger.info(f"Found {len(failed_tests)} unique email failures")
        self._log_found_tests(failed_tests)

        # Process each unique email failure
        for i, failed_test in enumerate(failed_tests, 1):
            logger.info(f"\nProcessing Email Failure {i}/{len(failed_tests)}: {failed_test.test_name}")

            try:
                # Mailbox verification with proper logic
                verification_result = await self._verify_mailbox(failed_test)

                # AI analysis with proper prompts
                ai_analysis = self._analyze_with_ai(failed_test, verification_result)

                # Final classification
                final_classification = self._determine_final_classification(
                    failed_test, verification_result, ai_analysis
                )

                # Create complete report
                complete_report = CompleteTestReport(
                    failed_test=failed_test,
                    mailbox_verification=verification_result,
                    ai_analysis=ai_analysis,
                    final_classification=final_classification,
                    report_timestamp=datetime.now()
                )

                self.complete_reports.append(complete_report)

                # Log results
                self._log_test_results(i, complete_report)

            except Exception as e:
                logger.error(f"Error processing test {i}: {e}")

        # Generate enhanced professional report with screenshots
        await self._generate_final_report()
        return self.complete_reports

    async def _verify_mailbox(self, failed_test: FailedTest):
        """Verify mailbox with proper configuration."""
        mailbox_verifier = PlaywrightMailboxVerifier(self.password)
        return await mailbox_verifier.verify_mail_delivery(failed_test)

    def _analyze_with_ai(self, failed_test: FailedTest, verification_result):
        """Analyze with AI."""
        return self.ai_analyzer.analyze_test_failure(failed_test, verification_result)

    def _determine_final_classification(self, failed_test: FailedTest, verification, ai_analysis) -> str:
        """Final classification with intelligent override of incorrect AI responses."""

        if verification.error_message and 'login' in verification.error_message.lower():
            return ClassificationType.CODE_ISSUE.value

        # Intelligent override: If verification shows clear results, use logic-based classification
        if verification.mail_found:
            mail_type = failed_test.mail_type

            logger.info("Intelligent Classification Logic:")
            logger.info(f"   Mail Type: {mail_type}")
            logger.info(f"   Mail Found: {verification.mail_found}")
            logger.info(f"   Original Found: {verification.original_subject_found}")
            logger.info(f"   Quarantined Found: {verification.quarantined_subject_found}")
            logger.info(f"   Phishing Alert Found: {verification.phishing_alert_found}")
            logger.info(f"   Action Applied Correctly: {verification.action_applied}")

            # Logic-based classification (overrides AI if needed)
            logic_classification = self._get_logic_based_classification(mail_type, verification)

            logger.info(f"   Logic-based classification: {logic_classification}")
            logger.info(f"   AI classification: {ai_analysis.classification}")

            # Override AI if it's clearly wrong
            if logic_classification != ai_analysis.classification:
                logger.info(
                    f"   OVERRIDING AI: Logic says {logic_classification}, AI says {ai_analysis.classification}"
                )
                if logic_classification in [ClassificationType.DELAY_ISSUE.value, ClassificationType.REAL_ISSUE.value]:
                    # Logic is confident about security classifications
                    return logic_classification

            # If AI agrees with logic or logic is uncertain, use AI
            return ai_analysis.classification

        # Use AI analysis for edge cases where verification is unclear
        return ai_analysis.classification

    def _get_logic_based_classification(self, mail_type: str, verification) -> str:
        """Get logic-based classification for a mail type."""

        if mail_type == 'clean':
            # Clean emails should be delivered normally
            if verification.original_subject_found and not verification.quarantined_subject_found:
                return ClassificationType.DELAY_ISSUE.value  # Correct behavior
            else:
                return ClassificationType.REAL_ISSUE.value  # Clean email was modified (wrong)

        elif mail_type == 'phishing':
            # Phishing emails should get alert prefix
            if verification.phishing_alert_found:
                return ClassificationType.DELAY_ISSUE.value  # Correct behavior
            else:
                return ClassificationType.REAL_ISSUE.value  # Phishing without alert (wrong)

        elif mail_type in ['eicar', 'malware']:
            # EICAR/malware should be quarantined
            if verification.quarantined_subject_found:
                return ClassificationType.DELAY_ISSUE.value  # Correct behavior
            else:
                return ClassificationType.REAL_ISSUE.value  # EICAR without quarantine (wrong)
        else:
            return ClassificationType.CODE_ISSUE.value  # Unknown mail type

    async def _generate_final_report(self):
        """Generate the final HTML report."""
        html_path = await self.html_reporter.generate_professional_report(self.complete_reports)
        logger.info(f"\nProfessional Dashboard Generated: {html_path}")
        logger.info("Features:")
        logger.info("   • Interactive stats and charts")
        logger.info("   • Integrated screenshots with click-to-expand")
        logger.info("   • AI analysis with confidence visualizations")
        logger.info("   • Mobile-responsive design")
        logger.info("   • Clean, professional codebase")

    def _log_found_tests(self, failed_tests: List[FailedTest]):
        """Log the found tests."""
        for i, test in enumerate(failed_tests, 1):
            logger.info(f"   {i}. {test.mail_type.upper()}: {test.mail_subject[:50]}...")
            logger.info(f"      Expected: {test.expected_behavior}")

    def _log_test_results(self, test_number: int, report: CompleteTestReport):
        """Log the results of a test analysis."""
        logger.info(f"Test {test_number} Analysis:")
        logger.info(f"   Found: {report.mailbox_verification.mail_found}")
        logger.info(f"   Original: {report.mailbox_verification.original_subject_found}")
        logger.info(f"   Quarantined: {report.mailbox_verification.quarantined_subject_found}")
        logger.info(f"   Phishing Alert: {report.mailbox_verification.phishing_alert_found}")
        logger.info(f"   Correct Action: {report.mailbox_verification.action_applied}")
        logger.info(f"   Final: {report.final_classification}")
        logger.info(f"   AI: {report.ai_analysis.classification} ({report.ai_analysis.confidence}%)")

    def get_summary_statistics(self) -> dict:
        """Get summary statistics of the analysis."""
        if not self.complete_reports:
            return {
                'total_tests': 0,
                'real_issues': 0,
                'delay_issues': 0,
                'code_issues': 0,
                'security_success_rate': 0.0
            }

        real_issues = sum(1 for r in self.complete_reports if r.final_classification == ClassificationType.REAL_ISSUE.value)
        delay_issues = sum(1 for r in self.complete_reports if r.final_classification == ClassificationType.DELAY_ISSUE.value)
        code_issues = sum(1 for r in self.complete_reports if r.final_classification == ClassificationType.CODE_ISSUE.value)

        total_security_tests = real_issues + delay_issues
        security_success_rate = (delay_issues / total_security_tests * 100) if total_security_tests > 0 else 100

        return {
            'total_tests': len(self.complete_reports),
            'real_issues': real_issues,
            'delay_issues': delay_issues,
            'code_issues': code_issues,
            'security_success_rate': security_success_rate
        }

    def _cleanup_old_files(self):
        """Clean up old files at startup."""
        logger.info("Cleaning up old files...")

        try:
            # Clean up old reports
            reports_dir = settings.REPORTS_DIR
            if reports_dir.exists():
                for file in reports_dir.glob("ES_AI_Report-*.html"):
                    file.unlink()
                    logger.info(f"Removed old report: {file.name}")

                # Clean up old screenshots in reports directory
                screenshots_dir = reports_dir / "screenshots"
                if screenshots_dir.exists():
                    for file in screenshots_dir.glob("*.png"):
                        file.unlink()
                    logger.info(f"Cleaned up screenshots directory")

            # Clean up screenshots in main screenshots directory
            screenshots_dir = settings.SCREENSHOTS_DIR
            if screenshots_dir.exists():
                for file in screenshots_dir.glob("*.png"):
                    file.unlink()
                    logger.info(f"Removed old screenshot: {file.name}")

            # Clean up old logs
            logs_dir = settings.OUTPUT_DIR / "logs"
            if logs_dir.exists():
                for file in logs_dir.glob("*.log"):
                    file.unlink()
                    logger.info(f"Removed old log: {file.name}")

            logger.info("Cleanup completed successfully")

        except Exception as e:
            logger.warning(f"Some files could not be cleaned up: {e}")