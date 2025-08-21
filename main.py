"""
Main entry point for Email Security Analyzer.

This script orchestrates the complete email security analysis process.
"""

import asyncio
import sys
import logging
import os
from pathlib import Path

# =============================================================================
# HARDCODED CONFIGURATION
# =============================================================================

# Required Settings
REPORTS_FOLDER = "/Users/ahmadzidane/Downloads/allure-reports"
MAILBOX_PASSWORD = ""
OPENAI_API_KEY = ""

# Optional Settings
OUTPUT_DIRECTORY = "./output"  # Custom output directory (None for default)
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE = None  # Custom log file path (None for default)
BROWSER_HEADLESS = False  # Run browser in headless mode
BROWSER_TIMEOUT = 300  # Browser timeout in seconds

# Application Info
VERSION = "Email Security Analyzer 1.0.0"

# =============================================================================

# Set environment variables from hardcoded values before importing settings
if OPENAI_API_KEY:
    os.environ['OPENAI_API_KEY'] = OPENAI_API_KEY
if MAILBOX_PASSWORD:
    os.environ['MAILBOX_PASSWORD'] = MAILBOX_PASSWORD

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.mail_verifier import CompleteMailVerifier
from src.utils.helpers import setup_logging, ProgressTracker
from config.settings import validate_environment, get_settings
from src.models.data_models import ClassificationType


async def main():
    """Main function with hardcoded configuration."""
    print("=" * 70)
    print("Email Security Analyzer - Professional Edition")
    print("=" * 70)
    print("Analyzes email security test failures with AI-powered classification")
    print("Generates professional HTML reports with integrated screenshots")
    print("Uses OpenAI for intelligent failure analysis")
    print("Email-based deduplication (no duplicate processing)")
    print("Mobile-responsive design with click-to-expand screenshots")
    print("=" * 70)

    # Use hardcoded configuration
    reports_folder = Path(REPORTS_FOLDER)

    print(f"\nConfiguration:")
    print(f"   Reports Folder: {reports_folder}")
    print(f"   Output Directory: {OUTPUT_DIRECTORY or 'default (./output)'}")
    print(f"   Log Level: {LOG_LEVEL}")
    print(f"   Browser Mode: {'Headless' if BROWSER_HEADLESS else 'Visible'}")
    print(f"   Browser Timeout: {BROWSER_TIMEOUT}s")
    print(f"   Version: {VERSION}")

    # Validate reports folder
    if not reports_folder.exists():
        print(f"Error: Reports folder not found: {reports_folder}")
        print(f"Please update REPORTS_FOLDER in main.py to the correct path")
        sys.exit(1)

    if not list(reports_folder.glob("*.html")):
        print(f"Error: No HTML files found in reports folder: {reports_folder}")
        print(f"Make sure the folder contains Allure HTML report files")
        sys.exit(1)

    # Set up output directory
    if OUTPUT_DIRECTORY:
        output_dir = Path(OUTPUT_DIRECTORY)
        # Update settings for custom output directory
        settings = get_settings()
        settings.OUTPUT_DIR = output_dir
        settings.REPORTS_DIR = output_dir / "reports"
        settings.SCREENSHOTS_DIR = output_dir / "screenshots"
        settings.create_directories()

    # Set up logging
    log_file = None
    if LOG_FILE:
        log_file = Path(LOG_FILE)
    else:
        log_file = get_settings().OUTPUT_DIR / "logs" / "analyzer.log"

    setup_logging(LOG_LEVEL, log_file)
    logger = logging.getLogger(__name__)

    logger.info("Starting Email Security Analyzer")
    logger.info(f"Reports folder: {reports_folder}")
    logger.info(f"Output directory: {get_settings().OUTPUT_DIR}")
    logger.info(f"Log level: {LOG_LEVEL}")
    logger.info(f"Browser headless: {BROWSER_HEADLESS}")
    logger.info(f"Browser timeout: {BROWSER_TIMEOUT}s")

    try:
        # Validate environment (hardcoded values are already set as env vars)
        validate_environment()

        # Apply optional settings to settings object
        settings = get_settings()
        settings.BROWSER_HEADLESS = BROWSER_HEADLESS
        settings.BROWSER_TIMEOUT = BROWSER_TIMEOUT * 1000  # Convert to milliseconds

        # Create and run verifier
        verifier = CompleteMailVerifier(
            reports_folder=str(reports_folder),
            password=MAILBOX_PASSWORD,
            openai_api_key=OPENAI_API_KEY
        )

        print(f"\nParsing Allure reports from: {reports_folder}")
        print("Extracting unique email failures (AssertionError only)...")

        reports = await verifier.run_complete_analysis()

        if reports:
            print("\n" + "=" * 50)
            print("ANALYSIS COMPLETE!")
            print("=" * 50)

            # Get summary statistics
            summary = verifier.get_summary_statistics()

            print("Results Summary:")
            print(f"   Total Unique Emails: {summary['total_tests']}")
            print(f"   Security Issues (Critical): {summary['real_issues']}")
            print(f"   Delay Issues (Security Working): {summary['delay_issues']}")
            print(f"   Code Issues (Infrastructure): {summary['code_issues']}")
            print(f"   Security Success Rate: {summary['security_success_rate']:.1f}%")

            print("\nDetailed Email Analysis:")
            for i, report in enumerate(reports, 1):
                status_icons = []
                if report.mailbox_verification.quarantined_subject_found:
                    status_icons.append("QUARANTINED")
                if report.mailbox_verification.phishing_alert_found:
                    status_icons.append("PHISHING_ALERT")
                if (report.mailbox_verification.original_subject_found
                        and report.failed_test.mail_type == 'clean'):
                    status_icons.append("NORMAL_DELIVERY")

                status_str = " " + " ".join(status_icons) if status_icons else ""
                screenshot_info = "Screenshot" if report.mailbox_verification.screenshot_path else "No Screenshot"

                classification_emoji = {
                    ClassificationType.REAL_ISSUE.value: "CRITICAL",
                    ClassificationType.DELAY_ISSUE.value: "DELAY",
                    ClassificationType.CODE_ISSUE.value: "CODE"
                }.get(report.final_classification, "UNKNOWN")

                print(f"   {i}. {classification_emoji} {report.failed_test.mail_type.upper()}: "
                      f"{report.final_classification.replace('_', ' ')}{status_str} {screenshot_info}")
                print(f"      Subject: {report.failed_test.mail_subject[:60]}...")

                if report.ai_analysis.confidence < 70:
                    print(f"      AI Confidence: {report.ai_analysis.confidence}% (Low)")

            print(f"\nProfessional Dashboard Generated!")
            print("Report Features:")
            print("   Interactive statistics and charts")
            print("   Integrated screenshots with click-to-expand modals")
            print("   AI analysis with confidence visualizations")
            print("   Mobile-responsive design")
            print("   Clean, professional UI/UX")

            # Print report path
            reports_dir = get_settings().REPORTS_DIR
            latest_report = max(reports_dir.glob("email_security_dashboard_*.html"),
                                key=lambda x: x.stat().st_mtime, default=None)
            if latest_report:
                print(f"\nReport Location: {latest_report}")
                print(f"Open in browser: file://{latest_report.absolute()}")

        else:
            print("\nNo AssertionError failures found to process")
            print("Make sure your Allure reports contain actual test failures")

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        logger.info("Analysis interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\nError during analysis: {e}")
        logger.error(f"Error during analysis: {e}", exc_info=True)

        # Print helpful troubleshooting info
        print("\nTroubleshooting:")
        print("   1. Check that REPORTS_FOLDER path is correct")
        print("   2. Verify OPENAI_API_KEY is valid")
        print("   3. Ensure MAILBOX_PASSWORD is correct")
        print("   4. Check internet connectivity")
        print("   5. Review logs for detailed error information")

        sys.exit(1)

    print("\n" + "=" * 70)
    print("Email Security Analysis Complete!")
    print("=" * 70)


def print_configuration_help():
    """Print help for updating hardcoded configuration."""
    print("\n" + "=" * 70)
    print("CONFIGURATION HELP")
    print("=" * 70)
    print("To modify settings, edit the following variables in main.py:")
    print()
    print("Required Settings:")
    print(f"   REPORTS_FOLDER = '{REPORTS_FOLDER}'")
    print(f"   MAILBOX_PASSWORD = '***'")  # Don't print actual password
    print(f"   OPENAI_API_KEY = 'sk-proj-***'")  # Don't print actual key
    print()
    print("Optional Settings:")
    print(f"   OUTPUT_DIRECTORY = '{OUTPUT_DIRECTORY}'")
    print(f"   LOG_LEVEL = '{LOG_LEVEL}'")
    print(f"   BROWSER_HEADLESS = {BROWSER_HEADLESS}")
    print(f"   BROWSER_TIMEOUT = {BROWSER_TIMEOUT}")
    print()
    print("Available LOG_LEVEL options: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    print("Set BROWSER_HEADLESS = True for server environments")
    print("Increase BROWSER_TIMEOUT for slow email systems")
    print("=" * 70)


if __name__ == "__main__":
    # Print configuration help if needed
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        print_configuration_help()
        sys.exit(0)

    # Handle event loop for Windows compatibility
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    asyncio.run(main())