"""
Allure Report Parser for Email Security Analyzer.

This module extracts failed email tests from Allure HTML reports,
specifically looking for AssertionError failures.
"""

import re
import base64
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from ..models.data_models import FailedTest
from ..utils.helpers import generate_test_id

logger = logging.getLogger(__name__)


class AllureParser:
    """Extract tests with AssertionError (actual failures)."""

    def __init__(self, reports_folder: str):
        """Initialize the parser with reports folder path."""
        self.reports_folder = Path(reports_folder)
        self.processed_report_name = None  # Store the name of the processed report
        self.html_content = ""  # Initialize the missing attribute

    def extract_failed_mail_tests(self) -> List[FailedTest]:
        """
        Extract failed email tests from Allure HTML reports.
        This is the main entry point that processes all HTML files.
        """
        logger.info("🔍 Starting extraction of failed mail tests...")
        all_failed_tests = []

        try:
            # Process all HTML files in the reports folder
            html_files = list(self.reports_folder.glob("*.html"))
            logger.info(f"📄 Found {len(html_files)} HTML files to process")

            if not html_files:
                logger.warning("⚠️ No HTML files found in reports folder")
                return []

            for html_file in html_files:
                logger.info(f"📖 Processing file: {html_file.name}")

                # Store the report name for later use
                if not self.processed_report_name:
                    self.processed_report_name = html_file.stem

                # Read the HTML content
                try:
                    with open(html_file, 'r', encoding='utf-8') as f:
                        self.html_content = f.read()

                    logger.info(f"📖 HTML file size: {len(self.html_content)} characters")

                    # Extract failed tests from this file using the existing sophisticated logic
                    file_tests = self._extract_assertion_error_failures_only(
                        self.html_content,
                        str(html_file)
                    )

                    logger.info(f"📧 Found {len(file_tests)} failed tests in {html_file.name}")
                    all_failed_tests.extend(file_tests)

                except Exception as e:
                    logger.error(f"❌ Error reading {html_file.name}: {e}")
                    continue

            # Deduplicate across all files
            unique_tests = self._deduplicate_by_email(all_failed_tests)

            # Log final results
            self._log_final_results(unique_tests)

            logger.info(f"✅ Extraction complete: {len(unique_tests)} unique failed email tests found")
            return unique_tests

        except Exception as e:
            logger.error(f"❌ Error during extraction: {e}")
            # Try fallback method if main extraction fails
            return self._fallback_extraction()

    def _fallback_extraction(self) -> List[FailedTest]:
        """
        Fallback extraction method using simpler base64 decoding approach.
        This matches the manual extraction logic that was working.
        """
        logger.info("🔧 Attempting fallback extraction method...")
        failed_tests = []

        try:
            if not self.html_content:
                # Try to read the first HTML file
                html_files = list(self.reports_folder.glob("*.html"))
                if html_files:
                    with open(html_files[0], 'r', encoding='utf-8') as f:
                        self.html_content = f.read()

            if not self.html_content:
                logger.warning("⚠️ No HTML content available for fallback extraction")
                return []

            # Use the simpler approach that was working in manual extraction
            base64_pattern = r"d\('data/attachments/[^']+','([^']+)'\)"
            matches = re.findall(base64_pattern, self.html_content)

            logger.info(f"🔍 Found {len(matches)} base64 strings to decode")

            processed_subjects = set()

            for i, match in enumerate(matches):
                try:
                    decoded = base64.b64decode(match).decode('utf-8')

                    # Look for email test failures
                    if "Email wasn't found" in decoded and "AUTO_" in decoded:
                        subject_match = re.search(r"Subject='([^']+)'", decoded)
                        recipient_match = re.search(r"Inbox='([^']+)'", decoded)

                        if subject_match and recipient_match:
                            subject = subject_match.group(1)
                            recipient = recipient_match.group(1)

                            # Skip duplicates
                            if subject in processed_subjects:
                                continue
                            processed_subjects.add(subject)

                            # Determine mail type and create test
                            mail_type = self._determine_mail_type(subject)
                            test_name = f"Email {mail_type.title()} Test - {subject}"

                            # Create FailedTest object with proper structure
                            failed_test = FailedTest(
                                test_name=test_name,
                                mail_address=recipient,
                                mail_subject=subject,
                                expected_behavior=self._get_expected_behavior(mail_type),
                                mail_type=mail_type,
                                failure_message="AssertionError: Email not found in recipient inbox",
                                test_duration=300.0,  # 5 minutes default
                                timestamp=datetime.now(),
                                test_id=generate_test_id(f"{subject}_{mail_type}_{recipient}"),
                                parameters={
                                    'recipient': recipient,
                                    'original_subject': subject,
                                    'mail_type': mail_type,
                                    'extraction_source': 'fallback_base64'
                                },
                                sent_timestamp=datetime.now()
                            )

                            failed_tests.append(failed_test)
                            logger.info(f"🎯 Extracted: {mail_type.upper()} - {subject}")

                except Exception as e:
                    logger.debug(f"Failed to decode base64 string {i}: {e}")
                    continue

            logger.info(f"✅ Fallback extraction found {len(failed_tests)} unique email tests")
            return failed_tests

        except Exception as e:
            logger.error(f"❌ Fallback extraction failed: {e}")
            return []

    def _get_expected_behavior(self, mail_type: str) -> str:
        """Get expected behavior for mail type."""
        try:
            from config.settings import settings
            return settings.EXPECTED_BEHAVIORS.get(mail_type, 'Unknown behavior')
        except ImportError:
            # Fallback if settings not available
            behaviors = {
                'clean': 'Clean email should be delivered normally',
                'phishing': 'Phishing email should be blocked or quarantined',
                'malware': 'Malware email should be blocked or quarantined',
                'eicar': 'EICAR test file should be blocked or quarantined'
            }
            return behaviors.get(mail_type, 'Unknown behavior')

    def get_processed_report_name(self) -> str:
        """Get the name of the processed report for use in final report naming."""
        return self.processed_report_name or "unknown_report"

    def _extract_assertion_error_failures_only(self, content: str, source_file: str) -> List[FailedTest]:
        """Extract ONLY tests that have AssertionError from base64 sections in script tags."""

        failed_tests = []

        # Extract script sections
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)

        logger.info(f"   Checking {len(scripts)} script sections for AssertionError")

        # Find the large script (Script with 2M+ chars)
        assertion_error_count = 0
        for i, script in enumerate(scripts):
            if len(script) > 1000000:  # The big script with 2M+ chars
                logger.info(f"   Analyzing Large Script {i + 1} (length: {len(script):,} chars)")

                # Find ALL base64 sections within this script
                base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
                base64_matches = re.findall(base64_pattern, script)

                logger.info(f"   Found {len(base64_matches)} base64 sections - checking for AssertionError")

                # Check EVERY base64 section for AssertionError
                for j, b64_data in enumerate(base64_matches):
                    try:
                        decoded = base64.b64decode(b64_data).decode('utf-8')

                        # Only process if contains AssertionError
                        has_assertion_error = 'assertionerror' in decoded.lower()

                        if has_assertion_error:
                            assertion_error_count += 1
                            logger.info(f"      Base64 section {j + 1} contains AssertionError (real failure)")

                            # Parse this AssertionError failure
                            section_tests = self._parse_assertion_error_attachment(decoded, j, source_file)
                            failed_tests.extend(section_tests)

                        # Progress tracking
                        if (j + 1) % 50 == 0:
                            logger.info(
                                f"      Processed {j + 1}/{len(base64_matches)} base64 sections... "
                                f"Found {assertion_error_count} AssertionErrors"
                            )

                    except Exception:
                        continue

        logger.info(f"   Found {assertion_error_count} base64 sections with AssertionError")
        return failed_tests

    def _parse_assertion_error_attachment(self, decoded_content: str, attachment_index: int,
                                        source_file: str) -> List[FailedTest]:
        """Parse a single attachment for AssertionError information with strict validation."""

        failed_tests = []

        # Multiple patterns to catch different AssertionError formats
        pattern1 = r"AssertionError:\s*Email with subject\s*:\s*([^!]+?)\s*not found in recipient\s*([^!]+?)\s*inbox!"
        pattern2 = r"AssertionError:\s*Email not found in recipient inbox!\s*subject:\s*([^,]+?),\s*recipient:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"

        assertion_error_patterns = [pattern1, pattern2]

        all_matches = []
        pattern_info = []

        for idx, pattern in enumerate(assertion_error_patterns):
            matches = re.findall(pattern, decoded_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                all_matches.append(match)
                pattern_info.append(f"Pattern{idx + 1}")
            if matches:
                logger.info(f"      Pattern {idx + 1} matched {len(matches)} AssertionError(s)")

        if not all_matches:
            return failed_tests

        logger.info(f"      Found {len(all_matches)} total AssertionError(s) in this section")

        # Track processed subjects to avoid duplicates within same section
        processed_in_section = set()

        for i, (match, pattern_used) in enumerate(zip(all_matches, pattern_info)):
            raw_subject = match[0].strip()
            raw_email = match[1].strip()

            logger.info(f"      Processing AssertionError {i + 1} (via {pattern_used}):")
            logger.info(f"          Raw subject: {raw_subject[:50]}...")
            logger.info(f"          Raw email: {raw_email}")

            # Validate and clean the extracted data
            subject = self._validate_and_clean_subject(raw_subject)
            email_addr = self._validate_and_clean_email(raw_email)

            if not subject or not email_addr:
                logger.warning(
                    f"      Skipping invalid extraction: subject='{raw_subject[:50]}', email='{raw_email[:50]}'"
                )
                continue

            logger.info(f"      Processing valid AssertionError {i + 1}: {subject[:40]}... → {email_addr}")

            # Extract complete test parameters for this specific failure
            test_params = self._extract_complete_test_parameters(decoded_content, subject, email_addr)

            logger.info(
                f"      Detected mail type: {test_params['mail_type'].upper()} for subject: {subject[:30]}..."
            )

            # Check for duplicates within this section using email-based key
            section_key = f"{subject}_{email_addr}_{test_params['mail_type']}"
            if section_key in processed_in_section:
                logger.info(
                    f"      Skipping duplicate email in same section: {test_params['mail_type']} - {subject[:30]}..."
                )
                continue

            processed_in_section.add(section_key)

            logger.info(f"      Processing unique email: {test_params['mail_type']} - {subject[:30]}...")

            test = FailedTest(
                test_name=test_params['test_name'],
                mail_address=email_addr,
                mail_subject=subject,
                expected_behavior=test_params['expected_behavior'],
                mail_type=test_params['mail_type'],
                failure_message=test_params['failure_message'],
                test_duration=test_params['test_duration'],
                timestamp=test_params['timestamp'],
                test_id=test_params['test_id'],
                parameters=test_params['parameters'],
                sent_timestamp=test_params['sent_timestamp']
            )

            failed_tests.append(test)
            logger.info(
                f"         VALID ASSERTION ERROR: {test_params['test_name']} - "
                f"{test_params['mail_type'].upper()}: {subject[:40]}..."
            )

        return failed_tests

    def _validate_and_clean_subject(self, raw_subject: str) -> str:
        """Validate and clean email subject, return empty string if invalid."""

        if not raw_subject:
            return ""

        # Clean up escaped characters, quotes, and newlines first
        subject = raw_subject.strip()

        # Remove escaped characters and quotes
        subject = re.sub(r'\\[ntr"]', ' ', subject)  # Replace \n, \t, \r, \" with space
        subject = re.sub(r'["\n\r\t]', ' ', subject)  # Replace quotes, newlines with space
        subject = re.sub(r'\s+', ' ', subject).strip()  # Normalize whitespace

        # Reject if it looks like JSON or metadata
        invalid_patterns = [
            r'^\s*[{"\[]',  # Starts with JSON characters
            r'["}]\s*,\s*["\[]',  # Contains JSON structure
            r'not found in recipient',  # Contains error message parts
            r'flaky.*false',  # Contains test metadata
            r'steps.*attachments',  # Contains test structure
            r'statusMessage',  # Contains status info
            r'parameterValues',  # Contains parameter info
        ]

        for pattern in invalid_patterns:
            if re.search(pattern, subject, re.IGNORECASE):
                logger.warning(f"      Rejecting subject (looks like metadata): {subject[:50]}...")
                return ""

        # Must look like a reasonable email subject
        if len(subject) < 5 or len(subject) > 200:
            logger.warning(f"      Rejecting subject (bad length {len(subject)}): {subject[:50]}...")
            return ""

        # Should contain some reasonable characters
        if not re.search(r'[A-Za-z0-9_-]', subject):
            logger.warning(f"      Rejecting subject (no valid chars): {subject[:50]}...")
            return ""

        logger.info(f"      Cleaned subject: {raw_subject[:30]} → {subject[:30]}")
        return subject

    def _validate_and_clean_email(self, raw_email: str) -> str:
        """Validate and clean email address, return empty string if invalid."""

        if not raw_email:
            return ""

        # Clean up escaped characters, quotes, newlines, and whitespace
        email = raw_email.strip()

        # Remove common escaped characters and quotes
        email = re.sub(r'\\[ntr"]', '', email)  # Remove \n, \t, \r, \"
        email = re.sub(r'[<>"\s\n\r\t]', '', email)  # Remove brackets, quotes, whitespace, newlines
        email = email.strip()

        # Must look like an email address
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            logger.warning(f"      Rejecting email (invalid format): {email}")
            return ""

        logger.info(f"      Cleaned email: {raw_email[:50]} → {email}")
        return email

    def _extract_complete_test_parameters(self, content: str, subject: str, email_addr: str) -> Dict:
        """Extract complete test parameters with better test identification."""

        # Determine mail type from subject
        mail_type = self._determine_mail_type(subject)

        # Extract test name from content to distinguish different scenarios
        test_name = self._extract_test_name_from_content(content, mail_type)

        # Expected behaviors
        expected_behavior = self._get_expected_behavior(mail_type)

        # Extract timestamp from content
        sent_timestamp = self._extract_timestamp_from_content(content)

        # Failure message specifically mentions AssertionError
        failure_message = "AssertionError: Email not found in recipient inbox after exhausting all search attempts"

        # Extract test duration from content
        test_duration = 300.0  # Default 5 minutes
        duration_match = re.search(r'"duration":(\d+)', content)
        if duration_match:
            test_duration = float(duration_match.group(1)) / 1000  # Convert from ms to seconds

        # Generate more specific test ID that includes email context
        test_context = self._extract_test_context(content)
        test_id = generate_test_id(f"{subject}_{mail_type}_{email_addr}_{test_context}")

        # Extract parameters
        parameters = {
            'recipient': email_addr,
            'original_subject': subject,
            'mail_type': mail_type,
            'test_timeout': test_duration,
            'test_context': test_context,
            'test_name': test_name,
            'extraction_source': 'allure_assertion_error'
        }

        return {
            'test_name': test_name,
            'expected_behavior': expected_behavior,
            'mail_type': mail_type,
            'failure_message': failure_message,
            'test_duration': test_duration,
            'timestamp': datetime.now(),
            'test_id': test_id,
            'parameters': parameters,
            'sent_timestamp': sent_timestamp
        }

    def _extract_test_name_from_content(self, content: str, mail_type: str) -> str:
        """Extract specific test name from content with better consistency."""

        # Look for test names in JSON content - prioritize more specific names
        test_name_patterns = [
            r'"fullName":\s*"([^"]*(?:SmartAPI|Manual)[^"]*)"',  # SmartAPI tests first
            r'"fullName":\s*"([^"]*(?:Smoke-Emails)[^"]*)"',  # Smoke-Emails tests
            r'"name":\s*"([^"]*(?:SmartAPI|Manual)[^"]*)"',  # Fallback for SmartAPI
            r'"name":\s*"([^"]*(?:Smoke-Emails)[^"]*)"',  # Fallback for Smoke
            r'"name":\s*"([^"]*@\d+\.\d+[^"]*)"',  # Pattern for @1.1, @1.2 etc.
            r'"fullName":\s*"([^"]*@\d+\.\d+[^"]*)"',  # Pattern for @1.1, @1.2 etc.
        ]

        for pattern in test_name_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Use the longest/most specific match
                test_name = max(matches, key=len).strip()
                # Clean up common variations
                test_name = re.sub(r'\s+', ' ', test_name)
                logger.info(f"   Extracted specific test name: {test_name}")
                return test_name

        # Fallback to mail type based name if no specific test found
        fallback_name = f"Email {mail_type.title()} inline - SMTP"
        logger.info(f"   Using fallback test name: {fallback_name}")
        return fallback_name

    def _extract_test_context(self, content: str) -> str:
        """Extract additional context to distinguish tests."""

        # Look for the most distinctive context markers
        context_patterns = [
            r'"fullName":\s*"([^"]*(?:SmartAPI|Manual)[^"]*)"',
            r'"fullName":\s*"([^"]*Smoke-Emails[^"]*)"',
            r'"name":\s*"([^"]*(?:SmartAPI|Manual)[^"]*)"',
            r'"name":\s*"([^"]*Smoke-Emails[^"]*)"',
            r'"historyId":\s*"([a-f0-9]{8})[a-f0-9]*"',
            r'"uuid":\s*"([a-f0-9]{8})[a-f0-9]*"'
        ]

        contexts = []
        for pattern in context_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                match_lower = match.lower()
                if 'smartapi' in match_lower or 'manual' in match_lower:
                    contexts.append("smartapi")
                elif 'smoke' in match_lower:
                    contexts.append("smoke")
                elif len(match) >= 8:
                    # Check if it's a hex string
                    hex_chars = '0123456789abcdef'
                    if all(c in hex_chars for c in match_lower[:8]):
                        contexts.append(match[:8])
                    else:
                        contexts.append(match[:16])
                else:
                    contexts.append(match[:16])

        if contexts:
            # Use the most specific context (prioritize smoke/smartapi over IDs)
            for ctx in ["smartapi", "smoke"]:
                if ctx in contexts:
                    logger.info(f"   Extracted test context: {ctx}")
                    return ctx

            # Use first context if no specific category found
            context = contexts[0]
            logger.info(f"   Extracted test context: {context}")
            return context

        return "default"

    def _extract_timestamp_from_content(self, content: str) -> Optional[datetime]:
        """Extract timestamp from attachment content."""
        patterns = [
            r'"start":(\d+)',  # Extract start time from JSON
            r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
        ]

        # Try to extract timestamp from JSON first
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                try:
                    if pattern.startswith('"start"'):
                        # Convert timestamp from milliseconds
                        timestamp_ms = int(match.group(1))
                        return datetime.fromtimestamp(timestamp_ms / 1000)
                    else:
                        timestamp_str = match.group(1)
                        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S']:
                            try:
                                return datetime.strptime(timestamp_str, fmt)
                            except ValueError:
                                continue
                except Exception:
                    continue
        return None

    def _determine_mail_type(self, subject: str) -> str:
        """Determine mail type from subject."""
        subject_lower = subject.lower()

        # Check for specific patterns in order of specificity
        if 'phishing' in subject_lower or 'AUTO_phishing' in subject:
            return 'phishing'
        elif 'clean' in subject_lower or 'AUTO_clean' in subject:
            return 'clean'
        elif any(keyword in subject_lower for keyword in ['malware', 'AUTO_malware', 'eicar']):
            return 'malware'  # Use 'eicar' for malware tests
        else:
            # Log for debugging
            logger.info(f"      Unable to determine mail type for subject: {subject[:50]}...")
            return 'unknown'

    def _deduplicate_by_email(self, failed_tests: List[FailedTest]) -> List[FailedTest]:
        """Email-based deduplication."""
        logger.info(f"Starting deduplication with {len(failed_tests)} tests")

        unique_tests = []
        seen_emails = set()

        for i, test in enumerate(failed_tests):
            # Deduplicate by email subject + address only (ignore test context)
            email_key = f"{test.mail_subject}_{test.mail_address}_{test.mail_type}"

            logger.info(f"Processing test {i+1}: {test.mail_type} - {test.mail_subject[:30]}...")
            logger.info(f"Email key: {email_key[:100]}...")

            if email_key not in seen_emails:
                unique_tests.append(test)
                seen_emails.add(email_key)
                logger.info(f"   UNIQUE EMAIL: {test.mail_type.upper()} - {test.mail_subject[:50]}...")
                logger.info(f"       Email Key: {email_key[:100]}...")
                logger.info(f"       Test Context: {test.test_name}")
            else:
                logger.info(f"   DUPLICATE EMAIL SKIPPED: {test.mail_type.upper()} - {test.mail_subject[:30]}...")
                logger.info(f"       Duplicate Key: {email_key[:100]}...")
                logger.info(f"       Skipped Context: {test.test_name}")

        logger.info(f"Deduplication complete: {len(unique_tests)} unique tests")
        return unique_tests

    def _log_final_results(self, failed_tests: List[FailedTest]) -> None:
        """Log what we're actually processing."""
        logger.info("UNIQUE EMAILS TO PROCESS:")
        for i, test in enumerate(failed_tests, 1):
            logger.info(f"   {i}. {test.mail_type.upper()}: {test.mail_subject}")
            logger.info(f"      Email: {test.mail_address}")
            logger.info(f"      Test Context: {test.test_name}")