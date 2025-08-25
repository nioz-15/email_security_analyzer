#!/usr/bin/env python3

"""
Complete Email Security Analysis Service
A FastAPI service that analyzes email security test failures from Allure reports
with AI-powered classification and automated mailbox verification.
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import json
import re
import os
import base64
import time
import asyncio
import hashlib
import shutil
import tempfile
import zipfile
import uuid
import yaml
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import logging
from contextlib import asynccontextmanager
import logging

# Third-party imports
import openai
from playwright.async_api import async_playwright, Page, Browser

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Configuration management
class ConfigManager:
    """Manages configuration from YAML file"""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = {}
        self.load_config()

    def load_config(self):
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            self.create_default_config()

        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
            logger.info(f"✅ Configuration loaded from {self.config_path}")

            # Log available email accounts (without passwords)
            email_accounts = self.config.get('email_accounts', {})
            logger.info(f"📧 Configured email accounts: {len(email_accounts)}")
            for email in email_accounts.keys():
                logger.info(f"   - {email}")

        except Exception as e:
            logger.error(f"❌ Failed to load config from {self.config_path}: {e}")
            self.config = {}

    def create_default_config(self):
        """Create a default configuration file"""
        default_config = {
            'openai_api_key': 'sk-your-openai-api-key-here',
            'email_accounts': {
                'test-user1@example.com': 'your-password-here',
                'test-user2@example.com': 'your-password-here'
            },
            'settings': {
                'default_timezone': 'Asia/Jerusalem',
                'max_analysis_time_minutes': 30,
                'screenshot_quality': 90
            }
        }

        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2)
            logger.info(f"📝 Created default configuration file: {self.config_path}")
            logger.info("⚠️  Please update the configuration file with your actual credentials!")
        except Exception as e:
            logger.error(f"❌ Failed to create default config: {e}")

    def get_openai_api_key(self) -> Optional[str]:
        """Get OpenAI API key from config"""
        api_key = self.config.get('openai_api_key')
        if not api_key or api_key == 'sk-your-openai-api-key-here':
            return None
        return api_key

    def get_email_password(self, email_address: str) -> Optional[str]:
        """Get password for specific email address"""
        email_accounts = self.config.get('email_accounts', {})
        return email_accounts.get(email_address)

    def get_all_configured_emails(self) -> List[str]:
        """Get list of all configured email addresses"""
        email_accounts = self.config.get('email_accounts', {})
        return list(email_accounts.keys())

    def get_setting(self, key: str, default=None):
        """Get a setting value"""
        settings = self.config.get('settings', {})
        return settings.get(key, default)


# Initialize global config manager
config_manager = ConfigManager()

# Update OPENAI_API_KEY from config
OPENAI_API_KEY = config_manager.get_openai_api_key() or os.getenv("OPENAI_API_KEY")


@dataclass
class FailedTest:
    """Failed test data structure with complete parameters"""
    test_name: str
    mail_address: str
    mail_subject: str
    expected_behavior: str
    mail_type: str  # clean, phishing, eicar, malware
    failure_message: str
    test_duration: float
    timestamp: datetime
    test_id: str = ""
    parameters: dict = None
    sent_timestamp: Optional[datetime] = None


@dataclass
class MailVerificationResult:
    """Result of mailbox verification"""
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
    mail_sent_time: Optional[datetime] = None
    mail_arrived_time: Optional[datetime] = None
    mail_arrived_time_str: str = ""


@dataclass
class AIAnalysisResult:
    """AI analysis result"""
    classification: str  # REAL_ISSUE, DELAY_ISSUE, CODE_ISSUE
    confidence: float
    explanation: str
    recommended_action: str
    analysis_successful: bool = True


@dataclass
class CompleteTestReport:
    """Complete test analysis report"""
    failed_test: FailedTest
    mailbox_verification: MailVerificationResult
    ai_analysis: AIAnalysisResult
    final_classification: str
    report_timestamp: datetime


class AllureParser:
    """Extract tests with AssertionError (actual failures)"""

    def __init__(self, reports_folder: str):
        self.reports_folder = Path(reports_folder)

    def extract_failed_mail_tests(self) -> List[FailedTest]:
        """Extract ONLY tests with AssertionError (true failures) with EMAIL-BASED deduplication"""

        logger.info("🔍 Parsing Allure reports for AssertionError failures")

        html_files = list(self.reports_folder.glob("*.html"))
        if not html_files:
            logger.error("No HTML files found")
            return []

        all_failed_tests = []

        for html_file in html_files:
            logger.info(f"📄 Processing: {html_file.name}")

            try:
                with open(html_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Extract ONLY AssertionError failures
                failed_tests = self._extract_assertion_error_failures_only(content, html_file.name)

                # Email-based deduplication
                unique_tests = []
                seen_emails = set()

                for test in failed_tests:
                    # Deduplicate by email subject + address only (ignore test context)
                    email_key = f"{test.mail_subject}_{test.mail_address}_{test.mail_type}"

                    if email_key not in seen_emails:
                        unique_tests.append(test)
                        seen_emails.add(email_key)
                        logger.info(
                            f"   ✅ UNIQUE EMAIL: {test.mail_type.upper()} - {test.mail_subject[:50]}...")
                        logger.info(f"       Email Key: {email_key[:100]}...")
                        logger.info(f"       Test Context: {test.test_name}")
                    else:
                        logger.info(
                            f"   📄 DUPLICATE EMAIL SKIPPED: {test.mail_type.upper()} - {test.mail_subject[:30]}...")
                        logger.info(f"       Duplicate Key: {email_key[:100]}...")
                        logger.info(f"       Skipped Context: {test.test_name}")

                all_failed_tests.extend(unique_tests)

            except Exception as e:
                logger.error(f"Error parsing {html_file.name}: {e}")

        logger.info(f"📊 Total unique emails found: {len(all_failed_tests)}")

        # Final validation - log what we're actually processing
        logger.info("🎯 UNIQUE EMAILS TO PROCESS:")
        for i, test in enumerate(all_failed_tests, 1):
            logger.info(f"   {i}. {test.mail_type.upper()}: {test.mail_subject}")
            logger.info(f"      📮 Email: {test.mail_address}")
            logger.info(f"      🏷️ Test Context: {test.test_name}")

        return all_failed_tests

    def _extract_assertion_error_failures_only(self, content: str, source_file: str) -> List[FailedTest]:
        """Extract ONLY tests that have AssertionError from base64 sections in script tags"""

        failed_tests = []

        # Extract script sections (like debug script)
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)

        logger.info(f"   🔎 Checking {len(scripts)} script sections for AssertionError")

        # Find the large script (Script 8 with 2M+ chars)
        assertion_error_count = 0
        for i, script in enumerate(scripts):
            if len(script) > 1000000:  # The big script with 2M+ chars
                logger.info(f"   🎯 Analyzing Large Script {i + 1} (length: {len(script):,} chars)")

                # Find ALL base64 sections within this script
                base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
                base64_matches = re.findall(base64_pattern, script)

                logger.info(f"   📦 Found {len(base64_matches)} base64 sections - checking for AssertionError")

                # Check EVERY base64 section for AssertionError
                for j, b64_data in enumerate(base64_matches):
                    try:
                        decoded = base64.b64decode(b64_data).decode('utf-8')

                        # Only process if contains AssertionError
                        has_assertion_error = 'assertionerror' in decoded.lower()

                        if has_assertion_error:
                            assertion_error_count += 1
                            logger.info(f"      🚨 Base64 section {j + 1} contains AssertionError (real failure)")

                            # Parse this AssertionError failure
                            section_tests = self._parse_assertion_error_attachment(decoded, j, source_file)
                            failed_tests.extend(section_tests)

                        # Progress tracking
                        if (j + 1) % 50 == 0:
                            logger.info(
                                f"      📊 Processed {j + 1}/{len(base64_matches)} base64 sections... Found {assertion_error_count} AssertionErrors")

                    except Exception as e:
                        continue

        logger.info(f"   🎯 Found {assertion_error_count} base64 sections with AssertionError")
        return failed_tests

    def _parse_assertion_error_attachment(self, decoded_content: str, attachment_index: int, source_file: str) -> List[
        FailedTest]:
        """Parse a single attachment for AssertionError information with strict validation"""

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
                logger.info(f"      🔍 Pattern {idx + 1} matched {len(matches)} AssertionError(s)")

        if not all_matches:
            return failed_tests

        logger.info(f"      🎯 Found {len(all_matches)} total AssertionError(s) in this section")

        # Track processed subjects to avoid duplicates within same section
        processed_in_section = set()

        for i, (match, pattern_used) in enumerate(zip(all_matches, pattern_info)):
            raw_subject = match[0].strip()
            raw_email = match[1].strip()

            logger.info(f"      📧 Processing AssertionError {i + 1} (via {pattern_used}):")
            logger.info(f"          Raw subject: {raw_subject[:50]}...")
            logger.info(f"          Raw email: {raw_email}")

            # Validate and clean the extracted data
            subject = self._validate_and_clean_subject(raw_subject)
            email_addr = self._validate_and_clean_email(raw_email)

            if not subject or not email_addr:
                logger.warning(
                    f"      ⚠️ Skipping invalid extraction: subject='{raw_subject[:50]}', email='{raw_email[:50]}'")
                continue

            logger.info(f"      📧 Processing valid AssertionError {i + 1}: {subject[:40]}... → {email_addr}")

            # Extract complete test parameters for this specific failure
            test_params = self._extract_complete_test_parameters(decoded_content, subject, email_addr)

            logger.info(
                f"      🏷️ Detected mail type: {test_params['mail_type'].upper()} for subject: {subject[:30]}...")

            # Check for duplicates within this section using email-based key
            section_key = f"{subject}_{email_addr}_{test_params['mail_type']}"
            if section_key in processed_in_section:
                logger.info(
                    f"      📄 Skipping duplicate email in same section: {test_params['mail_type']} - {subject[:30]}...")
                continue

            processed_in_section.add(section_key)

            logger.info(f"      ✅ Processing unique email: {test_params['mail_type']} - {subject[:30]}...")

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
                f"         ✅ VALID ASSERTION ERROR: {test_params['test_name']} - {test_params['mail_type'].upper()}: {subject[:40]}...")

        return failed_tests

    def _validate_and_clean_subject(self, raw_subject: str) -> str:
        """Validate and clean email subject, return empty string if invalid"""

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
                logger.warning(f"      ❌ Rejecting subject (looks like metadata): {subject[:50]}...")
                return ""

        # Must look like a reasonable email subject
        if len(subject) < 5 or len(subject) > 200:
            logger.warning(f"      ❌ Rejecting subject (bad length {len(subject)}): {subject[:50]}...")
            return ""

        # Should contain some reasonable characters
        if not re.search(r'[A-Za-z0-9_-]', subject):
            logger.warning(f"      ❌ Rejecting subject (no valid chars): {subject[:50]}...")
            return ""

        logger.info(f"      ✅ Cleaned subject: {raw_subject[:30]} → {subject[:30]}")
        return subject

    def _validate_and_clean_email(self, raw_email: str) -> str:
        """Validate and clean email address, return empty string if invalid"""

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
            logger.warning(f"      ❌ Rejecting email (invalid format): {email}")
            return ""

        logger.info(f"      ✅ Cleaned email: {raw_email[:50]} → {email}")
        return email

    def _extract_complete_test_parameters(self, content: str, subject: str, email_addr: str) -> Dict:
        """Extract complete test parameters with better test identification"""

        # Determine mail type from subject
        mail_type = self._determine_mail_type(subject)

        # Extract test name from content to distinguish different scenarios
        test_name = self._extract_test_name_from_content(content, mail_type)

        # Expected behaviors
        expected_behaviors = {
            'clean': 'Email should be delivered normally without any security modifications',
            'phishing': 'Email should arrive with "Phishing Alert!" prefix added to subject',
            'eicar': 'Email should be quarantined with "Quarantined" prefix added to subject',
            'malware': 'Email should be quarantined with "Quarantined" prefix added to subject'
        }

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
        test_id = self._generate_test_id(f"{subject}_{mail_type}_{email_addr}_{test_context}")

        # Extract parameters
        parameters = {
            'recipient': email_addr,
            'original_subject': subject,
            'mail_type': mail_type,
            'test_timeout': test_duration,
            'test_context': test_context,
            'test_name': test_name,  # Add test name to parameters
            'extraction_source': 'allure_assertion_error'
        }

        return {
            'test_name': test_name,
            'expected_behavior': expected_behaviors.get(mail_type, 'Unknown behavior'),
            'mail_type': mail_type,
            'failure_message': failure_message,
            'test_duration': test_duration,
            'timestamp': datetime.now(),
            'test_id': test_id,
            'parameters': parameters,
            'sent_timestamp': sent_timestamp
        }

    def _extract_test_name_from_content(self, content: str, mail_type: str) -> str:
        """Extract specific test name from content with better consistency"""

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
                logger.info(f"   🏷️ Extracted specific test name: {test_name}")
                return test_name

        # Fallback to mail type based name if no specific test found
        fallback_name = f"Email {mail_type.title()} inline - SMTP"
        logger.info(f"   🏷️ Using fallback test name: {fallback_name}")
        return fallback_name

    def _extract_test_context(self, content: str) -> str:
        """Extract additional context to distinguish tests"""

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
                    logger.info(f"   🏷️ Extracted test context: {ctx}")
                    return ctx

            # Use first context if no specific category found
            context = contexts[0]
            logger.info(f"   🏷️ Extracted test context: {context}")
            return context

        return "default"

    def _extract_timestamp_from_content(self, content: str) -> Optional[datetime]:
        """Extract timestamp from attachment content - ASSUMES ALLURE TIMESTAMPS ARE ALREADY UTC"""

        # Look for specific log patterns first (most accurate for email sending time)
        log_patterns = [
            r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*\[INFO\]\s*Sending from sender',
            # [2025-08-18 06:50:59][INFO] Sending from sender
            r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*\[INFO\]\s*Email sent successfully',
            # [2025-08-18 06:51:00][INFO] Email sent successfully
            r'"start":(\d+)',  # Extract start time from JSON (milliseconds)
            r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]',  # Any bracketed timestamp
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # ISO format
        ]

        logger.info("🕐 Extracting sent timestamp from allure content (should be UTC)...")

        # Try log patterns first (most reliable for sent time)
        for i, pattern in enumerate(log_patterns):
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                logger.info(f"   Found {len(matches)} timestamp matches with pattern {i + 1}")
                for j, match in enumerate(matches):
                    try:
                        if isinstance(match, tuple):
                            match = match[0] if match[0] else match[1]

                        timestamp_str = str(match).strip()
                        logger.info(f"   Match {j + 1}: Raw timestamp string = '{timestamp_str}'")

                        if pattern.startswith('"start"'):
                            # Convert timestamp from milliseconds - CRITICAL: Use UTC conversion
                            timestamp_ms = int(timestamp_str)
                            # Use utcfromtimestamp to ensure UTC, not local timezone
                            parsed_time = datetime.utcfromtimestamp(timestamp_ms / 1000)
                            logger.info(f"   ✅ Parsed JSON timestamp: {parsed_time} UTC (from {timestamp_ms}ms)")
                            return parsed_time
                        else:
                            # Parse log timestamps - CRITICAL: these are already UTC, don't convert!
                            formats_to_try = [
                                '%Y-%m-%d %H:%M:%S',
                                '%Y-%m-%dT%H:%M:%S'
                            ]

                            for fmt in formats_to_try:
                                try:
                                    parsed_time = datetime.strptime(timestamp_str, fmt)
                                    logger.info(
                                        f"   ✅ Parsed log timestamp: {parsed_time} (ALREADY UTC - no conversion needed)")
                                    logger.info(f"   📋 Using this as final sent time (UTC): {parsed_time}")
                                    return parsed_time
                                except ValueError:
                                    continue

                    except Exception as e:
                        logger.debug(f"   ❌ Failed to parse timestamp '{match}': {e}")
                        continue

        # Fallback to previous method if no specific log patterns found
        logger.warning("   ⚠️ No specific log patterns found, trying generic extraction...")

        general_patterns = [
            r'"start":(\d+)',  # Extract start time from JSON
            r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
        ]

        # Try to extract timestamp from JSON or general patterns
        for pattern in general_patterns:
            match = re.search(pattern, content)
            if match:
                try:
                    if pattern.startswith('"start"'):
                        # Convert timestamp from milliseconds - CRITICAL: Use UTC conversion
                        timestamp_ms = int(match.group(1))
                        # Use utcfromtimestamp to ensure UTC, not local timezone
                        parsed_time = datetime.utcfromtimestamp(timestamp_ms / 1000)
                        logger.info(f"   Fallback: Parsed JSON timestamp: {parsed_time} UTC (from {timestamp_ms}ms)")
                        return parsed_time
                    else:
                        timestamp_str = match.group(1)
                        logger.info(f"   Fallback: Raw timestamp = '{timestamp_str}'")
                        formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S']
                        for fmt in formats:
                            try:
                                parsed_time = datetime.strptime(timestamp_str, fmt)
                                logger.info(f"   Fallback: Parsed timestamp: {parsed_time} (ALREADY UTC)")
                                return parsed_time
                            except ValueError:
                                continue
                except Exception as e:
                    logger.debug(f"   Fallback parsing failed: {e}")
                    continue

        logger.error("   ❌ Could not extract any timestamp from allure content!")
        return None

    def _determine_mail_type(self, subject: str) -> str:
        """Determine mail type from subject"""
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
            logger.info(f"      🔍 Unable to determine mail type for subject: {subject[:50]}...")
            return 'unknown'

    def _generate_test_id(self, identifier: str) -> str:
        """Generate test ID"""
        return hashlib.md5(identifier.encode()).hexdigest()[:8]


class PlaywrightMailboxVerifier:
    """Mailbox verifier with proper search logic"""

    def __init__(self, email_address: str):
        self.email_address = email_address
        # Get password from config based on email address
        self.password = config_manager.get_email_password(email_address)

        if not self.password:
            raise ValueError(f"No password configured for email: {email_address}")

        self.screenshots_dir = Path("screenshots")
        self.screenshots_dir.mkdir(exist_ok=True)
        self.browser = None
        self.page = None

        logger.info(f"🔐 Using configured password for: {email_address}")

    async def verify_mail_delivery(self, failed_test: FailedTest) -> MailVerificationResult:
        """Verify mail delivery with proper search logic"""

        logger.info(f"🌐 Verifying mail for: {failed_test.mail_address}")
        logger.info(f"📧 Searching for ORIGINAL subject: {failed_test.mail_subject[:50]}...")
        logger.info(f"🔍 Expected behavior: {failed_test.expected_behavior}")
        logger.info(f"🕐 Mail sent time (UTC): {failed_test.sent_timestamp}")

        try:
            await self._init_browser()
            await self._login_to_webmail(failed_test.mail_address)
            verification_result = await self._search_and_verify(failed_test)

            # IMPORTANT: sent_timestamp is already UTC, don't convert it!
            # Only convert the arrived time from local timezone to UTC
            if verification_result.delivery_delay_minutes is not None:
                logger.info(f"📊 Final timing (both UTC):")
                logger.info(f"   Sent: {failed_test.sent_timestamp} (already UTC)")
                logger.info(f"   Arrived: {verification_result.mail_arrived_time} (converted to UTC)")
                logger.info(f"   Delay: {verification_result.delivery_delay_minutes:.1f} minutes")

            await self._cleanup_browser()
            return verification_result

        except Exception as e:
            logger.error(f"Browser verification failed: {e}")
            await self._cleanup_browser()

            return MailVerificationResult(
                mail_found=False,
                error_message=f"Browser verification failed: {str(e)}",
                verification_timestamp=datetime.now(),
                mail_sent_time=failed_test.sent_timestamp  # Keep original UTC time
            )

    async def _search_and_verify(self, failed_test: FailedTest) -> MailVerificationResult:
        """Search logic - searches for ORIGINAL subject first"""

        try:
            # Take initial screenshot
            initial_screenshot = await self._take_screenshot(failed_test, "01_initial_inbox")

            # Search for original subject first
            search_results = await self._search_strategy(failed_test)

            # Take search results screenshot
            search_screenshot = await self._take_screenshot(failed_test, "02_search_results")

            # If email found, click on it to get full details including arrived time
            mail_arrived_time = None
            mail_arrived_time_str = ""
            if search_results.get('original_found') or search_results.get('quarantined_found') or search_results.get(
                    'phishing_alert_found'):
                logger.info("📧 Email found, extracting arrived time...")
                mail_arrived_time, mail_arrived_time_str = await self._extract_mail_arrived_time(failed_test,
                                                                                                 search_results)

                if mail_arrived_time_str:
                    logger.info(f"📅 Raw arrived time string: '{mail_arrived_time_str}'")
                if mail_arrived_time:
                    logger.info(f"📅 Parsed arrived time: {mail_arrived_time}")
                else:
                    logger.warning("📅 Could not parse arrived time to datetime object")
            else:
                logger.info("📧 No email found, skipping time extraction")

            # Analyze results with proper logic
            analysis_result = await self._analyze_results(failed_test, search_results)

            # Take detailed screenshot if found
            if analysis_result['mail_found']:
                detail_screenshot = await self._take_screenshot(failed_test, "03_email_details")
                analysis_result['screenshot_path'] = detail_screenshot
            else:
                analysis_result['screenshot_path'] = search_screenshot

            # Calculate delivery timing - CRITICAL: sent_timestamp is already UTC!
            delivery_delay_minutes = None
            if failed_test.sent_timestamp and mail_arrived_time:
                # Both times should now be in UTC for accurate comparison
                delivery_delay_minutes = (mail_arrived_time - failed_test.sent_timestamp).total_seconds() / 60

                logger.info(f"📊 Delivery timing calculation (BOTH UTC):")
                logger.info(f"   📤 Sent at: {failed_test.sent_timestamp} UTC (from allure - already UTC)")
                logger.info(f"   📥 Arrived at: {mail_arrived_time} UTC (converted from Israel time)")
                logger.info(f"   ⏱️  Delivery delay: {delivery_delay_minutes:.1f} minutes")

                # Validate the calculation makes sense
                if delivery_delay_minutes < 0:
                    logger.warning(f"⚠️ Negative delivery delay: {delivery_delay_minutes:.1f} minutes")
                    logger.warning("   Check if timezone conversions are correct")
                elif delivery_delay_minutes > 60:  # More than 1 hour is suspicious for local tests
                    logger.warning(
                        f"⚠️ Large delivery delay: {delivery_delay_minutes:.1f} minutes ({delivery_delay_minutes / 60:.1f} hours)")
                    logger.warning("   This may indicate timezone conversion issues")
                else:
                    logger.info(f"✅ Reasonable delivery delay: {delivery_delay_minutes:.1f} minutes")

            else:
                logger.warning("📊 Cannot calculate delivery delay - missing timing information")
                if not failed_test.sent_timestamp:
                    logger.warning("   Missing sent timestamp")
                if not mail_arrived_time:
                    logger.warning("   Missing arrived timestamp")

            return MailVerificationResult(
                mail_found=analysis_result['mail_found'],
                mail_subject_found=analysis_result.get('found_subject', ''),
                original_subject_found=analysis_result.get('original_found', False),
                quarantined_subject_found=analysis_result.get('quarantined_found', False),
                phishing_alert_found=analysis_result.get('phishing_alert_found', False),
                action_applied=analysis_result.get('action_applied', False),
                expected_action=self._get_expected_action(failed_test.mail_type),
                actual_action=analysis_result.get('actual_action', 'No action detected'),
                screenshot_path=analysis_result['screenshot_path'],
                verification_timestamp=datetime.now(),
                delivery_delay_minutes=delivery_delay_minutes,
                mailbox_html_content=await self.page.content(),
                mail_sent_time=failed_test.sent_timestamp,  # CRITICAL: Use original UTC time, don't convert!
                mail_arrived_time=mail_arrived_time,  # This is already converted to UTC
                mail_arrived_time_str=mail_arrived_time_str  # Keep original local time string for reference
            )

        except Exception as e:
            logger.error(f"Search failed: {e}")
            error_screenshot = await self._take_screenshot(failed_test, "error")

            return MailVerificationResult(
                mail_found=False,
                error_message=f"Search failed: {str(e)}",
                screenshot_path=error_screenshot,
                verification_timestamp=datetime.now(),
                mail_sent_time=failed_test.sent_timestamp
            )

    async def _search_strategy(self, failed_test: FailedTest) -> Dict:
        """Search strategy - check for different security actions"""

        search_results = {
            'original_found': False,
            'quarantined_found': False,
            'phishing_alert_found': False,
            'found_subject': '',
        }

        # Find search box
        search_box = await self._find_search_box()
        if not search_box:
            logger.warning("⚠️ Could not find search box")
            return search_results

        original_subject = failed_test.mail_subject

        # Step 1: Search for ORIGINAL subject (as delivered)
        logger.info(f"🔍 Searching for ORIGINAL subject: {original_subject}")
        original_result = await self._search_for_term(search_box, original_subject)
        if original_result:
            search_results['original_found'] = True
            search_results['found_subject'] = original_subject

        # Step 2: Search for QUARANTINED version (for EICAR/malware)
        if failed_test.mail_type in ['eicar', 'malware']:
            quarantined_subject = f"Quarantined [{original_subject}]"
            logger.info(f"🔍 Searching for QUARANTINED version: {quarantined_subject}")
            quarantined_result = await self._search_for_term(search_box, quarantined_subject)
            if quarantined_result:
                search_results['quarantined_found'] = True
                search_results['found_subject'] = quarantined_subject

        # Step 3: Search for PHISHING ALERT version (for phishing)
        if failed_test.mail_type == 'phishing':
            phishing_alert_subject = f"Phishing Alert! [{original_subject}]"
            logger.info(f"🔍 Searching for PHISHING ALERT version: {phishing_alert_subject}")
            phishing_result = await self._search_for_term(search_box, phishing_alert_subject)
            if phishing_result:
                search_results['phishing_alert_found'] = True
                search_results['found_subject'] = phishing_alert_subject

        return search_results

    async def _search_for_term(self, search_box, term: str) -> bool:
        """Search for a specific term"""
        try:
            await search_box.fill('')
            await asyncio.sleep(0.5)
            await search_box.fill(term)
            await self.page.keyboard.press('Enter')
            await asyncio.sleep(4)  # Wait longer for results

            content = await self.page.content()
            found = term.lower() in content.lower()
            logger.info(f"   {'✅' if found else '❌'} Search result: {term[:40]}...")
            return found

        except Exception as e:
            logger.error(f"Search error: {e}")
            return False

    async def _analyze_results(self, failed_test: FailedTest, search_results: Dict) -> Dict:
        """Analysis with proper logic for each mail type"""

        analysis = {
            'mail_found': False,
            'found_subject': '',
            'original_found': search_results.get('original_found', False),
            'quarantined_found': search_results.get('quarantined_found', False),
            'phishing_alert_found': search_results.get('phishing_alert_found', False),
            'action_applied': False,
            'actual_action': 'Email not found'
        }

        # Check if mail was found in any form
        if any([search_results.get('original_found'), search_results.get('quarantined_found'),
                search_results.get('phishing_alert_found')]):
            analysis['mail_found'] = True
            analysis['found_subject'] = search_results.get('found_subject', '')

        # Determine action based on mail type and what was found
        mail_type = failed_test.mail_type

        if mail_type == 'clean':
            # Clean emails should be delivered normally (original subject only)
            if search_results.get('original_found') and not search_results.get('quarantined_found'):
                analysis['action_applied'] = True
                analysis['actual_action'] = 'Delivered normally (correct for clean email)'
            elif search_results.get('quarantined_found'):
                analysis['action_applied'] = False
                analysis['actual_action'] = 'Incorrectly quarantined (clean email should not be quarantined)'
            else:
                analysis['actual_action'] = 'Email not found'

        elif mail_type == 'phishing':
            # Phishing emails should get "Phishing Alert!" prefix
            if search_results.get('phishing_alert_found'):
                analysis['action_applied'] = True
                analysis['actual_action'] = 'Phishing Alert applied correctly'
            elif search_results.get('quarantined_found'):
                analysis['action_applied'] = False
                analysis['actual_action'] = 'Incorrectly quarantined (should have phishing alert instead)'
            elif search_results.get('original_found'):
                analysis['action_applied'] = False
                analysis['actual_action'] = 'No security action applied (delivered normally)'
            else:
                analysis['actual_action'] = 'Email not found'

        elif mail_type in ['eicar', 'malware']:
            # EICAR/malware emails should be quarantined
            if search_results.get('quarantined_found'):
                analysis['action_applied'] = True
                analysis['actual_action'] = 'Correctly quarantined'
            elif search_results.get('original_found'):
                analysis['action_applied'] = False
                analysis['actual_action'] = 'No security action applied (delivered normally - security failure)'
            else:
                analysis['actual_action'] = 'Email not found (possibly blocked completely)'

        return analysis

    def _get_expected_action(self, mail_type: str) -> str:
        """Get expected action for each mail type"""
        actions = {
            'clean': 'Deliver normally without modifications',
            'phishing': 'Add "Phishing Alert!" prefix to subject',
            'eicar': 'Quarantine with "Quarantined" prefix',
            'malware': 'Quarantine with "Quarantined" prefix'
        }
        return actions.get(mail_type, 'Unknown action')

    async def _extract_mail_arrived_time(self, failed_test: FailedTest, search_results: Dict):
        """Extract mail arrived time by clicking on the found email"""

        try:
            found_subject = search_results.get('found_subject', '')
            if not found_subject:
                logger.warning("No subject found to click on")
                return None, ""

            logger.info(f"🕒 Extracting arrived time for: {found_subject[:50]}...")

            # Try to find and click on the email with the found subject
            # Look for different possible selectors for the email row
            email_selectors = [
                f'[aria-label*="{found_subject[:30]}"]',
                f'[title*="{found_subject[:30]}"]',
                f'div:has-text("{found_subject[:30]}")',
                f'span:has-text("{found_subject[:30]}")',
                '.ms-List-cell',
                '[data-automationid="DetailsRow"]',
                '[role="gridcell"]'
            ]

            email_clicked = False
            for selector in email_selectors:
                try:
                    logger.info(f"   Trying selector: {selector}")
                    elements = await self.page.query_selector_all(selector)

                    for element in elements:
                        # Check if this element contains our subject
                        element_text = await element.inner_text()
                        if found_subject[:20] in element_text or any(
                                word in element_text for word in found_subject.split()[:3]):
                            logger.info(f"   Found matching element with text: {element_text[:100]}...")
                            await element.click()
                            email_clicked = True
                            break

                    if email_clicked:
                        break

                except Exception as e:
                    logger.debug(f"   Selector {selector} failed: {e}")
                    continue

            if not email_clicked:
                logger.warning("Could not click on email to get arrived time")
                return None, ""

            # Wait for email details to load
            await asyncio.sleep(3)

            # Extract arrived time from various possible locations
            arrived_time_str = await self._extract_time_from_email_details()

            if not arrived_time_str:
                logger.warning("Could not extract arrived time from email details")
                return None, ""

            # Parse the arrived time string to datetime
            arrived_datetime = self._parse_arrived_time(arrived_time_str)

            logger.info(f"✅ Extracted arrived time: {arrived_time_str}")
            if arrived_datetime:
                logger.info(f"✅ Parsed to datetime: {arrived_datetime}")

            return arrived_datetime, arrived_time_str

        except Exception as e:
            logger.error(f"Failed to extract arrived time: {e}")
            return None, ""

    async def _extract_time_from_email_details(self) -> str:
        """Extract time information from the opened email details"""

        # Wait for the email content to load
        await asyncio.sleep(2)

        # Try different selectors that might contain the timestamp
        time_selectors = [
            '[data-automationid="MessageHeader"] time',
            'time[datetime]',
            '[class*="time"]',
            '[class*="timestamp"]',
            '[class*="date"]',
            '[aria-label*="received"]',
            '[aria-label*="sent"]',
            'span:has-text("AM")',
            'span:has-text("PM")',
            '[data-automationid="MessageReadingPane"] [class*="time"]',
            '.ms-MessageHeader',
            '[data-automationid="MessageHeader"]'
        ]

        found_times = []

        for selector in time_selectors:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    # Get datetime attribute first
                    datetime_attr = await element.get_attribute('datetime')
                    if datetime_attr:
                        logger.info(f"   Found datetime attribute: {datetime_attr}")
                        found_times.append(datetime_attr)

                    # Get text content
                    text = await element.inner_text()
                    if text and self._looks_like_timestamp(text):
                        logger.info(f"   Found timestamp text: {text}")
                        found_times.append(text.strip())

            except Exception as e:
                logger.debug(f"   Selector {selector} failed: {e}")
                continue

        # If no specific selectors work, try to find timestamp patterns in the page content
        try:
            page_content = await self.page.content()

            # Look for common timestamp patterns
            timestamp_patterns = [
                r'(\w+\s+\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s*[AP]M)',  # Mon 8/18/2025 9:58 AM
                r'(\w+,?\s+\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}\s*[AP]M)',  # Mon, 8/18/2025, 9:58 AM
                r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s*[AP]M)',  # 8/18/2025 9:58 AM
                r'(\w+\s+\d{1,2}:\d{2}\s*[AP]M)',  # Mon 9:58 AM
                r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # ISO format
                r'(received:\s*[^<\n]+)',  # "received: ..." pattern
            ]

            for pattern in timestamp_patterns:
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if self._looks_like_timestamp(match):
                        logger.info(f"   Found timestamp via regex: {match}")
                        found_times.append(match.strip())

        except Exception as e:
            logger.debug(f"   Regex timestamp extraction failed: {e}")

        # Return the most complete timestamp (prioritize ones with full dates)
        if found_times:
            # Sort by length (longer strings likely have more complete info)
            sorted_times = sorted(set(found_times), key=len, reverse=True)
            logger.info(f"   All found times: {sorted_times}")

            # Prioritize timestamps that contain date info
            for time_str in sorted_times:
                if re.search(r'\d{1,2}/\d{1,2}/\d{4}', time_str):
                    logger.info(f"   Selected timestamp with date: {time_str}")
                    return time_str

            # If no date info, return the longest/most complete one
            selected_time = sorted_times[0]
            logger.info(f"   Selected most complete timestamp: {selected_time}")
            return selected_time

        return ""

    def _looks_like_timestamp(self, text: str) -> bool:
        """Check if text looks like a timestamp"""
        if not text or len(text) < 5:
            return False

        text_lower = text.lower().strip()

        # Check for time indicators
        time_indicators = ['am', 'pm', ':', 'received', 'sent', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

        return any(indicator in text_lower for indicator in time_indicators) and len(text) < 100

    def _parse_arrived_time(self, time_str: str) -> Optional[datetime]:
        """Parse various time string formats to datetime with timezone handling"""

        if not time_str:
            return None

        # Clean up the time string
        clean_time = time_str.strip().replace('\n', ' ').replace('\t', ' ')
        clean_time = re.sub(r'\s+', ' ', clean_time)

        logger.info(f"   Parsing time string: {clean_time}")

        # Try different datetime formats - prioritize formats with full dates
        formats_to_try = [
            '%Y-%m-%dT%H:%M:%S',  # ISO format: 2025-08-18T09:58:00
            '%Y-%m-%dT%H:%M:%S.%f',  # ISO with microseconds
            '%Y-%m-%dT%H:%M:%SZ',  # ISO with Z
            '%a %m/%d/%Y %I:%M %p',  # Mon 8/18/2025 9:58 AM
            '%a, %m/%d/%Y, %I:%M %p',  # Mon, 8/18/2025, 9:58 AM
            '%a, %m/%d/%Y %I:%M %p',  # Mon, 8/18/2025 9:58 AM
            '%m/%d/%Y %I:%M %p',  # 8/18/2025 9:58 AM
            '%m/%d/%Y, %I:%M %p',  # 8/18/2025, 9:58 AM
            '%B %d, %Y at %I:%M %p',  # August 18, 2025 at 9:58 AM
            '%a %b %d %Y %I:%M %p',  # Mon Aug 18 2025 9:58 AM
            '%b %d, %Y %I:%M %p',  # Aug 18, 2025 9:58 AM
        ]

        # First, try to extract a full date from the string if it contains date info
        # Look for patterns like "Mon 8/18/2025 9:58 AM"
        full_date_patterns = [
            r'(\w+\s+\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s*[AP]M)',  # Mon 8/18/2025 9:58 AM
            r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s*[AP]M)',  # 8/18/2025 9:58 AM
            r'(\w+,?\s+\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}\s*[AP]M)',  # Mon, 8/18/2025, 9:58 AM
        ]

        parsed_datetime = None

        # Try to extract full date format first
        for pattern in full_date_patterns:
            match = re.search(pattern, clean_time, re.IGNORECASE)
            if match:
                full_time_str = match.group(1).strip()
                logger.info(f"   Found full date pattern: {full_time_str}")

                # Try parsing this full date string
                for fmt in formats_to_try:
                    try:
                        # Handle different day name formats
                        test_str = full_time_str
                        if ',' in test_str:
                            test_str = re.sub(r'(\w+),\s*', r'\1 ', test_str)  # Remove comma after day

                        parsed_datetime = datetime.strptime(test_str, fmt)
                        logger.info(f"   Successfully parsed full date with format: {fmt} -> {parsed_datetime}")
                        break
                    except ValueError:
                        continue
                if parsed_datetime:
                    break

        # If no full date pattern found, try the original formats
        if not parsed_datetime:
            for fmt in formats_to_try:
                try:
                    parsed_datetime = datetime.strptime(clean_time, fmt)
                    logger.info(f"   Successfully parsed with format: {fmt}")
                    break
                except ValueError:
                    continue

        # If we have a parsed datetime, convert from Israel timezone to UTC
        if parsed_datetime:
            # Assume the browser/email client time is in Israel timezone (UTC+3)
            # Convert to UTC for consistent comparison
            try:
                import pytz
                israel_tz = pytz.timezone('Asia/Jerusalem')

                # Localize to Israel timezone first (assume it's naive local time)
                localized_time = israel_tz.localize(parsed_datetime)

                # Convert to UTC
                utc_time = localized_time.astimezone(pytz.UTC)

                logger.info(f"   Converted {parsed_datetime} (Israel) -> {utc_time} (UTC)")
                return utc_time.replace(tzinfo=None)  # Remove timezone info for consistency

            except ImportError:
                # Fallback without pytz - manually subtract 3 hours for Israel time
                logger.warning("   pytz not available, using manual timezone conversion")
                utc_time = parsed_datetime - timedelta(hours=3)  # Israel is typically UTC+3
                logger.info(f"   Manual conversion: {parsed_datetime} (Israel) -> {utc_time} (UTC)")
                return utc_time
            except Exception as e:
                logger.warning(f"   Timezone conversion failed: {e}, using original time")
                return parsed_datetime

        # Last resort: try extracting just time and use context date
        # But DON'T use today's date - try to infer from test context
        try:
            # Look for time pattern in the string
            time_match = re.search(r'(\d{1,2}:\d{2}\s*[AP]M)', clean_time, re.IGNORECASE)
            if time_match:
                time_part = time_match.group(1)

                # Try to extract date from the context or use a reasonable fallback
                # Look for date patterns in the original string
                date_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4})', clean_time)
                if date_match:
                    date_part = date_match.group(1)
                    combined_str = f"{date_part} {time_part}"
                    try:
                        combined_datetime = datetime.strptime(combined_str, '%m/%d/%Y %I:%M %p')
                        logger.info(f"   Parsed with extracted date: {combined_datetime}")

                        # Convert to UTC as above
                        try:
                            import pytz
                            israel_tz = pytz.timezone('Asia/Jerusalem')
                            localized_time = israel_tz.localize(combined_datetime)
                            utc_time = localized_time.astimezone(pytz.UTC)
                            return utc_time.replace(tzinfo=None)
                        except ImportError:
                            utc_time = combined_datetime - timedelta(hours=3)
                            return utc_time

                    except ValueError:
                        pass

                # If we can't find a date, warn and skip (don't use today's date)
                logger.warning(f"   Found time but no date context: {time_part}")
                return None

        except Exception as e:
            logger.debug(f"   Relative time parsing failed: {e}")

        logger.warning(f"   Could not parse time string: {clean_time}")
        return None

    async def _find_search_box(self):
        """Find search box"""
        selectors = [
            'input[aria-label*="Search"], input[placeholder*="Search"]',
            'input[type="search"]',
            '[role="searchbox"]',
            '.ms-SearchBox-field'
        ]

        for selector in selectors:
            try:
                search_box = await self.page.wait_for_selector(selector, timeout=5000)
                if search_box:
                    return search_box
            except:
                continue
        return None

    async def _init_browser(self):
        """Initialize browser"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=False)
        context = await self.browser.new_context(viewport={'width': 1920, 'height': 1080})
        self.page = await context.new_page()

    async def _login_to_webmail(self, email_address: str):
        """Login to webmail"""
        webmail_url = 'https://outlook.office.com'
        await self.page.goto(webmail_url)
        await self.page.wait_for_timeout(3000)

        # Enter email
        email_input = await self.page.wait_for_selector('input[name="loginfmt"], input[type="email"]', timeout=10000)
        await email_input.fill(email_address)

        # Click Next
        next_button = await self.page.wait_for_selector('#idSIButton9, input[type="submit"]', timeout=5000)
        await next_button.click()

        # Enter password
        await self.page.wait_for_timeout(2000)
        password_input = await self.page.wait_for_selector('input[name="passwd"], input[type="password"]',
                                                           timeout=10000)
        await password_input.fill(self.password)

        # Click Sign In
        signin_button = await self.page.wait_for_selector('#idSIButton9, input[type="submit"]', timeout=5000)
        await signin_button.click()

        # Handle stay signed in
        try:
            await self.page.wait_for_timeout(3000)
            stay_signed_in = await self.page.wait_for_selector('#idSIButton9', timeout=5000)
            await stay_signed_in.click()
        except:
            pass

        # Wait for mailbox
        await self.page.wait_for_selector('[aria-label*="Inbox"], [role="main"]', timeout=30000)

    async def _take_screenshot(self, failed_test: FailedTest, suffix: str) -> str:
        """Take screenshot with email-specific naming"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use email subject hash for consistent naming across same email
        email_hash = hashlib.md5(f"{failed_test.mail_subject}_{failed_test.mail_type}".encode()).hexdigest()[:8]
        filename = f"email_verification_{email_hash}_{suffix}_{timestamp}.png"
        screenshot_path = self.screenshots_dir / filename
        await self.page.screenshot(path=str(screenshot_path), full_page=True)
        logger.info(f"📸 Screenshot saved: {filename}")
        return str(screenshot_path)

    async def _cleanup_browser(self):
        """Clean up browser"""
        if self.browser:
            await self.browser.close()


class AIAnalyzer:
    """AI analyzer with proper security logic"""

    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)

    def analyze_test_failure(self, failed_test: FailedTest,
                             verification_result: MailVerificationResult) -> AIAnalysisResult:
        """AI analysis with improved logic and debugging"""

        logger.info(f"Running AI analysis for: {failed_test.test_name}")

        # Analyze screenshot if available
        screenshot_analysis = ""
        if verification_result.screenshot_path and os.path.exists(verification_result.screenshot_path):
            screenshot_analysis = self._analyze_screenshot(verification_result.screenshot_path)

        # Build analysis prompt
        prompt = self._build_analysis_prompt(failed_test, verification_result, screenshot_analysis)

        try:
            logger.info("Sending prompt to OpenAI...")
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.1  # Lower temperature for more consistent results
            )

            analysis_text = response.choices[0].message.content
            logger.info("Raw AI Response:")
            logger.info("=" * 50)
            logger.info(analysis_text)
            logger.info("=" * 50)

            parsed_result = self._parse_ai_response(analysis_text)

            # Log the parsed results for debugging
            logger.info(f"Parsed Classification: {parsed_result.classification}")
            logger.info(f"Parsed Confidence: {parsed_result.confidence}")
            logger.info(f"Parsed Explanation: {parsed_result.explanation[:100]}...")

            # Validate AI response makes sense
            if parsed_result.classification == "CODE_ISSUE" and verification_result.mail_found and verification_result.action_applied:
                logger.warning("AI classified as CODE_ISSUE but email found with correct action - this seems wrong!")
                logger.warning("Using intelligent fallback instead")
                fallback_result = self._intelligent_fallback_classification(failed_test, verification_result)
                return AIAnalysisResult(
                    classification=fallback_result,
                    confidence=90.0,
                    explanation=f"AI incorrectly classified as CODE_ISSUE. Overridden to {fallback_result} based on verification results.",
                    recommended_action="Security system working correctly, monitor delivery times",
                    analysis_successful=True
                )

            return parsed_result

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")

            # Provide intelligent fallback based on verification results
            fallback_classification = self._intelligent_fallback_classification(failed_test, verification_result)

            return AIAnalysisResult(
                classification=fallback_classification,
                confidence=85.0,  # High confidence in fallback logic
                explanation=f"AI service unavailable. Classified as {fallback_classification} based on verification results: {verification_result.actual_action}",
                recommended_action="Review delivery timing and security actions",
                analysis_successful=False
            )

    def _analyze_screenshot(self, screenshot_path: str) -> str:
        """Analyze screenshot for security actions"""
        try:
            with open(screenshot_path, 'rb') as f:
                screenshot_data = f.read()

            screenshot_b64 = base64.b64encode(screenshot_data).decode('utf-8')

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": """Analyze this email security screenshot. Look for:

1. CLEAN emails: Should have original subject (no prefix) ✅
2. PHISHING emails: Should have "Phishing Alert!" prefix ⚠️  
3. EICAR/MALWARE emails: Should have "Quarantined" prefix 🛡️

Report exactly what you see in the subject lines and any security modifications."""
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{screenshot_b64}"
                                }
                            }
                        ]
                    }
                ],
                max_tokens=300
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Screenshot analysis failed: {e}")
            return "Screenshot analysis failed"

    def _build_analysis_prompt(self, failed_test: FailedTest, verification_result: MailVerificationResult,
                               screenshot_analysis: str) -> str:
        """Build crystal-clear analysis prompt with explicit examples"""

        # Calculate delivery timing context
        timing_context = ""
        if failed_test.sent_timestamp and verification_result.verification_timestamp:
            delay_minutes = (
                                    verification_result.verification_timestamp - failed_test.sent_timestamp).total_seconds() / 60
            timing_context = f"DELIVERY TIMING: Email was delayed by approximately {delay_minutes:.1f} minutes"
        else:
            timing_context = "DELIVERY TIMING: Test failed after 5-minute timeout, but email was later found in mailbox"

        expected_classification = "DELAY_ISSUE" if verification_result.mail_found and verification_result.action_applied else "REAL_ISSUE" if verification_result.mail_found else "CODE_ISSUE"

        prompt = f"""
Email Security Test Analysis - CRYSTAL CLEAR CLASSIFICATION:

{timing_context}

CURRENT TEST DATA:
- Mail Type: {failed_test.mail_type.upper()}
- Mail Found in Mailbox: {verification_result.mail_found}
- Original Subject Found: {verification_result.original_subject_found}
- Quarantined Version Found: {verification_result.quarantined_subject_found}
- Phishing Alert Found: {verification_result.phishing_alert_found}
- Security Action Applied Correctly: {verification_result.action_applied}
- Actual Result: {verification_result.actual_action}

CLASSIFICATION DEFINITIONS WITH EXAMPLES:

**DELAY_ISSUE** = Security system worked correctly, just slow delivery
Examples:
- PHISHING email found WITH "Phishing Alert!" prefix → DELAY_ISSUE ✅
- EICAR/MALWARE email found WITH "Quarantined" prefix → DELAY_ISSUE ✅
- CLEAN email found WITHOUT any modifications → DELAY_ISSUE ✅
- Email took longer than expected but security worked → DELAY_ISSUE ✅

**REAL_ISSUE** = Security system failed to protect users  
Examples:
- PHISHING email found WITHOUT phishing alert → REAL_ISSUE ❌
- EICAR/MALWARE email found WITHOUT quarantine → REAL_ISSUE ❌
- CLEAN email incorrectly quarantined → REAL_ISSUE ❌
- Wrong security action applied → REAL_ISSUE ❌

**CODE_ISSUE** = Technical/infrastructure problems, not security
Examples:
- Browser login failures → CODE_ISSUE 🔧
- Email not found due to search problems → CODE_ISSUE 🔧
- Network/authentication issues → CODE_ISSUE 🔧
- Test framework bugs → CODE_ISSUE 🔧

DECISION TREE FOR THIS TEST:
1. Was the email found? {verification_result.mail_found}
2. Was the correct security action applied? {verification_result.action_applied}

If BOTH are YES → This is DELAY_ISSUE (security worked, just slow)
If email found but WRONG action → This is REAL_ISSUE (security failed)
If email NOT found due to technical issues → This is CODE_ISSUE (infrastructure)

BASED ON THE DATA ABOVE:
- Email found: {verification_result.mail_found}
- Correct action applied: {verification_result.action_applied}
- Result: {verification_result.actual_action}

This should be classified as: {expected_classification}

Provide your analysis in this exact format:
Classification: [DELAY_ISSUE|REAL_ISSUE|CODE_ISSUE]
Confidence: [0-100]%
Explanation: [Brief explanation of why this classification is correct]
Recommended Action: [What should be done next]
"""
        return prompt

    def _parse_ai_response(self, response_text: str) -> AIAnalysisResult:
        """Parse AI response with robust parsing logic"""

        logger.info("🔍 Parsing AI response...")

        lines = response_text.strip().split('\n')

        classification = "CODE_ISSUE"
        confidence = 50.0
        explanation = ""
        recommended_action = "Manual review required"

        # Try multiple parsing approaches
        full_text = response_text.lower()

        # Method 1: Look for explicit format
        for line in lines:
            line = line.strip()
            if line.startswith("Classification:") or line.startswith("classification:"):
                class_part = line.split(":", 1)[1].strip().upper()
                if "DELAY" in class_part:
                    classification = "DELAY_ISSUE"
                elif "REAL" in class_part:
                    classification = "REAL_ISSUE"
                elif "CODE" in class_part:
                    classification = "CODE_ISSUE"
                logger.info(f"Found classification in line: {line} → {classification}")

            elif line.startswith("Confidence:") or line.startswith("confidence:"):
                conf_str = re.sub(r'[^\d.]', '', line.split(":", 1)[1])
                try:
                    confidence = float(conf_str)
                    logger.info(f"Found confidence in line: {line} → {confidence}")
                except:
                    confidence = 50.0

            elif line.startswith("Explanation:") or line.startswith("explanation:"):
                explanation = line.split(":", 1)[1].strip()
                logger.info(f"Found explanation in line: {line[:50]}...")

            elif line.startswith("Recommended Action:") or line.startswith("recommended action:"):
                recommended_action = line.split(":", 1)[1].strip()

        # Method 2: Look for keywords in full text if explicit format failed
        if classification == "CODE_ISSUE" and confidence == 50.0:
            logger.info("Explicit parsing failed, trying keyword search...")
            if "delay_issue" in full_text or "delay issue" in full_text:
                classification = "DELAY_ISSUE"
                confidence = 80.0
                logger.info("Found DELAY_ISSUE via keyword search")
            elif "real_issue" in full_text or "real issue" in full_text:
                classification = "REAL_ISSUE"
                confidence = 80.0
                logger.info("Found REAL_ISSUE via keyword search")

        # Clean up explanation
        if explanation:
            explanation = re.sub(r'\*\*Classification:\*\*[^\*]*', '', explanation)
            explanation = re.sub(r'\*\*Confidence:\*\*[^\*]*', '', explanation)
            explanation = explanation.strip()

        if not explanation:
            explanation = f"Classified as {classification.replace('_', ' ')} based on verification results."

        logger.info(f"Final parsed result: {classification} ({confidence}%)")

        return AIAnalysisResult(
            classification=classification,
            confidence=confidence,
            explanation=explanation,
            recommended_action=recommended_action,
            analysis_successful=True
        )

    def _intelligent_fallback_classification(self, failed_test: FailedTest,
                                             verification_result: MailVerificationResult) -> str:
        """Intelligent fallback classification when AI fails"""

        if not verification_result.mail_found:
            return "CODE_ISSUE"  # Email not found = infrastructure issue

        mail_type = failed_test.mail_type

        # Apply the same logic as the main classifier
        if mail_type == 'clean':
            if verification_result.original_subject_found and not verification_result.quarantined_subject_found:
                return "DELAY_ISSUE"  # Correct behavior
            else:
                return "REAL_ISSUE"  # Clean email was incorrectly modified

        elif mail_type == 'phishing':
            if verification_result.phishing_alert_found:
                return "DELAY_ISSUE"  # Correct behavior
            else:
                return "REAL_ISSUE"  # Phishing without alert

        elif mail_type in ['eicar', 'malware']:
            if verification_result.quarantined_subject_found:
                return "DELAY_ISSUE"  # Correct behavior
            else:
                return "REAL_ISSUE"  # EICAR without quarantine

        return "CODE_ISSUE"  # Default fallback


class CompleteMailVerifier:
    """Complete mail verifier with enhanced professional reporting"""

    def __init__(self, reports_folder: str, openai_api_key: str):
        self.reports_folder = reports_folder
        self.openai_api_key = openai_api_key

        self.parser = AllureParser(reports_folder)
        self.ai_analyzer = AIAnalyzer(openai_api_key)
        self.complete_reports: List[CompleteTestReport] = []
        self.output_dir = Path("mail_verification_reports")
        self.output_dir.mkdir(exist_ok=True)

    async def run_complete_analysis(self) -> List[CompleteTestReport]:
        """Run complete analysis with enhanced reporting"""

        logger.info("Starting Complete Mail Verification Analysis")
        logger.info("=" * 70)

        # Extract AssertionError failures with email-based deduplication
        failed_tests = self.parser.extract_failed_mail_tests()

        if not failed_tests:
            logger.warning("No AssertionError failures found")
            return []

        logger.info(f"Found {len(failed_tests)} unique email failures")
        for i, test in enumerate(failed_tests, 1):
            logger.info(f"   {i}. {test.mail_type.upper()}: {test.mail_subject[:50]}...")
            logger.info(f"      Expected: {test.expected_behavior}")

        # Process each unique email failure
        for i, failed_test in enumerate(failed_tests, 1):
            logger.info(f"\nProcessing Email Failure {i}/{len(failed_tests)}: {failed_test.test_name}")
            logger.info(f"📧 Email address: {failed_test.mail_address}")

            try:
                # Check if we have password configured for this email
                if not config_manager.get_email_password(failed_test.mail_address):
                    logger.error(f"❌ No password configured for email: {failed_test.mail_address}")
                    logger.error(f"   Available configured emails: {config_manager.get_all_configured_emails()}")

                    # Create a report indicating configuration issue
                    verification_result = MailVerificationResult(
                        mail_found=False,
                        error_message=f"No password configured for email: {failed_test.mail_address}",
                        verification_timestamp=datetime.now(),
                        mail_sent_time=failed_test.sent_timestamp
                    )

                    ai_analysis = AIAnalysisResult(
                        classification="CODE_ISSUE",
                        confidence=100.0,
                        explanation="Email password not configured in config.yaml file",
                        recommended_action="Add email and password to config.yaml file",
                        analysis_successful=False
                    )

                    complete_report = CompleteTestReport(
                        failed_test=failed_test,
                        mailbox_verification=verification_result,
                        ai_analysis=ai_analysis,
                        final_classification="CODE_ISSUE",
                        report_timestamp=datetime.now()
                    )

                    self.complete_reports.append(complete_report)
                    continue

                # Mailbox verification with email address (password fetched from config)
                mailbox_verifier = PlaywrightMailboxVerifier(failed_test.mail_address)
                verification_result = await mailbox_verifier.verify_mail_delivery(failed_test)

                # AI analysis with proper prompts
                ai_analysis = self.ai_analyzer.analyze_test_failure(failed_test, verification_result)

                # Final classification
                final_classification = self._final_classification(failed_test, verification_result,
                                                                  ai_analysis)

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
                logger.info(f"Test {i} Analysis:")
                logger.info(f"   Found: {verification_result.mail_found}")
                logger.info(f"   Original: {verification_result.original_subject_found}")
                logger.info(f"   Quarantined: {verification_result.quarantined_subject_found}")
                logger.info(f"   Phishing Alert: {verification_result.phishing_alert_found}")
                logger.info(f"   Correct Action: {verification_result.action_applied}")
                logger.info(f"   Final: {final_classification}")
                logger.info(f"   AI: {ai_analysis.classification} ({ai_analysis.confidence}%)")

            except Exception as e:
                logger.error(f"Error processing test {i}: {e}")

        # Generate enhanced professional report with screenshots
        await self._generate_enhanced_professional_report()
        return self.complete_reports

    def _final_classification(self, failed_test: FailedTest, verification: MailVerificationResult,
                              ai_analysis: AIAnalysisResult) -> str:
        """Final classification with intelligent override of incorrect AI responses"""

        if verification.error_message and 'login' in verification.error_message.lower():
            return "CODE_ISSUE"

        # Intelligent override: If verification shows clear results, use logic-based classification
        if verification.mail_found:
            mail_type = failed_test.mail_type

            logger.info("🧠 Intelligent Classification Logic:")
            logger.info(f"   Mail Type: {mail_type}")
            logger.info(f"   Mail Found: {verification.mail_found}")
            logger.info(f"   Original Found: {verification.original_subject_found}")
            logger.info(f"   Quarantined Found: {verification.quarantined_subject_found}")
            logger.info(f"   Phishing Alert Found: {verification.phishing_alert_found}")
            logger.info(f"   Action Applied Correctly: {verification.action_applied}")

            # Logic-based classification (overrides AI if needed)
            if mail_type == 'clean':
                # Clean emails should be delivered normally
                if verification.original_subject_found and not verification.quarantined_subject_found:
                    logic_classification = "DELAY_ISSUE"  # Correct behavior
                else:
                    logic_classification = "REAL_ISSUE"  # Clean email was modified (wrong)

            elif mail_type == 'phishing':
                # Phishing emails should get alert prefix
                if verification.phishing_alert_found:
                    logic_classification = "DELAY_ISSUE"  # Correct behavior
                else:
                    logic_classification = "REAL_ISSUE"  # Phishing without alert (wrong)

            elif mail_type in ['eicar', 'malware']:
                # EICAR/malware should be quarantined
                if verification.quarantined_subject_found:
                    logic_classification = "DELAY_ISSUE"  # Correct behavior
                else:
                    logic_classification = "REAL_ISSUE"  # EICAR without quarantine (wrong)
            else:
                logic_classification = "CODE_ISSUE"  # Unknown mail type

            logger.info(f"   Logic-based classification: {logic_classification}")
            logger.info(f"   AI classification: {ai_analysis.classification}")

            # Override AI if it's clearly wrong
            if logic_classification != ai_analysis.classification:
                logger.info(
                    f"   OVERRIDING AI: Logic says {logic_classification}, AI says {ai_analysis.classification}")
                if logic_classification in ["DELAY_ISSUE", "REAL_ISSUE"]:
                    # Logic is confident about security classifications
                    return logic_classification

            # If AI agrees with logic or logic is uncertain, use AI
            return ai_analysis.classification

        # Use AI analysis for edge cases where verification is unclear
        return ai_analysis.classification

    async def _generate_enhanced_professional_report(self):
        """Generate enhanced professional report with screenshots and better UI"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        summary = {
            'total_tests': len(self.complete_reports),
            'real_issues': sum(1 for r in self.complete_reports if r.final_classification == 'REAL_ISSUE'),
            'delay_issues': sum(1 for r in self.complete_reports if r.final_classification == 'DELAY_ISSUE'),
            'code_issues': sum(1 for r in self.complete_reports if r.final_classification == 'CODE_ISSUE'),
        }

        # Calculate success rate
        total_security_tests = summary['real_issues'] + summary['delay_issues']
        security_success_rate = (
                summary['delay_issues'] / total_security_tests * 100) if total_security_tests > 0 else 100

        # Copy screenshots to report directory for web access
        screenshots_web_dir = self.output_dir / "screenshots"
        screenshots_web_dir.mkdir(exist_ok=True)

        # Copy screenshots and get web paths with better debugging
        logger.info(f"Setting up screenshots directory: {screenshots_web_dir}")

        for i, report in enumerate(self.complete_reports):
            logger.info(f"Processing screenshot for email {i + 1}: {report.failed_test.mail_subject[:30]}...")

            if report.mailbox_verification.screenshot_path:
                original_path = Path(report.mailbox_verification.screenshot_path)
                logger.info(f"   Original path: {original_path}")
                logger.info(f"   File exists: {original_path.exists()}")

                if original_path.exists():
                    # Create simple, predictable filename
                    screenshot_filename = f"email_{i + 1}_{report.failed_test.mail_type}_{timestamp}.png"
                    screenshot_dest = screenshots_web_dir / screenshot_filename

                    try:
                        # Copy screenshot
                        shutil.copy2(original_path, screenshot_dest)
                        logger.info(f"   Copied to: {screenshot_dest}")
                        logger.info(f"   Copy successful: {screenshot_dest.exists()}")

                        # Update path for HTML (relative to HTML file location)
                        report.mailbox_verification.screenshot_path = f"screenshots/{screenshot_filename}"
                        logger.info(f"   HTML relative path: {report.mailbox_verification.screenshot_path}")

                    except Exception as e:
                        logger.error(f"   Failed to copy screenshot: {e}")
                        report.mailbox_verification.screenshot_path = ""
                else:
                    logger.warning(f"   Original screenshot not found: {original_path}")
                    report.mailbox_verification.screenshot_path = ""
            else:
                logger.warning(f"   No screenshot path for email {i + 1}")
                report.mailbox_verification.screenshot_path = ""

        # Enhanced Professional HTML report
        html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Email Security Analysis Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #2563eb;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --secondary-color: #6b7280;
            --background-color: #f8fafc;
            --card-background: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px 0;
        }}

        .dashboard-container {{ max-width: 1400px; margin: 0 auto; padding: 0 20px; }}

        .dashboard-header {{
            background: var(--card-background);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-xl);
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .dashboard-title {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--card-background);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow-md);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--primary-color);
        }}

        .stat-card.success::before {{ background: var(--success-color); }}
        .stat-card.warning::before {{ background: var(--warning-color); }}
        .stat-card.danger::before {{ background: var(--danger-color); }}

        .stat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .security-score {{
            background: linear-gradient(135deg, var(--success-color), #059669);
            color: white;
            text-align: center;
        }}

        .score-circle {{
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: rgba(255,255,255,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 1rem auto;
            font-size: 1.5rem;
            font-weight: 700;
        }}

        .test-reports {{ display: grid; gap: 1.5rem; }}

        .test-card {{
            background: var(--card-background);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow-md);
            transition: all 0.3s ease;
        }}

        .test-header {{
            padding: 1.5rem;
            border-left: 4px solid;
            position: relative;
        }}

        .test-header.delay-issue {{
            border-left-color: var(--success-color);
            background: linear-gradient(135deg, #ecfdf5 0%, #f0fdf4 100%);
        }}

        .test-header.real-issue {{
            border-left-color: var(--danger-color);
            background: linear-gradient(135deg, #fef2f2 0%, #fef5f5 100%);
        }}

        .test-header.code-issue {{
            border-left-color: var(--warning-color);
            background: linear-gradient(135deg, #fffbeb 0%, #fefce8 100%);
        }}

        .test-title {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .test-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .test-badge.delay-issue {{ background: var(--success-color); color: white; }}
        .test-badge.real-issue {{ background: var(--danger-color); color: white; }}
        .test-badge.code-issue {{ background: var(--warning-color); color: var(--text-primary); }}

        .test-content {{ padding: 0 1.5rem 1.5rem; }}

        .section-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }}

        .detail-item {{
            background: var(--background-color);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            transition: all 0.2s ease;
        }}

        .detail-label {{
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .detail-value {{ color: var(--text-secondary); font-weight: 500; }}

        .screenshot-image {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: var(--shadow-md);
            cursor: pointer;
            transition: transform 0.2s ease;
        }}

        .screenshot-image:hover {{ transform: scale(1.02); }}

        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
            cursor: pointer;
        }}

        .modal-content {{
            margin: auto;
            display: block;
            width: 90%;
            max-width: 1200px;
            margin-top: 2%;
            cursor: default;
        }}

        .close {{
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }}

        .close:hover {{ color: #bbb; }}

        @media (max-width: 768px) {{
            .dashboard-container {{ padding: 0 10px; }}
            .dashboard-title {{ font-size: 2rem; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
            .detail-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="dashboard-header">
            <h1 class="dashboard-title">
                <i class="fas fa-shield-alt"></i>
                Email Security Analysis Dashboard
            </h1>
            <p>Generated: {datetime.now().strftime("%B %d, %Y at %H:%M")}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <div style="font-size: 2rem; color: var(--primary-color);">
                        <i class="fas fa-flask"></i>
                    </div>
                    <div class="stat-number" style="color: var(--primary-color);">{summary['total_tests']}</div>
                </div>
                <div class="stat-label">Total Tests</div>
            </div>

            <div class="stat-card danger">
                <div class="stat-header">
                    <div style="font-size: 2rem; color: var(--danger-color);">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-number" style="color: var(--danger-color);">{summary['real_issues']}</div>
                </div>
                <div class="stat-label">Security Issues</div>
            </div>

            <div class="stat-card success">
                <div class="stat-header">
                    <div style="font-size: 2rem; color: var(--success-color);">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-number" style="color: var(--success-color);">{summary['delay_issues']}</div>
                </div>
                <div class="stat-label">Delay Issues</div>
            </div>

            <div class="stat-card warning">
                <div class="stat-header">
                    <div style="font-size: 2rem; color: var(--warning-color);">
                        <i class="fas fa-tools"></i>
                    </div>
                    <div class="stat-number" style="color: var(--warning-color);">{summary['code_issues']}</div>
                </div>
                <div class="stat-label">Code Issues</div>
            </div>

            <div class="stat-card security-score">
                <div class="stat-header">
                    <div style="font-size: 2rem;">
                        <i class="fas fa-award"></i>
                    </div>
                    <div class="score-circle">{security_success_rate:.0f}%</div>
                </div>
                <div class="stat-label">Security Success Rate</div>
            </div>
        </div>

        <div class="test-reports">
        """

        # Generate individual test reports
        for i, report in enumerate(self.complete_reports, 1):
            classification_class = report.final_classification.lower().replace('_', '-')

            html_report += f"""
                <div class="test-card">
                    <div class="test-header {classification_class}">
                        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                            <div class="test-title">
                                Email {i}: {report.failed_test.mail_type.upper()} - {report.failed_test.mail_subject[:50]}...
                            </div>
                            <div class="test-badge {classification_class}">
                                {report.final_classification.replace('_', ' ')}
                            </div>
                        </div>
                    </div>

                    <div class="test-content">
                        <div style="margin-bottom: 2rem;">
                            <div class="section-title">
                                <i class="fas fa-cog" style="color: var(--primary-color);"></i>
                                Test Configuration
                            </div>
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <div class="detail-label">Mail Type</div>
                                    <div class="detail-value">{report.failed_test.mail_type.upper()}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Subject</div>
                                    <div class="detail-value">{report.failed_test.mail_subject}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Email Address</div>
                                    <div class="detail-value">{report.failed_test.mail_address}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Expected Behavior</div>
                                    <div class="detail-value">{report.failed_test.expected_behavior}</div>
                                </div>
                            </div>
                        </div>

                        <div style="margin-bottom: 2rem;">
                            <div class="section-title">
                                <i class="fas fa-clock" style="color: var(--primary-color);"></i>
                                Email Timing Analysis
                            </div>
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <div class="detail-label">Mail Sent Time (UTC)</div>
                                    <div class="detail-value">
                                        {report.mailbox_verification.mail_sent_time.strftime("%Y-%m-%d %H:%M:%S UTC") if report.mailbox_verification.mail_sent_time else "Not available"}
                                        <br><small style="color: var(--text-secondary); font-style: italic;">
                                            * From Allure logs 
                                        </small>
                                    </div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Mail Arrived Time (UTC)</div>
                                    <div class="detail-value">
                                        {report.mailbox_verification.mail_arrived_time.strftime("%Y-%m-%d %H:%M:%S UTC") if report.mailbox_verification.mail_arrived_time else "Not available"}
                                        <br><small style="color: var(--text-secondary); font-style: italic;">
                                            * Converted from: {report.mailbox_verification.mail_arrived_time_str if report.mailbox_verification.mail_arrived_time_str else "N/A"}
                                        </small>
                                    </div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Delivery Delay</div>
                                    <div class="detail-value">
                                        <strong>{f"{report.mailbox_verification.delivery_delay_minutes:.1f} minutes" if report.mailbox_verification.delivery_delay_minutes is not None else "Not calculated"}</strong>
                                    </div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Delivery Status</div>
                                    <div class="detail-value">
                                        {'🟢 On time' if report.mailbox_verification.delivery_delay_minutes and report.mailbox_verification.delivery_delay_minutes <= 5 else '🟡 Delayed' if report.mailbox_verification.delivery_delay_minutes and report.mailbox_verification.delivery_delay_minutes <= 15 else '🔴 Very delayed' if report.mailbox_verification.delivery_delay_minutes else '❓ Unknown'}
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div style="margin-bottom: 2rem;">
                            <div class="section-title">
                                <i class="fas fa-search" style="color: var(--primary-color);"></i>
                                Verification Results
                            </div>
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <div class="detail-label">Mail Found</div>
                                    <div class="detail-value">{'✅ Yes' if report.mailbox_verification.mail_found else '❌ No'}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Action Applied</div>
                                    <div class="detail-value">{'✅ Yes' if report.mailbox_verification.action_applied else '❌ No'}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Actual Action</div>
                                    <div class="detail-value">{report.mailbox_verification.actual_action}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">AI Confidence</div>
                                    <div class="detail-value">{report.ai_analysis.confidence}%</div>
                                </div>
                            </div>
                        </div>

                        <div style="margin-bottom: 2rem;">
                            <div class="section-title">
                                <i class="fas fa-camera" style="color: var(--primary-color);"></i>
                                Screenshot
                            </div>
            """

            # Screenshot section
            if report.mailbox_verification.screenshot_path:
                screenshot_full_path = self.output_dir / report.mailbox_verification.screenshot_path
                if screenshot_full_path.exists():
                    html_report += f"""
                            <div style="text-align: center; margin-top: 1rem;">
                                <img src="{report.mailbox_verification.screenshot_path}" 
                                     alt="Email verification screenshot"
                                     class="screenshot-image"
                                     onclick="openModal(this.src)">
                                <p style="margin-top: 0.5rem; color: var(--text-secondary);">Click to view full size</p>
                            </div>
                    """
                else:
                    html_report += f"""
                            <div style="text-align: center; padding: 2rem; background: #fef2f2; border-radius: 8px;">
                                <p style="color: var(--danger-color);">Screenshot file not found</p>
                            </div>
                    """
            else:
                html_report += f"""
                            <div style="text-align: center; padding: 2rem; background: #f8fafc; border-radius: 8px;">
                                <p style="color: var(--text-secondary);">No screenshot available</p>
                            </div>
                """

            html_report += f"""
                        </div>

                        <div style="background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); border-radius: 12px; padding: 1.5rem;">
                            <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem;">
                                <i class="fas fa-robot" style="color: var(--primary-color);"></i>
                                <span style="font-size: 1.1rem; font-weight: 600;">AI Analysis</span>
                            </div>
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <div class="detail-label">Classification</div>
                                    <div class="detail-value"><strong>{report.ai_analysis.classification.replace('_', ' ')}</strong></div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Confidence</div>
                                    <div class="detail-value">{report.ai_analysis.confidence}%</div>
                                </div>
                            </div>
                            <div style="margin-top: 1rem;">
                                <div class="detail-label">Explanation</div>
                                <div class="detail-value" style="margin-top: 0.5rem; line-height: 1.6;">
                                    {report.ai_analysis.explanation}
                                </div>
                            </div>
                            <div style="margin-top: 1rem;">
                                <div class="detail-label">Recommended Action</div>
                                <div class="detail-value" style="margin-top: 0.5rem; line-height: 1.6;">
                                    {report.ai_analysis.recommended_action}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            """

        html_report += f"""
            </div>

            <div style="background: var(--card-background); border-radius: 12px; padding: 2rem; text-align: center; margin-top: 2rem; box-shadow: var(--shadow-md); color: var(--text-secondary);">
                <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">
                    <strong>Email Security Analysis Complete</strong>
                </p>
                <p>
                    Report generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")} | 
                    Email Security Test Analysis System
                </p>
            </div>
        </div>

        <div id="screenshotModal" class="modal" onclick="closeModal()">
            <span class="close" onclick="closeModal()">&times;</span>
            <img class="modal-content" id="modalImage">
        </div>

        <script>
            function openModal(src) {{
                document.getElementById('screenshotModal').style.display = 'block';
                document.getElementById('modalImage').src = src;
                document.body.style.overflow = 'hidden';
            }}

            function closeModal() {{
                document.getElementById('screenshotModal').style.display = 'none';
                document.body.style.overflow = 'auto';
            }}

            document.addEventListener('keydown', function(event) {{
                if (event.key === 'Escape') {{
                    closeModal();
                }}
            }});
        </script>
    </body>
    </html>
        """

        # Save the enhanced report
        html_path = self.output_dir / f"email_security_dashboard_{timestamp}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_report)

        logger.info(f"Enhanced Dashboard saved: {html_path}")
        return html_path


# Pydantic models for API
class AnalysisRequest(BaseModel):
    """Request model for analysis"""
    note: Optional[str] = Field(None, description="Optional note for this analysis")


class AnalysisStatus(BaseModel):
    """Analysis status response"""
    task_id: str
    status: str  # pending, processing, completed, failed
    message: str
    created_at: datetime
    completed_at: Optional[datetime] = None


class AnalysisResult(BaseModel):
    """Analysis result response"""
    task_id: str
    status: str
    summary: Dict[str, Any]
    reports: List[Dict[str, Any]]
    html_report_url: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


# Global state management
analysis_tasks = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("Starting Email Security Analysis Service")
    # Create output directories
    Path("temp_reports").mkdir(exist_ok=True)
    Path("output_reports").mkdir(exist_ok=True)
    Path("screenshots").mkdir(exist_ok=True)
    yield
    logger.info("Shutting down Email Security Analysis Service")


# FastAPI app initialization
app = FastAPI(
    title="Email Security Analysis Service",
    description="Analyze email security test failures from Allure reports with AI-powered classification",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailAnalysisService:
    """Service wrapper for the complete mail verification"""

    def __init__(self):
        self.temp_dir = Path("temp_reports")
        self.output_dir = Path("output_reports")
        self.temp_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)

    async def analyze_allure_report(
            self,
            file_data: List[Dict[str, Any]],
            task_id: str
    ) -> Dict[str, Any]:
        """Analyze uploaded allure report files"""

        try:
            # Update task status
            analysis_tasks[task_id]["status"] = "processing"
            analysis_tasks[task_id]["message"] = "Processing uploaded files..."

            # Create temporary directory for this analysis
            temp_analysis_dir = self.temp_dir / task_id
            temp_analysis_dir.mkdir(exist_ok=True)

            logger.info(f"Processing {len(file_data)} files for task {task_id}")

            # Write uploaded file data to temporary directory
            for file_info in file_data:
                file_path = temp_analysis_dir / file_info['filename']
                with open(file_path, "wb") as f:
                    f.write(file_info['content'])

                logger.info(f"   Written file: {file_info['filename']} ({len(file_info['content']):,} bytes)")

                # If it's a zip file, extract it
                if file_info['filename'].endswith('.zip'):
                    logger.info(f"   Extracting ZIP file: {file_info['filename']}")
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_analysis_dir)

            analysis_tasks[task_id]["message"] = "Running email security analysis..."

            # Get OpenAI API key from config
            openai_api_key = config_manager.get_openai_api_key()
            if not openai_api_key:
                raise ValueError("OpenAI API key not configured. Please update config.yaml with your API key.")

            # Run the analysis using CompleteMailVerifier
            verifier = CompleteMailVerifier(
                reports_folder=str(temp_analysis_dir),
                openai_api_key=openai_api_key
            )

            # Set output directory for this specific analysis
            verifier.output_dir = self.output_dir / task_id
            verifier.output_dir.mkdir(exist_ok=True)

            # Run the complete analysis
            reports = await verifier.run_complete_analysis()

            # Generate summary with timing analysis
            timing_delays = [r.mailbox_verification.delivery_delay_minutes for r in reports if
                             r.mailbox_verification.delivery_delay_minutes is not None]
            avg_delay = sum(timing_delays) / len(timing_delays) if timing_delays else None

            summary = {
                'total_tests': len(reports),
                'real_issues': sum(1 for r in reports if r.final_classification == 'REAL_ISSUE'),
                'delay_issues': sum(1 for r in reports if r.final_classification == 'DELAY_ISSUE'),
                'code_issues': sum(1 for r in reports if r.final_classification == 'CODE_ISSUE'),
                'security_success_rate': 0,
                'timing_analysis': {
                    'emails_with_timing': len(timing_delays),
                    'average_delay_minutes': round(avg_delay, 1) if avg_delay is not None else None,
                    'max_delay_minutes': round(max(timing_delays), 1) if timing_delays else None,
                    'min_delay_minutes': round(min(timing_delays), 1) if timing_delays else None
                },
                'configured_emails': config_manager.get_all_configured_emails()
            }

            if summary['real_issues'] + summary['delay_issues'] > 0:
                summary['security_success_rate'] = (
                        summary['delay_issues'] / (summary['real_issues'] + summary['delay_issues']) * 100
                )

            # Convert reports to serializable format
            serializable_reports = []
            for report in reports:
                serializable_reports.append({
                    'test_name': report.failed_test.test_name,
                    'mail_type': report.failed_test.mail_type,
                    'mail_subject': report.failed_test.mail_subject,
                    'mail_address': report.failed_test.mail_address,
                    'final_classification': report.final_classification,
                    'mail_found': report.mailbox_verification.mail_found,
                    'action_applied': report.mailbox_verification.action_applied,
                    'ai_confidence': report.ai_analysis.confidence,
                    'ai_explanation': report.ai_analysis.explanation,
                    'screenshot_available': bool(report.mailbox_verification.screenshot_path),
                    'mail_sent_time': report.mailbox_verification.mail_sent_time.isoformat() + 'Z' if report.mailbox_verification.mail_sent_time else None,
                    'mail_arrived_time': report.mailbox_verification.mail_arrived_time.isoformat() + 'Z' if report.mailbox_verification.mail_arrived_time else None,
                    'mail_arrived_time_str': report.mailbox_verification.mail_arrived_time_str,
                    'delivery_delay_minutes': report.mailbox_verification.delivery_delay_minutes,
                    'timezone_note': 'All times are converted to UTC for accurate comparison'
                })

            # Find the HTML report
            html_files = list(verifier.output_dir.glob("email_security_dashboard_*.html"))
            html_report_path = html_files[0] if html_files else None

            # Update task completion
            analysis_tasks[task_id].update({
                "status": "completed",
                "message": "Analysis completed successfully",
                "summary": summary,
                "reports": serializable_reports,
                "html_report_path": str(html_report_path) if html_report_path else None,
                "completed_at": datetime.now()
            })

            # Cleanup temporary files
            if temp_analysis_dir.exists():
                shutil.rmtree(temp_analysis_dir)

            logger.info(f"Analysis completed for task {task_id}")
            return analysis_tasks[task_id]

        except Exception as e:
            logger.error(f"Analysis failed for task {task_id}: {e}")
            analysis_tasks[task_id].update({
                "status": "failed",
                "message": f"Analysis failed: {str(e)}",
                "error_message": str(e),
                "completed_at": datetime.now()
            })
            return analysis_tasks[task_id]


# Service instance
analysis_service = EmailAnalysisService()


@app.get("/")
async def root():
    """Root endpoint with service information"""
    configured_emails = config_manager.get_all_configured_emails()
    has_openai_key = bool(config_manager.get_openai_api_key())

    return {
        "service": "Email Security Analysis Service",
        "version": "1.0.0",
        "status": "running",
        "configuration": {
            "config_file": "config.yaml",
            "openai_configured": has_openai_key,
            "email_accounts_configured": len(configured_emails),
            "configured_emails": configured_emails[:3] if configured_emails else [],  # Show first 3 for security
            "total_emails": len(configured_emails)
        },
        "endpoints": {
            "POST /analyze": "Submit allure reports for analysis (no password required)",
            "GET /status/{task_id}": "Check analysis status",
            "GET /result/{task_id}": "Get analysis results",
            "GET /report/{task_id}": "Download HTML report",
            "GET /config": "View configuration status",
            "GET /health": "Health check"
        },
        "setup_required": not (has_openai_key and configured_emails)
    }


@app.get("/config")
async def get_config_status():
    """Get configuration status"""
    configured_emails = config_manager.get_all_configured_emails()
    has_openai_key = bool(config_manager.get_openai_api_key())

    return {
        "config_file_path": str(config_manager.config_path),
        "config_file_exists": config_manager.config_path.exists(),
        "openai_api_key_configured": has_openai_key,
        "email_accounts_configured": len(configured_emails),
        "configured_email_addresses": configured_emails,
        "setup_complete": has_openai_key and len(configured_emails) > 0,
        "settings": config_manager.config.get('settings', {}),
        "recommendations": [
            "Update OpenAI API key in config.yaml" if not has_openai_key else None,
            "Add email accounts to config.yaml" if not configured_emails else None,
            "Configuration looks good!" if has_openai_key and configured_emails else None
        ]
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "active_tasks": len([t for t in analysis_tasks.values() if t["status"] in ["pending", "processing"]])
    }


@app.post("/analyze")
async def analyze_reports(
        background_tasks: BackgroundTasks,
        files: List[UploadFile] = File(..., description="Allure report files (HTML or ZIP)")
):
    """
    Submit allure reports for analysis

    - **files**: Upload allure report files (HTML or ZIP format)

    Note: Email passwords and OpenAI API key are configured in config.yaml
    """

    # Validate files
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    # Validate file types
    valid_extensions = ['.html', '.zip']
    for file in files:
        if not any(file.filename.endswith(ext) for ext in valid_extensions):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file type: {file.filename}. Only .html and .zip files are allowed"
            )

    # Check if OpenAI API key is configured
    if not config_manager.get_openai_api_key():
        raise HTTPException(
            status_code=500,
            detail="OpenAI API key not configured. Please update config.yaml with your API key."
        )

    # Check if any email accounts are configured
    configured_emails = config_manager.get_all_configured_emails()
    if not configured_emails:
        raise HTTPException(
            status_code=500,
            detail="No email accounts configured. Please update config.yaml with email accounts and passwords."
        )

    # Generate task ID
    task_id = str(uuid.uuid4())

    # Initialize task tracking
    analysis_tasks[task_id] = {
        "task_id": task_id,
        "status": "pending",
        "message": "Analysis queued",
        "created_at": datetime.now(),
        "files_count": len(files),
        "file_names": [f.filename for f in files],
        "configured_emails_count": len(configured_emails)
    }

    try:
        # Read file contents immediately before they get closed
        file_data = []
        for file in files:
            content = await file.read()
            file_data.append({
                'filename': file.filename,
                'content': content
            })
            logger.info(f"Read file: {file.filename} ({len(content):,} bytes)")

        # Start background analysis with file data
        background_tasks.add_task(
            analysis_service.analyze_allure_report,
            file_data,
            task_id
        )

        logger.info(f"Started analysis task {task_id} with {len(files)} files")
        logger.info(f"Available configured emails: {configured_emails}")

        return {
            "task_id": task_id,
            "status": "pending",
            "message": "Analysis started",
            "files_submitted": len(files),
            "configured_emails": len(configured_emails),
            "check_status_url": f"/status/{task_id}",
            "estimated_time_minutes": len(files) * 2  # Rough estimate
        }

    except Exception as e:
        # Clean up task if file reading failed
        if task_id in analysis_tasks:
            del analysis_tasks[task_id]
        logger.error(f"Failed to read uploaded files: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process uploaded files: {str(e)}")


@app.get("/status/{task_id}")
async def get_analysis_status(task_id: str):
    """Get the status of an analysis task"""

    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = analysis_tasks[task_id]

    return AnalysisStatus(
        task_id=task_id,
        status=task["status"],
        message=task["message"],
        created_at=task["created_at"],
        completed_at=task.get("completed_at")
    )


@app.get("/result/{task_id}")
async def get_analysis_result(task_id: str):
    """Get the complete analysis results"""

    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = analysis_tasks[task_id]

    if task["status"] not in ["completed", "failed"]:
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    if task["status"] == "failed":
        raise HTTPException(status_code=500, detail=task.get("error_message", "Analysis failed"))

    return AnalysisResult(
        task_id=task_id,
        status=task["status"],
        summary=task.get("summary", {}),
        reports=task.get("reports", []),
        html_report_url=f"/report/{task_id}" if task.get("html_report_path") else None,
        created_at=task["created_at"],
        completed_at=task.get("completed_at")
    )


@app.get("/report/{task_id}")
async def download_html_report(task_id: str):
    """Download the complete report folder as a ZIP file"""

    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = analysis_tasks[task_id]

    if task["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not available")

    # Get the task output directory
    task_output_dir = Path("output_reports") / task_id
    if not task_output_dir.exists():
        raise HTTPException(status_code=404, detail="Report directory not found")

    try:
        # Create a temporary ZIP file
        temp_zip_path = Path("temp_reports") / f"email_security_report_{task_id}.zip"

        # Ensure temp_reports directory exists
        temp_zip_path.parent.mkdir(exist_ok=True)

        # Create ZIP file containing the entire task directory
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through all files in the task directory
            for file_path in task_output_dir.rglob('*'):
                if file_path.is_file():
                    # Add file to ZIP with relative path from task directory
                    arcname = file_path.relative_to(task_output_dir)
                    zipf.write(file_path, arcname)
                    logger.info(f"Added to ZIP: {arcname}")

        # Verify ZIP was created successfully
        if not temp_zip_path.exists():
            raise HTTPException(status_code=500, detail="Failed to create ZIP file")

        logger.info(f"Created ZIP file: {temp_zip_path} ({temp_zip_path.stat().st_size:,} bytes)")

        # Return ZIP file as download
        return FileResponse(
            path=str(temp_zip_path),
            filename=f"email_security_report_{task_id}.zip",
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=email_security_report_{task_id}.zip"}
        )

    except Exception as e:
        logger.error(f"Failed to create ZIP file for task {task_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create report ZIP: {str(e)}")


@app.get("/report/{task_id}/html")
async def view_html_report(task_id: str):
    """View the HTML report in browser (for quick preview)"""

    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = analysis_tasks[task_id]

    if task["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not available")

    html_report_path = task.get("html_report_path")
    if not html_report_path or not Path(html_report_path).exists():
        raise HTTPException(status_code=404, detail="HTML report file not found")

    # Return HTML for viewing in browser
    return FileResponse(
        path=html_report_path,
        media_type="text/html"
    )

@app.post("/cleanup-temp")
async def cleanup_temp_files():
    """Clean up temporary ZIP files (optional maintenance endpoint)"""

    temp_dir = Path("temp_reports")
    if not temp_dir.exists():
        return {"message": "No temp directory found"}

    zip_files = list(temp_dir.glob("*.zip"))
    cleaned_count = 0

    for zip_file in zip_files:
        try:
            # Only clean up ZIP files older than 1 hour
            file_age = time.time() - zip_file.stat().st_mtime
            if file_age > 3600:  # 1 hour in seconds
                zip_file.unlink()
                cleaned_count += 1
                logger.info(f"Cleaned up old ZIP: {zip_file.name}")
        except Exception as e:
            logger.warning(f"Failed to clean up {zip_file.name}: {e}")

    return {
        "message": f"Cleaned up {cleaned_count} temporary ZIP files",
        "remaining_files": len(list(temp_dir.glob("*.zip")))
    }

@app.delete("/cleanup/{task_id}")
async def cleanup_task(task_id: str):
    """Clean up task data and files"""

    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    # Remove task output directory
    task_output_dir = Path("output_reports") / task_id
    if task_output_dir.exists():
        shutil.rmtree(task_output_dir)

    # Remove from memory
    del analysis_tasks[task_id]

    return {"message": f"Task {task_id} cleaned up successfully"}


@app.get("/tasks")
async def list_active_tasks():
    """List all active tasks"""
    return {
        "active_tasks": len(analysis_tasks),
        "tasks": [
            {
                "task_id": task_id,
                "status": task["status"],
                "created_at": task["created_at"],
                "files_count": task.get("files_count", 0)
            }
            for task_id, task in analysis_tasks.items()
        ]
    }


# Example usage and main function
if __name__ == "__main__":
    import uvicorn

    # Configuration
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")

    logger.info(f"Starting Email Security Analysis Service on {host}:{port}")
    logger.info("=" * 60)
    logger.info("🚀 EMAIL SECURITY ANALYSIS SERVICE")
    logger.info("=" * 60)
    logger.info("🔧 Features:")
    logger.info("   📤 Multi-file upload (HTML/ZIP)")
    logger.info("   🤖 AI-powered classification")
    logger.info("   🔍 Automated mailbox verification")
    logger.info("   📊 Interactive HTML reports")
    logger.info("   📸 Screenshot capture")
    logger.info("   ⚡ Async processing")
    logger.info("   🕐 UTC timezone handling")
    logger.info("   🔐 Configuration-based credentials")
    logger.info("=" * 60)
    logger.info("📋 Configuration Status:")

    configured_emails = config_manager.get_all_configured_emails()
    has_openai_key = bool(config_manager.get_openai_api_key())

    logger.info(f"   📄 Config file: {config_manager.config_path}")
    logger.info(f"   🤖 OpenAI API key: {'✅ Configured' if has_openai_key else '❌ Missing'}")
    logger.info(f"   📧 Email accounts: {len(configured_emails)} configured")

    if configured_emails:
        logger.info("   📮 Available email accounts:")
        for email in configured_emails:
            logger.info(f"      - {email}")
    else:
        logger.info("   ⚠️  No email accounts configured!")

    if not has_openai_key or not configured_emails:
        logger.info("   🔧 Setup required: Please update config.yaml")
    else:
        logger.info("   ✅ Configuration complete!")

    logger.info("=" * 60)
    logger.info("📋 Dependencies Check:")
    try:
        import pytz

        logger.info("   ✅ pytz - Timezone handling available")
    except ImportError:
        logger.info("   ⚠️  pytz - Not installed, using manual timezone conversion")
        logger.info("       Install with: pip install pytz")

    try:
        import yaml

        logger.info("   ✅ PyYAML - Configuration file support available")
    except ImportError:
        logger.error("   ❌ PyYAML - Required for configuration files")
        logger.error("       Install with: pip install PyYAML")

    logger.info("=" * 60)
    logger.info("📋 API Endpoints:")
    logger.info("   POST /analyze - Submit reports for analysis")
    logger.info("   GET  /status/{task_id} - Check analysis status")
    logger.info("   GET  /result/{task_id} - Get complete results")
    logger.info("   GET  /report/{task_id} - Download HTML report")
    logger.info("   GET  /health - Health check")
    logger.info("   GET  /docs - API documentation")
    logger.info("=" * 60)
    logger.info("🌐 Access the service:")
    logger.info(f"   API: http://{host}:{port}")
    logger.info(f"   Docs: http://{host}:{port}/docs")
    logger.info("=" * 60)

    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=False,
        access_log=True,
        log_level="info"
    )