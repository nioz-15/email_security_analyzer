"""
Mailbox Verifier for Email Security Analyzer.

This module uses Playwright to verify email delivery in webmail systems.
"""

import asyncio
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict
from playwright.async_api import async_playwright, Page, Browser
from ..models.data_models import FailedTest, MailVerificationResult
from config.settings import settings

logger = logging.getLogger(__name__)


class PlaywrightMailboxVerifier:
    """Mailbox verifier with proper search logic."""

    def __init__(self, password: str = None):
        """Initialize the verifier."""
        self.password = password or settings.MAILBOX_PASSWORD
        self.screenshots_dir = settings.SCREENSHOTS_DIR
        self.screenshots_dir.mkdir(exist_ok=True)
        self.browser = None
        self.page = None

    async def verify_mail_delivery(self, failed_test: FailedTest) -> MailVerificationResult:
        """Verify mail delivery with proper search logic."""

        logger.info(f"Verifying mail for: {failed_test.mail_address}")
        logger.info(f"Searching for ORIGINAL subject: {failed_test.mail_subject[:50]}...")
        logger.info(f"Expected behavior: {failed_test.expected_behavior}")

        try:
            await self._init_browser()
            await self._login_to_webmail(failed_test.mail_address)
            verification_result = await self._search_and_verify(failed_test)

            # Calculate timing if possible
            if failed_test.sent_timestamp and verification_result.verification_timestamp:
                delay = (verification_result.verification_timestamp - failed_test.sent_timestamp).total_seconds() / 60
                verification_result.delivery_delay_minutes = delay

            await self._cleanup_browser()
            return verification_result

        except Exception as e:
            logger.error(f"Browser verification failed: {e}")
            await self._cleanup_browser()

            return MailVerificationResult(
                mail_found=False,
                error_message=f"Browser verification failed: {str(e)}",
                verification_timestamp=datetime.now()
            )

    async def _search_and_verify(self, failed_test: FailedTest) -> MailVerificationResult:
        """Search logic - searches for ORIGINAL subject first."""

        try:
            # Take initial screenshot
            initial_screenshot = await self._take_screenshot(failed_test, "01_initial_inbox")

            # Search for original subject first
            search_results = await self._search_strategy(failed_test)

            # Take search results screenshot
            search_screenshot = await self._take_screenshot(failed_test, "02_search_results")

            # Extract actual email timestamp if email was found
            actual_arrival_time = None
            if any([search_results.get('original_found'), search_results.get('quarantined_found'),
                    search_results.get('phishing_alert_found')]):
                # Click on the email to open it and get full timestamp
                actual_arrival_time = await self._click_email_and_extract_timestamp(failed_test)

            # Analyze results with proper logic
            analysis_result = await self._analyze_results(failed_test, search_results)

            # Take detailed screenshot if found
            if analysis_result['mail_found']:
                detail_screenshot = await self._take_screenshot(failed_test, "03_email_details")
                analysis_result['screenshot_path'] = detail_screenshot
            else:
                analysis_result['screenshot_path'] = search_screenshot

            return MailVerificationResult(
                mail_found=analysis_result['mail_found'],
                mail_subject_found=analysis_result.get('found_subject', ''),
                original_subject_found=analysis_result.get('original_found', False),
                quarantined_subject_found=analysis_result.get('quarantined_found', False),
                phishing_alert_found=analysis_result.get('phishing_alert_found', False),
                action_applied=analysis_result.get('action_applied', False),
                expected_action=settings.get_expected_action(failed_test.mail_type),
                actual_action=analysis_result.get('actual_action', 'No action detected'),
                screenshot_path=analysis_result['screenshot_path'],
                verification_timestamp=actual_arrival_time or datetime.now(),
                mailbox_html_content=await self.page.content()
            )

        except Exception as e:
            logger.error(f"Search failed: {e}")
            error_screenshot = await self._take_screenshot(failed_test, "error")

            return MailVerificationResult(
                mail_found=False,
                error_message=f"Search failed: {str(e)}",
                screenshot_path=error_screenshot,
                verification_timestamp=datetime.now()
            )

    async def _search_strategy(self, failed_test: FailedTest) -> Dict:
        """Search strategy - check for different security actions."""

        search_results = {
            'original_found': False,
            'quarantined_found': False,
            'phishing_alert_found': False,
            'found_subject': '',
        }

        # Find search box
        search_box = await self._find_search_box()
        if not search_box:
            logger.warning("Could not find search box")
            return search_results

        original_subject = failed_test.mail_subject

        # Step 1: Search for ORIGINAL subject (as delivered)
        logger.info(f"Searching for ORIGINAL subject: {original_subject}")
        original_result = await self._search_for_term(search_box, original_subject)
        if original_result:
            search_results['original_found'] = True
            search_results['found_subject'] = original_subject

        # Step 2: Search for QUARANTINED version (for EICAR/malware)
        if failed_test.mail_type in ['eicar', 'malware']:
            quarantined_subject = f"Quarantined [{original_subject}]"
            logger.info(f"Searching for QUARANTINED version: {quarantined_subject}")
            quarantined_result = await self._search_for_term(search_box, quarantined_subject)
            if quarantined_result:
                search_results['quarantined_found'] = True
                search_results['found_subject'] = quarantined_subject

        # Step 3: Search for PHISHING ALERT version (for phishing)
        if failed_test.mail_type == 'phishing':
            phishing_alert_subject = f"Phishing Alert! [{original_subject}]"
            logger.info(f"Searching for PHISHING ALERT version: {phishing_alert_subject}")
            phishing_result = await self._search_for_term(search_box, phishing_alert_subject)
            if phishing_result:
                search_results['phishing_alert_found'] = True
                search_results['found_subject'] = phishing_alert_subject

        return search_results

    async def _search_for_term(self, search_box, term: str) -> bool:
        """Search for a specific term."""
        try:
            await search_box.fill('')
            await asyncio.sleep(0.5)
            await search_box.fill(term)
            await self.page.keyboard.press('Enter')
            await asyncio.sleep(settings.SEARCH_DELAY_SECONDS)  # Wait for results

            content = await self.page.content()
            found = term.lower() in content.lower()
            logger.info(f"   {'Success' if found else 'Fail'} Search result: {term[:40]}...")
            return found

        except Exception as e:
            logger.error(f"Search error: {e}")
            return False

    async def _analyze_results(self, failed_test: FailedTest, search_results: Dict) -> Dict:
        """Analysis with proper logic for each mail type."""

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

    async def _find_search_box(self):
        """Find search box."""
        for selector in settings.SEARCH_SELECTORS:
            try:
                search_box = await self.page.wait_for_selector(selector, timeout=settings.SCREENSHOT_TIMEOUT)
                if search_box:
                    return search_box
            except:
                continue
        return None

    async def _init_browser(self):
        """Initialize browser."""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=settings.BROWSER_HEADLESS)
        context = await self.browser.new_context(viewport={'width': 1920, 'height': 1080})
        self.page = await context.new_page()

    async def _login_to_webmail(self, email_address: str):
        """Login to webmail."""
        await self.page.goto(settings.WEBMAIL_URL)
        await self.page.wait_for_timeout(3000)

        # Enter email
        email_input = await self.page.wait_for_selector(
            settings.EMAIL_SELECTORS['email_input'],
            timeout=settings.BROWSER_TIMEOUT
        )
        await email_input.fill(email_address)

        # Click Next
        next_button = await self.page.wait_for_selector(
            settings.EMAIL_SELECTORS['next_button'],
            timeout=settings.SCREENSHOT_TIMEOUT
        )
        await next_button.click()

        # Enter password
        await self.page.wait_for_timeout(2000)
        password_input = await self.page.wait_for_selector(
            settings.EMAIL_SELECTORS['password_input'],
            timeout=settings.BROWSER_TIMEOUT
        )
        await password_input.fill(self.password)

        # Click Sign In
        signin_button = await self.page.wait_for_selector(
            settings.EMAIL_SELECTORS['signin_button'],
            timeout=settings.SCREENSHOT_TIMEOUT
        )
        await signin_button.click()

        # Handle stay signed in
        try:
            await self.page.wait_for_timeout(3000)
            stay_signed_in = await self.page.wait_for_selector(
                settings.EMAIL_SELECTORS['stay_signed_in'],
                timeout=settings.SCREENSHOT_TIMEOUT
            )
            await stay_signed_in.click()
        except:
            pass

        # Wait for mailbox
        await self.page.wait_for_selector(
            settings.EMAIL_SELECTORS['mailbox'],
            timeout=settings.BROWSER_TIMEOUT
        )

    async def _take_screenshot(self, failed_test: FailedTest, suffix: str) -> str:
        """Take screenshot with email-specific naming."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use email subject hash for consistent naming across same email
        email_hash = hashlib.md5(f"{failed_test.mail_subject}_{failed_test.mail_type}".encode()).hexdigest()[:8]
        filename = f"email_verification_{email_hash}_{suffix}_{timestamp}.png"
        screenshot_path = self.screenshots_dir / filename
        await self.page.screenshot(path=str(screenshot_path), full_page=True)
        logger.info(f"Screenshot saved: {filename}")
        return str(screenshot_path)

    async def _cleanup_browser(self):
        """Clean up browser."""
        if self.browser:
            await self.browser.close()

    async def _click_email_and_extract_timestamp(self, failed_test: FailedTest):
        """Click on the found email and extract the full timestamp."""
        try:
            logger.info("Clicking on email to extract full timestamp...")

            # Wait a moment for search results to be fully loaded
            await asyncio.sleep(2)

            # Find the email subject in the search results and click on it
            subject_to_find = failed_test.mail_subject[:50]  # Use first 50 chars for matching

            # Try different selectors to find the email in the list
            email_selectors = [
                f'[aria-label*="{subject_to_find}"]',
                f'[title*="{subject_to_find}"]',
                f'*:has-text("{subject_to_find}")',
                # More specific Outlook selectors
                '[data-testid="message-subject"]',
                '.ms-List-cell [role="gridcell"]',
                '.ms-MessageCard',
                '.ms-DetailsRow',
                # Generic selectors for email items
                '[role="row"]',
                '.email-item',
                '.message-item'
            ]

            email_clicked = False

            # Try to find and click the email
            for selector in email_selectors:
                try:
                    elements = await self.page.query_selector_all(selector)
                    for element in elements:
                        text_content = await element.text_content()
                        if text_content and subject_to_find[:30] in text_content:
                            logger.info(f"Found email element with text: {text_content[:100]}...")
                            await element.click()
                            email_clicked = True
                            break

                    if email_clicked:
                        break

                except Exception as e:
                    logger.debug(f"Selector {selector} failed: {e}")
                    continue

            if not email_clicked:
                # Try a more general approach - click on the first email item
                try:
                    first_email = await self.page.wait_for_selector('[role="row"], .ms-List-cell, .ms-DetailsRow', timeout=5000)
                    if first_email:
                        await first_email.click()
                        email_clicked = True
                        logger.info("Clicked on first email item as fallback")
                except Exception:
                    pass

            if email_clicked:
                # Wait for email details to load
                await asyncio.sleep(3)

                # Now extract the full timestamp from the opened email
                return await self._extract_full_timestamp_from_email()
            else:
                logger.warning("Could not click on email to extract timestamp")
                return None

        except Exception as e:
            logger.error(f"Error clicking email and extracting timestamp: {e}")
            return None

    async def _extract_full_timestamp_from_email(self):
        """Extract the full timestamp from the opened email details."""
        try:
            # Wait for email content to fully load
            await asyncio.sleep(2)

            # Try different selectors to find the full email timestamp in the opened email
            timestamp_selectors = [
                # Outlook specific selectors for opened email
                '[data-testid="message-timestamp"]',
                '.ms-MessageCard-timestamp',
                '.ms-MessageCard-header time',
                '.ms-MessageHeader-timestamp',
                '.ms-DetailsHeader-timestamp',
                '.messageHeader-timestamp',
                '[aria-label*="Received"]',
                '[aria-label*="Sent"]',
                # Look for elements with datetime attributes
                'time[datetime]',
                # Look for elements containing full date patterns
                '[title*="AM"], [title*="PM"]',
                '[aria-label*="AM"], [aria-label*="PM"]'
            ]

            for selector in timestamp_selectors:
                try:
                    element = await self.page.wait_for_selector(selector, timeout=2000)
                    if element:
                        # Try datetime attribute first
                        datetime_attr = await element.get_attribute('datetime')
                        if datetime_attr:
                            parsed_time = self._parse_datetime_string(datetime_attr)
                            if parsed_time:
                                logger.info(f"Extracted timestamp from datetime attribute: {parsed_time}")
                                return parsed_time

                        # Try title attribute
                        title_attr = await element.get_attribute('title')
                        if title_attr:
                            parsed_time = self._parse_datetime_string(title_attr)
                            if parsed_time:
                                logger.info(f"Extracted timestamp from title: {parsed_time}")
                                return parsed_time

                        # Try text content
                        text_content = await element.text_content()
                        if text_content:
                            parsed_time = self._parse_datetime_string(text_content)
                            if parsed_time:
                                logger.info(f"Extracted timestamp from text: {parsed_time}")
                                return parsed_time

                except Exception:
                    continue

            # If no specific element found, search the entire page content for full date patterns
            page_content = await self.page.content()

            import re

            # Look for full date patterns like "Mon 8/18/2025 9:58 AM"
            date_patterns = [
                r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}\s+(?:AM|PM))',
                r'(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}\s+(?:AM|PM))',
                r'Received.*?(\d{1,2}/\d{1,2}/\d{4}.*?\d{1,2}:\d{2}.*?(?:AM|PM))',
                r'Sent.*?(\d{1,2}/\d{1,2}/\d{4}.*?\d{1,2}:\d{2}.*?(?:AM|PM))',
            ]

            for pattern in date_patterns:
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                if matches:
                    match = matches[0]
                    if isinstance(match, tuple):
                        if len(match) == 3:  # Day, Date, Time format
                            full_date = f"{match[1]} {match[2]}"
                        elif len(match) == 2:  # Date, Time format
                            full_date = f"{match[0]} {match[1]}"
                        else:
                            full_date = match[0]
                    else:
                        full_date = match

                    parsed_time = self._parse_datetime_string(full_date)
                    if parsed_time:
                        logger.info(f"Extracted timestamp from page content: {parsed_time}")
                        return parsed_time

            logger.warning("Could not extract full email timestamp from opened email")
            return None

        except Exception as e:
            logger.error(f"Error extracting timestamp from opened email: {e}")
            return None

    def _parse_datetime_string(self, date_string):
        """Parse various datetime string formats."""
        try:
            from datetime import datetime
            import re

            # Clean the string
            cleaned = re.sub(r'\s+', ' ', date_string.strip())
            logger.info(f"Attempting to parse datetime string: '{cleaned}'")

            # Common date formats to try
            formats = [
                "%m/%d/%Y %I:%M %p",  # 8/18/2025 9:58 AM
                "%m/%d/%Y %I:%M:%S %p",  # 8/18/2025 9:58:00 AM
                "%Y-%m-%d %H:%M:%S",  # 2025-08-18 09:58:00
                "%Y-%m-%dT%H:%M:%S",  # 2025-08-18T09:58:00
                "%Y-%m-%dT%H:%M:%SZ",  # 2025-08-18T09:58:00Z
                "%a %m/%d/%Y %I:%M %p",  # Mon 8/18/2025 9:58 AM
                "%a, %d %b %Y %H:%M:%S",  # Mon, 18 Aug 2025 09:58:00
                "%d %b %Y %I:%M %p",  # 18 Aug 2025 9:58 AM
                "%a, %m/%d/%Y %I:%M %p",  # Mon, 8/18/2025 9:58 AM
                "%B %d, %Y %I:%M %p",  # August 18, 2025 9:58 AM
                "%b %d, %Y %I:%M %p",  # Aug 18, 2025 9:58 AM
            ]

            for fmt in formats:
                try:
                    parsed = datetime.strptime(cleaned, fmt)
                    logger.info(f"Successfully parsed datetime: {parsed}")
                    return parsed
                except ValueError:
                    continue

            # Try to extract date and time parts if full parsing fails
            # Pattern for "Mon 8/18/2025 9:58 AM" or "8/18/2025 9:58 AM"
            full_date_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2})\s*(AM|PM)', cleaned, re.IGNORECASE)
            if full_date_match:
                date_part = full_date_match.group(1)
                time_part = full_date_match.group(2)
                ampm_part = full_date_match.group(3).upper()
                full_time = f"{date_part} {time_part} {ampm_part}"
                try:
                    parsed = datetime.strptime(full_time, "%m/%d/%Y %I:%M %p")
                    logger.info(f"Successfully parsed extracted datetime: {parsed}")
                    return parsed
                except ValueError:
                    pass

            # If we only have partial time like "Mon 9:57 AM", we need more context
            # This suggests we didn't click on the email properly
            partial_match = re.search(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d{1,2}:\d{2})\s*(AM|PM)', cleaned, re.IGNORECASE)
            if partial_match:
                logger.warning(f"Found partial timestamp '{cleaned}' - email might not be fully opened")
                # We can't parse this without the date, so return None to indicate we need to try clicking again
                return None

            logger.warning(f"Could not parse datetime string: {cleaned}")
            return None

        except Exception as e:
            logger.error(f"Error parsing datetime string '{date_string}': {e}")
            return None