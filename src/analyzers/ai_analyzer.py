"""
AI Analyzer for Email Security Analyzer.

This module uses OpenAI to analyze test failures and classify them.
"""

import os
import base64
import logging
from typing import Optional

import openai

from ..models.data_models import FailedTest, MailVerificationResult, AIAnalysisResult, ClassificationType
from config.settings import settings

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """AI analyzer with proper security logic."""

    def __init__(self, api_key: str = None):
        """Initialize the AI analyzer."""
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.client = openai.OpenAI(api_key=self.api_key)

    def analyze_test_failure(self, failed_test: FailedTest,
                             verification_result: MailVerificationResult) -> AIAnalysisResult:
        """AI analysis with improved logic and debugging."""

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
                model=settings.AI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=settings.AI_MAX_TOKENS,
                temperature=settings.AI_TEMPERATURE
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
            if (parsed_result.classification == ClassificationType.CODE_ISSUE.value
                and verification_result.mail_found and verification_result.action_applied):

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
        """Analyze screenshot for security actions."""
        try:
            with open(screenshot_path, 'rb') as f:
                screenshot_data = f.read()

            screenshot_b64 = base64.b64encode(screenshot_data).decode('utf-8')

            response = self.client.chat.completions.create(
                model=settings.AI_MODEL,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": """Analyze this email security screenshot. Look for:

1. CLEAN emails: Should have original subject (no prefix) 
2. PHISHING emails: Should have "Phishing Alert!" prefix  
3. EICAR/MALWARE emails: Should have "Quarantined" prefix 

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
        """Build crystal-clear analysis prompt with explicit examples."""

        # Calculate delivery timing context with detailed analysis
        timing_context = ""
        timing_analysis = ""

        if failed_test.sent_timestamp and verification_result.verification_timestamp:
            sent_time_str = failed_test.sent_timestamp.strftime("%Y-%m-%d %H:%M:%S")
            arrived_time_str = verification_result.verification_timestamp.strftime("%Y-%m-%d %H:%M:%S")
            delay_minutes = (verification_result.verification_timestamp - failed_test.sent_timestamp).total_seconds() / 60

            timing_context = f"""DELIVERY TIMING ANALYSIS:
- Email Sent Time: {sent_time_str}
- Email Arrived Time: {arrived_time_str}  
- Total Delivery Delay: {delay_minutes:.1f} minutes

TIMING INTERPRETATION:
"""

            # Provide context for the AI about what different delays might mean
            if delay_minutes < 1:
                timing_analysis = "VERY FAST delivery (< 1 minute) - Likely normal email flow"
            elif delay_minutes < 5:
                timing_analysis = "FAST delivery (< 5 minutes) - Normal email processing"
            elif delay_minutes < 15:
                timing_analysis = "MODERATE delay (5-15 minutes) - Could indicate minor processing delays"
            elif delay_minutes < 60:
                timing_analysis = "SIGNIFICANT delay (15-60 minutes) - May indicate security processing or system load"
            elif delay_minutes < 240:
                timing_analysis = "LONG delay (1-4 hours) - Likely indicates security analysis, quarantine processing, or system issues"
            else:
                timing_analysis = "VERY LONG delay (4+ hours) - Strong indication of security processing, manual review, or system problems"

            timing_context += timing_analysis
        else:
            timing_context = """DELIVERY TIMING ANALYSIS:
- Email Sent Time: Unknown
- Email Arrived Time: Unknown  
- Total Delivery Delay: Cannot be calculated
- Note: Test failed after timeout, but email was later found in mailbox"""

        expected_classification = (
            ClassificationType.DELAY_ISSUE.value
            if verification_result.mail_found and verification_result.action_applied
            else ClassificationType.REAL_ISSUE.value
            if verification_result.mail_found
            else ClassificationType.CODE_ISSUE.value
        )

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
- PHISHING email found WITH "Phishing Alert!" prefix → DELAY_ISSUE 
- EICAR/MALWARE email found WITH "Quarantined" prefix → DELAY_ISSUE 
- CLEAN email found WITHOUT any modifications → DELAY_ISSUE 
- Email took longer than expected but security worked → DELAY_ISSUE 
- Long delivery times (30+ minutes) often indicate security processing

**REAL_ISSUE** = Security system failed to protect users  
Examples:
- PHISHING email found WITHOUT phishing alert → REAL_ISSUE 
- EICAR/MALWARE email found WITHOUT quarantine → REAL_ISSUE 
- CLEAN email incorrectly quarantined → REAL_ISSUE 
- Wrong security action applied → REAL_ISSUE 

**CODE_ISSUE** = Technical/infrastructure problems, not security
Examples:
- Browser login failures → CODE_ISSUE 
- Email not found due to search problems → CODE_ISSUE 
- Network/authentication issues → CODE_ISSUE 
- Test framework bugs → CODE_ISSUE 

TIMING CONSIDERATIONS FOR CLASSIFICATION:
- Short delays (< 15 minutes) with correct security action = DELAY_ISSUE
- Long delays (30+ minutes) with correct security action = DELAY_ISSUE (security processing takes time)
- Very long delays (4+ hours) might indicate manual review processes = DELAY_ISSUE if security worked
- Immediate delivery of dangerous emails without security action = REAL_ISSUE
- Missing emails despite reasonable time = CODE_ISSUE (unless security blocked them entirely)

DECISION TREE FOR THIS TEST:
1. Was the email found? {verification_result.mail_found}
2. Was the correct security action applied? {verification_result.action_applied}
3. Does the delivery timing make sense for the mail type and action?

If BOTH email found AND correct action applied → DELAY_ISSUE (security worked)
If email found but WRONG action → REAL_ISSUE (security failed)
If email NOT found due to technical issues → CODE_ISSUE (infrastructure)

BASED ON THE DATA ABOVE:
- Email found: {verification_result.mail_found}
- Correct action applied: {verification_result.action_applied}
- Result: {verification_result.actual_action}
- Timing context: {timing_analysis if timing_analysis else 'No timing data available'}

This should be classified as: {expected_classification}

{"Screenshot Analysis: " + screenshot_analysis if screenshot_analysis else ""}

Provide your analysis in this exact format:
Classification: [DELAY_ISSUE|REAL_ISSUE|CODE_ISSUE]
Confidence: [0-100]%
Explanation: [Brief explanation considering both security action and delivery timing]
Recommended Action: [What should be done next, considering timing insights]
"""
        return prompt

    def _parse_ai_response(self, response_text: str) -> AIAnalysisResult:
        """Parse AI response with robust parsing logic."""
        import re

        logger.info("Parsing AI response...")

        lines = response_text.strip().split('\n')

        classification = ClassificationType.CODE_ISSUE.value
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
                    classification = ClassificationType.DELAY_ISSUE.value
                elif "REAL" in class_part:
                    classification = ClassificationType.REAL_ISSUE.value
                elif "CODE" in class_part:
                    classification = ClassificationType.CODE_ISSUE.value
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
        if classification == ClassificationType.CODE_ISSUE.value and confidence == 50.0:
            logger.info("Explicit parsing failed, trying keyword search...")
            if "delay_issue" in full_text or "delay issue" in full_text:
                classification = ClassificationType.DELAY_ISSUE.value
                confidence = 80.0
                logger.info("Found DELAY_ISSUE via keyword search")
            elif "real_issue" in full_text or "real issue" in full_text:
                classification = ClassificationType.REAL_ISSUE.value
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
        """Intelligent fallback classification when AI fails."""

        if not verification_result.mail_found:
            return ClassificationType.CODE_ISSUE.value

        mail_type = failed_test.mail_type

        # Apply the same logic as the main classifier
        if mail_type == 'clean':
            if verification_result.original_subject_found and not verification_result.quarantined_subject_found:
                return ClassificationType.DELAY_ISSUE.value
            else:
                return ClassificationType.REAL_ISSUE.value

        elif mail_type == 'phishing':
            if verification_result.phishing_alert_found:
                return ClassificationType.DELAY_ISSUE.value
            else:
                return ClassificationType.REAL_ISSUE.value

        elif mail_type in ['eicar', 'malware']:
            if verification_result.quarantined_subject_found:
                return ClassificationType.DELAY_ISSUE.value
            else:
                return ClassificationType.REAL_ISSUE.value

        return ClassificationType.CODE_ISSUE.value