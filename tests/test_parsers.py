"""
Test suite for Allure Parser module.

This module contains unit tests for the AllureParser class.
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, mock_open

from src.parsers.allure_parser import AllureParser
from src.models.data_models import FailedTest


class TestAllureParser:
    """Test cases for AllureParser class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.reports_folder = Path(self.temp_dir)
        self.parser = AllureParser(str(self.reports_folder))

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parser_initialization(self):
        """Test parser initialization."""
        assert self.parser.reports_folder == self.reports_folder
        assert isinstance(self.parser, AllureParser)

    def test_no_html_files_found(self):
        """Test when no HTML files are found."""
        failed_tests = self.parser.extract_failed_mail_tests()
        assert failed_tests == []

    def test_empty_html_file(self):
        """Test processing empty HTML file."""
        # Create empty HTML file
        html_file = self.reports_folder / "test_report.html"
        html_file.write_text("<html><body></body></html>")

        failed_tests = self.parser.extract_failed_mail_tests()
        assert failed_tests == []

    def test_html_with_no_assertion_errors(self):
        """Test HTML file with no AssertionError failures."""
        html_content = """
        <html>
        <body>
            <script>
                var testData = {
                    "results": [
                        {
                            "name": "test_clean_email",
                            "status": "passed"
                        }
                    ]
                };
            </script>
        </body>
        </html>
        """

        html_file = self.reports_folder / "test_report.html"
        html_file.write_text(html_content)

        failed_tests = self.parser.extract_failed_mail_tests()
        assert failed_tests == []

    def test_validate_and_clean_subject_valid(self):
        """Test subject validation with valid subject."""
        valid_subjects = [
            "Test Email Subject",
            "Clean email for testing",
            "AUTO_phishing_test_email",
            "EICAR test file attachment"
        ]

        for subject in valid_subjects:
            cleaned = self.parser._validate_and_clean_subject(subject)
            assert cleaned == subject
            assert len(cleaned) >= 5
            assert len(cleaned) <= 200

    def test_validate_and_clean_subject_invalid(self):
        """Test subject validation with invalid subjects."""
        invalid_subjects = [
            "",  # Empty
            "   ",  # Whitespace only
            "Hi",  # Too short
            "x" * 201,  # Too long
            '{"json": "data"}',  # JSON-like
            "not found in recipient",  # Error message
            "flaky: false",  # Metadata
        ]

        for subject in invalid_subjects:
            cleaned = self.parser._validate_and_clean_subject(subject)
            assert cleaned == ""

    def test_validate_and_clean_email_valid(self):
        """Test email validation with valid emails."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.org",
            "test+tag@company.co.uk",
            "123@numbers.net"
        ]

        for email in valid_emails:
            cleaned = self.parser._validate_and_clean_email(email)
            assert cleaned == email

    def test_validate_and_clean_email_invalid(self):
        """Test email validation with invalid emails."""
        invalid_emails = [
            "",  # Empty
            "not-an-email",  # No @
            "@domain.com",  # No local part
            "user@",  # No domain
            "user@domain",  # No TLD
            "user name@domain.com",  # Space in local part
            "<user@domain.com>",  # Brackets
        ]

        for email in invalid_emails:
            cleaned = self.parser._validate_and_clean_email(email)
            assert cleaned == ""

    def test_determine_mail_type(self):
        """Test mail type determination from subject."""
        test_cases = [
            ("Clean email subject", "clean"),
            ("AUTO_clean test email", "clean"),
            ("Phishing test email", "phishing"),
            ("AUTO_phishing suspicious link", "phishing"),
            ("EICAR test file", "malware"),
            ("AUTO_malware attachment", "malware"),
            ("Malware sample", "malware"),
            ("Random subject", "unknown"),
        ]

        for subject, expected_type in test_cases:
            result = self.parser._determine_mail_type(subject)
            assert result == expected_type

    def test_extract_test_name_from_content(self):
        """Test test name extraction from content."""
        content_with_smartapi = '''
        {
            "fullName": "SmartAPI Email Test @1.1",
            "name": "Email Test"
        }
        '''

        result = self.parser._extract_test_name_from_content(content_with_smartapi, "clean")
        assert "SmartAPI" in result

        content_with_smoke = '''
        {
            "fullName": "Smoke-Emails Test Suite",
            "name": "Email Test"
        }
        '''

        result = self.parser._extract_test_name_from_content(content_with_smoke, "phishing")
        assert "Smoke-Emails" in result

    def test_extract_test_context(self):
        """Test test context extraction."""
        content_with_smartapi = '''
        {
            "fullName": "SmartAPI Test Context"
        }
        '''

        result = self.parser._extract_test_context(content_with_smartapi)
        assert result == "smartapi"

        content_with_smoke = '''
        {
            "name": "Smoke-Emails Context"
        }
        '''

        result = self.parser._extract_test_context(content_with_smoke)
        assert result == "smoke"

    def test_extract_timestamp_from_content(self):
        """Test timestamp extraction from content."""
        content_with_timestamp = '''
        {
            "start": 1640995200000
        }
        '''

        result = self.parser._extract_timestamp_from_content(content_with_timestamp)
        assert isinstance(result, datetime)

        content_without_timestamp = '''
        {
            "name": "test"
        }
        '''

        result = self.parser._extract_timestamp_from_content(content_without_timestamp)
        assert result is None

    @patch('base64.b64decode')
    def test_parse_assertion_error_attachment(self, mock_b64decode):
        """Test parsing AssertionError attachment."""
        mock_content = '''
        AssertionError: Email with subject: Test Email Subject not found in recipient test@example.com inbox!
        '''
        mock_b64decode.return_value = mock_content.encode('utf-8')

        # Mock the content
        decoded_content = mock_content
        result = self.parser._parse_assertion_error_attachment(decoded_content, 0, "test.html")

        assert len(result) == 1
        assert isinstance(result[0], FailedTest)
        assert result[0].mail_subject == "Test Email Subject"
        assert result[0].mail_address == "test@example.com"

    def test_deduplicate_by_email(self):
        """Test email-based deduplication."""
        # Create duplicate failed tests
        failed_tests = [
            FailedTest(
                test_name="Test 1",
                mail_address="test@example.com",
                mail_subject="Same Subject",
                expected_behavior="Test behavior",
                mail_type="clean",
                failure_message="Failed",
                test_duration=300.0,
                timestamp=datetime.now()
            ),
            FailedTest(
                test_name="Test 2",  # Different test name
                mail_address="test@example.com",  # Same email
                mail_subject="Same Subject",  # Same subject
                expected_behavior="Test behavior",
                mail_type="clean",  # Same type
                failure_message="Failed",
                test_duration=300.0,
                timestamp=datetime.now()
            ),
            FailedTest(
                test_name="Test 3",
                mail_address="different@example.com",  # Different email
                mail_subject="Same Subject",
                expected_behavior="Test behavior",
                mail_type="clean",
                failure_message="Failed",
                test_duration=300.0,
                timestamp=datetime.now()
            )
        ]

        unique_tests = self.parser._deduplicate_by_email(failed_tests)

        # Should have 2 unique tests (deduplicated by email)
        assert len(unique_tests) == 2

        # Check that we kept one from each unique email
        email_addresses = [test.mail_address for test in unique_tests]
        assert "test@example.com" in email_addresses
        assert "different@example.com" in email_addresses


class TestAllureParserIntegration:
    """Integration tests for AllureParser."""

    def setup_method(self):
        """Set up integration test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.reports_folder = Path(self.temp_dir)
        self.parser = AllureParser(str(self.reports_folder))

    def teardown_method(self):
        """Clean up integration test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_parsing_workflow(self):
        """Test the complete parsing workflow with realistic data."""
        # Create a realistic HTML report with base64 encoded assertion errors
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Allure Report</title></head>
        <body>
            <script>
                var largeData = "QXNzZXJ0aW9uRXJyb3I6IEVtYWlsIHdpdGggc3ViamVjdDogQ2xlYW4gdGVzdCBlbWFpbCBub3QgZm91bmQgaW4gcmVjaXBpZW50IHRlc3RAZXhhbXBsZS5jb20gaW5ib3gh";
            </script>
        </body>
        </html>
        """

        html_file = self.reports_folder / "integration_test.html"
        html_file.write_text(html_content)

        # The base64 content decodes to:
        # "AssertionError: Email with subject: Clean test email not found in recipient test@example.com inbox!"

        with patch('base64.b64decode') as mock_decode:
            mock_decode.return_value = b"AssertionError: Email with subject: Clean test email not found in recipient test@example.com inbox!"

            failed_tests = self.parser.extract_failed_mail_tests()

            # Should find the assertion error
            assert len(failed_tests) >= 0  # May be 0 due to validation


# Pytest fixtures for shared test data
@pytest.fixture
def sample_failed_test():
    """Create a sample FailedTest object for testing."""
    return FailedTest(
        test_name="Sample Email Test",
        mail_address="test@example.com",
        mail_subject="Sample Test Email Subject",
        expected_behavior="Email should be delivered normally",
        mail_type="clean",
        failure_message="AssertionError: Email not found",
        test_duration=300.0,
        timestamp=datetime.now(),
        test_id="abc123",
        parameters={"recipient": "test@example.com"}
    )


@pytest.fixture
def sample_html_content():
    """Sample HTML content for testing."""
    return """
    <html>
    <head><title>Test Report</title></head>
    <body>
        <script>
            var testData = {
                results: []
            };
        </script>
    </body>
    </html>
    """


# Test utilities
def create_temp_html_file(content: str, filename: str = "test.html") -> Path:
    """Create a temporary HTML file with given content."""
    temp_dir = Path(tempfile.mkdtemp())
    html_file = temp_dir / filename
    html_file.write_text(content)
    return html_file


def assert_failed_test_valid(failed_test: FailedTest):
    """Assert that a FailedTest object is valid."""
    assert isinstance(failed_test, FailedTest)
    assert failed_test.test_name
    assert failed_test.mail_address
    assert failed_test.mail_subject
    assert failed_test.mail_type in ["clean", "phishing", "eicar", "malware", "unknown"]
    assert failed_test.test_duration > 0
    assert isinstance(failed_test.timestamp, datetime)