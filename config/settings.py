"""
Configuration settings for Email Security Analyzer.

This module handles all configuration including environment variables,
API keys, and application settings.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Settings:
    """Application settings with environment variable support."""

    # API Configuration
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Email Configuration
    MAILBOX_PASSWORD: str = os.getenv("MAILBOX_PASSWORD", "")
    WEBMAIL_URL: str = os.getenv("WEBMAIL_URL", "https://outlook.office.com")

    # Browser Configuration
    BROWSER_HEADLESS: bool = os.getenv("BROWSER_HEADLESS", "false").lower() == "true"
    BROWSER_TIMEOUT: int = int(os.getenv("BROWSER_TIMEOUT", "30000"))
    SCREENSHOT_TIMEOUT: int = int(os.getenv("SCREENSHOT_TIMEOUT", "5000"))

    # Test Configuration
    DEFAULT_TEST_TIMEOUT: float = float(os.getenv("DEFAULT_TEST_TIMEOUT", "300.0"))
    SEARCH_RETRY_ATTEMPTS: int = int(os.getenv("SEARCH_RETRY_ATTEMPTS", "3"))
    SEARCH_DELAY_SECONDS: float = float(os.getenv("SEARCH_DELAY_SECONDS", "4.0"))

    # AI Configuration
    AI_MODEL: str = os.getenv("AI_MODEL", "gpt-4o")
    AI_TEMPERATURE: float = float(os.getenv("AI_TEMPERATURE", "0.1"))
    AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "1000"))

    # File Paths
    PROJECT_ROOT: Path = Path(__file__).parent.parent
    OUTPUT_DIR: Path = PROJECT_ROOT / "output"
    REPORTS_DIR: Path = OUTPUT_DIR / "reports"
    SCREENSHOTS_DIR: Path = OUTPUT_DIR / "screenshots"

    # Expected Behaviors
    EXPECTED_BEHAVIORS = {
        'clean': 'Email should be delivered normally without any security modifications',
        'phishing': 'Email should arrive with "Phishing Alert!" prefix added to subject',
        'eicar': 'Email should be quarantined with "Quarantined" prefix added to subject',
        'malware': 'Email should be quarantined with "Quarantined" prefix added to subject'
    }

    # Browser Selectors
    SEARCH_SELECTORS = [
        'input[aria-label*="Search"], input[placeholder*="Search"]',
        'input[type="search"]',
        '[role="searchbox"]',
        '.ms-SearchBox-field'
    ]

    EMAIL_SELECTORS = {
        'email_input': 'input[name="loginfmt"], input[type="email"]',
        'password_input': 'input[name="passwd"], input[type="password"]',
        'next_button': '#idSIButton9, input[type="submit"]',
        'signin_button': '#idSIButton9, input[type="submit"]',
        'stay_signed_in': '#idSIButton9',
        'mailbox': '[aria-label*="Inbox"], [role="main"]'
    }

    @classmethod
    def validate_required_settings(cls) -> None:
        """Validate that all required settings are provided."""
        required_settings = [
            ("OPENAI_API_KEY", cls.OPENAI_API_KEY),
            ("MAILBOX_PASSWORD", cls.MAILBOX_PASSWORD)
        ]

        missing_settings = []
        for setting_name, setting_value in required_settings:
            if not setting_value:
                missing_settings.append(setting_name)

        if missing_settings:
            raise ValueError(
                f"Missing required settings: {', '.join(missing_settings)}. "
                f"Please set these in your environment variables or .env file."
            )

    @classmethod
    def create_directories(cls) -> None:
        """Create necessary directories if they don't exist."""
        directories = [cls.OUTPUT_DIR, cls.REPORTS_DIR, cls.SCREENSHOTS_DIR]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_expected_action(cls, mail_type: str) -> str:
        """Get expected action for each mail type."""
        actions = {
            'clean': 'Deliver normally without modifications',
            'phishing': 'Add "Phishing Alert!" prefix to subject',
            'eicar': 'Quarantine with "Quarantined" prefix',
            'malware': 'Quarantine with "Quarantined" prefix'
        }
        return actions.get(mail_type, 'Unknown action')


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def validate_environment() -> None:
    """Validate the environment and create necessary directories."""
    settings.validate_required_settings()
    settings.create_directories()