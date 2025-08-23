"""
Email Security Analyzer - Configuration Settings
Centralized configuration management for the service
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""

    # Server Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    debug: bool = Field(default=False, env="DEBUG")

    # API Configuration
    api_title: str = Field(default="Email Security Analyzer API", env="API_TITLE")
    api_version: str = Field(default="2.0.0", env="API_VERSION")
    allowed_origins: List[str] = Field(default=["*"], env="ALLOWED_ORIGINS")

    # Authentication (optional - can be disabled for internal use)
    require_auth: bool = Field(default=False, env="REQUIRE_AUTH")
    api_key: Optional[str] = Field(default=None, env="API_KEY")

    # Email Configuration
    default_webmail_url: str = Field(default="https://outlook.office.com", env="WEBMAIL_URL")
    default_mailbox_password: Optional[str] = Field(default=None, env="MAILBOX_PASSWORD")

    # Browser Configuration
    browser_headless: bool = Field(default=True, env="BROWSER_HEADLESS")
    browser_timeout: int = Field(default=30000, env="BROWSER_TIMEOUT")

    # OpenAI Configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    ai_model: str = Field(default="gpt-4o", env="AI_MODEL")
    ai_temperature: float = Field(default=0.1, env="AI_TEMPERATURE")

    # File Upload Configuration
    max_file_size: int = Field(default=100 * 1024 * 1024, env="MAX_FILE_SIZE")  # 100MB
    upload_path: str = Field(default="uploads", env="UPLOAD_PATH")
    output_path: str = Field(default="output", env="OUTPUT_PATH")

    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT"
    )

    # Job Management
    max_concurrent_jobs: int = Field(default=5, env="MAX_CONCURRENT_JOBS")
    job_timeout: int = Field(default=3600, env="JOB_TIMEOUT")  # 1 hour
    cleanup_old_jobs: bool = Field(default=True, env="CLEANUP_OLD_JOBS")
    job_retention_days: int = Field(default=7, env="JOB_RETENTION_DAYS")

    # Database Configuration (for future use)
    database_url: Optional[str] = Field(default=None, env="DATABASE_URL")
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")

    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore"
    }

    def create_directories(self):
        """Create necessary directories"""
        directories = [
            self.upload_path,
            self.output_path,
            f"{self.output_path}/jobs",
            f"{self.output_path}/reports",
            "logs"
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    @property
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return not self.debug and os.getenv("ENVIRONMENT", "development") == "production"

    def validate_required_settings(self):
        """Validate that required settings are present"""
        errors = []

        if not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required for the server")

        if not self.default_mailbox_password:
            errors.append("MAILBOX_PASSWORD is required for email verification")

        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")


# Environment-specific configurations
class DevelopmentSettings(Settings):
    """Development environment settings"""
    debug: bool = True
    log_level: str = "DEBUG"
    browser_headless: bool = False
    require_auth: bool = False


class ProductionSettings(Settings):
    """Production environment settings"""
    debug: bool = False
    log_level: str = "WARNING"
    browser_headless: bool = True
    require_auth: bool = False  # Simplified - no auth required
    cleanup_old_jobs: bool = True


class TestingSettings(Settings):
    """Testing environment settings"""
    debug: bool = True
    log_level: str = "DEBUG"
    database_url: str = "sqlite:///test.db"
    job_retention_days: int = 1


def get_settings() -> Settings:
    """Get settings based on environment"""
    environment = os.getenv("ENVIRONMENT", "development").lower()

    if environment == "production":
        return ProductionSettings()
    elif environment == "testing":
        return TestingSettings()
    else:
        return DevelopmentSettings()


# Global settings instance
settings = get_settings()

def validate_environment():
    """Validate environment configuration - for backward compatibility with existing modules"""
    try:
        settings.validate_required_settings()
        return True
    except ValueError as e:
        print(f"Environment validation failed: {e}")
        return False