"""
OPDA configuration management using Pydantic settings.

Handles environment variables, validation, and configuration for:
- Okta API credentials and connection settings
- Application runtime configuration
- Logging levels and output directories
- Policy and report generation settings
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class OktaSettings(BaseSettings):
    """Okta API connection and authentication settings."""

    domain: str = Field(
        default="",
        description="Okta domain (e.g., company.okta.com)",
        env="OKTA_DOMAIN"
    )

    token: str = Field(
        default="",
        description="Okta API token with read permissions",
        env="OKTA_TOKEN"
    )

    api_version: str = Field(
        default="v1",
        description="Okta API version to use",
        env="OKTA_API_VERSION"
    )

    rate_limit_max_retries: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum number of rate limit retries",
        env="OKTA_RATE_LIMIT_MAX_RETRIES"
    )

    rate_limit_backoff_factor: float = Field(
        default=2.0,
        ge=1.0,
        le=10.0,
        description="Exponential backoff factor for rate limiting",
        env="OKTA_RATE_LIMIT_BACKOFF_FACTOR"
    )

    request_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="HTTP request timeout in seconds",
        env="OKTA_REQUEST_TIMEOUT"
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate Okta domain format."""
        # Allow empty domain for testing/default case
        if not v:
            return v

        # Remove protocol if provided
        domain = v.lower().replace("https://", "").replace("http://", "")

        # Basic domain validation
        if "." not in domain:
            raise ValueError("Invalid Okta domain format")

        # Common Okta domain patterns
        if not (domain.endswith(".okta.com") or domain.endswith(".oktapreview.com") or
                domain.endswith(".okta-emea.com")):
            # Allow custom domains but warn
            pass

        return domain

    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        """Basic Okta token format validation."""
        # Allow empty token for testing/default case
        if not v:
            return v
        if len(v) < 10:
            raise ValueError("Okta token appears to be invalid")
        return v


class AppSettings(BaseSettings):
    """Application runtime configuration."""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Application log level",
        env="OPDA_LOG_LEVEL"
    )

    log_format: Literal["json", "text"] = Field(
        default="json",
        description="Log output format",
        env="OPDA_LOG_FORMAT"
    )

    output_dir: Path = Field(
        default_factory=lambda: Path("./reports"),
        description="Output directory for reports and data",
        env="OPDA_OUTPUT_DIR"
    )

    policies_dir: Path = Field(
        default_factory=lambda: Path("./policies"),
        description="Directory containing Rego policy files",
        env="OPDA_POLICIES_DIR"
    )

    data_dir: Path = Field(
        default_factory=lambda: Path("./data"),
        description="Directory for temporary data storage",
        env="OPDA_DATA_DIR"
    )

    max_concurrent_requests: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum concurrent API requests",
        env="OPDA_MAX_CONCURRENT_REQUESTS"
    )

    enable_cache: bool = Field(
        default=True,
        description="Enable local data caching",
        env="OPDA_ENABLE_CACHE"
    )

    cache_ttl_hours: int = Field(
        default=1,
        ge=0,
        le=24,
        description="Cache TTL in hours (0 to disable)",
        env="OPDA_CACHE_TTL_HOURS"
    )

    @field_validator("output_dir", "policies_dir", "data_dir")
    @classmethod
    def ensure_path_exists(cls, v: Path) -> Path:
        """Ensure directory exists or can be created."""
        try:
            v.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            raise ValueError(f"Cannot create directory {v}: {e}") from e
        return v


class PolicySettings(BaseSettings):
    """Policy engine and evaluation settings."""

    opa_binary_path: str = Field(
        default="opa",
        description="Path to OPA binary executable",
        env="OPDA_OPA_BINARY_PATH"
    )

    policy_timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Policy evaluation timeout in seconds",
        env="OPDA_POLICY_TIMEOUT"
    )

    enable_policy_tests: bool = Field(
        default=True,
        description="Run OPA policy tests before evaluation",
        env="OPDA_ENABLE_POLICY_TESTS"
    )

    strict_mode: bool = Field(
        default=True,
        description="Enable strict policy validation mode",
        env="OPDA_STRICT_MODE"
    )


class ReportSettings(BaseSettings):
    """Report generation configuration."""

    enable_pdf_signing: bool = Field(
        default=False,
        description="Enable PDF digital signatures",
        env="OPDA_ENABLE_PDF_SIGNING"
    )

    pdf_signing_cert_path: Path | None = Field(
        default=None,
        description="Path to PDF signing certificate (P12 format)",
        env="OPDA_PDF_SIGNING_CERT_PATH"
    )

    pdf_signing_cert_password: str | None = Field(
        default=None,
        description="Password for PDF signing certificate",
        env="OPDA_PDF_SIGNING_CERT_PASSWORD"
    )

    report_title: str = Field(
        default="OPDA Privilege Audit Report",
        description="Default report title",
        env="OPDA_REPORT_TITLE"
    )

    include_raw_data: bool = Field(
        default=False,
        description="Include raw API data in reports",
        env="OPDA_INCLUDE_RAW_DATA"
    )


class Settings(BaseSettings):
    """Main OPDA configuration combining all setting categories."""

    okta: OktaSettings = Field(default_factory=OktaSettings)
    app: AppSettings = Field(default_factory=AppSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    report: ReportSettings = Field(default_factory=ReportSettings)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @classmethod
    def load(cls) -> "Settings":
        """Load settings from environment and config files."""
        return cls()

    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.app.log_level == "DEBUG"

    def validate_okta_connection(self) -> bool:
        """Validate that Okta configuration is complete."""
        try:
            return bool(self.okta.domain and self.okta.token and
                       len(self.okta.domain) > 0 and len(self.okta.token) > 0)
        except Exception:
            return False


# Global settings instance
settings = Settings.load()
