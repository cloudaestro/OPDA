"""Tests for configuration management system."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from opda.config.settings import (
    AppSettings,
    OktaSettings,
    PolicySettings,
    ReportSettings,
    Settings,
)


class TestOktaSettings:
    """Test Okta configuration validation."""

    def test_valid_okta_domain(self) -> None:
        """Test valid Okta domain formats."""
        valid_domains = [
            "company.okta.com",
            "dev.oktapreview.com",
            "test.okta-emea.com",
            "https://company.okta.com",
        ]

        for domain in valid_domains:
            settings = OktaSettings(domain=domain, token="valid_token_12345")
            # Domain should be normalized (no protocol)
            assert "https://" not in settings.domain
            assert "http://" not in settings.domain

    def test_invalid_okta_domain(self) -> None:
        """Test invalid Okta domain validation."""
        with pytest.raises(ValidationError, match="Invalid Okta domain format"):
            OktaSettings(domain="invalid-domain", token="valid_token")

    def test_invalid_okta_token(self) -> None:
        """Test Okta token validation."""
        with pytest.raises(ValidationError, match="Okta token appears to be invalid"):
            OktaSettings(domain="company.okta.com", token="short")

    def test_rate_limit_settings(self) -> None:
        """Test rate limiting configuration validation."""
        settings = OktaSettings(
            domain="company.okta.com",
            token="valid_token_12345",
            rate_limit_max_retries=3,
            rate_limit_backoff_factor=1.5,
        )

        assert settings.rate_limit_max_retries == 3
        assert settings.rate_limit_backoff_factor == 1.5

    def test_rate_limit_bounds(self) -> None:
        """Test rate limiting bounds validation."""
        # Test max retries bounds
        with pytest.raises(ValidationError):
            OktaSettings(
                domain="company.okta.com",
                token="valid_token_12345",
                rate_limit_max_retries=11,  # Above maximum
            )

        # Test backoff factor bounds
        with pytest.raises(ValidationError):
            OktaSettings(
                domain="company.okta.com",
                token="valid_token_12345",
                rate_limit_backoff_factor=0.5,  # Below minimum
            )


class TestAppSettings:
    """Test application configuration."""

    def test_default_app_settings(self) -> None:
        """Test default application settings."""
        settings = AppSettings()

        assert settings.log_level == "INFO"
        assert settings.log_format == "json"
        assert settings.max_concurrent_requests == 10
        assert settings.enable_cache is True

    def test_directory_creation(self) -> None:
        """Test that directories are created when specified."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_output"

            AppSettings(output_dir=test_path)

            # Directory should be created
            assert test_path.exists()
            assert test_path.is_dir()

    def test_invalid_directory_creation(self) -> None:
        """Test handling of invalid directory paths."""
        # Try to create directory in read-only location (on most systems)
        if os.name == "nt":  # Windows
            invalid_path = Path("C:/invalid/path/that/cannot/be/created")
        else:  # Unix-like
            invalid_path = Path("/root/invalid/path")

        # Should raise validation error if cannot create directory
        try:
            AppSettings(output_dir=invalid_path)
        except ValidationError as e:
            assert "Cannot create directory" in str(e)

    def test_concurrent_requests_bounds(self) -> None:
        """Test concurrent requests validation."""
        with pytest.raises(ValidationError):
            AppSettings(max_concurrent_requests=0)  # Below minimum

        with pytest.raises(ValidationError):
            AppSettings(max_concurrent_requests=51)  # Above maximum


class TestSettings:
    """Test main Settings class integration."""

    @patch.dict(os.environ, {
        "OKTA_DOMAIN": "test.okta.com",
        "OKTA_TOKEN": "test_token_12345",
        "OPDA_LOG_LEVEL": "DEBUG",
    })
    def test_settings_from_environment(self) -> None:
        """Test loading settings from environment variables."""
        settings = Settings()

        assert settings.okta.domain == "test.okta.com"
        assert settings.okta.token == "test_token_12345"
        assert settings.app.log_level == "DEBUG"

    def test_okta_connection_validation(self) -> None:
        """Test Okta connection validation."""
        # Valid connection
        settings = Settings(
            okta=OktaSettings(domain="test.okta.com", token="valid_token_12345")
        )
        assert settings.validate_okta_connection() is True

        # Invalid connection (empty credentials)
        settings = Settings(
            okta=OktaSettings(domain="", token="")
        )
        assert settings.validate_okta_connection() is False

    def test_development_mode_detection(self) -> None:
        """Test development mode detection."""
        settings = Settings(
            app=AppSettings(log_level="DEBUG")
        )
        assert settings.is_development() is True

        settings = Settings(
            app=AppSettings(log_level="INFO")
        )
        assert settings.is_development() is False


class TestPolicySettings:
    """Test policy engine configuration."""

    def test_default_policy_settings(self) -> None:
        """Test default policy settings."""
        settings = PolicySettings()

        assert settings.opa_binary_path == "opa"
        assert settings.policy_timeout == 30
        assert settings.enable_policy_tests is True
        assert settings.strict_mode is True

    def test_policy_timeout_bounds(self) -> None:
        """Test policy timeout validation."""
        with pytest.raises(ValidationError):
            PolicySettings(policy_timeout=0)  # Below minimum

        with pytest.raises(ValidationError):
            PolicySettings(policy_timeout=301)  # Above maximum


class TestReportSettings:
    """Test report generation configuration."""

    def test_default_report_settings(self) -> None:
        """Test default report settings."""
        settings = ReportSettings()

        assert settings.enable_pdf_signing is False
        assert settings.pdf_signing_cert_path is None
        assert settings.report_title == "OPDA Privilege Audit Report"
        assert settings.include_raw_data is False

    def test_pdf_signing_configuration(self) -> None:
        """Test PDF signing configuration."""
        with tempfile.NamedTemporaryFile(suffix=".p12", delete=False) as temp_cert:
            cert_path = Path(temp_cert.name)

            settings = ReportSettings(
                enable_pdf_signing=True,
                pdf_signing_cert_path=cert_path,
                pdf_signing_cert_password="test_password",
            )

            assert settings.enable_pdf_signing is True
            assert settings.pdf_signing_cert_path == cert_path
            assert settings.pdf_signing_cert_password == "test_password"

        # Clean up
        cert_path.unlink(missing_ok=True)
