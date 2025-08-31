"""Tests for structured logging configuration."""

import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog

from opda.config.logging_config import (
    LoggingContextManager,
    add_app_context,
    add_caller_info,
    configure_logging,
    filter_sensitive_data,
    get_logger,
)


class TestLoggingProcessors:
    """Test custom logging processors."""

    def test_add_app_context(self) -> None:
        """Test application context processor."""
        event_dict = {"message": "test"}
        result = add_app_context(None, "info", event_dict)
        
        assert result["app"] == "opda"
        assert result["version"] == "0.1.0"
        assert result["message"] == "test"

    def test_add_caller_info(self) -> None:
        """Test caller information processor."""
        event_dict = {"message": "test"}
        result = add_caller_info(None, "info", event_dict)
        
        assert "caller" in result
        assert "file" in result["caller"]
        assert "function" in result["caller"]
        assert "line" in result["caller"]
        
        # Should be current test file
        assert result["caller"]["file"] == "test_logging_config.py"
        assert result["caller"]["function"] == "test_add_caller_info"

    def test_filter_sensitive_data(self) -> None:
        """Test sensitive data filtering."""
        event_dict = {
            "message": "login attempt",
            "user": "john.doe",
            "token": "secret_token_123",
            "okta_token": "secret_okta_token",
            "password": "secret_password",
            "data": {
                "api_key": "secret_key",
                "username": "john.doe",
            },
            "list_data": [
                {"token": "list_secret", "value": "normal"},
                "normal_string",
            ],
        }
        
        result = filter_sensitive_data(None, "info", event_dict)
        
        # Sensitive data should be redacted
        assert result["token"] == "[REDACTED]"
        assert result["okta_token"] == "[REDACTED]" 
        assert result["password"] == "[REDACTED]"
        assert result["data"]["api_key"] == "[REDACTED]"
        assert result["list_data"][0]["token"] == "[REDACTED]"
        
        # Normal data should remain
        assert result["user"] == "john.doe"
        assert result["data"]["username"] == "john.doe"
        assert result["list_data"][0]["value"] == "normal"
        assert result["list_data"][1] == "normal_string"


class TestLoggingConfiguration:
    """Test logging configuration setup."""

    def test_configure_logging_json_format(self) -> None:
        """Test JSON format logging configuration."""
        configure_logging(log_level="INFO", log_format="json")
        
        logger = get_logger("test")
        assert isinstance(logger, structlog.stdlib.BoundLogger)
        
        # Test that logger works
        logger.info("test message", extra_field="test_value")

    def test_configure_logging_text_format(self) -> None:
        """Test text format logging configuration."""
        configure_logging(log_level="DEBUG", log_format="text")
        
        logger = get_logger("test")
        assert isinstance(logger, structlog.stdlib.BoundLogger)
        
        # Test that logger works
        logger.debug("test debug message", extra_field="test_value")

    def test_configure_logging_with_file(self) -> None:
        """Test logging configuration with file output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"
            
            configure_logging(
                log_level="INFO",
                log_format="json",
                log_file=log_file,
            )
            
            logger = get_logger("test")
            logger.info("test file logging", test_field="test_value")
            
            # Check that log file was created and contains content
            assert log_file.exists()
            
            # Read and verify log content
            log_content = log_file.read_text()
            assert "test file logging" in log_content
            
            # For JSON format, should be valid JSON
            if log_content.strip():
                log_entry = json.loads(log_content.strip().split('\n')[0])
                assert log_entry["event"] == "test file logging"
                assert log_entry["test_field"] == "test_value"
                assert log_entry["app"] == "opda"

    def test_get_logger(self) -> None:
        """Test logger factory function."""
        logger = get_logger("opda.test")
        assert isinstance(logger, structlog.stdlib.BoundLogger)
        
        # Test that logger has expected methods
        assert hasattr(logger, "info")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_sensitive_data_filtering_in_logs(self) -> None:
        """Test that sensitive data is filtered in actual log output."""
        configure_logging(log_level="INFO", log_format="json")
        
        # Capture log output
        with patch('sys.stdout') as mock_stdout:
            logger = get_logger("test")
            logger.info(
                "User authentication",
                user="john.doe",
                token="secret_token_123",
                okta_token="secret_okta_token",
            )
            
            # Check that sensitive data was redacted
            log_calls = [str(call) for call in mock_stdout.write.call_args_list]
            log_output = ''.join(log_calls)
            
            assert "john.doe" in log_output
            assert "secret_token_123" not in log_output
            assert "secret_okta_token" not in log_output
            assert "[REDACTED]" in log_output


class TestLoggingContextManager:
    """Test logging context manager."""

    def test_context_manager_success(self) -> None:
        """Test context manager with successful operation."""
        configure_logging(log_level="INFO", log_format="json")
        logger = get_logger("test")
        
        with LoggingContextManager(logger, operation="test_op", user_id="123") as ctx_logger:
            assert isinstance(ctx_logger, structlog.stdlib.BoundLogger)
            ctx_logger.info("Operation started")

    def test_context_manager_exception(self) -> None:
        """Test context manager with exception handling."""
        configure_logging(log_level="INFO", log_format="json")
        logger = get_logger("test")
        
        with patch.object(logger, 'error') as mock_error:
            try:
                with LoggingContextManager(logger, operation="test_op") as ctx_logger:
                    ctx_logger.info("About to raise exception")
                    raise ValueError("Test exception")
            except ValueError:
                pass
            
            # Should have logged the exception
            mock_error.assert_called_once()
            call_args = mock_error.call_args
            assert "Exception occurred in logging context" in str(call_args)

    def test_log_level_filtering(self) -> None:
        """Test that log levels are properly filtered."""
        configure_logging(log_level="WARNING", log_format="json")
        
        with patch('sys.stdout') as mock_stdout:
            logger = get_logger("test")
            
            # These should not appear in output
            logger.debug("Debug message")
            logger.info("Info message")
            
            # This should appear
            logger.warning("Warning message")
            
            log_output = ''.join(str(call) for call in mock_stdout.write.call_args_list)
            
            assert "Debug message" not in log_output
            assert "Info message" not in log_output
            assert "Warning message" in log_output