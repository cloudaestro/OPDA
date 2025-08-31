"""
Structured logging configuration using structlog.

Provides consistent JSON logging for production environments and
human-readable console output for development.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def add_app_context(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add OPDA application context to log entries."""
    event_dict["app"] = "opda"
    event_dict["version"] = "0.1.0"
    return event_dict


def add_caller_info(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add caller information to log entries."""
    frame = sys._getframe(6)  # Adjust frame depth as needed

    # Extract filename without full path
    filename = Path(frame.f_code.co_filename).name

    event_dict["caller"] = {
        "file": filename,
        "function": frame.f_code.co_name,
        "line": frame.f_lineno,
    }
    return event_dict


def filter_sensitive_data(
    logger: Any, method_name: str, event_dict: EventDict
) -> EventDict:
    """Filter out sensitive data from log entries."""
    sensitive_keys = {
        "token", "password", "secret", "key", "authorization",
        "okta_token", "api_key", "cert_password"
    }

    def _filter_dict(data: dict[str, Any]) -> dict[str, Any]:
        """Recursively filter sensitive keys from dictionaries."""
        filtered = {}
        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = _filter_dict(value)
            elif isinstance(value, list):
                filtered[key] = [
                    _filter_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                filtered[key] = value
        return filtered

    # Filter the main event_dict
    return _filter_dict(event_dict)


def configure_logging(
    log_level: str = "INFO",
    log_format: str = "json",
    log_file: Path | None = None,
) -> None:
    """
    Configure structured logging for OPDA.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_format: Output format ("json" or "text")
        log_file: Optional file path for log output
    """
    # Configure log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(level=level)

    # Base processors for all configurations
    processors: list[Processor] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        add_app_context,
        filter_sensitive_data,
    ]

    # Add caller info for debug mode
    if log_level.upper() == "DEBUG":
        processors.insert(-2, add_caller_info)

    # Choose final processor based on format
    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
        formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
        )
    else:
        # Human-readable console format
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
        formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True),
        )

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        context_class=structlog.threadlocal.wrap_dict(dict),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Setup file logging if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("okta").setLevel(logging.INFO)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


class LoggingContextManager:
    """Context manager for adding structured logging context."""

    def __init__(self, logger: structlog.stdlib.BoundLogger, **context: Any) -> None:
        self.logger = logger
        self.context = context
        self.bound_logger: structlog.stdlib.BoundLogger | None = None

    def __enter__(self) -> structlog.stdlib.BoundLogger:
        self.bound_logger = self.logger.bind(**self.context)
        return self.bound_logger

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None and self.bound_logger:
            self.bound_logger.error(
                "Exception occurred in logging context",
                exc_type=exc_type.__name__ if exc_type else None,
                exc_message=str(exc_val) if exc_val else None,
            )
