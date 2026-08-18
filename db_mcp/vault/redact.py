"""Redaction utilities for sensitive data in logs and exception messages.

This module provides utilities to ensure credentials and connection strings
are never accidentally logged or included in error messages.
"""

import re
from typing import Any

# Fields that should always be redacted
_REDACTED_FIELDS = {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey"}

# Patterns for connection strings that contain credentials
_URL_CREDENTIAL_PATTERN = re.compile(r"(://[^:/@]+:)[^@]+(@)", re.IGNORECASE)

_REDACTED_PLACEHOLDER = "[REDACTED]"


def _redact_dict_recursive(data: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Recursively redact sensitive fields from a dictionary."""
    if depth > 10:  # Prevent infinite recursion
        return {"...": "[REDACTED - max depth reached]"}

    result: dict[str, Any] = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if the key itself is sensitive
        if any(sensitive in key_lower for sensitive in _REDACTED_FIELDS):
            result[key] = _REDACTED_PLACEHOLDER
            continue

        # Recursively process nested structures
        if isinstance(value, dict):
            result[key] = _redact_dict_recursive(value, depth + 1)
        elif isinstance(value, list):
            result[key] = [_redact_item(item, depth + 1) for item in value]
        elif isinstance(value, str):
            result[key] = _redact_url_credentials(value)
        else:
            result[key] = value

    return result


def _redact_item(item: Any, depth: int = 0) -> Any:
    """Redact sensitive data from a single item."""
    if isinstance(item, dict):
        return _redact_dict_recursive(item, depth)
    elif isinstance(item, list):
        return [_redact_item(sub_item, depth + 1) for sub_item in item]
    elif isinstance(item, str):
        return _redact_url_credentials(item)
    else:
        return item


def _redact_url_credentials(url: str) -> str:
    """Redact credentials from a URL connection string.

    Converts: postgresql://user:password@host:5432/db
    To:      postgresql://user:[REDACTED]@host:5432/db
    """

    def replace_credentials(match: re.Match[str]) -> str:
        prefix = match.group(1)  # //user:
        suffix = match.group(2)  # @
        return f"{prefix}{_REDACTED_PLACEHOLDER}{suffix}"

    return _URL_CREDENTIAL_PATTERN.sub(replace_credentials, url)


def redact_connection_dict(conn: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive fields from a connection dictionary.

    This is the main entry point for redacting connection dictionaries.
    It ensures passwords and other sensitive data are never logged.
    """
    return _redact_dict_recursive(conn)


def redact_string(value: str) -> str:
    """Redact sensitive patterns from a string.

    Use this for exception messages and log strings that might contain
    connection information.
    """
    return _redact_url_credentials(value)


def redact_for_logging(obj: Any) -> Any:
    """Redact sensitive data from any object for safe logging.

    This handles dictionaries, lists, strings, and nested structures.
    Use this before logging any object that might contain credentials.
    """
    if isinstance(obj, dict):
        return _redact_dict_recursive(obj)
    elif isinstance(obj, list):
        return [_redact_item(item) for item in obj]
    elif isinstance(obj, str):
        return _redact_url_credentials(obj)
    elif isinstance(obj, tuple):
        return tuple(_redact_item(item) for item in obj)
    else:
        return obj


def redact_exception(exc: Exception) -> str:
    """Redact sensitive data from an exception message.

    Use this to ensure exception messages don't leak credentials.
    """
    if not isinstance(exc, Exception):
        return str(exc)

    original_msg = str(exc)
    redacted_msg = _redact_url_credentials(original_msg)

    # Also redact any sensitive fields that might appear in the message
    for field in _REDACTED_FIELDS:
        # Case-insensitive pattern matching
        pattern = re.compile(
            rf"({field}=[^\s,;]+|{field}['\"]?\s*:\s*['\"]?[^\s,;\"']+['\"]?)",
            re.IGNORECASE,
        )
        redacted_msg = pattern.sub(f"{field}={_REDACTED_PLACEHOLDER}", redacted_msg)

    return redacted_msg
