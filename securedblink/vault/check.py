"""Connection reachability check utilities for the credential vault.

This module provides functionality to verify database connection reachability
before persisting credentials to the vault. It ensures that connections are
tested using the same URL normalization path as runtime queries.
"""

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError

from securedblink.connections import _normalize_oracle_url
from securedblink.log import get_logger
from securedblink.vault.redact import redact_exception, redact_string

log = get_logger("securedblink.vault.check")

# Default timeout for connection checks (seconds)
DEFAULT_CHECK_TIMEOUT = 5

# Environment variable to skip connection checks
SKIP_CHECK_ENV_VAR = "SECUREDBLINK_SKIP_CONNECT_CHECK"

# Dialect-specific probe statements
# Some databases don't support SELECT 1 (e.g., Oracle requires FROM DUAL)
PROBE_STATEMENTS: dict[str, str] = {
    "oracle": "SELECT 1 FROM DUAL",
    "oracle+oracledb": "SELECT 1 FROM DUAL",
    "oracle+cx_oracle": "SELECT 1 FROM DUAL",
    "postgresql": "SELECT 1",
    "mysql": "SELECT 1",
    "mariadb": "SELECT 1",
    "sqlite": "SELECT 1",
    "mssql": "SELECT 1",
    "mssql+pyodbc": "SELECT 1",
    "mssql+pymssql": "SELECT 1",
}

# Default probe statement for unknown dialects
DEFAULT_PROBE = "SELECT 1"


@dataclass
class ConnectionCheckResult:
    """Result of a connection reachability check.

    Attributes:
        success: Whether the connection check succeeded
        error: Error message if the check failed (redacted)
        error_type: Type name of the exception if the check failed
        probe_used: The probe statement that was attempted
        check_duration: Duration of the check in seconds
        timestamp: When the check was performed
        dialect: The database dialect detected from the URL
        unverified: Whether the connection was saved without verification
    """

    success: bool
    error: str | None = None
    error_type: str | None = None
    probe_used: str = ""
    check_duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    dialect: str = ""
    unverified: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "success": self.success,
            "probe_used": self.probe_used,
            "check_duration": round(self.check_duration, 3),
            "timestamp": self.timestamp,
            "dialect": self.dialect,
            "unverified": self.unverified,
        }
        if self.error:
            result["error"] = self.error
        if self.error_type:
            result["error_type"] = self.error_type
        return result


def _get_probe_statement(dialect: str) -> str:
    """Get the appropriate probe statement for a database dialect.

    Args:
        dialect: The SQLAlchemy dialect name

    Returns:
        The probe SQL statement to use for the check
    """
    return PROBE_STATEMENTS.get(dialect, DEFAULT_PROBE)


def _get_timeout() -> float:
    """Get the connection check timeout from environment or use default.

    Returns:
        Timeout in seconds (always positive)
    """
    try:
        timeout = float(
            os.getenv("SECUREDBLINK_CONNECT_CHECK_TIMEOUT", DEFAULT_CHECK_TIMEOUT)
        )
        # Ensure timeout is positive
        return max(0.1, timeout) if timeout > 0 else DEFAULT_CHECK_TIMEOUT
    except ValueError:
        return DEFAULT_CHECK_TIMEOUT


def _should_skip_check() -> bool:
    """Check if connection checks should be skipped based on environment variable.

    Returns:
        True if checks should be skipped, False otherwise
    """
    return os.getenv(SKIP_CHECK_ENV_VAR, "").lower() in ("1", "true", "yes")


def _build_engine_for_check(
    jdbc_url: str,
    username: str | None = None,
    password: str | None = None,
) -> URL:
    """Build a SQLAlchemy URL for connection checking.

    This uses the same normalization path as the runtime query path,
    including Oracle URL normalization.

    Args:
        jdbc_url: The JDBC connection URL
        username: Database username (optional)
        password: Database password (optional)

    Returns:
        SQLAlchemy URL object ready for engine creation
    """
    url = make_url(jdbc_url)

    # For SQLite, don't apply username/password as they're not supported
    # in the same way and can cause connection errors
    if url.drivername and url.drivername.startswith("sqlite"):
        # SQLite doesn't support username/password in the URL for file-based databases
        # For in-memory SQLite, we can ignore credentials
        pass
    else:
        # Apply vault credentials if provided (they take precedence over URL credentials)
        if username:
            url = url.set(username=username)
        if password:
            url = url.set(password=password)

    # Normalize Oracle URLs the same way as runtime
    return _normalize_oracle_url(url)


def check_connection_reachability(
    jdbc_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: float | None = None,
) -> ConnectionCheckResult:
    """Check if a database connection is reachable.

    This function:
    1. Builds the engine from the supplied jdbc_url and credentials through
       the same path used at runtime, including _normalize_oracle_url
    2. Opens a connection and executes a trivial probe statement
    3. Returns a result object with the check outcome

    Args:
        jdbc_url: The JDBC connection URL
        username: Database username (optional)
        password: Database password (optional)
        timeout: Connection timeout in seconds (optional, uses default if not provided)

    Returns:
        ConnectionCheckResult with the check outcome

    Note:
        All error messages are redacted to prevent credential leaks.
        The check is bounded by a configurable timeout to prevent hanging.
    """
    import time

    start_time = time.time()

    # Use provided timeout or get from environment
    if timeout is None:
        timeout = _get_timeout()

    # Get dialect from URL for probe statement selection
    try:
        url_obj = make_url(jdbc_url)
        dialect = url_obj.drivername or ""
    except Exception:
        dialect = ""

    probe_statement = _get_probe_statement(dialect)

    # Build the URL with normalization
    try:
        normalized_url = _build_engine_for_check(jdbc_url, username, password)
    except Exception as e:
        # URL parsing/normalization failed
        error_msg = redact_exception(e) if isinstance(e, Exception) else str(e)
        log.warning(
            "connection_check_failed",
            error_type=type(e).__name__,
            error="URL parsing failed",
        )
        return ConnectionCheckResult(
            success=False,
            error=f"Failed to parse connection URL: {error_msg}",
            error_type=type(e).__name__,
            probe_used=probe_statement,
            check_duration=time.time() - start_time,
            dialect=dialect,
        )

    # Create engine for connection check
    # Note: We use a fresh engine for each check to avoid connection pooling issues
    try:
        # For SQLite, we cannot use connect_timeout as it's not supported
        # For other databases, we'll use the timeout in connect_args
        engine_kwargs: dict[str, Any] = {}

        # Only set timeout for non-SQLite databases
        if dialect not in ("sqlite",) and timeout > 0:
            # connect_timeout is supported by some database drivers
            engine_kwargs["connect_timeout"] = timeout

        # Create engine - this doesn't actually connect yet
        engine = create_engine(normalized_url, **engine_kwargs)

        # Try to execute the probe statement
        with engine.connect() as conn:
            # Execute the probe statement
            result = conn.execute(text(probe_statement))
            # Fetch one row to ensure the query actually executed
            result.fetchone()

        check_duration = time.time() - start_time

        log.info(
            "connection_check_succeeded",
            dialect=dialect,
            check_duration=round(check_duration, 3),
        )

        return ConnectionCheckResult(
            success=True,
            probe_used=probe_statement,
            check_duration=check_duration,
            dialect=dialect,
        )

    except SQLAlchemyError as e:
        check_duration = time.time() - start_time
        error_msg = redact_exception(e)
        error_type = type(e).__name__

        # Also redact the URL from the error message
        if jdbc_url:
            error_msg = redact_string(error_msg)

        log.warning(
            "connection_check_failed",
            dialect=dialect,
            error_type=error_type,
            check_duration=round(check_duration, 3),
        )

        return ConnectionCheckResult(
            success=False,
            error=f"Connection check failed: {error_msg}",
            error_type=error_type,
            probe_used=probe_statement,
            check_duration=check_duration,
            dialect=dialect,
        )

    except Exception as e:
        check_duration = time.time() - start_time
        error_msg = redact_exception(e) if isinstance(e, Exception) else str(e)
        error_type = type(e).__name__

        log.warning(
            "connection_check_failed",
            dialect=dialect,
            error_type=error_type,
            check_duration=round(check_duration, 3),
        )

        return ConnectionCheckResult(
            success=False,
            error=f"Unexpected error during connection check: {error_msg}",
            error_type=error_type,
            probe_used=probe_statement,
            check_duration=check_duration,
            dialect=dialect,
        )


def verify_and_store_connection(
    vault_store: Any,
    alias: str,
    jdbc_url: str,
    username: str | None = None,
    password: str | None = None,
    driver: str | None = None,
    source: str = "direct",
    overwrite: bool = False,
    skip_check: bool = False,
    force_save: bool = False,
) -> tuple[bool, ConnectionCheckResult | None]:
    """Verify connection reachability and store if checks pass or user forces save.

    This is the main entry point for connection registration with verification.

    Args:
        vault_store: The VaultStore instance to use for storage
        alias: The alias to store under
        jdbc_url: The JDBC connection URL
        username: Database username (optional)
        password: Database password (optional)
        driver: JDBC driver class (optional)
        source: Source of the connection ("direct" or "path")
        overwrite: If True, overwrite existing alias
        skip_check: If True, skip the reachability check entirely
        force_save: If True, save even if the check fails

    Returns:
        Tuple of (stored: bool, check_result: ConnectionCheckResult | None)
        - stored: True if the connection was stored
        - check_result: The result of the connection check (None if skipped)

    Note:
        If skip_check is True, the connection is stored without verification.
        If the check fails and force_save is False, the connection is NOT stored.
        If the check fails and force_save is True, the connection IS stored with
        unverified=True in the result.
    """
    # Check if we should skip the check entirely
    if skip_check or _should_skip_check():
        # Store without verification
        vault_store.set(
            alias=alias,
            jdbc_url=jdbc_url,
            username=username,
            password=password,
            driver=driver,
            source=source,
            overwrite=overwrite,
        )
        return True, None

    # Perform the reachability check
    check_result = check_connection_reachability(jdbc_url, username, password)

    if check_result.success:
        # Check passed - store the connection
        vault_store.set(
            alias=alias,
            jdbc_url=jdbc_url,
            username=username,
            password=password,
            driver=driver,
            source=source,
            overwrite=overwrite,
        )
        return True, check_result

    # Check failed - decide whether to save anyway
    if force_save:
        # User explicitly wants to save even though check failed
        vault_store.set(
            alias=alias,
            jdbc_url=jdbc_url,
            username=username,
            password=password,
            driver=driver,
            source=source,
            overwrite=overwrite,
        )
        # Mark as unverified in the result
        check_result.unverified = True
        log.info(
            "connection_saved_unverified",
            alias=alias,
            error_type=check_result.error_type,
        )
        return True, check_result

    # Check failed and user didn't force save - don't store
    log.warning(
        "connection_not_stored_check_failed",
        alias=alias,
        error_type=check_result.error_type,
    )
    return False, check_result
