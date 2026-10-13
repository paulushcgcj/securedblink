"""Tests for connection reachability check functionality.

This module tests the connection verification features added in issue #20.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, text

from securedblink.vault.check import (
    DEFAULT_CHECK_TIMEOUT,
    ConnectionCheckResult,
    _build_engine_for_check,
    _engine_timeout_kwargs,
    _get_probe_statement,
    _get_timeout,
    _should_skip_check,
    check_connection_reachability,
    verify_and_store_connection,
    verify_and_update_connection,
)
from securedblink.vault.redact import redact_exception

# ---------------------------------------------------------------------------
# Probe Statement Tests
# ---------------------------------------------------------------------------


class TestProbeStatements:
    """Tests for dialect-specific probe statements."""

    def test_oracle_probe_statement(self):
        """Oracle should use SELECT 1 FROM DUAL."""
        assert _get_probe_statement("oracle") == "SELECT 1 FROM DUAL"
        assert _get_probe_statement("oracle+oracledb") == "SELECT 1 FROM DUAL"
        assert _get_probe_statement("oracle+cx_oracle") == "SELECT 1 FROM DUAL"

    def test_postgresql_probe_statement(self):
        """PostgreSQL should use SELECT 1."""
        assert _get_probe_statement("postgresql") == "SELECT 1"

    def test_mysql_probe_statement(self):
        """MySQL should use SELECT 1."""
        assert _get_probe_statement("mysql") == "SELECT 1"
        assert _get_probe_statement("mariadb") == "SELECT 1"

    def test_sqlite_probe_statement(self):
        """SQLite should use SELECT 1."""
        assert _get_probe_statement("sqlite") == "SELECT 1"

    def test_mssql_probe_statement(self):
        """MSSQL should use SELECT 1."""
        assert _get_probe_statement("mssql") == "SELECT 1"
        assert _get_probe_statement("mssql+pyodbc") == "SELECT 1"

    def test_unknown_dialect_default_probe(self):
        """Unknown dialects should default to SELECT 1."""
        assert _get_probe_statement("unknown") == "SELECT 1"
        assert _get_probe_statement("") == "SELECT 1"


# ---------------------------------------------------------------------------
# Configuration Tests
# ---------------------------------------------------------------------------


class TestConfiguration:
    """Tests for configuration options."""

    def test_default_timeout(self):
        """Default timeout should be 5 seconds."""
        assert _get_timeout() == 5

    def test_custom_timeout_from_env(self, monkeypatch):
        """Custom timeout should be read from environment variable."""
        monkeypatch.setenv("SECUREDBLINK_CONNECT_CHECK_TIMEOUT", "10")
        assert _get_timeout() == 10.0

    def test_invalid_timeout_falls_back_to_default(self, monkeypatch):
        """Invalid timeout value should fall back to default."""
        monkeypatch.setenv("SECUREDBLINK_CONNECT_CHECK_TIMEOUT", "invalid")
        assert _get_timeout() == 5

    def test_skip_check_env_var_false_by_default(self, monkeypatch):
        """Skip check should be False by default."""
        monkeypatch.delenv("SECUREDBLINK_SKIP_CONNECT_CHECK", raising=False)
        assert _should_skip_check() is False

    def test_skip_check_env_var_true_values(self, monkeypatch):
        """Skip check should be True for various true-like values."""
        for value in ["1", "true", "True", "TRUE", "yes", "YES"]:
            monkeypatch.setenv("SECUREDBLINK_SKIP_CONNECT_CHECK", value)
            assert _should_skip_check() is True

    def test_skip_check_env_var_false_values(self, monkeypatch):
        """Skip check should be False for various false-like values."""
        for value in ["0", "false", "False", "FALSE", "no", "NO", ""]:
            monkeypatch.setenv("SECUREDBLINK_SKIP_CONNECT_CHECK", value)
            assert _should_skip_check() is False


# ---------------------------------------------------------------------------
# URL Building Tests
# ---------------------------------------------------------------------------


class TestUrlBuilding:
    """Tests for URL building with normalization."""

    def test_build_url_basic(self):
        """Basic URL should be built correctly."""
        url = _build_engine_for_check("sqlite:///./test.db")
        assert url.drivername == "sqlite"
        assert url.database == "./test.db"

    def test_build_url_with_credentials(self):
        """URL with embedded credentials should be preserved."""
        url = _build_engine_for_check("postgresql://user:pass@localhost/db")
        assert url.drivername == "postgresql"
        assert url.username == "user"
        assert url.password == "pass"
        assert url.host == "localhost"
        assert url.database == "db"

    def test_build_url_override_credentials(self):
        """Provided credentials should override URL credentials."""
        url = _build_engine_for_check(
            "postgresql://olduser:oldpass@localhost/db",
            username="newuser",
            password="newpass",
        )
        assert url.username == "newuser"
        assert url.password == "newpass"

    def test_oracle_url_normalization(self):
        """Oracle URLs should be normalized with service_name promotion."""
        # Oracle URL with service name in path should be promoted to query param
        url = _build_engine_for_check("oracle+oracledb://user:pass@host:1521/service")
        assert url.drivername == "oracle+oracledb"
        assert url.username == "user"
        assert url.password == "pass"
        assert url.host == "host"
        assert url.port == 1521
        # The database (path) should be empty and service_name should be in query
        assert url.database == ""
        assert "service_name" in url.query
        assert url.query["service_name"] == "service"

    def test_oracle_url_with_explicit_service_name(self):
        """Oracle URLs with explicit service_name should not be modified."""
        url = _build_engine_for_check(
            "oracle+oracledb://user:pass@host:1521/?service_name=myservice"
        )
        assert url.query.get("service_name") == "myservice"

    def test_oracle_url_with_sid(self):
        """Oracle URLs with explicit sid should not be modified."""
        url = _build_engine_for_check(
            "oracle+oracledb://user:pass@host:1521/?sid=mysid"
        )
        assert url.query.get("sid") == "mysid"
        # Database should still be empty since sid is present
        assert url.database == ""


# ---------------------------------------------------------------------------
# Connection Check Result Tests
# ---------------------------------------------------------------------------


class TestConnectionCheckResult:
    """Tests for ConnectionCheckResult dataclass."""

    def test_success_result_to_dict(self):
        """Successful check result should serialize correctly."""
        result = ConnectionCheckResult(
            success=True,
            probe_used="SELECT 1",
            check_duration=1.234,
            dialect="sqlite",
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["probe_used"] == "SELECT 1"
        assert d["check_duration"] == 1.234
        assert d["dialect"] == "sqlite"
        assert d["unverified"] is False
        assert "error" not in d
        assert "error_type" not in d

    def test_failure_result_to_dict(self):
        """Failed check result should serialize correctly."""
        result = ConnectionCheckResult(
            success=False,
            error="Connection failed",
            error_type="OperationalError",
            probe_used="SELECT 1",
            check_duration=0.5,
            dialect="postgresql",
        )
        d = result.to_dict()
        assert d["success"] is False
        assert d["error"] == "Connection failed"
        assert d["error_type"] == "OperationalError"
        assert d["probe_used"] == "SELECT 1"
        assert d["dialect"] == "postgresql"

    def test_unverified_result(self):
        """Unverified result should have unverified=True."""
        result = ConnectionCheckResult(
            success=False,
            error="Connection failed",
            unverified=True,
        )
        assert result.unverified is True
        d = result.to_dict()
        assert d["unverified"] is True


# ---------------------------------------------------------------------------
# Connection Check Tests (Mocked)
# ---------------------------------------------------------------------------


class TestCheckConnectionReachability:
    """Tests for check_connection_reachability function."""

    def test_successful_check(self, sqlite_engine):
        """Successful connection check should return success=True."""
        # Use the existing sqlite engine's URL
        url = str(sqlite_engine.url)

        result = check_connection_reachability(url)
        assert result.success is True
        assert result.error is None
        assert result.error_type is None
        assert result.check_duration > 0
        assert result.dialect == "sqlite"
        assert result.probe_used == "SELECT 1"

    def test_failed_check_with_redacted_error(self):
        """Failed connection check should redact credentials in error."""
        # Invalid URL that will fail - use a URL that embeds credentials
        result = check_connection_reachability(
            "postgresql://user:secretpassword@invalid-host:5432/nonexistent"
        )
        assert result.success is False
        assert result.error is not None
        assert result.error_type is not None
        # The error message should not contain the password
        # Note: The error might not contain the password if the connection failed early
        # but we ensure it's redacted if it does appear
        if "secretpassword" in result.error:
            assert "[REDACTED]" in result.error
        assert result.check_duration > 0

    def test_invalid_url_error(self):
        """Invalid URL should return appropriate error."""
        result = check_connection_reachability("not-a-valid-url")
        assert result.success is False
        assert result.error is not None
        assert "Failed to parse" in result.error or "Invalid" in result.error

    def test_check_with_provided_credentials(self, sqlite_engine):
        """Check with provided credentials should work."""
        url = str(sqlite_engine.url)
        result = check_connection_reachability(
            url, username="testuser", password="testpass"
        )
        assert result.success is True

    def test_check_with_custom_timeout(self, sqlite_engine):
        """Check with custom timeout should work."""
        url = str(sqlite_engine.url)
        result = check_connection_reachability(url, timeout=1.0)
        assert result.success is True
        assert result.check_duration <= 1.0

    def test_check_redacts_url_in_error(self):
        """Error messages must not contain the password or the credentials URL.

        The username may appear: database servers quote it in their own
        authentication errors ("password authentication failed for user ..."),
        and the project's redaction contract deliberately keeps usernames
        visible while masking passwords (see test_redact_url_credentials).
        """
        url = "postgresql://testuser:testpass@localhost:5432/testdb"
        result = check_connection_reachability(url)

        # Whether it succeeds or fails, the secret must never surface
        if result.error:
            assert "testpass" not in result.error
            assert "testuser:testpass" not in result.error
            assert url not in result.error


# ---------------------------------------------------------------------------
# Verify and Store Tests (Mocked)
# ---------------------------------------------------------------------------


class TestVerifyAndStoreConnection:
    """Tests for verify_and_store_connection function."""

    def test_store_with_successful_check(self, tmp_path, monkeypatch):
        """Successful check should store the connection."""
        import securedblink.vault.store as store_module

        with (
            patch.object(store_module, "INDEX_FILE", tmp_path / "aliases.json"),
            patch.object(store_module, "INDEX_DIR", tmp_path),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value=None),
        ):
            store_module._vault_store = None
            from securedblink.vault.store import VaultStore

            vault = VaultStore()

            # Mock successful check
            with patch(
                "securedblink.vault.check.check_connection_reachability",
                return_value=ConnectionCheckResult(
                    success=True,
                    probe_used="SELECT 1",
                    check_duration=0.1,
                    dialect="sqlite",
                ),
            ):
                stored, check_result = verify_and_store_connection(
                    vault_store=vault,
                    alias="test",
                    jdbc_url="sqlite:///./test.db",
                    skip_check=False,
                    force_save=False,
                )

                assert stored is True
                assert check_result is not None
                assert check_result.success is True
                assert check_result.unverified is False

    def test_store_with_failed_check_no_force(self, tmp_path, monkeypatch):
        """Failed check without force_save should not store."""
        import securedblink.vault.store as store_module

        mock_vault = MagicMock()

        with (
            patch.object(store_module, "INDEX_FILE", tmp_path / "aliases.json"),
            patch.object(store_module, "INDEX_DIR", tmp_path),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value=None),
        ):
            store_module._vault_store = None
            from securedblink.vault.store import VaultStore

            vault = VaultStore()

            # Mock failed check
            with patch(
                "securedblink.vault.check.check_connection_reachability",
                return_value=ConnectionCheckResult(
                    success=False,
                    error="Connection failed",
                    error_type="OperationalError",
                    probe_used="SELECT 1",
                    check_duration=0.1,
                    dialect="postgresql",
                ),
            ):
                stored, check_result = verify_and_store_connection(
                    vault_store=vault,
                    alias="test",
                    jdbc_url="postgresql://user:pass@invalid-host/db",
                    skip_check=False,
                    force_save=False,
                )

                assert stored is False
                assert check_result is not None
                assert check_result.success is False
                # Vault.set should not have been called
                mock_vault.set.assert_not_called()

    def test_store_with_failed_check_with_force(self, tmp_path, monkeypatch):
        """Failed check with force_save should store and mark as unverified."""
        import securedblink.vault.store as store_module

        with (
            patch.object(store_module, "INDEX_FILE", tmp_path / "aliases.json"),
            patch.object(store_module, "INDEX_DIR", tmp_path),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value=None),
        ):
            store_module._vault_store = None
            from securedblink.vault.store import VaultStore

            vault = VaultStore()

            # Mock failed check
            with patch(
                "securedblink.vault.check.check_connection_reachability",
                return_value=ConnectionCheckResult(
                    success=False,
                    error="Connection failed",
                    error_type="OperationalError",
                    probe_used="SELECT 1",
                    check_duration=0.1,
                    dialect="postgresql",
                ),
            ):
                stored, check_result = verify_and_store_connection(
                    vault_store=vault,
                    alias="test",
                    jdbc_url="postgresql://user:pass@invalid-host/db",
                    skip_check=False,
                    force_save=True,
                )

                assert stored is True
                assert check_result is not None
                assert check_result.success is False
                assert check_result.unverified is True

    def test_skip_check_stores_without_verification(self, tmp_path, monkeypatch):
        """Skip check should store without performing verification."""
        import securedblink.vault.store as store_module

        with (
            patch.object(store_module, "INDEX_FILE", tmp_path / "aliases.json"),
            patch.object(store_module, "INDEX_DIR", tmp_path),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value=None),
        ):
            store_module._vault_store = None
            from securedblink.vault.store import VaultStore

            vault = VaultStore()

            with patch(
                "securedblink.vault.check.check_connection_reachability"
            ) as mock_check:
                stored, check_result = verify_and_store_connection(
                    vault_store=vault,
                    alias="test",
                    jdbc_url="sqlite:///./test.db",
                    skip_check=True,
                    force_save=False,
                )

                # Check should not have been called
                mock_check.assert_not_called()
                assert stored is True
                assert check_result is None

    def test_skip_check_via_env_var(self, tmp_path, monkeypatch):
        """Skip check via environment variable should work."""
        import securedblink.vault.store as store_module

        monkeypatch.setenv("SECUREDBLINK_SKIP_CONNECT_CHECK", "1")

        with (
            patch.object(store_module, "INDEX_FILE", tmp_path / "aliases.json"),
            patch.object(store_module, "INDEX_DIR", tmp_path),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value=None),
        ):
            store_module._vault_store = None
            from securedblink.vault.store import VaultStore

            vault = VaultStore()

            with patch(
                "securedblink.vault.check.check_connection_reachability"
            ) as mock_check:
                stored, check_result = verify_and_store_connection(
                    vault_store=vault,
                    alias="test",
                    jdbc_url="sqlite:///./test.db",
                    skip_check=False,  # Not explicitly set, but env var should override
                    force_save=False,
                )

                # Check should not have been called due to env var
                mock_check.assert_not_called()
                assert stored is True
                assert check_result is None

    def test_overwrite_existing_alias(self, tmp_path, monkeypatch):
        """Overwrite should work with successful check."""
        import securedblink.vault.store as store_module

        index_file = tmp_path / "aliases.json"
        index_file.write_text(
            json.dumps({"test": {"created_at": "2024-01-01", "source": "direct"}})
        )

        with (
            patch.object(store_module, "INDEX_FILE", index_file),
            patch.object(store_module, "INDEX_DIR", tmp_path),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value=None),
        ):
            store_module._vault_store = None
            from securedblink.vault.store import VaultStore

            vault = VaultStore()

            with patch(
                "securedblink.vault.check.check_connection_reachability",
                return_value=ConnectionCheckResult(
                    success=True,
                    probe_used="SELECT 1",
                    check_duration=0.1,
                    dialect="sqlite",
                ),
            ):
                stored, check_result = verify_and_store_connection(
                    vault_store=vault,
                    alias="test",
                    jdbc_url="sqlite:///./new.db",
                    overwrite=True,
                    skip_check=False,
                    force_save=False,
                )

                assert stored is True
                assert check_result.success is True


# ---------------------------------------------------------------------------
# Verify and Update Tests (issue #27)
# ---------------------------------------------------------------------------


class TestVerifyAndUpdateConnection:
    """Partial updates must validate the merged config before writing."""

    def test_check_runs_against_merged_config(self):
        """The stored URL and username are combined with the new password.

        Validating only the overridden field would let a new password paired
        with a stale username pass here and fail at the next query.
        """
        vault = MagicMock()
        current = {
            "jdbc_url": "sqlite:///:memory:",
            "username": "stored-user",
            "password": "stored-pass",
        }
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            check.return_value = ConnectionCheckResult(success=True, dialect="sqlite")
            updated, result = verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                password="rotated",
            )

        assert updated is True
        assert result.success is True
        args = check.call_args.args
        assert args[0] == "sqlite:///:memory:"
        assert args[1] == "stored-user"
        assert args[2] == "rotated"

    def test_only_overridden_fields_are_written(self):
        """None overrides are passed through so the store keeps its values."""
        vault = MagicMock()
        current = {"jdbc_url": "sqlite:///:memory:", "username": "app"}
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            check.return_value = ConnectionCheckResult(success=True, dialect="sqlite")
            verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                password="rotated",
            )

        vault.update.assert_called_once()
        kwargs = vault.update.call_args.kwargs
        assert kwargs["alias"] == "prod"
        assert kwargs["password"] == "rotated"
        assert kwargs["jdbc_url"] is None
        assert kwargs["username"] is None
        assert kwargs["driver"] is None

    def test_overridden_url_is_checked_not_the_stored_one(self):
        vault = MagicMock()
        current = {"jdbc_url": "sqlite:///stored.db"}
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            check.return_value = ConnectionCheckResult(success=True, dialect="sqlite")
            verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                jdbc_url="sqlite:///replacement.db",
            )
        assert check.call_args.args[0] == "sqlite:///replacement.db"

    def test_failed_check_leaves_vault_untouched(self):
        vault = MagicMock()
        current = {"jdbc_url": "sqlite:///:memory:"}
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            check.return_value = ConnectionCheckResult(
                success=False, error_type="OperationalError", dialect="sqlite"
            )
            updated, result = verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                password="bad",
            )

        assert updated is False
        assert result.success is False
        vault.update.assert_not_called()

    def test_force_save_writes_and_marks_unverified(self):
        vault = MagicMock()
        current = {"jdbc_url": "sqlite:///:memory:"}
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            check.return_value = ConnectionCheckResult(
                success=False, error_type="OperationalError", dialect="sqlite"
            )
            updated, result = verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                password="bad",
                force_save=True,
            )

        assert updated is True
        assert result.unverified is True
        vault.update.assert_called_once()

    def test_skip_check_writes_without_verifying(self):
        vault = MagicMock()
        current = {"jdbc_url": "sqlite:///:memory:"}
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            updated, result = verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                password="rotated",
                skip_check=True,
            )

        assert updated is True
        assert result is None
        check.assert_not_called()
        vault.update.assert_called_once()

    def test_skip_check_env_var_is_honoured(self, monkeypatch):
        vault = MagicMock()
        current = {"jdbc_url": "sqlite:///:memory:"}
        monkeypatch.setenv("SECUREDBLINK_SKIP_CONNECT_CHECK", "1")
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            updated, result = verify_and_update_connection(
                vault_store=vault,
                alias="prod",
                current_config=current,
                password="rotated",
            )

        assert updated is True
        assert result is None
        check.assert_not_called()

    def test_missing_url_checks_empty_and_does_not_write(self):
        """A config with no URL anywhere must not be written on a failed check."""
        vault = MagicMock()
        with patch("securedblink.vault.check.check_connection_reachability") as check:
            check.return_value = ConnectionCheckResult(
                success=False, error_type="ValueError", dialect=""
            )
            updated, _ = verify_and_update_connection(
                vault_store=vault, alias="prod", current_config={}, password="x"
            )

        assert updated is False
        assert check.call_args.args[0] == ""
        vault.update.assert_not_called()

    def test_end_to_end_update_against_real_sqlite(self, tmp_path):
        """No mocks: a rotated URL is verified against the real database."""
        vault = MagicMock()
        target = tmp_path / "rotated.db"
        engine = create_engine(f"sqlite:///{target}")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE marker (label TEXT)"))
        engine.dispose()

        updated, result = verify_and_update_connection(
            vault_store=vault,
            alias="prod",
            current_config={"jdbc_url": "sqlite:///does-not-exist-anywhere.db"},
            jdbc_url=f"sqlite:///{target}",
        )

        assert updated is True
        assert result.success is True
        vault.update.assert_called_once()


# ---------------------------------------------------------------------------
# Integration Tests with Real SQLite Database
# ---------------------------------------------------------------------------


class TestIntegrationWithRealDatabase:
    """Integration tests using real SQLite database."""

    def test_check_with_real_sqlite_database(self, tmp_path):
        """Check should succeed with a real SQLite database file."""
        db_file = tmp_path / "test.db"
        db_url = f"sqlite:///{db_file}"

        # Create the database file
        engine = create_engine(db_url)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE test (id INTEGER)"))

        # Now check the connection
        result = check_connection_reachability(db_url)
        assert result.success is True
        assert result.dialect == "sqlite"

    def test_check_with_memory_sqlite(self):
        """Check should succeed with in-memory SQLite."""
        # Note: We need to use a shared memory URL for the check to work
        result = check_connection_reachability("sqlite:///:memory:")
        assert result.success is True
        assert result.dialect == "sqlite"

    def test_check_with_nonexistent_sqlite_file(self, tmp_path):
        """Check should succeed with non-existent SQLite file (SQLite creates it).

        Note: SQLite automatically creates the database file if it doesn't exist,
        so this test verifies that the check works even when the file doesn't exist yet.
        """
        db_url = f"sqlite:///{tmp_path / 'nonexistent.db'}"
        result = check_connection_reachability(db_url)
        # SQLite will create the file, so this should succeed
        assert result.success is True
        assert result.dialect == "sqlite"


# ---------------------------------------------------------------------------
# Redaction Tests for Connection Check
# ---------------------------------------------------------------------------


class TestRedactionInConnectionCheck:
    """Tests for credential redaction in connection check errors."""

    def test_redacted_error_for_invalid_host(self):
        """Error for invalid host should have redacted credentials."""
        url = "postgresql://myuser:mypassword@invalid-host:5432/mydb"
        result = check_connection_reachability(url)

        assert result.success is False
        if result.error:
            assert "mypassword" not in result.error
            assert "myuser" not in result.error or "[REDACTED]" in result.error

    def test_redacted_error_for_url_with_credentials(self):
        """URL credentials should be redacted in error messages."""
        url = "mysql://admin:secret123@localhost:3306/test"
        result = check_connection_reachability(url)

        # Whether it succeeds or fails, credentials should be redacted in errors
        if result.error:
            assert "secret123" not in result.error
            assert "[REDACTED]" in result.error or "admin" not in result.error

    def test_redact_exception_directly(self):
        """Test the redact_exception function directly."""
        # Create an exception with credentials in the message
        try:
            raise ValueError("Connection failed: postgresql://user:password@host/db")
        except ValueError as e:
            redacted = redact_exception(e)
            assert "password" not in redacted
            assert "[REDACTED]" in redacted


# ---------------------------------------------------------------------------
# Timeout Tests
# ---------------------------------------------------------------------------


class TestTimeoutHandling:
    """Tests for timeout handling in connection checks."""

    def test_timeout_via_parameter(self, sqlite_engine):
        """Custom timeout via parameter should be respected."""
        url = str(sqlite_engine.url)
        start = time.time()
        result = check_connection_reachability(url, timeout=0.5)
        duration = time.time() - start

        assert result.success is True
        # Should complete within timeout
        assert duration < 1.0

    def test_default_timeout_used_when_not_specified(self, sqlite_engine):
        """Default timeout should be used when not specified."""
        url = str(sqlite_engine.url)
        result = check_connection_reachability(url)

        assert result.success is True
        assert result.check_duration < 10  # Should be much less than default 5s


# ---------------------------------------------------------------------------
# Connect Timeout Argument Tests (issue #29)
# ---------------------------------------------------------------------------


class TestConnectTimeoutArgs:
    """The timeout must reach the driver, not create_engine itself.

    A top-level ``connect_timeout`` kwarg made ``create_engine`` raise TypeError
    before any network access, which failed every non-SQLite reachability check.
    SQLite skips the timeout branch entirely, so a SQLite-only suite could not
    see it.
    """

    def test_never_passes_a_toplevel_connect_timeout(self):
        """Regression: the kwarg that produced the TypeError is gone."""
        engine = create_engine("sqlite:///:memory:")
        with (
            patch("securedblink.vault.check.create_engine", return_value=engine) as ce,
            patch.object(engine, "dispose"),
        ):
            check_connection_reachability("postgresql://u@h:5432/db", timeout=3)
        assert "connect_timeout" not in ce.call_args.kwargs
        assert set(ce.call_args.kwargs) <= {"connect_args"}

    @pytest.mark.parametrize(
        ("url", "expected_key"),
        [
            ("postgresql://u@h:5432/db", "connect_timeout"),
            ("postgresql+psycopg2://u@h/db", "connect_timeout"),
            ("mysql+pymysql://u@h/db", "connect_timeout"),
            ("oracle+oracledb://u@h:1521/?service_name=S", "tcp_connect_timeout"),
            ("mssql+pyodbc://u@h/db", "timeout"),
        ],
    )
    def test_driver_specific_timeout_key(self, url, expected_key):
        engine = create_engine("sqlite:///:memory:")
        with (
            patch("securedblink.vault.check.create_engine", return_value=engine) as ce,
            patch.object(engine, "dispose"),
        ):
            check_connection_reachability(url, timeout=4)
        assert ce.call_args.kwargs == {"connect_args": {expected_key: 4}}

    def test_sqlite_gets_no_connect_args(self):
        engine = create_engine("sqlite:///:memory:")
        with (
            patch("securedblink.vault.check.create_engine", return_value=engine) as ce,
            patch.object(engine, "dispose"),
        ):
            check_connection_reachability("sqlite:///:memory:", timeout=4)
        assert ce.call_args.kwargs == {}

    def test_unknown_driver_gets_no_timeout_kwarg(self):
        """A guessed keyword is another TypeError; driver default is safer."""
        assert _engine_timeout_kwargs("snowflake", 5.0) == {}
        assert _engine_timeout_kwargs("cockroachdb", 5.0) == {}

    @pytest.mark.parametrize(
        ("dialect", "timeout", "expected"),
        [
            ("postgresql", 5.5, {"connect_args": {"connect_timeout": 5}}),
            ("postgresql+psycopg2", 5.5, {"connect_args": {"connect_timeout": 5}}),
            ("mysql+pymysql", 2.9, {"connect_args": {"connect_timeout": 2}}),
            ("mssql+pyodbc", 3.7, {"connect_args": {"timeout": 3}}),
            ("oracle+oracledb", 5.5, {"connect_args": {"tcp_connect_timeout": 5.5}}),
            ("postgresql+psycopg", 5.5, {"connect_args": {"connect_timeout": 5.5}}),
        ],
    )
    def test_fractional_timeouts_coerced_per_driver(self, dialect, timeout, expected):
        """psycopg2, PyMySQL and pyodbc reject a fractional timeout."""
        assert _engine_timeout_kwargs(dialect, timeout) == expected

    @pytest.mark.parametrize("timeout", [0, -1])
    def test_nonpositive_timeout_adds_no_kwargs(self, timeout):
        assert _engine_timeout_kwargs("postgresql", timeout) == {}
        assert _engine_timeout_kwargs("oracle+oracledb", timeout) == {}

    def test_oracle_check_no_longer_fails_with_typeerror(self):
        """The reported symptom: Oracle failed in ~0.0s with TypeError."""
        engine = create_engine("sqlite:///:memory:")
        with (
            patch("securedblink.vault.check.create_engine", return_value=engine) as ce,
            patch.object(engine, "dispose"),
        ):
            result = check_connection_reachability(
                "oracle+oracledb://u:p@h:1521/?service_name=SVC", timeout=5
            )
        assert result.error_type != "TypeError"
        assert ce.call_args.kwargs == {"connect_args": {"tcp_connect_timeout": 5.0}}


# ---------------------------------------------------------------------------
# Edge Cases and Error Handling
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_jdbc_url(self):
        """Empty JDBC URL should fail gracefully."""
        result = check_connection_reachability("")
        assert result.success is False
        assert result.error is not None

    def test_none_jdbc_url(self):
        """None JDBC URL should fail gracefully."""
        result = check_connection_reachability(None)  # type: ignore[arg-type]
        assert result.success is False

    def test_url_with_special_characters(self):
        """URL with special characters should be handled."""
        # This might fail to connect but should not crash
        result = check_connection_reachability(
            "postgresql://user%40domain:pass%20word@host/db"
        )
        assert result.success is False
        if result.error:
            assert "pass%20word" not in result.error or "[REDACTED]" in result.error

    def test_very_long_timeout(self, monkeypatch):
        """Very long timeout should still work."""
        monkeypatch.setenv("SECUREDBLINK_CONNECT_CHECK_TIMEOUT", "300")
        assert _get_timeout() == 300.0

    def test_negative_timeout_falls_back(self, monkeypatch):
        """Negative timeout should fall back to default."""
        monkeypatch.setenv("SECUREDBLINK_CONNECT_CHECK_TIMEOUT", "-1")
        # Should fall back to default
        timeout = _get_timeout()
        assert timeout == DEFAULT_CHECK_TIMEOUT  # Should fall back to default
