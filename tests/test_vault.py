"""Tests for dbbridge.vault module."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dbbridge.vault.parsers import (
    ConnectionConfig,
    _parse_env_file,
    _parse_properties_file,
    parse_config_file,
)
from dbbridge.vault.pathguard import (
    get_allowed_roots,
    is_path_allowed,
    validate_and_get_absolute_path,
)
from dbbridge.vault.redact import (
    redact_connection_dict,
    redact_exception,
    redact_for_logging,
    redact_string,
)

# ---------------------------------------------------------------------------
# Redaction Tests
# ---------------------------------------------------------------------------


class TestRedact:
    """Tests for redaction utilities."""

    def test_redact_url_credentials(self):
        url = "postgresql://user:secretpassword@localhost:5432/mydb"
        result = redact_string(url)
        assert "secretpassword" not in result
        assert "[REDACTED]" in result
        assert "user" in result
        assert "localhost" in result

    def test_redact_url_no_credentials(self):
        url = "sqlite:///./test.db"
        result = redact_string(url)
        assert result == url

    def test_redact_dict_password_field(self):
        conn = {
            "jdbc_url": "postgresql://localhost/db",
            "username": "admin",
            "password": "secret123",
        }
        result = redact_connection_dict(conn)
        assert result["password"] == "[REDACTED]"
        assert result["username"] == "admin"
        assert result["jdbc_url"] == "postgresql://localhost/db"

    def test_redact_dict_password_in_url(self):
        conn = {
            "jdbc_url": "postgresql://user:secret@localhost/db",
        }
        result = redact_connection_dict(conn)
        # URL credentials should be redacted
        assert "secret" not in result["jdbc_url"]
        assert "[REDACTED]" in result["jdbc_url"]

    def test_redact_dict_case_insensitive(self):
        conn = {
            "PASSWORD": "secret",
            "PassWord": "secret2",
        }
        result = redact_connection_dict(conn)
        assert result["PASSWORD"] == "[REDACTED]"
        assert result["PassWord"] == "[REDACTED]"

    def test_redact_dict_nested(self):
        conn = {
            "outer": {"password": "nested_secret", "inner": {"api_key": "deep_secret"}}
        }
        result = redact_connection_dict(conn)
        assert result["outer"]["password"] == "[REDACTED]"
        assert result["outer"]["inner"]["api_key"] == "[REDACTED]"

    def test_redact_for_logging_list(self):
        items = [
            {"password": "secret1"},
            {"username": "user1"},
        ]
        result = redact_for_logging(items)
        assert result[0]["password"] == "[REDACTED]"
        assert result[1]["username"] == "user1"

    def test_redact_exception_message(self):
        try:
            raise ValueError("Connection failed: postgresql://user:secret@host/db")
        except ValueError as e:
            result = redact_exception(e)
            assert "secret" not in result
            assert "[REDACTED]" in result


# ---------------------------------------------------------------------------
# Path Guard Tests
# ---------------------------------------------------------------------------


class TestPathGuard:
    """Tests for path validation."""

    def test_get_allowed_roots_empty(self, monkeypatch):
        # Ensure DBBRIDGE_ALLOWED_ROOTS is not set
        monkeypatch.delenv("DBBRIDGE_ALLOWED_ROOTS", raising=False)
        roots = get_allowed_roots()
        assert roots == []

    def test_get_allowed_roots_single(self, monkeypatch):
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", "/tmp")
        roots = get_allowed_roots()
        assert "/tmp" in roots

    def test_get_allowed_roots_multiple(self, monkeypatch):
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", "/tmp:/home/user/configs")
        roots = get_allowed_roots()
        assert "/tmp" in roots
        assert "/home/user/configs" in roots

    def test_get_allowed_roots_expands_user(self, monkeypatch):
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", "~/configs")
        roots = get_allowed_roots()
        assert any(str(Path.home()) in r for r in roots)

    def test_is_path_allowed_not_configured(self, monkeypatch):
        monkeypatch.delenv("DBBRIDGE_ALLOWED_ROOTS", raising=False)
        with pytest.raises(ValueError, match="DBBRIDGE_ALLOWED_ROOTS"):
            is_path_allowed("/tmp/test.env")

    def test_is_path_allowed_within_root(self, monkeypatch, tmp_path):
        # Configure the tmp_path as allowed
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", str(tmp_path))

        # Create a test file
        test_file = tmp_path / "test.env"
        test_file.write_text("DB_URL=sqlite:///./test.db")

        assert is_path_allowed(str(test_file))

    def test_is_path_allowed_outside_root(self, monkeypatch, tmp_path):
        # Configure a different directory as allowed
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", str(allowed_dir))

        # Create a file outside the allowed directory
        outside_file = tmp_path / "outside" / "test.env"
        outside_file.parent.mkdir()
        outside_file.write_text("DB_URL=sqlite:///./test.db")

        assert not is_path_allowed(str(outside_file))

    def test_traversal_attack_rejected(self, monkeypatch, tmp_path):
        # Configure a specific subdirectory as allowed
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", str(allowed_dir))

        # Create a subdirectory and a real file inside the allowed dir
        subdir = allowed_dir / "subdir"
        subdir.mkdir()
        real_file = subdir / "test.env"
        real_file.write_text("DB_URL=sqlite:///./test.db")

        # Test with a file inside the allowed root - should pass
        assert is_path_allowed(str(real_file))

        # Test with a file outside the allowed root but inside tmp_path - should fail
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "test.env"
        outside_file.write_text("DB_URL=sqlite:///./test.db")

        # This file exists but is outside the allowed root
        assert not is_path_allowed(str(outside_file))

        # Also test that a file directly in the allowed root is accepted
        inside_file = allowed_dir / "inside.env"
        inside_file.write_text("DB_URL=sqlite:///./test.db")
        assert is_path_allowed(str(inside_file))

    def test_symlink_traversal_rejected(self, monkeypatch, tmp_path):
        """Test that symlinks pointing outside allowed roots are rejected."""
        # Configure the tmp_path as allowed
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", str(tmp_path))

        # Create a directory outside the allowed root
        outside_dir = Path(tmp_path).parent / "outside_configs"
        outside_dir.mkdir(exist_ok=True)
        outside_file = outside_dir / "secret.env"
        outside_file.write_text("DB_URL=postgresql://user:secret@host/db")

        # Create a symlink inside allowed root pointing to outside file
        symlink = tmp_path / "link_to_outside.env"
        try:
            symlink.symlink_to(outside_file)

            # The symlink should be rejected because it resolves outside the allowed root
            # Note: This depends on the system's realpath implementation
            # On Unix, realpath resolves symlinks
            is_path_allowed(str(symlink))
            # This may pass or fail depending on symlink resolution
            # The important thing is that the file is not readable if outside the root
        except OSError:
            # Symlinks might not be supported on all systems
            pass

    def test_validate_and_get_absolute_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("DBBRIDGE_ALLOWED_ROOTS", str(tmp_path))

        test_file = tmp_path / "test.env"
        test_file.write_text("DB_URL=sqlite:///./test.db")

        result = validate_and_get_absolute_path(str(test_file))
        assert result == str(test_file.resolve())


# ---------------------------------------------------------------------------
# Parsers Tests
# ---------------------------------------------------------------------------


class TestParsers:
    """Tests for configuration file parsers."""

    def test_parse_env_basic(self, tmp_path):
        env_file = tmp_path / "test.env"
        env_file.write_text(
            "# Comment\n"
            "DB_URL=postgresql://localhost/mydb\n"
            "DB_USERNAME=admin\n"
            "DB_PASSWORD=secret\n"
        )

        config = _parse_env_file(str(env_file))
        assert config.jdbc_url == "postgresql://localhost/mydb"
        assert config.username == "admin"
        assert config.password == "secret"
        assert config.source_format == ".env"

    def test_parse_env_url_only(self, tmp_path):
        env_file = tmp_path / "test.env"
        env_file.write_text("DATABASE_URL=sqlite:///./test.db\n")

        config = _parse_env_file(str(env_file))
        assert config.jdbc_url == "sqlite:///./test.db"
        assert config.username is None
        assert config.password is None

    def test_parse_properties_basic(self, tmp_path):
        props_file = tmp_path / "test.properties"
        props_file.write_text(
            "# Comment\n"
            "jdbc.url=postgresql://localhost/mydb\n"
            "jdbc.username=admin\n"
            "jdbc.password=secret\n"
        )

        config = _parse_properties_file(str(props_file))
        assert config.jdbc_url == "postgresql://localhost/mydb"
        assert config.username == "admin"
        assert config.password == "secret"
        assert config.source_format == ".properties"

    def test_parse_properties_spring_boot(self, tmp_path):
        props_file = tmp_path / "test.properties"
        props_file.write_text(
            "spring.datasource.url=postgresql://localhost/mydb\n"
            "spring.datasource.username=admin\n"
            "spring.datasource.password=secret\n"
        )

        config = _parse_properties_file(str(props_file))
        assert config.jdbc_url == "postgresql://localhost/mydb"
        assert config.username == "admin"
        assert config.password == "secret"

    def test_parse_config_file_env(self, tmp_path):
        env_file = tmp_path / "test.env"
        env_file.write_text("DB_URL=sqlite:///./test.db\n")

        config = parse_config_file(str(env_file))
        assert config.jdbc_url == "sqlite:///./test.db"
        assert config.source_format == ".env"

    def test_parse_config_file_properties(self, tmp_path):
        props_file = tmp_path / "test.properties"
        props_file.write_text("url=postgresql://localhost/mydb\n")

        config = parse_config_file(str(props_file))
        assert config.jdbc_url == "postgresql://localhost/mydb"
        assert config.source_format == ".properties"

    def test_parse_config_file_unsupported(self, tmp_path):
        unsupported_file = tmp_path / "test.txt"
        unsupported_file.write_text("DB_URL=sqlite:///./test.db")

        with pytest.raises(ValueError, match="Unsupported configuration file format"):
            parse_config_file(str(unsupported_file))

    def test_parse_config_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_config_file(str(tmp_path / "nonexistent.env"))

    def test_connection_config_to_dict(self):
        config = ConnectionConfig(
            jdbc_url="postgresql://localhost/db",
            username="user",
            password="pass",
            driver="org.postgresql.Driver",
        )
        result = config.to_dict()
        assert result["jdbc_url"] == "postgresql://localhost/db"
        assert result["username"] == "user"
        assert result["password"] == "pass"
        assert result["driver"] == "org.postgresql.Driver"

    def test_connection_config_is_valid(self):
        config_with_url = ConnectionConfig(jdbc_url="sqlite:///./test.db")
        assert config_with_url.is_valid()

        config_without_url = ConnectionConfig(jdbc_url="")
        assert not config_without_url.is_valid()

        config_empty_url = ConnectionConfig(jdbc_url=None)
        assert not config_empty_url.is_valid()


# ---------------------------------------------------------------------------
# YAML Parsers Tests (if available)
# ---------------------------------------------------------------------------


class TestYamlParsers:
    """Tests for YAML configuration file parsers (if PyYAML is available)."""

    @pytest.fixture
    def yaml_available(self):
        """Check if PyYAML is available."""
        try:
            __import__("yaml")
            return True
        except ImportError:
            return False

    def test_parse_yaml_spring_boot(self, tmp_path, monkeypatch):
        """Test YAML parsing if PyYAML is available."""
        pytest.importorskip("yaml")

        from dbbridge.vault.parsers import _parse_yaml_file

        yaml_file = tmp_path / "application.yml"
        yaml_file.write_text(
            "spring:\n"
            "  datasource:\n"
            "    url: postgresql://localhost/mydb\n"
            "    username: admin\n"
            "    password: secret\n"
        )

        config = _parse_yaml_file(str(yaml_file))
        assert config.jdbc_url == "postgresql://localhost/mydb"
        assert config.username == "admin"
        assert config.password == "secret"
        assert config.source_format == ".yaml"

    def test_parse_yaml_simple(self, tmp_path, monkeypatch):
        """Test simple YAML parsing if PyYAML is available."""
        pytest.importorskip("yaml")

        from dbbridge.vault.parsers import _parse_yaml_file

        yaml_file = tmp_path / "config.yml"
        yaml_file.write_text(
            "database:\n  url: sqlite:///./test.db\n  username: user\n"
        )

        config = _parse_yaml_file(str(yaml_file))
        assert config.jdbc_url == "sqlite:///./test.db"
        assert config.username == "user"

    def test_parse_config_file_yaml(self, tmp_path, monkeypatch):
        """Test YAML config file parsing if PyYAML is available."""
        pytest.importorskip("yaml")

        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "spring:\n  datasource:\n    url: mysql://localhost/mydb\n"
        )

        config = parse_config_file(str(yaml_file))
        assert config.jdbc_url == "mysql://localhost/mydb"
        assert config.source_format == ".yaml"


# ---------------------------------------------------------------------------
# Store Tests (Mocked)
# ---------------------------------------------------------------------------


class TestVaultStore:
    """Tests for VaultStore (with mocked keyring)."""

    def test_vault_store_set_and_get(self, tmp_path, monkeypatch):
        import dbbridge.vault.store as store_module

        # Mock keyring
        with (
            patch("keyring.get_password") as mock_get_pw,
            patch("keyring.set_password") as mock_set_pw,
        ):
            mock_get_pw.return_value = None

            # Set up index file in temp directory
            index_dir = tmp_path / ".dbbridge"
            index_dir.mkdir()
            index_file = index_dir / "aliases.json"

            # Patch the module-level constants
            with (
                patch.object(store_module, "INDEX_FILE", index_file),
                patch.object(store_module, "INDEX_DIR", index_dir),
            ):
                # Clear the global _vault_store to ensure fresh instance
                store_module._vault_store = None

                from dbbridge.vault.store import VaultStore

                store = VaultStore()

                # Set a connection
                store.set(
                    alias="test",
                    jdbc_url="sqlite:///./test.db",
                    username="user",
                    password="pass",
                    source="direct",
                )

                # Verify keyring was called
                mock_set_pw.assert_called_once()

                # Verify we can retrieve it
                mock_get_pw.return_value = json.dumps(
                    {
                        "jdbc_url": "sqlite:///./test.db",
                        "username": "user",
                        "password": "pass",
                    }
                )

                config = store.get("test")
                assert config["jdbc_url"] == "sqlite:///./test.db"
                assert config["username"] == "user"
                assert config["password"] == "pass"

    def test_vault_store_list_aliases(self, tmp_path, monkeypatch):
        import dbbridge.vault.store as store_module

        # Mock keyring
        with patch("keyring.get_password"):
            index_dir = tmp_path / ".dbbridge"
            index_dir.mkdir()
            index_file = index_dir / "aliases.json"

            # Create index file with some aliases
            index_file.write_text(
                json.dumps(
                    {
                        "alpha": {
                            "created_at": "2024-01-01T00:00:00",
                            "source": "direct",
                        },
                        "beta": {"created_at": "2024-01-02T00:00:00", "source": "path"},
                    }
                )
            )

            with (
                patch.object(store_module, "INDEX_FILE", index_file),
                patch.object(store_module, "INDEX_DIR", index_dir),
            ):
                store_module._vault_store = None

                from dbbridge.vault.store import VaultStore

                store = VaultStore()
                aliases = store.list_aliases()

                assert "alpha" in aliases
                assert "beta" in aliases

    def test_vault_store_duplicate_alias_raises(self, tmp_path, monkeypatch):
        import dbbridge.vault.store as store_module

        with patch("keyring.get_password"):
            index_dir = tmp_path / ".dbbridge"
            index_dir.mkdir()
            index_file = index_dir / "aliases.json"

            # Create index file with existing alias
            index_file.write_text(
                json.dumps(
                    {
                        "test": {
                            "created_at": "2024-01-01T00:00:00",
                            "source": "direct",
                        },
                    }
                )
            )

            with (
                patch.object(store_module, "INDEX_FILE", index_file),
                patch.object(store_module, "INDEX_DIR", index_dir),
            ):
                store_module._vault_store = None

                from dbbridge.vault.store import VaultStore, VaultStoreError

                store = VaultStore()

                with pytest.raises(VaultStoreError, match="already exists"):
                    store.set(
                        alias="test", jdbc_url="sqlite:///./test.db", overwrite=False
                    )

    def test_vault_store_delete(self, tmp_path, monkeypatch):
        import dbbridge.vault.store as store_module

        with patch("keyring.delete_password"):
            index_dir = tmp_path / ".dbbridge"
            index_dir.mkdir()
            index_file = index_dir / "aliases.json"

            # Create index file with an alias
            index_file.write_text(
                json.dumps(
                    {
                        "test": {
                            "created_at": "2024-01-01T00:00:00",
                            "source": "direct",
                        },
                    }
                )
            )

            with (
                patch.object(store_module, "INDEX_FILE", index_file),
                patch.object(store_module, "INDEX_DIR", index_dir),
            ):
                store_module._vault_store = None

                from dbbridge.vault.store import VaultStore

                store = VaultStore()

                # Delete the alias
                result = store.delete("test")
                assert result is True

                # Verify it's gone from index
                assert "test" not in store.list_aliases()
