"""Tests for the securedblink command-line interface (securedblink.server.cli_main)."""

from unittest.mock import Mock, patch

from securedblink.server import cli_main
from securedblink.vault.store import VaultStoreError


class TestCliRegister:
    """Tests for the ``register`` subcommand."""

    def test_register_success(self, capfd):
        mock_vault = Mock()
        with patch("securedblink.vault.store.get_vault_store", return_value=mock_vault):
            rc = cli_main(
                [
                    "register",
                    "--alias",
                    "prod",
                    "--jdbc-url",
                    "postgresql://localhost/db",
                ]
            )
        assert rc == 0
        mock_vault.set.assert_called_once_with(
            alias="prod",
            jdbc_url="postgresql://localhost/db",
            username=None,
            password=None,
            driver=None,
            source="direct",
            overwrite=False,
        )
        assert "registered" in capfd.readouterr().err

    def test_register_full_credentials(self, capfd):
        mock_vault = Mock()
        with patch("securedblink.vault.store.get_vault_store", return_value=mock_vault):
            rc = cli_main(
                [
                    "register",
                    "--alias",
                    "prod",
                    "--jdbc-url",
                    "postgresql://localhost/db",
                    "--username",
                    "app",
                    "--password",
                    "secret",
                    "--driver",
                    "org.postgresql.Driver",
                    "--overwrite",
                ]
            )
        assert rc == 0
        mock_vault.set.assert_called_once_with(
            alias="prod",
            jdbc_url="postgresql://localhost/db",
            username="app",
            password="secret",
            driver="org.postgresql.Driver",
            source="direct",
            overwrite=True,
        )

    def test_register_duplicate_returns_error(self, capfd):
        mock_vault = Mock()
        mock_vault.set.side_effect = VaultStoreError(
            "Alias 'prod' already exists. Use overwrite=True to replace."
        )
        with patch("securedblink.vault.store.get_vault_store", return_value=mock_vault):
            rc = cli_main(
                [
                    "register",
                    "--alias",
                    "prod",
                    "--jdbc-url",
                    "postgresql://localhost/db",
                ]
            )
        assert rc == 1
        err = capfd.readouterr().err
        assert "already exists" in err


class TestCliRegisterFromPath:
    """Tests for the ``register-from-path`` subcommand."""

    def test_register_from_path_success(self, tmp_path, monkeypatch, capfd):
        env_file = tmp_path / "conn.env"
        env_file.write_text("DB_URL=postgresql://user:secret@localhost/db\n")
        monkeypatch.setenv("SECUREDBLINK_ALLOWED_ROOTS", str(tmp_path))

        mock_vault = Mock()
        with patch("securedblink.vault.store.get_vault_store", return_value=mock_vault):
            rc = cli_main(
                ["register-from-path", "--alias", "prod", "--file-path", str(env_file)]
            )
        assert rc == 0
        mock_vault.set.assert_called_once()
        _, kwargs = mock_vault.set.call_args
        assert kwargs["alias"] == "prod"
        assert kwargs["source"] == "path"
        assert kwargs["jdbc_url"] == "postgresql://user:secret@localhost/db"
        assert kwargs["username"] is None
        assert "registered" in capfd.readouterr().err

    def test_register_from_path_outside_root(self, tmp_path, monkeypatch, capfd):
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        outside_file = tmp_path / "conn.env"
        outside_file.write_text("DB_URL=sqlite:///./db.sqlite\n")
        monkeypatch.setenv("SECUREDBLINK_ALLOWED_ROOTS", str(allowed_dir))

        rc = cli_main(
            ["register-from-path", "--alias", "prod", "--file-path", str(outside_file)]
        )
        assert rc == 1
        err = capfd.readouterr().err
        assert "not within an allow-listed root" in err

    def test_register_from_path_no_roots(self, tmp_path, monkeypatch, capfd):
        env_file = tmp_path / "conn.env"
        env_file.write_text("DB_URL=sqlite:///./db.sqlite\n")
        monkeypatch.delenv("SECUREDBLINK_ALLOWED_ROOTS", raising=False)

        rc = cli_main(
            ["register-from-path", "--alias", "prod", "--file-path", str(env_file)]
        )
        assert rc == 1
        err = capfd.readouterr().err
        assert "SECUREDBLINK_ALLOWED_ROOTS" in err


class TestCliList:
    """Tests for the ``list`` subcommand."""

    def test_list_empty(self, capfd):
        mock_vault = Mock()
        mock_vault.list_aliases.return_value = []
        with patch("securedblink.vault.store.get_vault_store", return_value=mock_vault):
            rc = cli_main(["list"])
        assert rc == 0
        assert "No vault aliases registered" in capfd.readouterr().err

    def test_list_sorted_aliases(self, capfd):
        mock_vault = Mock()
        mock_vault.list_aliases.return_value = ["beta", "alpha"]
        mock_vault.get_metadata.side_effect = lambda alias: {
            "source": "direct",
            "created_at": "2024-01-01T00:00:00+00:00",
        }
        with patch("securedblink.vault.store.get_vault_store", return_value=mock_vault):
            rc = cli_main(["list"])
        assert rc == 0
        err = capfd.readouterr().err
        assert err.index("- alpha") < err.index("- beta")
        assert "source: direct" in err


class TestCliEdgeCases:
    """Tests for CLI dispatch and validation edge cases."""

    def test_no_command_starts_server(self):
        with patch("securedblink.server.main") as mock_main:
            assert cli_main([]) == 0
        mock_main.assert_called_once_with()

    def test_register_from_path_invalid_config(self, tmp_path, monkeypatch, capfd):
        env_file = tmp_path / "invalid.env"
        env_file.write_text("DB_USERNAME=alice\n")
        monkeypatch.setenv("SECUREDBLINK_ALLOWED_ROOTS", str(tmp_path))

        assert (
            cli_main(
                [
                    "register-from-path",
                    "--alias",
                    "prod",
                    "--file-path",
                    str(env_file),
                ]
            )
            == 1
        )
        assert "valid connection URL" in capfd.readouterr().err
