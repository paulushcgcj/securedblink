"""Tests for securedblink.connections module."""

import os
from unittest.mock import Mock, patch

import pytest
from sqlalchemy.engine import make_url

from securedblink.connections import (
    ConnectionManager,
    _load_urls,
    _normalize_oracle_url,
)


class TestLoadUrls:
    def test_filters_reserved(self, monkeypatch):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        monkeypatch.setenv("DB_MAX_ROWS", "100")
        urls = _load_urls()
        assert "test" in urls
        assert "max_rows" not in urls

    def test_lowercases_keys(self, monkeypatch):
        monkeypatch.setenv("DB_PROD", "postgresql://localhost/prod")
        urls = _load_urls()
        assert "prod" in urls

    def test_empty_when_no_db_vars(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("DB_"):
                monkeypatch.delenv(key)
        urls = _load_urls()
        assert urls == {}


class TestConnectionManager:
    def test_names_sorted(self, monkeypatch):
        monkeypatch.setenv("DB_ZEBRA", "sqlite:///:memory:")
        monkeypatch.setenv("DB_ALPHA", "sqlite:///:memory:")
        mgr = ConnectionManager()
        assert mgr.names() == ["alpha", "zebra"]

    def test_names_empty(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("DB_"):
                monkeypatch.delenv(key)
        mgr = ConnectionManager()
        assert mgr.names() == []

    def test_engine_creates_and_caches(self, monkeypatch):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        mgr = ConnectionManager()
        e1 = mgr.engine("test")
        e2 = mgr.engine("test")
        assert e1 is e2

    def test_engine_missing_raises(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("DB_"):
                monkeypatch.delenv(key)
        mgr = ConnectionManager()
        with pytest.raises(ValueError, match="not found"):
            mgr.engine("nonexistent")

    def test_engine_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        mgr = ConnectionManager()
        e1 = mgr.engine("TEST")
        e2 = mgr.engine("test")
        assert e1 is e2

    def test_vault_names_and_all_names(self, monkeypatch):
        monkeypatch.setenv("DB_ENV", "sqlite:///:memory:")
        vault = Mock()
        vault.list_aliases.return_value = ["vault", "env"]
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            assert manager.vault_names() == ["vault", "env"]
            assert manager.all_names() == ["env", "vault"]

    def test_vault_engine_is_cached_and_case_insensitive(self):
        vault = Mock()
        vault.get.return_value = {"jdbc_url": "sqlite:///:memory:"}
        vault.exists.return_value = True
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            first = manager.get_engine_by_alias("PROD")
            assert manager.engine("prod") is first
            assert manager.is_vault_alias("PROD") is True

    def test_vault_engine_applies_stored_credentials(self):
        """Vault username/password must reach the engine URL (DPY-4001 regression)."""
        vault = Mock()
        vault.get.return_value = {
            "jdbc_url": "oracle+oracledb://host:1521/?service_name=waste",
            "username": "app",
            "password": "secret",
        }
        vault.exists.return_value = True
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.get_engine_by_alias("waste-local")
            assert engine.url.username == "app"
            assert engine.url.password == "secret"

    def test_vault_credentials_override_url_embedded(self):
        """Separately stored credentials take precedence over URL-embedded ones."""
        vault = Mock()
        vault.get.return_value = {
            "jdbc_url": "postgresql://stale:old@host:5432/db",
            "username": "fresh",
            "password": "new",
        }
        vault.exists.return_value = True
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.get_engine_by_alias("prod")
            assert engine.url.username == "fresh"
            assert engine.url.password == "new"
            assert engine.url.host == "host"
            assert engine.url.database == "db"

    def test_vault_username_without_password_is_applied(self):
        vault = Mock()
        vault.get.return_value = {
            "jdbc_url": "postgresql://host:5432/db",
            "username": "user",
        }
        vault.exists.return_value = True
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.get_engine_by_alias("partial")
            assert engine.url.username == "user"
            assert engine.url.password is None

    def test_vault_engine_without_credentials_stays_credential_less(self):
        vault = Mock()
        vault.get.return_value = {"jdbc_url": "sqlite:///:memory:"}
        vault.exists.return_value = True
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.get_engine_by_alias("anon")
            assert engine.url.username is None
            assert engine.url.password is None

    def test_vault_engine_errors(self):
        vault = Mock()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            vault.get.return_value = None
            with pytest.raises(ValueError, match="not found"):
                manager.get_engine_by_alias("missing")
            vault.get.return_value = {"username": "user"}
            with pytest.raises(ValueError, match="no connection URL"):
                manager.get_engine_by_alias("broken")


class TestNormalizeOracleUrl:
    """Oracle URL paths must resolve as service names, not SIDs (DPY-6003)."""

    @pytest.mark.parametrize("drivername", ["oracle+oracledb", "oracle"])
    def test_promotes_bare_path_to_service_name(self, drivername):
        url = _normalize_oracle_url(make_url(f"{drivername}://host:1521/waste"))
        assert url.query["service_name"] == "waste"
        assert not url.database

    def test_explicit_service_name_is_untouched(self):
        url = _normalize_oracle_url(
            make_url("oracle+oracledb://host:1521/?service_name=waste")
        )
        assert url.query["service_name"] == "waste"
        assert not url.database

    def test_explicit_sid_respected_over_path(self):
        url = _normalize_oracle_url(
            make_url("oracle+oracledb://host:1521/waste?sid=waste")
        )
        assert url.database == "waste"
        assert "service_name" not in url.query

    def test_non_oracle_urls_pass_through(self):
        url = _normalize_oracle_url(make_url("postgresql://user:pass@host:5432/mydb"))
        assert url.database == "mydb"
        assert "service_name" not in url.query


class TestOracleServiceNameRegression:
    """Engines built from stored URLs must use service-name semantics."""

    def test_vault_engine_promotes_path_to_service_name(self):
        vault = Mock()
        vault.get.return_value = {
            "jdbc_url": "oracle+oracledb://10.0.0.59:1521/WASTE",
            "username": "app",
            "password": "secret",
        }
        vault.exists.return_value = True
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.get_engine_by_alias("waste-local")
            assert engine.url.query["service_name"] == "WASTE"
            assert not engine.url.database
            assert engine.url.username == "app"

    def test_env_engine_promotes_path_to_service_name(self, monkeypatch):
        monkeypatch.setenv(
            "DB_WAREHOUSE", "oracle+oracledb://user:pass@host:1521/warehouse"
        )
        manager = ConnectionManager()
        engine = manager.engine("warehouse")
        assert engine.url.query["service_name"] == "warehouse"
        assert not engine.url.database
