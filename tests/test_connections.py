"""Tests for securedblink.connections module."""

import os
from unittest.mock import Mock, patch

import pytest

from securedblink.connections import ConnectionManager, _load_urls


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
