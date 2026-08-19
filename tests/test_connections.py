"""Tests for securedblink.connections module."""

import os

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
