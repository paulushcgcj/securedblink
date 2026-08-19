"""Shared fixtures for db-mcp tests."""

import pytest
from sqlalchemy import create_engine, text


@pytest.fixture
def sqlite_engine():
    """Create an in-memory SQLite engine with sample schema and data."""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT,
                    active INTEGER DEFAULT 1
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    total REAL DEFAULT 0.0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX idx_orders_user ON orders(user_id)
                """
            )
        )
        conn.execute(
            text(
                "INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'alice@test.com')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO users (id, name, email) VALUES (2, 'Bob', 'bob@test.com')"
            )
        )
        conn.execute(
            text("INSERT INTO orders (id, user_id, total) VALUES (1, 1, 99.99)")
        )
    return engine


@pytest.fixture
def sample_db_env(monkeypatch):
    """Set DB_TEST env var pointing to an in-memory SQLite database."""
    monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")


@pytest.fixture
def clean_tokens():
    """Clear the server module's _tokens dict before each test."""
    import db_mcp.server as srv

    srv._tokens.clear()
    yield srv._tokens
    srv._tokens.clear()
