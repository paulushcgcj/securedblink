"""Tests for dbbridge.server module."""

import os
import time
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine, text

import dbbridge.server as srv
from dbbridge.connections import ConnectionManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestFmtTable:
    def test_basic(self):
        result = srv._fmt_table(["id", "name"], [(1, "Alice"), (2, "Bob")])
        assert "| id | name |" in result
        assert "| 1 | Alice |" in result
        assert "| 2 | Bob |" in result

    def test_null_values(self):
        result = srv._fmt_table(["col"], [(None,)])
        assert "NULL" in result

    def test_pipe_escaped(self):
        result = srv._fmt_table(["col"], [("a|b",)])
        assert "a\\|b" in result

    def test_newlines_escaped(self):
        result = srv._fmt_table(["col"], [("line1\nline2",)])
        assert "line1 line2" in result


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------


class TestPurgeTokens:
    def test_removes_expired(self, clean_tokens):
        clean_tokens["old"] = srv._PendingToken("c", "sql", time.time() - 10)
        srv._purge_tokens()
        assert "old" not in clean_tokens

    def test_keeps_valid(self, clean_tokens):
        clean_tokens["good"] = srv._PendingToken("c", "sql", time.time() + 300)
        srv._purge_tokens()
        assert "good" in clean_tokens


# ---------------------------------------------------------------------------
# list_connections
# ---------------------------------------------------------------------------


class TestListConnections:
    def test_empty(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("DB_"):
                monkeypatch.delenv(key)
        result = srv.list_connections()
        assert "No connections configured" in result

    def test_with_connections(self, monkeypatch):
        monkeypatch.setenv("DB_ALPHA", "sqlite:///:memory:")
        monkeypatch.setenv("DB_BETA", "sqlite:///:memory:")
        # Reset the global connection manager
        srv._db = ConnectionManager()
        result = srv.list_connections()
        assert "alpha" in result
        assert "beta" in result


# ---------------------------------------------------------------------------
# list_tables
# ---------------------------------------------------------------------------


class TestListTables:
    def test_with_tables(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.list_tables("test")
        assert "users" in result
        assert "orders" in result

    def test_with_views(self, monkeypatch):
        engine = create_engine("sqlite:///:memory:")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER)"))
            conn.execute(text("CREATE VIEW v AS SELECT id FROM t"))
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=engine):
            result = srv.list_tables("test")
        assert "Views" in result
        assert "v" in result

    def test_empty_db(self, monkeypatch):
        engine = create_engine("sqlite:///:memory:")
        monkeypatch.setenv("DB_EMPTY", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=engine):
            result = srv.list_tables("empty")
        assert "No tables or views found" in result


# ---------------------------------------------------------------------------
# describe_table
# ---------------------------------------------------------------------------


class TestDescribeTable:
    def test_columns(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.describe_table("test", "users")
        assert "id" in result
        assert "name" in result

    def test_primary_key(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.describe_table("test", "users")
        assert "Primary Key" in result

    def test_foreign_keys(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.describe_table("test", "orders")
        assert "Foreign Keys" in result
        assert "user_id" in result

    def test_indexes(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.describe_table("test", "orders")
        assert "Indexes" in result


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


class TestQuery:
    def test_safe_returns_rows(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.query("test", "SELECT * FROM users")
        assert "| id | name |" in result
        assert "row(s) returned" in result

    def test_zero_rows(self, monkeypatch):
        engine = create_engine("sqlite:///:memory:")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE empty_t (id INTEGER)"))
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=engine):
            result = srv.query("test", "SELECT * FROM empty_t")
        assert "0 rows" in result

    def test_blocked_mutation(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.query(
                "test", "INSERT INTO users (id, name) VALUES (3, 'Charlie')"
            )
        assert "blocked" in result.lower()
        assert "mutation" in result.lower()

    def test_blocked_destructive(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.query("test", "DROP TABLE users")
        assert "blocked" in result.lower()
        assert "destructive" in result.lower()

    def test_truncated(self, monkeypatch):
        engine = create_engine("sqlite:///:memory:")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE big (id INTEGER)"))
            for i in range(501):
                conn.execute(text(f"INSERT INTO big VALUES ({i})"))
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        monkeypatch.setenv("DB_MAX_ROWS", "500")
        srv._db = ConnectionManager()
        srv._MAX_ROWS = 500
        with patch.object(srv._db, "engine", return_value=engine):
            result = srv.query("test", "SELECT * FROM big")
        assert "capped" in result.lower()


# ---------------------------------------------------------------------------
# preview_mutation
# ---------------------------------------------------------------------------


class TestPreviewMutation:
    def test_safe_rejected(self, monkeypatch, sqlite_engine):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.preview_mutation("test", "SELECT 1")
        assert "safe" in result.lower()

    def test_mutation(self, monkeypatch, sqlite_engine, clean_tokens):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.preview_mutation(
                "test", "INSERT INTO users VALUES (3, 'C', 'c@t.com', 1)"
            )
        assert "DATA MODIFICATION" in result
        assert "token" in result.lower()

    def test_destructive(self, monkeypatch, sqlite_engine, clean_tokens):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.preview_mutation("test", "DROP TABLE users")
        assert "DESTRUCTIVE" in result

    def test_unknown_classified(self, monkeypatch, sqlite_engine, clean_tokens):
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.preview_mutation("test", "BANANA INTO users VALUES (1)")
        assert "UNCLASSIFIED" in result


# ---------------------------------------------------------------------------
# execute_mutation
# ---------------------------------------------------------------------------


class TestExecuteMutation:
    def _make_token(self, connection, sql, ttl=300):
        import secrets

        token = secrets.token_urlsafe(16)
        srv._tokens[token] = srv._PendingToken(
            connection=connection.lower(),
            sql=sql.strip(),
            expires_at=time.time() + ttl,
        )
        return token

    def test_valid_token(self, monkeypatch, sqlite_engine, clean_tokens):
        sql = "INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'c@test.com')"
        token = self._make_token("test", sql)
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.execute_mutation("test", sql, token)
        assert "Executed successfully" in result
        assert token not in srv._tokens

    def test_invalid_token(self, clean_tokens):
        result = srv.execute_mutation("test", "SELECT 1", "bad-token")
        assert "Invalid" in result

    def test_expired_token(self, monkeypatch, sqlite_engine, clean_tokens):
        sql = "INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'c@test.com')"
        # Directly insert a token with an expiry far in the past
        clean_tokens["expired_tok"] = srv._PendingToken(
            connection="test",
            sql=sql.strip(),
            expires_at=time.time() - 10,
        )
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.execute_mutation("test", sql, "expired_tok")
        # _purge_tokens deletes expired tokens before the expiry check,
        # so the token is invalid rather than expired
        assert "invalid" in result.lower()

    def test_expired_token_reaches_expiry_check(
        self, monkeypatch, sqlite_engine, clean_tokens
    ):
        sql = "INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'c@test.com')"
        # Insert a token that will expire soon
        clean_tokens["tok"] = srv._PendingToken(
            connection="test",
            sql=sql.strip(),
            expires_at=time.time() - 1,
        )
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        # Mock _purge_tokens to be a no-op so the expired token survives to the expiry check
        with patch.object(srv, "_purge_tokens"):
            with patch.object(srv._db, "engine", return_value=sqlite_engine):
                result = srv.execute_mutation("test", sql, "tok")
        assert "expired" in result.lower()

    def test_wrong_connection(self, monkeypatch, sqlite_engine, clean_tokens):
        sql = "INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'c@test.com')"
        token = self._make_token("other", sql)
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.execute_mutation("test", sql, token)
        assert "token was issued for" in result.lower()

    def test_wrong_sql(self, monkeypatch, sqlite_engine, clean_tokens):
        sql = "INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'c@test.com')"
        token = self._make_token("test", sql)
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        with patch.object(srv._db, "engine", return_value=sqlite_engine):
            result = srv.execute_mutation("test", "DELETE FROM users WHERE id=1", token)
        assert "does not match" in result.lower()

    def test_executed_without_rowcount(self, monkeypatch, sqlite_engine, clean_tokens):
        sql = "INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'c@test.com')"
        token = self._make_token("test", sql)
        monkeypatch.setenv("DB_TEST", "sqlite:///:memory:")
        srv._db = ConnectionManager()
        mock_result = MagicMock()
        mock_result.rowcount = -1
        mock_conn = MagicMock()
        mock_conn.execute.return_value = mock_result
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_engine = MagicMock()
        mock_engine.begin.return_value = mock_conn
        with patch.object(srv._db, "engine", return_value=mock_engine):
            result = srv.execute_mutation("test", sql, token)
        assert result == "Executed successfully."


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_calls_run(self):
        with patch.object(srv.mcp, "run") as mock_run:
            srv.main()
            mock_run.assert_called_once()
