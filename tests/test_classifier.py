"""Tests for db_mcp.classifier module."""

import pytest

from db_mcp.classifier import _first_keyword, _strip_comments, classify

# ---------------------------------------------------------------------------
# _strip_comments
# ---------------------------------------------------------------------------


class TestStripComments:
    def test_single_line_comment(self):
        assert _strip_comments("SELECT 1 -- comment") == "SELECT 1"

    def test_multi_line_comment(self):
        assert _strip_comments("SELECT /* block\ncomment */ 1") == "SELECT  1"

    def test_mixed_comments(self):
        sql = "SELECT /* block */ 1 -- inline"
        assert _strip_comments(sql) == "SELECT  1"

    def test_no_comments(self):
        assert _strip_comments("SELECT 1") == "SELECT 1"

    def test_only_comment(self):
        assert _strip_comments("-- nothing here") == ""

    def test_leading_whitespace(self):
        assert _strip_comments("  SELECT 1") == "SELECT 1"


# ---------------------------------------------------------------------------
# _first_keyword
# ---------------------------------------------------------------------------


class TestFirstKeyword:
    def test_leading_whitespace(self):
        assert _first_keyword("  \t\nSELECT 1") == "SELECT"

    def test_empty_string(self):
        assert _first_keyword("") == ""

    def test_whitespace_only(self):
        assert _first_keyword("   ") == ""

    def test_simple_keyword(self):
        assert _first_keyword("INSERT INTO t VALUES (1)") == "INSERT"


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


class TestClassify:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1",
            "EXPLAIN ANALYZE SELECT 1",
            "SHOW TABLES",
            "DESCRIBE users",
            "DESC users",
            "PRAGMA table_info(users)",
        ],
    )
    def test_safe_keywords(self, sql):
        assert classify(sql) == "safe"

    def test_with_cte_safe(self):
        assert classify("WITH cte AS (SELECT 1) SELECT * FROM cte") == "safe"

    def test_with_cte_mutation(self):
        assert (
            classify(
                "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted"
            )
            == "mutation"
        )

    def test_with_cte_destructive(self):
        assert classify("WITH gone AS (DROP TABLE tmp) SELECT 1") == "mutation"

    @pytest.mark.parametrize(
        "sql",
        [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x=1",
            "DELETE FROM t WHERE id=1",
            "UPSERT INTO t VALUES (1)",
            "MERGE INTO t USING s ON t.id=s.id",
            "REPLACE INTO t VALUES (1)",
        ],
    )
    def test_mutation_keywords(self, sql):
        assert classify(sql) == "mutation"

    @pytest.mark.parametrize(
        "sql",
        [
            "DROP TABLE t",
            "TRUNCATE TABLE t",
            "ALTER TABLE t ADD x INT",
            "CREATE TABLE t (id INT)",
            "GRANT SELECT ON t TO user",
            "REVOKE SELECT ON t FROM user",
            "RENAME TABLE t TO s",
            "COMMENT ON TABLE t IS 'test'",
        ],
    )
    def test_destructive_keywords(self, sql):
        assert classify(sql) == "destructive"

    def test_unknown_keyword(self):
        assert classify("BANANA 1") == "unknown"

    def test_with_comments_classified_correctly(self):
        sql = "-- bad stuff\nDROP TABLE t"
        assert classify(sql) == "destructive"
