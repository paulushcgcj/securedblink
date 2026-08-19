"""SQL query classifier. Determines if a statement is safe, mutation, or destructive."""

import re
from typing import Literal

SAFE = {"SELECT", "EXPLAIN", "SHOW", "DESCRIBE", "DESC", "PRAGMA", "WITH"}
MUTATION = {"INSERT", "UPDATE", "DELETE", "UPSERT", "MERGE", "REPLACE"}
DESTRUCTIVE = {
    "DROP",
    "TRUNCATE",
    "ALTER",
    "CREATE",
    "GRANT",
    "REVOKE",
    "RENAME",
    "COMMENT",
}

QueryKind = Literal["safe", "mutation", "destructive", "unknown"]


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return sql.strip()


def _first_keyword(sql: str) -> str:
    match = re.match(r"\s*(\w+)", _strip_comments(sql))
    return match.group(1).upper() if match else ""


def classify(sql: str) -> QueryKind:
    """Classify a SQL statement as safe, mutation, destructive, or unknown."""
    kw = _first_keyword(sql)

    if kw in SAFE:
        # WITH can contain data-modifying CTEs (e.g. Postgres: WITH del AS (DELETE...) SELECT...)
        if kw == "WITH":
            upper = _strip_comments(sql).upper()
            for dangerous in MUTATION | DESTRUCTIVE:
                if re.search(rf"\b{dangerous}\b", upper):
                    return "mutation"
        return "safe"

    if kw in DESTRUCTIVE:
        return "destructive"

    if kw in MUTATION:
        return "mutation"

    return "unknown"
