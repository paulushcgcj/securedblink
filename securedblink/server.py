"""securedblink: MCP server for multi-database access with LLM permission gating.

Tools:
  list_connections         list configured DB connections
  list_tables              list tables/views in a connection
  describe_table           describe columns, PKs, FKs, indexes
  query                    execute read-only SQL (SELECT etc.)
  preview_mutation         preview a write/destructive query, get confirmation token
  execute_mutation         execute after user confirms (requires token)
  vault_register_connection register a connection with credentials in the vault
  vault_register_from_path register a connection from a config file in the vault
  vault_list               list all registered vault aliases
  vault_revoke             remove a connection from the vault
"""

import os
import secrets
import time
from typing import Any, NamedTuple

from mcp.server.fastmcp import FastMCP
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text

from securedblink.classifier import classify
from securedblink.connections import ConnectionManager
from securedblink.log import get_logger
from securedblink.vault import (
    get_resolver,
    get_vault_store,
    parse_config_file,
    redact_exception,
    validate_and_get_absolute_path,
)
from securedblink.vault.store import (
    InsecureKeyringError,
    VaultStoreError,
    verify_secure_backend,
)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "securedblink",
    instructions="""
You have access to one or more databases via securedblink.

## Rules you MUST follow

1. **Read queries** (`SELECT`, `EXPLAIN`, `SHOW`, `DESCRIBE`): use `query` directly.

2. **Write/destructive queries** (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, etc.):
   - Call `preview_mutation` first.
   - **Show the full preview to the user.**
   - **Explicitly ask**: "Do you confirm running this [type] query on `<connection>`?"
   - Only call `execute_mutation` after the user says **yes**.
   - Never pass `confirmed=true` or call `execute_mutation` without explicit user approval.

3. Use `list_connections` when the user doesn't specify a connection.
4. Use `list_tables` + `describe_table` to explore schema before writing queries.
""",
)

log = get_logger("securedblink.server")

_db = ConnectionManager()
_MAX_ROWS = int(os.getenv("DB_MAX_ROWS", "500"))
_vault = get_vault_store()
_resolver = get_resolver()

# Verify secure keyring backend on startup (only when vault is used)
try:
    verify_secure_backend()
except InsecureKeyringError as exc:
    # Don't fail startup - vault tools will fail when called
    log.warning(
        "vault_unavailable",
        reason="no secure keyring backend detected",
        detail=str(exc),
    )


class _PendingToken(NamedTuple):
    connection: str
    sql: str
    expires_at: float


_TOKEN_TTL = 300  # seconds
_tokens: dict[str, _PendingToken] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt_table(cols: list[str], rows: list[tuple[Any, ...]]) -> str:
    """Format rows as a Markdown table."""

    def cell(v: Any) -> str:
        return "NULL" if v is None else str(v).replace("|", "\\|").replace("\n", " ")

    header = "| " + " | ".join(cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    body = ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join([header, sep] + body)


def _purge_tokens() -> None:
    now = time.time()
    expired = [k for k, v in _tokens.items() if v.expires_at < now]
    for k in expired:
        del _tokens[k]


# ---------------------------------------------------------------------------
# Vault Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def vault_register_connection(
    alias: str,
    jdbc_url: str,
    username: str | None = None,
    password: str | None = None,
    driver: str | None = None,
    overwrite: bool = False,
) -> dict[str, str]:
    """Register a database connection in the credential vault.

    Stores the JDBC URL and credentials securely using the system's
    credential manager. The alias can then be used with other tools
    instead of passing the connection URL directly.

    Args:
        alias: Unique name for this connection (e.g., 'prod', 'local')
        jdbc_url: JDBC connection URL (e.g., 'postgresql://user:pass@host:5432/db')
        username: Database username (optional if embedded in URL)
        password: Database password (optional if embedded in URL)
        driver: JDBC driver class (optional)
        overwrite: If True, replace existing alias (default: False)

    Returns:
        {"alias": alias, "status": "registered"}

    Note:
        Credentials are NEVER returned in responses, logs, or error messages.
        Use vault_list to see registered aliases.
    """
    try:
        _vault.set(
            alias=alias,
            jdbc_url=jdbc_url,
            username=username,
            password=password,
            driver=driver,
            source="direct",
            overwrite=overwrite,
        )
        return {"alias": alias, "status": "registered"}
    except (VaultStoreError, InsecureKeyringError, ValueError, OSError) as e:
        # Log only the error class + alias — never str(e), which may embed
        # credentials from the JDBC URL.
        log.warning("vault_register_failed", alias=alias, error=type(e).__name__)
        return {
            "error": str(e),
            "alias": alias,
            "status": "failed",
        }


@mcp.tool()
def vault_register_from_path(
    alias: str,
    file_path: str,
    overwrite: bool = False,
) -> dict[str, str]:
    """Register a database connection from a configuration file.

    Reads and parses a configuration file (.env, .properties, .yml, .yaml)
    to extract connection details, then stores them securely in the vault.

    Args:
        alias: Unique name for this connection
        file_path: Path to configuration file
        overwrite: If True, replace existing alias (default: False)

    Returns:
        {"alias": alias, "status": "registered"}

    Raises:
        ValueError: If the file path is outside the allow-listed roots
                   (configure with SECUREDBLINK_ALLOWED_ROOTS environment variable)

    Supported formats:
        - .env: DB_URL=jdbc:... , DB_USERNAME=..., DB_PASSWORD=...
        - .properties: jdbc.url=jdbc:..., jdbc.username=..., jdbc.password=...
        - .yml/.yaml: spring.datasource.url: jdbc:..., spring.datasource.username: ...

    Note:
        The file must be within a directory listed in SECUREDBLINK_ALLOWED_ROOTS.
        Set SECUREDBLINK_ALLOWED_ROOTS=/path1:/path2 to configure allowed roots.
        Credentials are NEVER returned in responses, logs, or error messages.
    """
    try:
        # Validate path is within allow-listed roots
        absolute_path = validate_and_get_absolute_path(file_path)

        # Parse the config file
        config = parse_config_file(absolute_path)

        if not config.is_valid():
            return {
                "error": f"Could not extract valid connection URL from {file_path}",
                "alias": alias,
                "status": "failed",
            }

        # Store in vault
        _vault.set(
            alias=alias,
            jdbc_url=config.jdbc_url or "",
            username=config.username,
            password=config.password,
            driver=config.driver,
            source="path",
            overwrite=overwrite,
        )

        return {"alias": alias, "status": "registered"}
    except ValueError as e:
        # Path validation errors are expected and should be returned
        log.warning("vault_register_from_path_failed", alias=alias, error="path")
        return {
            "error": str(e),
            "alias": alias,
            "status": "failed",
        }
    except (VaultStoreError, InsecureKeyringError, OSError) as e:
        # For other errors, redact any potential credentials
        safe_error = redact_exception(e) if isinstance(e, Exception) else str(e)
        log.warning(
            "vault_register_from_path_failed",
            alias=alias,
            error=type(e).__name__,
        )
        return {
            "error": safe_error,
            "alias": alias,
            "status": "failed",
        }


@mcp.tool()
def vault_list() -> dict[str, Any]:
    """List all registered credential vault aliases.

    Returns metadata for all connections stored in the vault.
    This includes alias names, creation timestamps, and source type.

    Returns:
        {"aliases": [{"name": alias, "created_at": timestamp, "source": source}, ...]}

    Note:
        This only lists metadata. Credentials are NEVER returned.
        Use vault_revoke to remove a connection from the vault.
    """
    metadata = _vault.list_all_metadata()
    aliases = []
    for alias, meta in sorted(metadata.items()):
        aliases.append(
            {
                "name": alias,
                "created_at": meta.get("created_at", "unknown"),
                "source": meta.get("source", "unknown"),
            }
        )
    return {"aliases": aliases}


@mcp.tool()
def vault_revoke(alias: str) -> dict[str, Any]:
    """Remove a connection from the credential vault.

    Deletes the stored credentials and removes the alias from the index.
    This is idempotent - it succeeds even if the alias doesn't exist.

    Args:
        alias: The alias to remove

    Returns:
        {"alias": alias, "status": "revoked", "existed": bool}
    """
    existed = _vault.exists(alias)
    _vault.delete(alias)
    return {
        "alias": alias,
        "status": "revoked",
        "existed": existed,
    }


# ---------------------------------------------------------------------------
# Connection Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_connections() -> str:
    """List all database connections (env vars + vault aliases)."""
    env_names = _db.names()
    vault_names = _db.vault_names()

    if not env_names and not vault_names:
        return (
            "No connections configured.\n\n"
            "Option 1: Set DB_<NAME>=<connection_url> environment variables:\n"
            "  DB_PROD=postgresql://user:pass@host:5432/mydb\n"
            "  DB_LOCAL=sqlite:///./app.db\n\n"
            "Option 2: Register via vault:\n"
            "  Use vault_register_connection to store credentials securely\n"
            "  Use vault_register_from_path to load from a config file"
        )

    lines = []

    if env_names:
        lines.append("Environment variable connections:")
        lines += [f"  - {n} (env)" for n in env_names]

    if vault_names:
        if lines:
            lines.append("")
        lines.append("Vault connections:")
        lines += [f"  - {n} (vault)" for n in vault_names]

    return "\n".join(lines)


@mcp.tool()
def list_tables(connection_name: str) -> str:
    """List all tables and views in the specified database connection."""
    engine = _db.engine(connection_name)
    insp = sa_inspect(engine)
    tables = sorted(insp.get_table_names())
    views = sorted(insp.get_view_names())

    lines: list[str] = [f"**{connection_name}**\n"]
    if tables:
        lines += ["**Tables:**"] + [f"  - {t}" for t in tables]
    if views:
        lines += ["\n**Views:**"] + [f"  - {v}" for v in views]
    if not tables and not views:
        lines.append("No tables or views found.")
    return "\n".join(lines)


@mcp.tool()
def describe_table(connection_name: str, table_name: str) -> str:
    """Describe columns, primary key, foreign keys, and indexes for a table."""
    engine = _db.engine(connection_name)
    insp = sa_inspect(engine)

    cols = insp.get_columns(table_name)
    pk = insp.get_pk_constraint(table_name)
    fks = insp.get_foreign_keys(table_name)
    idxs = insp.get_indexes(table_name)

    lines = [f"### `{connection_name}`.`{table_name}`\n", "**Columns:**"]
    for c in cols:
        nullable = "NULL" if c.get("nullable", True) else "NOT NULL"
        default = f" DEFAULT {c['default']}" if c.get("default") else ""
        lines.append(f"  - `{c['name']}` {c['type']} {nullable}{default}")

    if pk and pk.get("constrained_columns"):
        lines.append(f"\n**Primary Key:** {', '.join(pk['constrained_columns'])}")

    if fks:
        lines.append("\n**Foreign Keys:**")
        for fk in fks:
            lines.append(
                f"  - `{', '.join(fk['constrained_columns'])}` -> "
                f"`{fk['referred_table']}({', '.join(fk['referred_columns'])})`"
            )

    if idxs:
        lines.append("\n**Indexes:**")
        for idx in idxs:
            unique = " UNIQUE" if idx.get("unique") else ""
            lines.append(f"  - `{idx['name']}`{unique}: {idx['column_names']}")

    return "\n".join(lines)


@mcp.tool()
def query(connection_name: str, sql: str) -> str:
    """Execute a read-only SQL query on the specified connection."""
    kind = classify(sql)
    if kind != "safe":
        return (
            f"Query classified as **{kind}** -- blocked in `query`.\n\n"
            "Write operations require user confirmation:\n"
            "1. Call `preview_mutation` to get a preview + token\n"
            "2. Show preview to user, ask for confirmation\n"
            "3. Call `execute_mutation` only after user says yes"
        )

    engine = _db.engine(connection_name)
    with engine.connect() as conn:
        result = conn.execute(text(sql))
        rows = result.fetchmany(_MAX_ROWS + 1)
        cols = list(result.keys())

    truncated = len(rows) > _MAX_ROWS
    rows = rows[:_MAX_ROWS]

    if not rows:
        return "Query returned 0 rows."

    out = _fmt_table(cols, [tuple(row) for row in rows])
    if truncated:
        out += f"\n\nResults capped at {_MAX_ROWS} rows. Add `LIMIT` to your query."
    else:
        out += f"\n\n{len(rows)} row(s) returned."
    return out


@mcp.tool()
def preview_mutation(connection_name: str, sql: str) -> str:
    """Preview a write or destructive SQL statement and get a one-time confirmation token."""
    kind = classify(sql)
    if kind == "safe":
        return "This query is safe (read-only). Use `query` instead."

    _purge_tokens()
    token = secrets.token_urlsafe(16)
    _tokens[token] = _PendingToken(
        connection=connection_name.lower(),
        sql=sql.strip(),
        expires_at=time.time() + _TOKEN_TTL,
    )

    badge = {
        "mutation": "DATA MODIFICATION",
        "destructive": "DESTRUCTIVE -- POTENTIAL DATA LOSS",
        "unknown": "UNCLASSIFIED QUERY (treated as mutation)",
    }.get(kind, "UNKNOWN")

    return f"""**{badge}**

**Connection:** `{connection_name}`
**Query type:** {kind.upper()}

```sql
{sql.strip()}
```

**Confirmation token:** `{token}`
*(expires in 5 minutes, single-use)*

---
**YOU MUST show the above to the user and ask:**
> "Do you confirm running this {kind} query on `{connection_name}`?"

Only call `execute_mutation` after the user explicitly answers **yes**."""


@mcp.tool()
def execute_mutation(connection_name: str, sql: str, confirmation_token: str) -> str:
    """Execute a confirmed write or destructive SQL statement."""
    _purge_tokens()

    if confirmation_token not in _tokens:
        return (
            "Invalid or expired confirmation token.\n"
            "Call `preview_mutation` again and ask the user for confirmation."
        )

    pending = _tokens[confirmation_token]

    if time.time() > pending.expires_at:
        del _tokens[confirmation_token]
        return "Token expired. Call `preview_mutation` again."

    if pending.connection != connection_name.lower():
        return (
            f"Token was issued for connection `{pending.connection}`, "
            f"not `{connection_name}`. Call `preview_mutation` again."
        )

    if pending.sql != sql.strip():
        return (
            "SQL does not match what was previewed.\n"
            "Call `preview_mutation` again with the exact SQL you intend to run."
        )

    del _tokens[confirmation_token]

    engine = _db.engine(connection_name)
    with engine.begin() as conn:
        result = conn.execute(text(sql))
        affected = result.rowcount

    if affected >= 0:
        return f"Executed successfully. {affected} row(s) affected."
    return "Executed successfully."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    mcp.run()


def _notify_update() -> None:
    """Print a non-blocking update notice when a newer release is available."""
    from securedblink.update import check_for_update

    status = check_for_update()
    if status.update_available and status.latest_version:
        log.info(
            f"Update available: {status.installed_version} → {status.latest_version}. "
            "Run `securedblink update` to upgrade."
        )


def cli_main(argv: list[str] | None = None) -> int:
    """Run the vault-management command-line interface.

    Returns the process exit code. With no subcommand, starts the MCP
    server (blocking); the CLI subcommands ``register``,
    ``register-from-path`` and ``list`` manage the credential vault.

    All output goes to **stderr** via structlog; stdout is reserved for
    the MCP stdio protocol.
    """
    import argparse

    from securedblink.update import installed_version

    parser = argparse.ArgumentParser(
        prog="securedblink",
        description="MCP server for multi-database access\n\n"
        f"Version: {installed_version()}",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {installed_version()}",
    )
    subparsers = parser.add_subparsers(dest="command")

    # Register subcommand
    register_parser = subparsers.add_parser(
        "register", help="Register a connection in the vault"
    )
    register_parser.add_argument("--alias", required=True, help="Unique alias name")
    register_parser.add_argument(
        "--jdbc-url", required=True, help="JDBC connection URL"
    )
    register_parser.add_argument(
        "--username", required=False, default=None, help="Database username"
    )
    register_parser.add_argument(
        "--password", required=False, default=None, help="Database password"
    )
    register_parser.add_argument(
        "--driver", required=False, default=None, help="JDBC driver class"
    )
    register_parser.add_argument(
        "--overwrite", action="store_true", help="Replace existing alias"
    )

    # Register from path subcommand
    register_path_parser = subparsers.add_parser(
        "register-from-path", help="Register a connection from a config file"
    )
    register_path_parser.add_argument(
        "--alias", required=True, help="Unique alias name"
    )
    register_path_parser.add_argument(
        "--file-path",
        required=True,
        help="Path to configuration file (.env, .properties, .yml, .yaml)",
    )
    register_path_parser.add_argument(
        "--overwrite", action="store_true", help="Replace existing alias"
    )

    # List subcommand
    subparsers.add_parser("list", help="List all registered vault aliases")

    # Update subcommand
    update_parser = subparsers.add_parser(
        "update", help="Check for updates and optionally upgrade"
    )
    update_parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the update with uv after checking",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        # No subcommand: start the server
        main()
        return 0

    # Notify about updates for normal commands (but not for help, version, or update)
    if args.command not in ("update",) and "--help" not in (argv or []):
        _notify_update()

    from securedblink.update import (
        apply_uv_upgrade,
        check_for_update,
        installation_guidance,
    )
    from securedblink.vault.store import VaultStoreError, get_vault_store

    try:
        if args.command == "register":
            vault = get_vault_store()
            vault.set(
                alias=args.alias,
                jdbc_url=args.jdbc_url,
                username=args.username,
                password=args.password,
                driver=args.driver,
                source="direct",
                overwrite=args.overwrite,
            )
            log.info(f"Alias {args.alias!r} registered in vault.")
        elif args.command == "register-from-path":
            from securedblink.vault.parsers import parse_config_file
            from securedblink.vault.pathguard import validate_and_get_absolute_path

            absolute_path = validate_and_get_absolute_path(args.file_path)
            config = parse_config_file(absolute_path)

            if not config.is_valid():
                log.error(
                    f"Error: could not extract a valid connection URL "
                    f"from {args.file_path}"
                )
                return 1

            vault = get_vault_store()
            vault.set(
                alias=args.alias,
                jdbc_url=config.jdbc_url or "",
                username=config.username,
                password=config.password,
                driver=config.driver,
                source="path",
                overwrite=args.overwrite,
            )
            log.info(f"Alias {args.alias!r} registered in vault from {args.file_path}.")
        elif args.command == "list":
            vault = get_vault_store()
            aliases = vault.list_aliases()
            if not aliases:
                log.info("No vault aliases registered.")
            else:
                for a in sorted(aliases):
                    meta = vault.get_metadata(a) or {}
                    log.info(
                        f"- {a} (source: {meta.get('source', 'unknown')}, "
                        f"created: {meta.get('created_at', 'unknown')})"
                    )
    except (VaultStoreError, ValueError, FileNotFoundError) as exc:
        log.error(f"Error: {exc}")
        return 1

    # Handle update command separately
    if args.command == "update":
        status = check_for_update()
        if status.error:
            log.error(f"Update check skipped: {status.error}")
            return 1
        elif status.skipped:
            log.info("Update checks are disabled by SECUREDBLINK_NO_UPDATE_CHECK=1.")
            return 0
        elif not status.update_available:
            log.info(f"securedblink is up to date ({status.installed_version}).")
            return 0
        elif args.apply:
            try:
                result = apply_uv_upgrade()
                message = (
                    result.stdout.strip()
                    or f"Updated securedblink from {status.installed_version} to {status.latest_version}."
                )
                log.info(message)
            except RuntimeError as exc:
                log.error(f"Error: {exc}")
                return 1
        else:
            log.info(
                f"Update available: {status.installed_version} → {status.latest_version}.\n"
                f"Run `securedblink update --apply` to update explicitly.\n"
                f"{installation_guidance()}"
            )
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(cli_main())
