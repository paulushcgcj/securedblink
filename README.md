# securedblink

> An MCP database gateway for LLM agents: read freely, preview writes, approve explicitly.

[![PyPI version](https://img.shields.io/pypi/v/securedblink.svg)](https://pypi.org/project/securedblink/)
[![Python versions](https://img.shields.io/pypi/pyversions/securedblink.svg)](https://pypi.org/project/securedblink/)
[![CI](https://github.com/paulushcgcj/securedblink/actions/workflows/ci.yml/badge.svg)](https://github.com/paulushcgcj/securedblink/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/paulushcgcj/securedblink.svg)](LICENSE)

`securedblink` gives an LLM a controlled way to inspect and query databases
through the Model Context Protocol (MCP). Read-only work runs immediately;
mutating SQL must pass through a preview and an explicit approval before it can
execute.

```text
                         read path
  agent ──────────────── SELECT / EXPLAIN ──────────────── database
    │
    │ write path
    └── INSERT / UPDATE / DELETE ── preview ── approval ── execute ── database
                                      │
                                      └── exact SQL + connection bound to token
```

## Start here

### 1. Install the command

For normal use, install the `securedblink` command. It is the primary entry
point for terminal use and MCP clients.

**macOS / Linux** — install the latest standalone release binary:

```bash
curl -fsSL https://raw.githubusercontent.com/paulushcgcj/securedblink/main/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/paulushcgcj/securedblink/main/install.ps1 | iex
```

**PyPI / uv (all platforms):**

```bash
uv tool install securedblink
```

PostgreSQL support is included by default. Install optional SQLAlchemy drivers
with an extra when using the PyPI package:

```bash
uv tool install 'securedblink[oracle]'
uv tool install 'securedblink[mysql]'
uv tool install 'securedblink[mssql]'
```

The release installers provide standalone binaries with the default
PostgreSQL support. Use the PyPI/`uv tool` installation when you need optional
drivers such as Oracle.

### 2. Connect a database

Set one or more `DB_<NAME>` environment variables. The suffix becomes the
connection name used by MCP tools.

```bash
export DB_LOCAL=sqlite:///./local.db
export DB_ANALYTICS=postgresql://user:password@db.example.com:5432/analytics
export DB_MAX_ROWS=500  # optional; defaults to 500
```

### 3. Run it

```bash
securedblink
```

With the example above, an MCP client can discover `local` and `analytics`,
inspect their schemas, and run read queries. Credentials can instead be stored
in the operating system credential manager through the vault.

## Configure an MCP client

The binary must be installed and available on the MCP client's `PATH`. If it
is not, replace `securedblink` with its absolute path, such as
`/usr/local/bin/securedblink`.

<details>
<summary><strong>OpenCode</strong></summary>

Add this to `~/.config/opencode/opencode.jsonc` or `.opencode.json` in a
project:

```json
{
  "mcp": {
    "securedblink": {
      "type": "local",
      "command": ["securedblink"],
      "environment": {
        "DB_ANALYTICS": "postgresql://user:password@host:5432/analytics",
        "DB_LOCAL": "sqlite:///./local.db",
        "DB_MAX_ROWS": "500"
      }
    }
  }
}
```

</details>

<details>
<summary><strong>VS Code Copilot</strong></summary>

Add this to `.vscode/mcp.json` or `~/.vscode/mcp.json`:

```json
{
  "servers": {
    "securedblink": {
      "type": "stdio",
      "command": "securedblink",
      "env": {
        "DB_ANALYTICS": "postgresql://user:password@host:5432/analytics",
        "DB_LOCAL": "sqlite:///./local.db",
        "DB_MAX_ROWS": "500"
      }
    }
  }
}
```

</details>

Keep connection values in your MCP client's environment configuration or use
the credential vault. Do not commit real credentials to configuration files.

## What it protects

| Operation | Behavior |
|---|---|
| `SELECT`, `EXPLAIN`, `SHOW`, `DESCRIBE`, safe `WITH` | Runs immediately through `query` |
| `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, and other writes | Requires `preview_mutation`, user approval, then `execute_mutation` |
| Approval token | Binds the exact SQL and connection; expires after five minutes and is single-use |
| Credentials | Vault values stay in the system credential manager and out of tool responses and logs |

The write flow is deliberately visible:

```text
1. Agent calls preview_mutation(connection, sql)
2. securedblink returns the planned operation and a one-time token
3. Agent shows the preview and asks for explicit confirmation
4. Agent calls execute_mutation(connection, sql, token)
5. securedblink validates the token, executes the SQL, and consumes the token
```

## Supported databases

`securedblink` uses SQLAlchemy URLs. PostgreSQL and SQLite work out of the box
with the standard package install; other dialects need their driver.

| Database | URL example | Install |
|---|---|---|
| PostgreSQL | `postgresql://user:pass@host:5432/db` | Included |
| SQLite | `sqlite:///./path/to/file.db` | Built in |
| Oracle | `oracle+oracledb://user:pass@host:1521/service` | `uv tool install 'securedblink[oracle]'` |
| MySQL | `mysql+pymysql://user:pass@host:3306/db` | `uv tool install 'securedblink[mysql]'` |
| SQL Server | `mssql+pyodbc://user:pass@host/db?driver=...` | `uv tool install 'securedblink[mssql]'` |
| Snowflake | `snowflake://user:pass@account/db/schema` | Install `snowflake-sqlalchemy` manually |

Any SQLAlchemy-compatible dialect can be used once its driver is installed.

## Tools

| Tool | Purpose |
|---|---|
| `list_connections` | List environment and vault connections |
| `list_tables` | List tables and views |
| `describe_table` | Show columns, keys, foreign keys, and indexes |
| `query` | Execute read-only SQL |
| `preview_mutation` | Preview a write and issue an approval token |
| `execute_mutation` | Execute an approved write |
| `vault_register_connection` | Store a connection in the credential vault |
| `vault_register_from_path` | Import a connection from `.env`, `.properties`, or YAML |
| `vault_list` | List registered vault aliases and metadata |
| `vault_revoke` | Remove a vault alias |

## Credential vault

The vault stores connection credentials in the platform's secure credential
manager: macOS Keychain, Linux Secret Service, or Windows Credential Manager.
The agent can use an alias without receiving the stored username or password.

To register a connection from the terminal:

```bash
securedblink register \
  --alias analytics \
  --jdbc-url "postgresql://host:5432/analytics" \
  --username user \
  --password password \
  --driver org.postgresql.Driver

securedblink list
```

To import a configuration file, first allow-list its directory:

```bash
export SECUREDBLINK_ALLOWED_ROOTS="/path/to/configs"
securedblink register-from-path \
  --alias analytics \
  --file-path /path/to/configs/analytics.env
```

Supported input formats are `.env`, `.properties`, and Spring Boot-style
`.yml`/`.yaml`. Paths outside `SECUREDBLINK_ALLOWED_ROOTS` are rejected, and
credentials are redacted from logs and error messages.

## Source checkout

Use `run.sh` for development or when you want the launcher to prepare the
environment automatically:

```bash
cd securedblink
DB_LOCAL=sqlite:///./local.db ./run.sh
```

`run.sh` syncs the project, reads `.env` for manual runs, detects drivers from
`DB_*` URL schemes, installs missing drivers, and then starts `securedblink`.
The installed binary does none of that setup; configure its environment and
install optional drivers explicitly.

## Environment reference

| Variable | Default | Description |
|---|---:|---|
| `DB_<NAME>` | — | SQLAlchemy URL for a named connection |
| `DB_MAX_ROWS` | `500` | Maximum rows returned by `query` |
| `SECUREDBLINK_ALLOWED_ROOTS` | — | Colon-separated roots allowed for vault file imports |

## Development

Requirements: Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy --strict securedblink
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Security

Please report vulnerabilities according to [SECURITY.md](SECURITY.md). Never
place real database credentials in issues, pull requests, or committed config
files.

## License

[GPL-3.0](LICENSE)
