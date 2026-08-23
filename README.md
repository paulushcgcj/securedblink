<div align="center" style="overflow:hidden; border-radius:26px; line-height:0">
  <img src="./assets/readme/hero.svg" width="100%" alt="securedblink — MCP database gateway. Read freely, preview writes, approve explicitly." style="display:block; border-radius:26px" />
</div>

<p align="center">
  <a href="https://pypi.org/project/securedblink/"><img src="https://img.shields.io/pypi/v/securedblink.svg" alt="PyPI version"/></a>
  <a href="https://pypi.org/project/securedblink/"><img src="https://img.shields.io/pypi/pyversions/securedblink.svg" alt="Python versions"/></a>
  <a href="https://github.com/paulushcgcj/securedblink/actions/workflows/ci.yml"><img src="https://github.com/paulushcgcj/securedblink/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/paulushcgcj/securedblink.svg" alt="License: GPL-3.0"/></a>
</p>

> **An MCP database gateway for LLM agents: read freely, preview writes, approve explicitly.**

`securedblink` gives an LLM a controlled, auditable way to inspect and query databases through the [Model Context Protocol](https://modelcontextprotocol.io). Read-only work runs immediately; every mutating statement must be previewed, bound to a single-use token, and explicitly approved before it touches the database. Credentials live in your OS credential manager — never in chat history, logs, or tool responses.

---

## Table of Contents

- [About](#about)
- [How it works](#how-it-works)
- [Getting started](#getting-started)
- [Configure an MCP client](#configure-an-mcp-client)
- [What it protects](#what-it-protects)
- [Supported databases](#supported-databases)
- [Tools](#tools)
- [Credential vault](#credential-vault)
- [Configuration](#configuration)
- [Source checkout](#source-checkout)
- [Development](#development)
- [Security](#security)
- [License](#license)

---

## About

`securedblink` is a local MCP server that sits between your agent and your databases. You declare connections as `DB_<NAME>` environment variables — the suffix becomes the connection name exposed to the agent. The server classifies every statement: `SELECT`, `EXPLAIN`, `SHOW`/`DESCRIBE`, and safe `WITH` run through `query`; everything else (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`…) is forced through the gated path.

Stack: **Python 3.12+**, **SQLAlchemy 2.0**, **MCP 1.x**, **structlog**, **keyring**. PostgreSQL and SQLite work out of the box; other dialects load via optional drivers.

**Who it's for:** engineers who want to let an agent explore schemas and run reads autonomously, but keep every write visible and reversible — ideal for analytics databases, staging environments, and local development.

---

## How it works

<div align="center" style="overflow:hidden; border-radius:22px; line-height:0">
  <img src="./assets/readme/workflow.svg" width="100%" alt="How securedblink gates writes: reads run immediately, writes require preview, bound token, explicit human approval, and validated execution. Vault credentials stay on-host." style="display:block; border-radius:22px" />
</div>

**Read lane — free.** `query` executes immediately and returns rows capped by `DB_MAX_ROWS` (default 500).

**Write lane — gated.** The flow is deliberately visible:

```text
1. Agent → preview_mutation(connection, sql)   → securedblink returns plan + one-time token
2. Agent shows preview and asks for confirmation
3. Human approves in the MCP client
4. Agent → execute_mutation(connection, sql, token) → securedblink validates token
5. securedblink executes, consumes the token, returns the result
```

The token binds the **exact SQL string and connection name** (SHA-256), expires after **5 minutes**, and is **single-use**. A mismatched connection, altered SQL, expired token, or replay is rejected — even if the agent tries.

**Vault lane — isolated.** Aliases registered with `securedblink register` or `register-from-path` are stored in the OS credential manager (macOS Keychain, Linux Secret Service, Windows Credential Manager). The agent sees only the alias; values are redacted from logs and tool output.

---

## Getting started

### 1. Install the command

Pick one distribution. The binary is the primary entry point for terminals and MCP clients.

**macOS / Linux — standalone binary (recommended):**

```bash
curl -fsSL https://raw.githubusercontent.com/paulushcgcj/securedblink/main/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/paulushcgcj/securedblink/main/install.ps1 | iex
```

**PyPI / uv — all platforms (use when you need extra drivers):**

```bash
uv tool install securedblink
# optional drivers
uv tool install 'securedblink[oracle]'
uv tool install 'securedblink[mysql]'
uv tool install 'securedblink[mssql]'
```

> Standalone installers bundle PostgreSQL support only. Install via PyPI/`uv tool` when you need Oracle, MySQL, or MSSQL drivers.

### 2. Connect a database

Set one or more `DB_<NAME>` variables. The suffix becomes the MCP connection name.

```bash
export DB_LOCAL=sqlite:///./local.db
export DB_ANALYTICS=postgresql://user:password@db.example.com:5432/analytics
export DB_MAX_ROWS=500  # optional; defaults to 500
```

> Prefer the credential vault for secrets (see below) rather than exporting passwords in plain text. Never commit real credentials.

### 3. Run it

```bash
securedblink
```

An MCP client can now discover `local` and `analytics`, list tables, describe schemas, and run reads. Writes will surface a preview and wait for your explicit approval.

---

## Configure an MCP client

The binary must be on the MCP client's `PATH`. If it isn't, replace `securedblink` with its absolute path (e.g. `/usr/local/bin/securedblink`).

<details>
<summary><strong>OpenCode</strong></summary>

Add to `~/.config/opencode/opencode.jsonc` or `.opencode.json` in a project:

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

Add to `.vscode/mcp.json` or `~/.vscode/mcp.json`:

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

Keep connection values in your MCP client's environment block or in the vault. Do not commit real credentials to config files.

---

## What it protects

| Operation | Behavior |
|---|---|
| `SELECT`, `EXPLAIN`, `SHOW`, `DESCRIBE`, safe `WITH` | Runs immediately through `query` |
| `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, and other writes | Requires `preview_mutation` → human approval → `execute_mutation` |
| Approval token | Binds the exact SQL and connection; 5-minute expiry; single-use |
| Credentials | Vault values stay in the system credential manager and never appear in tool responses or logs |

---

## Supported databases

Any SQLAlchemy-compatible dialect works once its driver is installed. PostgreSQL and SQLite need no extra setup.

| Database | URL example | Install |
|---|---|---|
| PostgreSQL | `postgresql://user:pass@host:5432/db` | Included |
| SQLite | `sqlite:///./path/to/file.db` | Built in |
| Oracle | `oracle+oracledb://user:pass@host:1521/service` | `uv tool install 'securedblink[oracle]'` |
| MySQL | `mysql+pymysql://user:pass@host:3306/db` | `uv tool install 'securedblink[mysql]'` |
| SQL Server | `mssql+pyodbc://user:pass@host/db?driver=...` | `uv tool install 'securedblink[mssql]'` |
| Snowflake | `snowflake://user:pass@account/db/schema` | Install `snowflake-sqlalchemy` manually |

---

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
| `vault_list` | List vault aliases and metadata |
| `vault_revoke` | Remove a vault alias |

---

## Credential vault

The vault stores credentials in the platform's secure store so the agent can use an alias without ever receiving the username or password.

**Register from the terminal:**

```bash
securedblink register \
  --alias analytics \
  --jdbc-url "postgresql://host:5432/analytics" \
  --username user \
  --password password \
  --driver org.postgresql.Driver

securedblink list
```

**Import from a file** — allow-list the directory first:

```bash
export SECUREDBLINK_ALLOWED_ROOTS="/path/to/configs"
securedblink register-from-path \
  --alias analytics \
  --file-path /path/to/configs/analytics.env
```

Supported formats: `.env`, `.properties`, and Spring Boot-style `.yml`/`.yaml`. Paths outside `SECUREDBLINK_ALLOWED_ROOTS` are rejected; values are redacted from logs and errors.

---

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `DB_<NAME>` | — | SQLAlchemy URL for a named connection |
| `DB_MAX_ROWS` | `500` | Maximum rows returned by `query` |
| `SECUREDBLINK_ALLOWED_ROOTS` | — | Colon-separated roots allowed for vault file imports |

---

## Source checkout

Use `run.sh` for development — it syncs the project, reads `.env`, detects drivers from `DB_*` URLs, and installs missing drivers before starting:

```bash
DB_LOCAL=sqlite:///./local.db ./run.sh
```

The installed binary does no setup preparation; configure its environment and optional drivers explicitly.

---

## Development

Requirements: Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy --strict securedblink
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and release process.

---

## Security

Please report vulnerabilities according to [SECURITY.md](SECURITY.md). Never place real database credentials in issues, pull requests, or committed config files.

---

## License

Distributed under [GPL-3.0](LICENSE).

---

<p align="center">
  <sub>Built for teams who let agents read, but never write silently.</sub>
</p>
