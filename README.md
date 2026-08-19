# securedblink

[![PyPI version](https://img.shields.io/pypi/v/securedblink.svg)](https://pypi.org/project/securedblink/)
[![Python versions](https://img.shields.io/pypi/pyversions/securedblink.svg)](https://pypi.org/project/securedblink/)
[![CI](https://github.com/paulushcgcj/securedblink/actions/workflows/ci.yml/badge.svg)](https://github.com/paulushcgcj/securedblink/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/paulushcgcj/securedblink.svg)](LICENSE)

MCP server that gives LLM agents read access to any database, with built-in gates for writes.

## Installation

**Mac / Linux**
```bash
curl -fsSL https://raw.githubusercontent.com/paulushcgcj/securedblink/main/install.sh | bash
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/paulushcgcj/securedblink/main/install.ps1 | iex
```

**Via pip / uv (all platforms)**

```bash
pip install securedblink
# or
uv tool install securedblink
```

> **macOS note:** If you see a security warning on first run, clear the quarantine flag once: `xattr -d com.apple.quarantine /usr/local/bin/securedblink`

## Why securedblink

LLMs handle read-only database work: schema exploration, query writing, data analysis. A stray `DELETE` or `DROP` from an agent can wipe production data. securedblink draws a hard line: reads go through, writes require the agent to show you exactly what it plans to do and wait for your explicit approval.

## Features

- **Read queries** run immediately: `SELECT`, `EXPLAIN`, `SHOW`, `DESCRIBE`, and `WITH` (when safe).
- **Write and destructive queries** go through a two-step confirmation: the agent previews the change, you approve it.
- **Token-bound execution.** Approval tokens encode the exact SQL and connection. Swap the query or target a different database, and the server rejects it.
- **Named connections** via `DB_<NAME>=<url>` environment variables. No config files to manage.
- **Credential vault** for secure storage. Register connections with aliases, and the MCP stores credentials in the system's secure credential manager. No credentials in env vars, logs, or tool responses.
- **Any SQLAlchemy-compatible database:** PostgreSQL, SQLite, Oracle, MySQL, SQL Server, Snowflake, or whatever you install the driver for.

## Supported databases

| Database    | URL format                                        | Extra install          |
|-------------|---------------------------------------------------|------------------------|
| PostgreSQL  | `postgresql://user:pass@host:5432/db`             | included               |
| SQLite      | `sqlite:///./path/to/file.db`                     | included (built-in)    |
| Oracle      | `oracle+oracledb://user:pass@host:1521/service`   | `[oracle]`             |
| MySQL       | `mysql+pymysql://user:pass@host:3306/db`          | `[mysql]`              |
| SQL Server  | `mssql+pyodbc://user:pass@host/db?driver=...`     | `[mssql]`              |
| Snowflake   | `snowflake://user:pass@account/db/schema`         | `snowflake-sqlalchemy` |

Any other database works too. Install the right SQLAlchemy driver and use its URL format.

## Quick start

```bash
# Clone the repo
git clone git@github.com:paulushcgcj/securedblink.git
cd securedblink

# Run with a local SQLite database
DB_LOCAL=sqlite:///./test.db ./run.sh
```

The server starts and your LLM tool can list tables, describe schemas, and run read queries against `local`.

## Configure your connections

Set `DB_<NAME>=<url>` environment variables. The part after `DB_` (lowercased) is the name you reference in prompts.

```bash
DB_PROD=postgresql://user:pass@db.internal:5432/production
DB_LOCAL=sqlite:///./dev.db
DB_MAX_ROWS=1000   # optional, default 500
```

Put these in a `.env` file if you run the server manually.

## Run the server

`run.sh` is the recommended launcher. It syncs dependencies, detects which database drivers your `DB_*` env vars need, installs them if missing, and hands off to the MCP server.

```bash
# Run manually
DB_LOCAL=sqlite:///./test.db ./run.sh

# Or with a .env file
./run.sh
```

When your IDE launches securedblink, point it at `run.sh` instead of calling `uv run securedblink` directly. The script handles driver installation so you don't have to `pip install` extras like `[oracle]` or `[mysql]` by hand.

## Connect your IDE

<details>
<summary><strong>VS Code Copilot</strong></summary>

Add to `.vscode/mcp.json` (workspace) or `~/.vscode/mcp.json` (global):

```json
{
  "servers": {
    "securedblink": {
      "type": "stdio",
      "command": "/absolute/path/to/securedblink/run.sh",
      "env": {
        "DB_PROD": "postgresql://user:pass@host:5432/mydb",
        "DB_LOCAL": "sqlite:///./local.db",
        "DB_MAX_ROWS": "500"
      }
    }
  }
}
```

</details>

<details>
<summary><strong>OpenCode</strong></summary>

Add to `~/.config/opencode/opencode.jsonc` or `.opencode.json` in your project:

```json
{
  "mcp": {
    "securedblink": {
      "type": "local",
      "command": ["/absolute/path/to/securedblink/run.sh"],
      "environment": {
        "DB_PROD": "postgresql://user:pass@host:5432/mydb",
        "DB_LOCAL": "sqlite:///./local.db",
        "DB_MAX_ROWS": "500"
      }
    }
  }
}
```

</details>

## Tools

| Tool                       | Description                                              |
|----------------------------|----------------------------------------------------------|
| `list_connections`         | List all configured DB connections (env + vault)        |
| `list_tables`              | List tables and views in a connection                    |
| `describe_table`           | Show columns, PK, FKs, indexes for a table               |
| `query`                    | Execute read-only SQL (SELECT, EXPLAIN, etc.)            |
| `preview_mutation`         | Preview a write/destructive query, get a confirmation token |
| `execute_mutation`         | Execute after you confirm (requires token from above)    |
| `vault_register_connection` | Register a connection in the credential vault            |
| `vault_register_from_path` | Register a connection from a config file                 |
| `vault_list`               | List all registered vault aliases                         |
| `vault_revoke`             | Remove a connection from the vault                        |

## How writes get approved

Every write or destructive query follows the same flow:

```
Agent calls preview_mutation(connection, sql)
  → Server returns a preview of the change + a one-time token (5-minute TTL)

Agent shows you the preview:
  "This will DELETE 42 rows from orders. Do you confirm?"

You say yes.

Agent calls execute_mutation(connection, sql, token)
  → Server validates the token, executes, and consumes it.
```

The token binds the connection name and the exact SQL to the approval. If the agent tries to run different SQL or target a different connection, the server rejects the token. Tokens expire after 5 minutes and can only be used once.

## Custom drivers

`run.sh` detects the URL scheme and installs the driver for you. For example, setting `DB_SNOW=snowflake://...` causes the script to install `snowflake-sqlalchemy` on first launch.

If you prefer to install manually:

```bash
uv pip install snowflake-sqlalchemy
```

The SQLAlchemy dialect registry resolves the driver from the URL prefix.

## Environment reference

| Variable       | Default | Description                                      |
|----------------|---------|--------------------------------------------------|
| `DB_<NAME>`    | —       | Connection URL for a named database              |
| `DB_MAX_ROWS`  | `500`   | Max rows returned per `query` call               |
| `SECUREDBLINK_ALLOWED_ROOTS` | — | Colon-separated list of directories for vault file registration |

## Credential Vault

The credential vault lets you store database credentials securely using your system's credential manager (macOS Keychain, Linux Secret Service, Windows Credential Manager). Once stored, credentials are **never** visible to the agent or in tool responses, logs, or traces.

### Why use the vault

- **Security:** Credentials are stored using the OS credential manager, not in plaintext files or environment variables
- **Isolation:** The MCP server is the only component that ever holds plaintext credentials
- **Clean separation:** Use descriptive aliases instead of exposing connection strings in agent conversations

### Vault tools

| Tool | Description |
|------|-------------|
| `vault_register_connection` | Register a connection by providing JDBC URL, username, and password directly |
| `vault_register_from_path` | Register a connection by reading a config file (.env, .properties, .yml) |
| `vault_list` | List all registered vault aliases with metadata |
| `vault_revoke` | Remove a connection from the vault |

### Using the vault

#### Register a connection directly

```bash
# The agent calls:
vault_register_connection(
  alias="prod",
  jdbc_url="postgresql://user:password@host:5432/mydb",
  username="user",
  password="password"
)
# Returns: {"alias": "prod", "status": "registered"}
# The credentials are now stored securely and never echoed back
```

Then use the alias with any query tool:
```bash
query(connection_name="prod", sql="SELECT * FROM users")
```

#### Register from a config file

First, configure the allowed directories:
```bash
export SECUREDBLINK_ALLOWED_ROOTS="/path/to/configs:/another/path"
```

Then register:
```bash
# Agent calls:
vault_register_from_path(
  alias="prod",
  file_path="/path/to/configs/prod.env"
)
```

Supported file formats:
- **.env:** `DB_URL=postgresql://...`, `DB_USERNAME=...`, `DB_PASSWORD=...`
- **.properties:** `jdbc.url=postgresql://...`, `jdbc.username=...`, `jdbc.password=...`
- **.yml/.yaml:** Spring Boot style with `spring.datasource.url/username/password`

#### List and revoke

```bash
# List all vault aliases
vault_list()
# Returns: {"aliases": [{"name": "prod", "created_at": "...", "source": "direct"}, ...]}

# Remove a connection
vault_revoke(alias="prod")
# Returns: {"alias": "prod", "status": "revoked", "existed": true}
```

#### Command-line interface

You can also register connections from the terminal without going through the agent. Use the `securedblink` command with a subcommand (or `python -m securedblink.server` if you run from a source checkout):

```bash
# Register a connection directly (prompts-free, useful for scripting)
securedblink register \
  --alias prod \
  --jdbc-url "postgresql://user:password@host:5432/mydb" \
  --username user \
  --password password \
  --driver org.postgresql.Driver

# Overwrite an existing alias
securedblink register --alias prod --jdbc-url "..." --overwrite

# Register from a config file (requires SECUREDBLINK_ALLOWED_ROOTS)
export SECUREDBLINK_ALLOWED_ROOTS="/path/to/configs"
securedblink register-from-path --alias prod --file-path /path/to/configs/prod.env

# List registered aliases
securedblink list
```

Running `securedblink` with no subcommand starts the MCP server.

> **Note (macOS):** `SECUREDBLINK_ALLOWED_ROOTS` is compared against resolved paths. `/tmp` resolves to `/private/tmp`, so use `SECUREDBLINK_ALLOWED_ROOTS="/private/tmp"` if your config files live in `/tmp`.

### Security requirements

- The `vault_register_from_path` tool **requires** `SECUREDBLINK_ALLOWED_ROOTS` to be set
- Paths outside the allow-listed roots are **rejected** — no exceptions
- All logging and exception messages are **redacted** to prevent credential leaks
- No tool returns plaintext credentials under any circumstance

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR guidelines.

## License

[GPL-3.0](LICENSE)
