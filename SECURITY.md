# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Considerations

securedblink is an MCP server that executes SQL queries against databases on behalf of
LLM agents. Be aware of the following:

### Credentials

Database connection strings are passed via `DB_<NAME>` environment variables.
**Never** commit `.env` files, hardcode credentials, or log connection strings.
Connection URLs may contain usernames and passwords in plain text.

### SQL Execution

Raw SQL is passed through SQLAlchemy's `text()` construct. While this does not
perform parameter interpolation (reducing injection risk compared to string
formatting), users are responsible for:

- Restricting database user permissions to the minimum necessary
- Not exposing production databases without proper access controls
- Reviewing queries before confirmation

### Confirmation Token System

Write and destructive queries require explicit user confirmation via a
two-step flow:

1. `preview_mutation` returns a one-time token (5-minute TTL)
2. `execute_mutation` requires the token plus matching connection and SQL

Tokens are generated with `secrets.token_urlsafe` and are cryptographically
random. The token encodes the connection name and exact SQL to prevent the LLM
from swapping queries between preview and execution.

### Query Classification

The SQL classifier (`classifier.py`) categorizes queries as safe, mutation,
destructive, or unknown. **Unknown queries default to mutation** (require
confirmation). This is a conservative default — any unrecognized statement
treated as potentially dangerous.

### Row Limits

`DB_MAX_ROWS` (default 500) caps results per `query` call to prevent accidental
large data dumps.

## Reporting a Vulnerability

If you discover a security vulnerability in securedblink, please report it
responsibly.

### GitHub Security Advisories (Preferred)

Use the **"Report a vulnerability"** button on the
[Security tab](../../security/advisories/new) of the GitHub repository.

### Email

Send vulnerability details to: **paulushc@gmail.com**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Please do **not** open public GitHub issues for security vulnerabilities.

## Response Timeline

| Step | Timeframe |
|------|-----------|
| Acknowledgment | Within 48 hours |
| Assessment and initial response | Within 7 days |
| Fix timeline | Communicated based on severity |

## Scope

**In scope:**

- `securedblink` server code (`securedblink/`)
- The confirmation token flow
- The SQL query classifier
- The database connection manager
- `run.sh` launcher script

**Out of scope:**

- Vulnerabilities in upstream dependencies (report to the upstream project)
- Issues arising from misconfigured database user permissions
- Issues arising from insecure deployment configurations

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter notifies us privately
2. We acknowledge and assess the issue
3. We develop and test a fix
4. We release the fix
5. We publicly disclose the vulnerability, crediting the reporter (unless they
   prefer anonymity)
