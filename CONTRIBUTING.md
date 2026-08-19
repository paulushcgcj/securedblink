# Contributing to dbbridge

Thanks for your interest in contributing! This guide will help you get started.

## Prerequisites

- **Python** >= 3.11
- **[uv](https://docs.astral.sh/uv/)** (recommended package manager)
- **Git**

## Development Setup

```bash
# 1. Fork and clone the repo
git clone git@github.com:<your-username>/dbbridge.git
cd dbbridge

# 2. Install core dependencies
uv sync

# 3. Install dev dependencies (pytest, pytest-cov, pytest-mock)
uv pip install -e ".[dev]"

# 4. (Optional) Install database driver extras
uv pip install -e ".[oracle]"
uv pip install -e ".[mysql]"
uv pip install -e ".[mssql]"

# 5. Set up a local test database
export DB_LOCAL=sqlite:///./dev.db
```

## Running Locally

```bash
# Direct run
DB_LOCAL=sqlite:///./test.db uv run dbbridge

# Or via the launcher script (auto-installs drivers from DB_* env vars)
DB_LOCAL=sqlite:///./test.db ./run.sh
```

## Project Structure

```
dbbridge/
  server.py       # FastMCP server, tools, token management
  classifier.py   # SQL query classification (safe/mutation/destructive)
  connections.py  # DB connection manager via DB_* env vars
tests/
  conftest.py     # Shared fixtures (sqlite_engine, sample_db_env, clean_tokens)
  test_server.py
  test_classifier.py
  test_connections.py
```

## Code Style

This project uses **[ruff](https://docs.astral.sh/ruff/)** for linting and formatting:

```bash
# Check for issues
ruff check .

# Auto-fix
ruff check --fix .

# Format
ruff format .
```

Guidelines:

- Type hints are required on all functions and methods
- Python 3.11+ syntax is welcome (e.g., `X | Y` unions, `match` statements)
- Follow existing patterns in the codebase
- Keep functions focused — one responsibility per function

## Testing

```bash
# Run all tests
uv run pytest

# Run a specific test file
uv run pytest tests/test_classifier.py

# Generate HTML coverage report
uv run pytest --cov-report=html
open htmlcov/index.html
```

The project enforces a **95% coverage threshold** (configured in `pyproject.toml`).
New code must include tests. Coverage drops will cause CI to fail.

### Writing Tests

- Tests live in `tests/` mirroring the source structure
- Use the shared fixtures from `conftest.py`:
  - `sqlite_engine` — in-memory SQLite with sample schema and data
  - `sample_db_env` — sets `DB_TEST` env var
  - `clean_tokens` — clears the server's token dict between tests
- Name test files `test_<module>.py` and functions `test_<what>`

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes, including tests
3. Ensure all checks pass:
   ```bash
   ruff check .
   ruff format --check .
   uv run pytest
   ```
4. Write a clear PR description explaining **what** changed and **why**
5. Keep PRs focused — one feature or fix per PR

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use for |
|--------|---------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `test:` | Adding or updating tests |
| `chore:` | Maintenance, CI, tooling |
| `refactor:` | Code change that neither fixes a bug nor adds a feature |

Examples:

```
feat: add support for Snowflake connections
fix: token expiry check in execute_mutation
test: add edge cases for SQL classifier
```

## Reporting Issues

Open a [GitHub Issue](../../issues). For bugs, please include:

- Steps to reproduce
- Expected behavior
- Actual behavior
- Python version and OS

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).
By participating, you agree to uphold its standards.

## License

dbbridge is licensed under [GPL-3.0](LICENSE). By contributing, you agree that
your contributions will be licensed under the same license.
