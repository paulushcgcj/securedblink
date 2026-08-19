#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run.sh — securedblink MCP server launcher
#
# Set this script as the MCP "command" in your tool config.
# The tool passes DB_* env vars; this script preps the environment and
# hands off to the MCP server via exec. ALL setup output goes to stderr
# so stdout remains clean for the MCP stdio protocol.
#
# ┌─ OpenCode (.opencode.json or ~/.config/opencode/config.json) ──────────┐
# │  "mcp": {                                                               │
# │    "db": {                                                              │
# │      "type": "local",                                                   │
# │      "command": ["/path/to/securedblink/run.sh"],                            │
# │      "environment": {                                                   │
# │        "DB_PROD":  "postgresql://user:pass@host:5432/mydb",            │
# │        "DB_LOCAL": "sqlite:///./app.db"                                 │
# │      }                                                                  │
# │    }                                                                    │
# │  }                                                                      │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─ VS Code (.vscode/mcp.json) ───────────────────────────────────────────┐
# │  "servers": {                                                           │
# │    "securedblink": {                                                          │
# │      "type":    "stdio",                                                │
# │      "command": "/path/to/securedblink/run.sh",                              │
# │      "env": {                                                           │
# │        "DB_PROD":  "postgresql://user:pass@host:5432/mydb",            │
# │        "DB_LOCAL": "sqlite:///./app.db"                                 │
# │      }                                                                  │
# │    }                                                                    │
# │  }                                                                      │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─ Manual run ────────────────────────────────────────────────────────────┐
# │  DB_LOCAL=sqlite:///./app.db ./run.sh                                   │
# │  ./run.sh          (picks up .env if present)                           │
# └─────────────────────────────────────────────────────────────────────────┘
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── ALL diagnostic output goes to stderr ─────────────────────────────────────
# stdout is reserved exclusively for the MCP stdio protocol.
log()  { echo "[securedblink] ▶  $*" >&2; }
ok()   { echo "[securedblink] ✔  $*" >&2; }
warn() { echo "[securedblink] ⚠  $*" >&2; }
err()  { echo "[securedblink] ✘  $*" >&2; }
die()  { err "$*"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# DRIVER MAP
#
# Maps a SQLAlchemy connection URL prefix → "python_module|pip_install_spec"
#   python_module   — what Python imports (used to check if already installed)
#   pip_install_spec — what `uv pip install` receives
#
# To add a custom driver: add a line matching your URL prefix and map it to
# the importable module name and the pip package name.
# ─────────────────────────────────────────────────────────────────────────────
driver_for_url() {
  case "$1" in
    # ── PostgreSQL ────────────────────────────────────────────────────────
    postgresql+asyncpg://*)
      echo "asyncpg|asyncpg" ;;
    postgresql+psycopg://*)
      echo "psycopg|psycopg[binary]" ;;
    postgresql+psycopg2://*|postgresql://*)
      echo "psycopg2|psycopg2-binary" ;;

    # ── SQLite (built-in — no driver needed) ──────────────────────────────
    sqlite://*)
      echo "__builtin__" ;;

    # ── Oracle ────────────────────────────────────────────────────────────
    oracle+oracledb://*|oracle://*)
      echo "oracledb|oracledb" ;;
    oracle+cx_oracle://*)
      echo "cx_Oracle|cx_Oracle" ;;

    # ── MySQL / MariaDB ───────────────────────────────────────────────────
    mysql+pymysql://*|mysql://*)
      echo "pymysql|PyMySQL" ;;
    mysql+mysqlclient://*)
      echo "MySQLdb|mysqlclient" ;;
    mysql+aiomysql://*)
      echo "aiomysql|aiomysql" ;;

    # ── SQL Server ────────────────────────────────────────────────────────
    mssql+pyodbc://*|mssql://*)
      echo "pyodbc|pyodbc" ;;
    mssql+pymssql://*)
      echo "pymssql|pymssql" ;;

    # ── Snowflake ─────────────────────────────────────────────────────────
    snowflake://*)
      echo "snowflake.sqlalchemy|snowflake-sqlalchemy" ;;

    # ── Unknown ───────────────────────────────────────────────────────────
    *)
      echo "__unknown__" ;;
  esac
}

# Returns 0 if the python module is importable in the uv env, 1 otherwise
is_importable() {
  uv run python -c "import $1" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 0 — Optional .env for manual runs
#
# When launched by a tool (OpenCode / VS Code Copilot), env vars are injected
# directly by the tool's config — no .env needed.
# This block is only useful when running ./run.sh manually.
# ─────────────────────────────────────────────────────────────────────────────
if [[ -f ".env" ]]; then
  log "Loading .env (manual run mode)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*$  ]] && continue   # blank
    [[ "$line" =~ ^[[:space:]]*# ]] && continue    # comment
    key="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}" ; val="${val#\"}"               # strip double quotes
    val="${val%\'}" ; val="${val#\'}"               # strip single quotes
    [[ -n "$key" ]] && export "$key=$val"
  done < ".env"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Core dependencies
#
# uv sync installs mcp, sqlalchemy, psycopg2-binary (from pyproject.toml).
# stdout suppressed — MCP stdio must stay clean.
# ─────────────────────────────────────────────────────────────────────────────
log "Syncing core dependencies..."

if ! uv sync --frozen 1>/dev/null 2>&1; then
  # No lockfile yet or outdated — generate/update it
  warn "Lockfile missing or outdated, running full sync..."
  uv sync 1>/dev/null 2>&1 \
    || die "uv sync failed — check pyproject.toml and network access"
fi

ok "Core dependencies ready"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Database drivers
#
# Scan every DB_* env var, resolve the required driver, install if missing.
# Deduplicates: two connections on the same driver only install it once.
# ─────────────────────────────────────────────────────────────────────────────
log "Checking database drivers..."

DB_COUNT=0
FAIL_COUNT=0
SEEN_SPECS=""           # space-separated list of already-handled specs

while IFS= read -r line; do
  key="${line%%=*}"
  val="${line#*=}"

  [[ "$key" == DB_* ]] || continue          # only DB_* vars
  suffix="${key#DB_}"
  [[ "$suffix" == "MAX_ROWS" ]] && continue # config knob, not a connection
  [[ -z "$val" ]]               && continue

  conn="$(echo "$suffix" | tr '[:upper:]' '[:lower:]')"  # lowercase display name
  DB_COUNT=$((DB_COUNT + 1))

  driver_info="$(driver_for_url "$val")"
  module="${driver_info%%|*}"
  spec="${driver_info##*|}"

  # ── Built-in (SQLite) ──
  if [[ "$module" == "__builtin__" ]]; then
    ok "  [$conn] sqlite — built-in, no driver needed"
    continue
  fi

  # ── Unknown scheme ──
  if [[ "$module" == "__unknown__" ]]; then
    warn "  [$conn] Unrecognised URL scheme '${val%%://*}'"
    warn "         Add it to driver_for_url() in run.sh or install the driver manually"
    continue
  fi

  # ── Deduplicate ──
  if echo "$SEEN_SPECS" | grep -qw "$spec"; then
    ok "  [$conn] $spec — already handled"
    continue
  fi
  SEEN_SPECS="$SEEN_SPECS $spec"

  # ── Check + install ──
  if is_importable "$module"; then
    ok "  [$conn] $spec — already installed"
  else
    log "  [$conn] Installing $spec..."
    if uv pip install "$spec" 1>/dev/null 2>&1; then
      ok "  [$conn] $spec — installed"
    else
      err "  [$conn] Failed to install $spec"
      err "         Run manually: uv pip install '$spec'"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  fi

done < <(env)

# ── Summary ──
if [[ $DB_COUNT -eq 0 ]]; then
  warn "No DB_* environment variables found"
  warn "The MCP server will start but have no connections available"
  warn "Add DB_<NAME>=<url> to your tool's environment config"
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
  die "$FAIL_COUNT driver(s) failed to install — fix errors above and restart the MCP server"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Hand off to the MCP server
#
# exec replaces this shell process with securedblink.
# From this point: stdin/stdout belong entirely to the MCP protocol.
# The tool sees a clean process with no prior stdout noise.
# ─────────────────────────────────────────────────────────────────────────────
log "Handing off to MCP server ($DB_COUNT connection(s))"
exec uv run securedblink
