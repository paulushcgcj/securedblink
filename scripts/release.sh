#!/bin/bash
# Release management script for securedblink
# Usage: ./scripts/release.sh [major|minor|patch|version] [--dry-run]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check if we're in the right directory
if [ ! -f "$PROJECT_ROOT/pyproject.toml" ]; then
    echo "Error: Not in project root directory"
    exit 1
fi

# Check if uv is available
if ! command -v uv &> /dev/null; then
    echo "Error: uv is required but not found. Install it from https://github.com/astral-sh/uv"
    exit 1
fi

# Check if we're on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "Warning: Not on main branch. Current branch: $CURRENT_BRANCH"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: Uncommitted changes detected. Please commit or stash them first."
    git status --short
    exit 1
fi

# Check that we're up to date with remote
if [ "$(git rev-parse HEAD)" != "$(git rev-parse @{u})" ]; then
    echo "Error: Local branch is not up to date with remote."
    echo "Run: git pull"
    exit 1
fi

# Parse arguments
DRY_RUN=false
VERSION_OR_BUMP=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=true
            ;;
        --help)
            echo "Usage: $0 [major|minor|patch|version] [--dry-run]"
            echo ""
            echo "Examples:"
            echo "  $0 patch           # Bump patch version"
            echo "  $0 minor           # Bump minor version"
            echo "  $0 major           # Bump major version"
            echo "  $0 0.9.1           # Set specific version"
            echo "  $0 patch --dry-run # Preview changes"
            exit 0
            ;;
        *)
            VERSION_OR_BUMP="$arg"
            ;;
    esac
done

if [ -z "$VERSION_OR_BUMP" ]; then
    echo "Error: Please specify version or bump type (major, minor, patch)"
    echo "Use --help for usage information"
    exit 1
fi

# Run the version bump script
if $DRY_RUN; then
    echo "=== DRY RUN MODE ==="
    uv run python "$SCRIPT_DIR/bump_version.py" "$VERSION_OR_BUMP" --dry-run
else
    echo "=== RELEASE PROCESS ==="
    uv run python "$SCRIPT_DIR/bump_version.py" "$VERSION_OR_BUMP"
    
    echo ""
    echo "Release process completed!"
    echo "The GitHub Actions release workflow will trigger automatically."
    echo "Monitor progress at: https://github.com/paulushcgcj/securedblink/actions"
fi