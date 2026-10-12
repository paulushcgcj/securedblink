#!/usr/bin/env python3
"""
Version bumping and release management script for securedblink.

Usage:
    python scripts/bump_version.py [major|minor|patch|version] [--dry-run]
    
Examples:
    python scripts/bump_version.py patch           # Bump patch version (0.1.0 -> 0.1.1)
    python scripts/bump_version.py minor           # Bump minor version (0.1.1 -> 0.2.0)
    python scripts/bump_version.py major           # Bump major version (0.2.0 -> 1.0.0)
    python scripts/bump_version.py 0.9.1           # Set specific version
    python scripts/bump_version.py patch --dry-run # Preview changes without committing
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent
PYPROJECT_TOML = PROJECT_ROOT / "pyproject.toml"
CHANGELOG_MD = PROJECT_ROOT / "CHANGELOG.md"


def get_current_version() -> str:
    """Extract current version from pyproject.toml."""
    with open(PYPROJECT_TOML, "r") as f:
        content = f.read()
    
    # Find version line
    version_match = re.search(r'version = "([^"]+)"', content)
    if not version_match:
        raise ValueError("Could not find version in pyproject.toml")
    
    return version_match.group(1)


def bump_version(current_version: str, bump_type: str = None, target_version: str = None) -> str:
    """Calculate new version based on bump type or target version."""
    if target_version:
        # Validate target version format
        if not re.match(r'^\d+\.\d+\.\d+$', target_version):
            raise ValueError(f"Invalid version format: {target_version}. Use X.Y.Z format.")
        return target_version
    
    if not bump_type:
        raise ValueError("Either bump_type or target_version must be provided")
    
    # Parse current version
    try:
        major, minor, patch = map(int, current_version.split('.'))
    except ValueError:
        raise ValueError(f"Invalid current version format: {current_version}")
    
    # Calculate new version
    if bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump_type == "minor":
        minor += 1
        patch = 0
    elif bump_type == "patch":
        patch += 1
    else:
        raise ValueError(f"Invalid bump type: {bump_type}. Use major, minor, or patch.")
    
    return f"{major}.{minor}.{patch}"


def update_pyproject_toml(new_version: str, dry_run: bool = False) -> None:
    """Update version in pyproject.toml."""
    with open(PYPROJECT_TOML, "r") as f:
        content = f.read()
    
    new_content = re.sub(
        r'version = "[^"]+"',
        f'version = "{new_version}"',
        content
    )
    
    if dry_run:
        print(f"[DRY RUN] Would update pyproject.toml version to {new_version}")
        return
    
    with open(PYPROJECT_TOML, "w") as f:
        f.write(new_content)
    
    print(f"Updated pyproject.toml version to {new_version}")


def update_changelog(new_version: str, dry_run: bool = False) -> None:
    """Update CHANGELOG.md with new version section."""
    with open(CHANGELOG_MD, "r") as f:
        content = f.read()
    
    # Find the Unreleased section
    unreleased_pattern = r'## \[Unreleased\]'
    if not re.search(unreleased_pattern, content):
        print("Warning: No [Unreleased] section found in CHANGELOG.md")
        return
    
    # Replace [Unreleased] with the new version and add new [Unreleased] section
    today = subprocess.run(["date", "+%Y-%m-%d"], capture_output=True, text=True).stdout.strip()
    
    new_content = re.sub(
        unreleased_pattern,
        f'## [v{new_version}] - {today}\n\n### Features\n\n### Fixed\n\n### Documentation\n\n### Dependencies\n\n## [Unreleased]',
        content
    )
    
    # Update the comparison link at the bottom
    new_content = re.sub(
        r'\[Unreleased\]:.*',
        f'[Unreleased]: https://github.com/paulushcgcj/securedblink/compare/v{new_version}...HEAD\n[v{new_version}]: https://github.com/paulushcgcj/securedblink/compare/',
        new_content
    )
    
    if dry_run:
        print(f"[DRY RUN] Would update CHANGELOG.md for version {new_version}")
        return
    
    with open(CHANGELOG_MD, "w") as f:
        f.write(new_content)
    
    print(f"Updated CHANGELOG.md for version {new_version}")


def create_git_tag(new_version: str, dry_run: bool = False) -> None:
    """Create and push git tag for the new version."""
    tag_name = f"v{new_version}"
    
    if dry_run:
        print(f"[DRY RUN] Would create and push git tag {tag_name}")
        return
    
    # Create tag
    subprocess.run(["git", "tag", "-a", tag_name, "-m", f"Release v{new_version}"], check=True)
    print(f"Created git tag {tag_name}")
    
    # Push tag
    subprocess.run(["git", "push", "origin", tag_name], check=True)
    print(f"Pushed git tag {tag_name} to origin")


def commit_changes(new_version: str, dry_run: bool = False) -> None:
    """Commit version changes to git."""
    if dry_run:
        print(f"[DRY RUN] Would commit version changes for {new_version}")
        return
    
    # Add changed files
    subprocess.run(["git", "add", str(PYPROJECT_TOML), str(CHANGELOG_MD)], check=True)
    
    # Commit
    commit_message = f"chore(release): bump version to v{new_version}"
    subprocess.run(["git", "commit", "-m", commit_message], check=True)
    print(f"Committed version changes: {commit_message}")


def main():
    parser = argparse.ArgumentParser(
        description="Bump version and manage releases for securedblink"
    )
    parser.add_argument(
        "version_or_bump",
        help="Version to set (e.g., 0.9.1) or bump type (major, minor, patch)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without actually making them"
    )
    parser.add_argument(
        "--no-commit",
        action="store_true",
        help="Don't commit changes (useful for manual review)"
    )
    parser.add_argument(
        "--no-tag",
        action="store_true",
        help="Don't create git tag"
    )
    
    args = parser.parse_args()
    
    try:
        # Get current version
        current_version = get_current_version()
        print(f"Current version: {current_version}")
        
        # Determine new version
        if args.version_or_bump in ["major", "minor", "patch"]:
            new_version = bump_version(current_version, bump_type=args.version_or_bump)
        else:
            new_version = bump_version(current_version, target_version=args.version_or_bump)
        
        print(f"New version: {new_version}")
        
        if args.dry_run:
            print("\n[DRY RUN MODE - No changes will be made]")
        
        # Update files
        update_pyproject_toml(new_version, args.dry_run)
        update_changelog(new_version, args.dry_run)
        
        if not args.dry_run:
            # Commit changes if not in dry-run mode and not disabled
            if not args.no_commit:
                commit_changes(new_version, args.dry_run)
            
            # Create tag if not in dry-run mode and not disabled
            if not args.no_tag:
                create_git_tag(new_version, args.dry_run)
            
            print(f"\nVersion bumped to {new_version}")
            print("Next steps:")
            if args.no_commit:
                print("  - Review changes and commit manually")
            if args.no_tag:
                print("  - Create git tag manually: git tag -a v{new_version} -m 'Release v{new_version}'")
            print("  - Push changes: git push origin main")
            print("  - Push tag: git push origin v{new_version}")
            print("  - The release workflow will trigger automatically on tag push")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()