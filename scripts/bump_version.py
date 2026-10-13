#!/usr/bin/env python3
"""
Version bumping and release management script for securedblink.

Usage:
    python scripts/bump_version.py [major|minor|patch|version] [--dry-run]

The current version is read from the latest git tag, not from pyproject.toml:
that file carries a placeholder which release.yml overwrites from the tag at
build time, so the tags are what has actually shipped.

Examples:
    python scripts/bump_version.py patch           # Bump patch version (0.9.0 -> 0.9.1)
    python scripts/bump_version.py minor           # Bump minor version (0.9.0 -> 0.10.0)
    python scripts/bump_version.py major           # Bump major version (0.9.0 -> 1.0.0)
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
REPO_URL = "https://github.com/paulushcgcj/securedblink"


def get_current_version() -> str:
    """Return the latest released version, read from git tags.

    pyproject.toml holds a placeholder that release.yml rewrites from the tag
    during the build, so reading it here would compute the next version from a
    stale number and publish something lower than the current release. The tags
    are the source of truth for what has shipped.

    Returns:
        The version string of the most recent tag, without the leading ``v``

    Raises:
        ValueError: If no version can be determined from tags or pyproject.toml
    """
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0", "--match", "v*.*.*"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip().lstrip("v")

    # No tags yet: this is a first release, so fall back to the manifest.
    return _version_from_pyproject()


def _version_from_pyproject() -> str:
    """Extract the version placeholder from pyproject.toml.

    Returns:
        The version string declared in the project manifest

    Raises:
        ValueError: If no version line is present
    """
    with open(PYPROJECT_TOML) as f:
        content = f.read()

    version_match = re.search(r'version = "([^"]+)"', content)
    if not version_match:
        raise ValueError("Could not find version in pyproject.toml")

    return version_match.group(1)


def bump_version(
    current_version: str,
    bump_type: str | None = None,
    target_version: str | None = None,
) -> str:
    """Calculate new version based on bump type or target version.

    Args:
        current_version: The version to bump from
        bump_type: One of ``major``, ``minor``, or ``patch``
        target_version: An explicit version to set, taking precedence over
            ``bump_type``

    Returns:
        The resulting version string

    Raises:
        ValueError: If neither argument is given, the bump type is unknown, or
            a version string is not in ``X.Y.Z`` form
    """
    if target_version:
        # Validate target version format
        if not re.match(r"^\d+\.\d+\.\d+$", target_version):
            raise ValueError(
                f"Invalid version format: {target_version}. Use X.Y.Z format."
            )
        return target_version

    if not bump_type:
        raise ValueError("Either bump_type or target_version must be provided")

    # Parse current version
    try:
        major, minor, patch = map(int, current_version.split("."))
    except ValueError as exc:
        raise ValueError(f"Invalid current version format: {current_version}") from exc

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
    with open(PYPROJECT_TOML) as f:
        content = f.read()

    new_content = re.sub(r'version = "[^"]+"', f'version = "{new_version}"', content)

    if dry_run:
        print(f"[DRY RUN] Would update pyproject.toml version to {new_version}")
        return

    with open(PYPROJECT_TOML, "w") as f:
        f.write(new_content)

    print(f"Updated pyproject.toml version to {new_version}")


def update_changelog(
    new_version: str, previous_version: str, dry_run: bool = False
) -> None:
    """Promote the [Unreleased] entries into a dated section for this release.

    The entries logged since the last release move into the new section and a
    fresh empty [Unreleased] heading is left above them. Replacing the heading
    with empty section stubs instead would silently discard everything
    accumulated since the previous release.

    Args:
        new_version: The version being released
        previous_version: The version it supersedes, used for the compare link
        dry_run: Report what would change without writing
    """
    with open(CHANGELOG_MD) as f:
        content = f.read()

    # Capture the Unreleased heading and everything beneath it, up to the next
    # version heading or end of file. The lookahead is not consumed, so the
    # following section stays intact when the match is spliced back in.
    section = re.search(
        r"## \[Unreleased\]\n(?P<body>.*?)(?=\n## \[v|\Z)",
        content,
        re.DOTALL,
    )
    if section is None:
        print("Warning: No [Unreleased] section found in CHANGELOG.md")
        return

    body = section.group("body").strip()
    if not body:
        print("Warning: [Unreleased] section is empty; nothing to release")

    today = subprocess.run(
        ["date", "+%Y-%m-%d"], capture_output=True, text=True, check=True
    ).stdout.strip()

    released = f"## [Unreleased]\n\n## [v{new_version}] - {today}\n\n{body}\n"
    new_content = content[: section.start()] + released + content[section.end() :]

    # Repoint [Unreleased] at the new tag and give the release a real compare
    # range. The previous version is required here: a link ending in a bare
    # "compare/" resolves to nothing.
    new_content = re.sub(
        r"^\[Unreleased\]:.*$",
        f"[Unreleased]: {REPO_URL}/compare/v{new_version}...HEAD\n"
        f"[v{new_version}]: {REPO_URL}/compare/"
        f"v{previous_version}...v{new_version}",
        new_content,
        count=1,
        flags=re.MULTILINE,
    )

    if dry_run:
        print(f"[DRY RUN] Would update CHANGELOG.md for version {new_version}")
        return

    with open(CHANGELOG_MD, "w") as f:
        f.write(new_content)

    print(f"Updated CHANGELOG.md for version {new_version}")


def push_branch(dry_run: bool = False) -> None:
    """Push the current branch so the release commit reaches the remote.

    Tagging without this leaves the release workflow building a commit that
    the remote's default branch does not contain.

    Args:
        dry_run: Report what would happen without pushing
    """
    if dry_run:
        print("[DRY RUN] Would push the current branch to origin")
        return

    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    subprocess.run(["git", "push", "origin", branch], check=True)
    print(f"Pushed {branch} to origin")


def create_git_tag(new_version: str, dry_run: bool = False) -> None:
    """Create and push git tag for the new version.

    Args:
        new_version: The version to tag
        dry_run: Report what would happen without tagging
    """
    tag_name = f"v{new_version}"

    if dry_run:
        print(f"[DRY RUN] Would create and push git tag {tag_name}")
        return

    # Create tag
    subprocess.run(
        ["git", "tag", "-a", tag_name, "-m", f"Release v{new_version}"], check=True
    )
    print(f"Created git tag {tag_name}")

    # Push tag
    subprocess.run(["git", "push", "origin", tag_name], check=True)
    print(f"Pushed git tag {tag_name} to origin")


def commit_changes(new_version: str, dry_run: bool = False) -> None:
    """Commit version changes to git.

    Args:
        new_version: The version being recorded
        dry_run: Report what would happen without committing
    """
    if dry_run:
        print(f"[DRY RUN] Would commit version changes for {new_version}")
        return

    # Add changed files
    subprocess.run(["git", "add", str(PYPROJECT_TOML), str(CHANGELOG_MD)], check=True)

    # Commit
    commit_message = f"chore(release): bump version to v{new_version}"
    subprocess.run(["git", "commit", "-m", commit_message], check=True)
    print(f"Committed version changes: {commit_message}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bump version and manage releases for securedblink"
    )
    parser.add_argument(
        "version_or_bump",
        help="Version to set (e.g., 0.9.1) or bump type (major, minor, patch)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without actually making them",
    )
    parser.add_argument(
        "--no-commit",
        action="store_true",
        help="Don't commit changes (useful for manual review)",
    )
    parser.add_argument("--no-tag", action="store_true", help="Don't create git tag")

    args = parser.parse_args()

    try:
        # Get current version
        current_version = get_current_version()
        print(f"Current version: {current_version}")

        # Determine new version
        if args.version_or_bump in ["major", "minor", "patch"]:
            new_version = bump_version(current_version, bump_type=args.version_or_bump)
        else:
            new_version = bump_version(
                current_version, target_version=args.version_or_bump
            )

        print(f"New version: {new_version}")

        if args.dry_run:
            print("\n[DRY RUN MODE - No changes will be made]")

        # Update files
        update_pyproject_toml(new_version, args.dry_run)
        update_changelog(new_version, current_version, args.dry_run)

        if not args.dry_run:
            # Commit changes if not in dry-run mode and not disabled
            if not args.no_commit:
                commit_changes(new_version, args.dry_run)

            # The release commit has to reach the remote before the tag does,
            # otherwise the workflow builds a commit main does not contain.
            if not args.no_commit:
                push_branch(args.dry_run)

            # Create tag if not in dry-run mode and not disabled
            if not args.no_tag:
                create_git_tag(new_version, args.dry_run)

            print(f"\nVersion bumped to {new_version}")
            print("Next steps:")
            if args.no_commit:
                print("  - Review changes, commit them, and push the branch")
            if args.no_tag:
                print(
                    f"  - Create the git tag manually: git tag -a v{new_version} "
                    f"-m 'Release v{new_version}'"
                )
                print(f"  - Push the tag: git push origin v{new_version}")
            print("  - The release workflow triggers automatically on tag push")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
