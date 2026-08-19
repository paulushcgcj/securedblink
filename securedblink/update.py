"""Opt-in release update detection and explicit uv upgrade support for securedblink."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

PACKAGE_NAME = "securedblink"
PYPI_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
UPDATE_CHECK_DISABLED_ENV = "SECUREDBLINK_NO_UPDATE_CHECK"
UPDATE_CACHE_PATH_ENV = "SECUREDBLINK_UPDATE_CACHE_PATH"
UPDATE_CHECK_INTERVAL = timedelta(days=1)
DEFAULT_TIMEOUT = 2.0


@dataclass(frozen=True, slots=True)
class UpdateStatus:
    """Result of checking the installed release against PyPI."""

    installed_version: str
    latest_version: str | None
    update_available: bool
    checked_at: str | None = None
    skipped: bool = False
    error: str | None = None


def installed_version() -> str:
    """Return the installed package version, or ``unknown`` in a source tree."""
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return "unknown"


def _version_key(value: str) -> tuple[int, ...] | None:
    """Return a comparable key for stable numeric PEP 440 versions."""
    match = re.fullmatch(r"v?(\d+)(?:\.(\d+))+(?:\.post(\d+))?", value)
    if match is None:
        return None
    numbers = tuple(int(part) for part in value.removeprefix("v").split(".") if part.isdigit())
    post_match = re.search(r"\.post(\d+)$", value)
    return numbers + ((int(post_match.group(1)),) if post_match else (0,))


def _latest_stable(releases: dict[str, Any]) -> str | None:
    """Select the highest stable release from PyPI release metadata."""
    candidates: list[tuple[str, tuple[int, ...]]] = []
    for release in releases:
        version_key = _version_key(release)
        if version_key is not None:
            candidates.append((release, version_key))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[1])[0]


def fetch_latest_version(timeout: float = DEFAULT_TIMEOUT) -> str:
    """Fetch the latest stable package version from the PyPI JSON API.

    Raises:
        RuntimeError: If PyPI cannot be reached or returns invalid metadata.
    """
    try:
        with urlopen(PYPI_URL, timeout=timeout) as response:  # noqa: S310
            payload = json.load(response)
    except (OSError, URLError, ValueError) as error:
        raise RuntimeError(f"Could not check PyPI: {error}") from error

    latest = _latest_stable(payload.get("releases", {}))
    if latest is None:
        raise RuntimeError("PyPI returned no stable releases")
    return latest


def cache_path() -> Path:
    """Return the update cache path, honoring the testable environment override."""
    configured = os.environ.get(UPDATE_CACHE_PATH_ENV)
    return (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".cache" / "securedblink" / "update.json"
    )


def _read_cache(path: Path, now: datetime, installed: str) -> UpdateStatus | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["installed_version"] != installed:
            return None
        checked_at = datetime.fromisoformat(data["checked_at"])
        if now - checked_at >= UPDATE_CHECK_INTERVAL:
            return None
        return UpdateStatus(
            installed_version=data["installed_version"],
            latest_version=data.get("latest_version"),
            update_available=data["update_available"],
            checked_at=data["checked_at"],
            error=data.get("error"),
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _write_cache(path: Path, status: UpdateStatus) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(status), indent=2), encoding="utf-8")


def check_for_update(
    *,
    timeout: float = DEFAULT_TIMEOUT,
    now: datetime | None = None,
    force: bool = False,
) -> UpdateStatus:
    """Check for a newer stable release with daily caching and offline safety."""
    current_time = now or datetime.now(UTC)
    current = installed_version()
    if os.environ.get(UPDATE_CHECK_DISABLED_ENV) == "1":
        return UpdateStatus(current, None, False, skipped=True)

    path = cache_path()
    if not force:
        cached = _read_cache(path, current_time, current)
        if cached is not None:
            return cached

    checked_at = current_time.isoformat()
    try:
        latest = fetch_latest_version(timeout)
        current_key = _version_key(current)
        latest_key = _version_key(latest)
        available = (
            current_key is not None
            and latest_key is not None
            and latest_key > current_key
        )
        status = UpdateStatus(current, latest, available, checked_at=checked_at)
    except RuntimeError as error:
        status = UpdateStatus(
            current, None, False, checked_at=checked_at, error=str(error)
        )

    try:
        _write_cache(path, status)
    except OSError:
        # A read-only home directory must not make the explicit check fail.
        pass
    return status


def apply_uv_upgrade() -> subprocess.CompletedProcess[str]:
    """Run the explicitly requested uv tool upgrade without local-project shadowing."""
    if shutil.which("uv") is None:
        raise RuntimeError("uv is not installed or is not on PATH")
    try:
        return subprocess.run(
            ["uv", "tool", "upgrade", PACKAGE_NAME],
            check=True,
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"uv tool upgrade failed: {error}") from error


def installation_guidance() -> str:
    """Return installation-specific guidance without assuming an install mode."""
    executable = Path(sys.argv[0]).name
    return (
        f"If installed with uv, run: uv tool upgrade {PACKAGE_NAME}\n"
        f"If using uvx, run: uvx {PACKAGE_NAME}@latest\n"
        f"If using the standalone {executable} binary, download a newer release from GitHub."
    )
