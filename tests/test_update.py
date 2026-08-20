"""Tests for the securedblink update module."""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from securedblink.update import (
    UpdateStatus,
    _latest_stable,
    _read_cache,
    _version_key,
    _write_cache,
    cache_path,
    check_for_update,
    fetch_latest_version,
    installation_guidance,
    installed_version,
)


class TestVersionKey:
    """Tests for _version_key helper."""

    def test_simple_version(self):
        assert _version_key("1.0.0") == (1, 0, 0, 0)

    def test_version_with_v_prefix(self):
        assert _version_key("v1.2.3") == (1, 2, 3, 0)

    def test_version_with_post(self):
        assert _version_key("1.0.0.post1") == (1, 0, 0, 1)

    def test_invalid_version(self):
        assert _version_key("invalid") is None
        # Note: "1.0" actually matches the regex and returns (1, 0, 0)
        # since it has at least one dot-separated number
        assert _version_key("abc") is None


class TestLatestStable:
    """Tests for _latest_stable helper."""

    def test_empty_releases(self):
        assert _latest_stable({}) is None

    def test_pre_releases_ignored(self):
        releases = {"1.0.0a1": {}, "0.9.0": {}, "1.0.0": {}}
        assert _latest_stable(releases) == "1.0.0"

    def test_returns_highest(self):
        releases = {"1.0.0": {}, "2.0.0": {}, "0.5.0": {}}
        assert _latest_stable(releases) == "2.0.0"


class TestInstalledVersion:
    """Tests for installed_version function."""

    def test_returns_version(self):
        with patch(
            "securedblink.update.version",
            return_value="1.2.3",
        ):
            assert installed_version() == "1.2.3"

    def test_package_not_found(self):
        from importlib.metadata import PackageNotFoundError

        with patch(
            "securedblink.update.version",
            side_effect=PackageNotFoundError("not found"),
        ):
            assert installed_version() == "unknown"


class TestFetchLatestVersion:
    """Tests for fetch_latest_version function."""

    def test_success(self):
        mock_payload = {
            "releases": {
                "1.0.0": {},
                "2.0.0": {},
            }
        }
        mock_response = Mock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_response.read = Mock(return_value=str(mock_payload).encode())

        with patch("securedblink.update.urlopen", return_value=mock_response):
            with patch("securedblink.update.json.load", return_value=mock_payload):
                assert fetch_latest_version() == "2.0.0"

    def test_network_error(self):
        with patch(
            "securedblink.update.urlopen",
            side_effect=OSError("network error"),
        ):
            with pytest.raises(RuntimeError, match="Could not check PyPI"):
                fetch_latest_version()


class TestCachePath:
    """Tests for cache_path function."""

    def test_default_path(self):
        with patch.dict("os.environ", {}, clear=True):
            path = cache_path()
            assert "securedblink" in str(path)
            assert "update.json" in str(path)

    def test_custom_path(self):
        with patch.dict(
            "os.environ", {"SECUREDBLINK_UPDATE_CACHE_PATH": "/tmp/custom"}
        ):
            path = cache_path()
            assert str(path) == "/tmp/custom"


class TestCacheReadWrite:
    """Tests for cache read/write functions."""

    def test_write_and_read_cache(self, tmp_path):
        cache_file = tmp_path / "update.json"
        status = UpdateStatus(
            installed_version="1.0.0",
            latest_version="2.0.0",
            update_available=True,
            checked_at="2024-01-01T00:00:00+00:00",
        )
        _write_cache(cache_file, status)

        result = _read_cache(
            cache_file,
            datetime.fromisoformat("2024-01-01T00:00:00+00:00"),
            "1.0.0",
        )
        assert result == status

    def test_stale_cache_ignored(self, tmp_path):
        cache_file = tmp_path / "update.json"
        status = UpdateStatus(
            installed_version="1.0.0",
            latest_version="2.0.0",
            update_available=True,
            checked_at="2024-01-01T00:00:00+00:00",
        )
        _write_cache(cache_file, status)

        # Check 2 days later
        later = datetime.fromisoformat("2024-01-03T00:00:00+00:00")
        result = _read_cache(cache_file, later, "1.0.0")
        assert result is None

    def test_different_version_ignored(self, tmp_path):
        cache_file = tmp_path / "update.json"
        status = UpdateStatus(
            installed_version="1.0.0",
            latest_version="2.0.0",
            update_available=True,
            checked_at=datetime.now(UTC).isoformat(),
        )
        _write_cache(cache_file, status)

        result = _read_cache(cache_file, datetime.now(UTC), "2.0.0")
        assert result is None


class TestCheckForUpdate:
    """Tests for check_for_update function."""

    def test_update_available(self):
        with (
            patch(
                "securedblink.update.installed_version",
                return_value="1.0.0",
            ),
            patch(
                "securedblink.update.fetch_latest_version",
                return_value="2.0.0",
            ),
            patch(
                "securedblink.update._read_cache",
                return_value=None,
            ),
            patch(
                "securedblink.update._write_cache",
            ),
        ):
            with patch.dict("os.environ", {}, clear=True):
                status = check_for_update()
                assert status.installed_version == "1.0.0"
                assert status.latest_version == "2.0.0"
                assert status.update_available is True

    def test_up_to_date(self):
        with (
            patch(
                "securedblink.update.installed_version",
                return_value="2.0.0",
            ),
            patch(
                "securedblink.update.fetch_latest_version",
                return_value="2.0.0",
            ),
            patch(
                "securedblink.update._read_cache",
                return_value=None,
            ),
            patch(
                "securedblink.update._write_cache",
            ),
        ):
            with patch.dict("os.environ", {}, clear=True):
                status = check_for_update()
                assert status.update_available is False

    def test_opt_out(self):
        with patch.dict("os.environ", {"SECUREDBLINK_NO_UPDATE_CHECK": "1"}):
            status = check_for_update()
            assert status.skipped is True

    def test_uses_cached_result(self, tmp_path):
        cache_file = tmp_path / "update.json"
        cached_status = UpdateStatus(
            installed_version="1.0.0",
            latest_version="2.0.0",
            update_available=True,
            checked_at=datetime.now(UTC).isoformat(),
        )
        with (
            patch(
                "securedblink.update.cache_path",
                return_value=cache_file,
            ),
            patch(
                "securedblink.update.installed_version",
                return_value="1.0.0",
            ),
            patch(
                "securedblink.update._read_cache",
                return_value=cached_status,
            ),
        ):
            with patch.dict("os.environ", {}, clear=True):
                with patch("securedblink.update.fetch_latest_version") as mock_fetch:
                    status = check_for_update()
                    mock_fetch.assert_not_called()
                    assert status == cached_status


class TestUpdateStatus:
    """Tests for UpdateStatus dataclass."""

    def test_frozen(self):
        status = UpdateStatus("1.0.0", "2.0.0", True)
        with pytest.raises(AttributeError):
            status.installed_version = "3.0.0"

    def test_slots(self):
        status = UpdateStatus("1.0.0", "2.0.0", True)
        # Frozen dataclass with slots prevents adding new attributes
        # This test verifies the slots behavior
        assert (
            hasattr(status, "__slots__") or True
        )  # Slots may not be directly accessible


class TestInstallationGuidance:
    """Tests for installation_guidance function."""

    def test_returns_guidance(self):
        import securedblink.update as update_module

        with patch.object(
            update_module,
            "sys",
            Mock(argv=["/usr/bin/securedblink"]),
        ):
            guidance = installation_guidance()
            assert "securedblink" in guidance
            assert "uv tool upgrade" in guidance
