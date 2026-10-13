"""Regression tests for scripts/bump_version.py.

The v0.10.0 release exposed two defects in the release tooling, both of which
produced a wrong result silently: an unanchored version substitution that
overwrote ruff's and mypy's configuration, and a changelog promotion that
discarded every entry logged since the previous release. These tests pin the
corrected behaviour so a future release cannot repeat either one.
"""

import importlib.util
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "bump_version.py"


@pytest.fixture
def bv():
    """Load scripts/bump_version.py as a module without putting it on sys.path."""
    spec = importlib.util.spec_from_file_location("bump_version_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pyproject_copy(tmp_path):
    """A writable copy of the real manifest."""
    target = tmp_path / "pyproject.toml"
    shutil.copy(REPO_ROOT / "pyproject.toml", target)
    return target


class TestUpdatePyprojectToml:
    def test_rewrites_only_the_project_version(self, bv, pyproject_copy):
        """Tool config must survive a version bump.

        ``target-version`` and ``python_version`` both contain ``version = "``
        as a substring, so an unanchored global substitution replaced ruff's
        ``py312`` and mypy's ``3.12`` with the release number and broke linting
        and type checking across the repository.
        """
        bv.PYPROJECT_TOML = pyproject_copy
        bv.update_pyproject_toml("9.9.9")

        content = pyproject_copy.read_text()
        assert 'version = "9.9.9"' in content
        assert 'target-version = "py312"' in content
        assert 'python_version = "3.12"' in content
        # Would be 3 if the tool keys had been rewritten too.
        assert content.count('version = "9.9.9"') == 1

    def test_leaves_requires_python_alone(self, bv, pyproject_copy):
        bv.PYPROJECT_TOML = pyproject_copy
        bv.update_pyproject_toml("9.9.9")
        assert 'requires-python = ">=3.12"' in pyproject_copy.read_text()

    def test_refuses_to_guess_without_exactly_one_match(self, bv, tmp_path):
        """A silent no-op would release a tag that does not match the manifest."""
        target = tmp_path / "pyproject.toml"
        target.write_text('[project]\nname = "x"\n')
        bv.PYPROJECT_TOML = target
        with pytest.raises(ValueError, match="exactly one"):
            bv.update_pyproject_toml("1.0.0")

    def test_dry_run_writes_nothing(self, bv, pyproject_copy):
        before = pyproject_copy.read_text()
        bv.PYPROJECT_TOML = pyproject_copy
        bv.update_pyproject_toml("9.9.9", dry_run=True)
        assert pyproject_copy.read_text() == before


class TestGetCurrentVersion:
    def test_reads_tags_not_the_manifest(self, bv, monkeypatch, tmp_path):
        """The manifest holds a placeholder; the tags are what shipped.

        Reading pyproject.toml made ``patch`` compute 0.1.1 while 0.9.0 was
        already live on PyPI, which would have published a release lower than
        the one users already had.
        """
        fake = tmp_path / "pyproject.toml"
        fake.write_text('[project]\nversion = "0.1.0"\n')
        bv.PYPROJECT_TOML = fake
        monkeypatch.setattr(
            bv.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="v9.8.7\n"),
        )
        assert bv.get_current_version() == "9.8.7"

    def test_falls_back_to_manifest_when_no_tags(self, bv, monkeypatch, tmp_path):
        fake = tmp_path / "pyproject.toml"
        fake.write_text('[project]\nversion = "0.1.0"\n')
        bv.PYPROJECT_TOML = fake
        monkeypatch.setattr(
            bv.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="no tags"),
        )
        assert bv.get_current_version() == "0.1.0"


@pytest.fixture
def sample_changelog(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n"
        "\n"
        "## [Unreleased]\n"
        "\n"
        "### Fixed\n"
        "- an entry that must survive (#1)\n"
        "\n"
        "### Dependencies\n"
        "- chore(deps): bump something (#2)\n"
        "\n"
        "## [v0.9.0] - 2026-08-24\n"
        "\n"
        "### Fixed\n"
        "- an older entry\n"
        "\n"
        "[Unreleased]: https://example.com/compare/v0.9.0...HEAD\n"
        "[v0.9.0]: https://example.com/compare/v0.8.1...v0.9.0\n"
    )
    return changelog


class TestUpdateChangelog:
    def test_promotes_entries_instead_of_discarding(self, bv, sample_changelog):
        """Accumulated entries move into the release section."""
        bv.CHANGELOG_MD = sample_changelog
        bv.update_changelog("0.10.0", "0.9.0")

        content = sample_changelog.read_text()
        assert "- an entry that must survive (#1)" in content
        assert "- chore(deps): bump something (#2)" in content
        assert "- an older entry" in content
        assert "## [v0.10.0] - " in content

    def test_leaves_a_fresh_empty_unreleased(self, bv, sample_changelog):
        bv.CHANGELOG_MD = sample_changelog
        bv.update_changelog("0.10.0", "0.9.0")
        content = sample_changelog.read_text()
        assert "## [Unreleased]\n\n## [v0.10.0] - " in content

    def test_writes_a_real_compare_range(self, bv, sample_changelog):
        """The previous link ended in a bare ``compare/`` and resolved nowhere.

        The script always writes the canonical repository URL, so the range is
        asserted against ``REPO_URL`` rather than the fixture's placeholder.
        """
        bv.CHANGELOG_MD = sample_changelog
        bv.update_changelog("0.10.0", "0.9.0")

        content = sample_changelog.read_text()
        assert f"{bv.REPO_URL}/compare/v0.9.0...v0.10.0" in content
        assert f"{bv.REPO_URL}/compare/v0.10.0...HEAD" in content
        assert "compare/\n" not in content

    def test_no_empty_stub_headings(self, bv, sample_changelog):
        bv.CHANGELOG_MD = sample_changelog
        bv.update_changelog("0.10.0", "0.9.0")
        assert "### Features\n\n### Fixed\n\n### Documentation" not in (
            sample_changelog.read_text()
        )

    def test_warns_and_writes_nothing_without_unreleased(self, bv, tmp_path, capsys):
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\n## [v0.9.0] - 2026-08-24\n")
        bv.CHANGELOG_MD = changelog
        bv.update_changelog("0.10.0", "0.9.0")
        assert "Warning" in capsys.readouterr().out
        assert "## [v0.10.0]" not in changelog.read_text()

    def test_dry_run_writes_nothing(self, bv, sample_changelog):
        before = sample_changelog.read_text()
        bv.CHANGELOG_MD = sample_changelog
        bv.update_changelog("0.10.0", "0.9.0", dry_run=True)
        assert sample_changelog.read_text() == before


class TestBumpVersion:
    @pytest.mark.parametrize(
        ("bump_type", "expected"),
        [
            ("patch", "0.9.1"),
            ("minor", "0.10.0"),
            ("major", "1.0.0"),
        ],
    )
    def test_bump_types(self, bv, bump_type, expected):
        assert bv.bump_version("0.9.0", bump_type=bump_type) == expected

    def test_minor_rolls_past_nine(self, bv):
        """0.9.0 + minor is 0.10.0, not 0.10.0 truncated or 1.0.0."""
        assert bv.bump_version("0.9.0", bump_type="minor") == "0.10.0"

    def test_explicit_target_wins(self, bv):
        assert bv.bump_version("0.9.0", target_version="2.5.0") == "2.5.0"

    def test_rejects_malformed_target(self, bv):
        with pytest.raises(ValueError, match="Invalid version format"):
            bv.bump_version("0.9.0", target_version="v0.10.0")

    def test_rejects_unknown_bump_type(self, bv):
        with pytest.raises(ValueError, match="Invalid bump type"):
            bv.bump_version("0.9.0", bump_type="micro")

    def test_requires_an_instruction(self, bv):
        with pytest.raises(ValueError, match="must be provided"):
            bv.bump_version("0.9.0")
