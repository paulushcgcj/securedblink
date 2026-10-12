"""Regression tests for engine cache invalidation (issue #22).

Revoking a vault alias and rotating its credentials both have to reach the
running server. Before this fix ``ConnectionManager`` cached one engine per
name for the life of the process and nothing ever evicted it, so ``vault_revoke``
reported success while an authenticated pool stayed usable, and ``overwrite=true``
updated the keyring without changing runtime behaviour.

These tests cover both defensive layers: explicit ``invalidate()`` calls from
the mutating tools, and the credential fingerprint that makes a mutation
self-invalidating even when no call site remembered.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import keyring
import pytest
from keyring.errors import PasswordDeleteError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

import securedblink.server as srv
import securedblink.vault.store as store_module
from securedblink.connections import ConnectionManager
from securedblink.vault.check import check_connection_reachability
from securedblink.vault.store import VaultStoreError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_double():
    """A vault double backed by a mutable dict, keyed by lowercased alias.

    Mutating the dict simulates a credential change made behind the manager's
    back, which is what the fingerprint layer has to detect.
    """
    configs: dict[str, dict[str, Any]] = {}
    vault = MagicMock()
    vault.get.side_effect = lambda alias: configs.get(alias)
    vault.exists.side_effect = lambda alias: alias in configs
    vault.list_aliases.side_effect = lambda: sorted(configs)
    return vault, configs


def vault_config(password: str = "pw", username: str = "app") -> dict[str, Any]:
    """A vault config entry carrying credentials.

    Uses a PostgreSQL URL because SQLite rejects a userinfo component, and
    these tests only construct engines - they never connect.
    """
    return {
        "jdbc_url": "postgresql://host:5432/db",
        "username": username,
        "password": password,
    }


# ---------------------------------------------------------------------------
# Fingerprint layer: rotation detected without an explicit invalidate() call
# ---------------------------------------------------------------------------


class TestCredentialFingerprint:
    def test_unchanged_credentials_reuse_cached_engine(self, vault_double):
        """The safety net must not defeat caching when nothing changed."""
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            first = manager.engine("prod")
            second = manager.engine("prod")
        assert first is second

    def test_rotated_password_rebuilds_engine(self, vault_double):
        """Issue #22 probe 1b: a wrong password must not keep working."""
        vault, configs = vault_double
        configs["prod"] = vault_config(password="good")
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            before = manager.engine("prod")
            assert before.url.password == "good"

            configs["prod"] = vault_config(password="rotated")
            after = manager.engine("prod")

        assert after.url.password == "rotated"
        assert after is not before

    def test_rotated_username_rebuilds_engine(self, vault_double):
        vault, configs = vault_double
        configs["prod"] = vault_config(username="old")
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            before = manager.engine("prod")
            configs["prod"] = vault_config(username="new")
            after = manager.engine("prod")
        assert before.url.username == "old"
        assert after.url.username == "new"

    def test_changed_url_rebuilds_engine(self, vault_double):
        vault, configs = vault_double
        configs["prod"] = {"jdbc_url": "sqlite:///:memory:"}
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            before = manager.engine("prod")
            configs["prod"] = {"jdbc_url": "sqlite:///other.db"}
            after = manager.engine("prod")
        assert str(after.url) != str(before.url)

    def test_rotation_disposes_previous_engine(self, vault_double):
        """Evicting the dict entry is not enough; the pool must be closed."""
        vault, configs = vault_double
        configs["prod"] = vault_config(password="good")
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            before = manager.engine("prod")
            with patch.object(before, "dispose", wraps=before.dispose) as spy:
                configs["prod"] = vault_config(password="rotated")
                manager.engine("prod")
        spy.assert_called_once()

    def test_fingerprint_is_keyed_per_manager(self, vault_double):
        """A leaked fingerprint must not be brute-forceable offline.

        Each manager salts its digest, so the same config yields different
        fingerprints across instances.
        """
        config = vault_config(password="hunter2")
        first = ConnectionManager()._fingerprint(config)
        second = ConnectionManager()._fingerprint(config)
        assert first != second
        assert "hunter2" not in first


# ---------------------------------------------------------------------------
# Fail closed on revocation
# ---------------------------------------------------------------------------


class TestRevocationFailsClosed:
    def test_revoked_alias_stops_resolving(self, vault_double):
        """Issue #22 probe 2d: no live connection attempt after revoke."""
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            manager.engine("prod")

            del configs["prod"]
            with pytest.raises(ValueError, match="not found"):
                manager.engine("prod")

    def test_revoked_alias_disposes_pool_and_builds_no_engine(self, vault_double):
        """The pool is closed and no replacement engine is constructed."""
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.engine("prod")

            del configs["prod"]
            with (
                patch.object(engine, "dispose", wraps=engine.dispose) as spy,
                patch("securedblink.connections.create_engine") as build,
                pytest.raises(ValueError, match="not found"),
            ):
                manager.engine("prod")

        spy.assert_called_once()
        build.assert_not_called()

    def test_unreadable_vault_is_distinguished_from_revoked(self, vault_double):
        """A locked keyring must not be reported as a missing alias.

        Both look like ``get() -> None``. Misattributing one to the other sends
        the operator hunting for a credential problem that does not exist.
        """
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.engine("prod")

            # Index still lists the alias, but the secret cannot be read.
            vault.get.side_effect = lambda alias: None
            vault.exists.side_effect = lambda alias: True

            with (
                patch.object(engine, "dispose", wraps=engine.dispose) as spy,
                pytest.raises(ValueError, match="could not be read"),
            ):
                manager.engine("prod")

        spy.assert_called_once()

    def test_unreadable_vault_still_fails_closed(self, vault_double):
        """An unverifiable credential must never be served from cache."""
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            manager.engine("prod")
            vault.get.side_effect = lambda alias: None
            vault.exists.side_effect = lambda alias: True
            with pytest.raises(ValueError):
                manager.engine("prod")
            assert manager._vault_engines == {}


# ---------------------------------------------------------------------------
# Env-var engines are a separate namespace
# ---------------------------------------------------------------------------


class TestEnvEnginesAreIsolated:
    def test_vault_miss_does_not_dispose_env_engine(self, monkeypatch, vault_double):
        """A vault lookup failure must not tear down a live env pool.

        ``engine()`` probes the vault before falling back to env vars, so an
        over-broad eviction here would dispose a healthy pool on every query.
        """
        monkeypatch.setenv("DB_ENV", "sqlite:///:memory:")
        vault, _configs = vault_double
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            first = manager.engine("env")
            with patch.object(first, "dispose") as spy:
                second = manager.engine("env")
        assert second is first
        spy.assert_not_called()

    def test_env_engine_stays_cached_across_lookups(self, monkeypatch, vault_double):
        monkeypatch.setenv("DB_ENV", "sqlite:///:memory:")
        vault, _configs = vault_double
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            assert manager.engine("ENV") is manager.engine("env")


# ---------------------------------------------------------------------------
# Explicit invalidate()
# ---------------------------------------------------------------------------


class TestInvalidate:
    def test_named_alias_is_disposed_and_evicted(self, vault_double):
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.engine("prod")
            with patch.object(engine, "dispose", wraps=engine.dispose) as spy:
                assert manager.invalidate("prod") == 1
            spy.assert_called_once()
            assert manager._vault_engines == {}
            assert manager._vault_fingerprints == {}

    def test_alias_lookup_is_case_insensitive(self, vault_double):
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            manager.engine("prod")
            assert manager.invalidate("PROD") == 1

    def test_unknown_alias_is_a_noop(self, vault_double):
        vault, _configs = vault_double
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            assert manager.invalidate("never-registered") == 0

    def test_none_clears_both_namespaces(self, monkeypatch, vault_double):
        monkeypatch.setenv("DB_ENV", "sqlite:///:memory:")
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            manager.engine("env")
            manager.engine("prod")
            assert manager.invalidate() == 2
            assert manager._engines == {}
            assert manager._vault_engines == {}

    def test_dispose_failure_does_not_propagate(self, vault_double):
        """Cleanup is best effort and must not mask the caller's outcome."""
        vault, configs = vault_double
        configs["prod"] = vault_config()
        with patch("securedblink.vault.get_vault_store", return_value=vault):
            manager = ConnectionManager()
            engine = manager.engine("prod")
            with patch.object(engine, "dispose", side_effect=OSError("socket gone")):
                assert manager.invalidate("prod") == 1
            assert manager._vault_engines == {}


# ---------------------------------------------------------------------------
# Tool wiring: every vault mutation invalidates
# ---------------------------------------------------------------------------


class TestToolsInvalidate:
    def test_register_connection_invalidates(self):
        manager = MagicMock()
        manager.invalidate.return_value = 1
        with (
            patch.object(srv, "_db", manager),
            patch(
                "securedblink.server.verify_and_store_connection",
                return_value=(True, None),
            ),
        ):
            result = srv.vault_register_connection("prod", "sqlite:///db")
        manager.invalidate.assert_called_once_with("prod")
        assert result["status"] == "registered"
        assert result["engines_disposed"] == 1

    def test_register_from_path_invalidates(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.env"
        config_file.write_text("DB_URL=sqlite:///db\nDB_USERNAME=alice\n")
        monkeypatch.setenv("SECUREDBLINK_ALLOWED_ROOTS", str(tmp_path))
        manager = MagicMock()
        manager.invalidate.return_value = 1
        with (
            patch.object(srv, "_db", manager),
            patch(
                "securedblink.server.verify_and_store_connection",
                return_value=(True, None),
            ),
        ):
            result = srv.vault_register_from_path("local", str(config_file))
        manager.invalidate.assert_called_once_with("local")
        assert result["status"] == "registered"

    def test_failed_check_does_not_invalidate(self):
        """Nothing was stored, so no cached engine became stale."""
        manager = MagicMock()
        with (
            patch.object(srv, "_db", manager),
            patch(
                "securedblink.server.verify_and_store_connection",
                return_value=(False, None),
            ),
        ):
            result = srv.vault_register_connection("prod", "sqlite:///db")
        manager.invalidate.assert_not_called()
        assert result["status"] == "check_failed"

    def test_revoke_invalidates(self):
        vault = MagicMock()
        vault.exists.return_value = True
        manager = MagicMock()
        manager.invalidate.return_value = 1
        with patch.object(srv, "_vault", vault), patch.object(srv, "_db", manager):
            result = srv.vault_revoke("prod")
        manager.invalidate.assert_called_once_with("prod")
        assert result["status"] == "revoked"
        assert result["engines_disposed"] == 1

    def test_revoke_invalidates_even_when_secret_deletion_fails(self):
        """The alias is de-listed, so it must stop resolving regardless."""
        vault = MagicMock()
        vault.exists.return_value = True
        vault.delete.side_effect = VaultStoreError("keyring locked")
        manager = MagicMock()
        manager.invalidate.return_value = 1
        with patch.object(srv, "_vault", vault), patch.object(srv, "_db", manager):
            result = srv.vault_revoke("prod")
        manager.invalidate.assert_called_once_with("prod")
        assert result["status"] == "revoke_incomplete"
        assert "error" in result
        assert result["engines_disposed"] == 1

    def test_revoke_incomplete_error_is_redacted(self):
        vault = MagicMock()
        vault.exists.return_value = True
        vault.delete.side_effect = VaultStoreError(
            "failed for postgresql://user:supersecret@host/db"
        )
        with patch.object(srv, "_vault", vault), patch.object(srv, "_db", MagicMock()):
            result = srv.vault_revoke("prod")
        assert "supersecret" not in result["error"]

    def test_update_connection_invalidates(self):
        """Issue #21 added this path after #22 was filed, without invalidating."""
        vault = MagicMock()
        vault.get.return_value = {"jdbc_url": "sqlite:///db", "username": "app"}
        manager = MagicMock()
        manager.invalidate.return_value = 1
        with patch.object(srv, "_vault", vault), patch.object(srv, "_db", manager):
            result = srv.vault_update_connection("prod", password="rotated")
        manager.invalidate.assert_called_once_with("prod")
        assert result["status"] == "updated"
        assert result["fields_updated"] == ["password"]
        assert result["engines_disposed"] == 1

    def test_update_missing_alias_does_not_invalidate(self):
        vault = MagicMock()
        vault.get.return_value = None
        manager = MagicMock()
        with patch.object(srv, "_vault", vault), patch.object(srv, "_db", manager):
            result = srv.vault_update_connection("ghost", password="x")
        manager.invalidate.assert_not_called()
        assert result["status"] == "failed"


# ---------------------------------------------------------------------------
# Reachability check disposes its throwaway engine
# ---------------------------------------------------------------------------


class TestCheckEngineDisposal:
    def test_disposes_engine_on_success(self):
        engine = create_engine("sqlite:///:memory:")
        with (
            patch("securedblink.vault.check.create_engine", return_value=engine),
            patch.object(engine, "dispose", wraps=engine.dispose) as spy,
        ):
            result = check_connection_reachability("sqlite:///:memory:")
        assert result.success is True
        spy.assert_called_once()

    def test_disposes_engine_when_probe_fails(self):
        """The failure paths return early, so cleanup cannot live in them."""
        engine = create_engine("sqlite:///:memory:")
        with (
            patch("securedblink.vault.check.create_engine", return_value=engine),
            patch.object(engine, "dispose", wraps=engine.dispose) as spy,
            patch(
                "securedblink.vault.check.text",
                side_effect=SQLAlchemyError("probe failed"),
            ),
        ):
            result = check_connection_reachability("sqlite:///:memory:")
        assert result.success is False
        spy.assert_called_once()

    def test_no_dispose_when_engine_construction_fails(self):
        """There is no engine to clean up if create_engine itself raised."""
        with patch(
            "securedblink.vault.check.create_engine",
            side_effect=SQLAlchemyError("cannot build"),
        ):
            result = check_connection_reachability("sqlite:///:memory:")
        assert result.success is False


# ---------------------------------------------------------------------------
# End to end: the scenario from the bug report, through the real tools
# ---------------------------------------------------------------------------


@pytest.fixture
def live_stack(tmp_path, monkeypatch):
    """A real VaultStore and ConnectionManager wired into the server module.

    The keyring is replaced with an in-memory dict so the vault genuinely
    stores and forgets secrets, and the alias index lives in tmp_path. Nothing
    here is mocked except the credential manager itself, which is the boundary.
    """
    secrets: dict[str, str] = {}

    def fake_set(service: str, username: str, password: str) -> None:
        secrets[username] = password

    def fake_get(service: str, username: str) -> str | None:
        return secrets.get(username)

    def fake_delete(service: str, username: str) -> None:
        if username not in secrets:
            raise PasswordDeleteError(username)
        del secrets[username]

    monkeypatch.setattr(keyring, "set_password", fake_set)
    monkeypatch.setattr(keyring, "get_password", fake_get)
    monkeypatch.setattr(keyring, "delete_password", fake_delete)

    index_dir = tmp_path / ".securedblink"
    index_dir.mkdir()
    monkeypatch.setattr(store_module, "INDEX_DIR", index_dir)
    monkeypatch.setattr(store_module, "INDEX_FILE", index_dir / "aliases.json")
    monkeypatch.setattr(store_module, "_vault_store", None)

    vault = store_module.VaultStore()
    manager = ConnectionManager()

    with (
        patch.object(srv, "_vault", vault),
        patch.object(srv, "_db", manager),
        patch("securedblink.vault.get_vault_store", return_value=vault),
    ):
        yield vault, manager, tmp_path

    monkeypatch.setattr(store_module, "_vault_store", None)


def seed_sqlite(path, label: str) -> None:
    """Create a SQLite file holding one row that identifies it."""
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE marker (label TEXT)"))
            conn.execute(
                text("INSERT INTO marker (label) VALUES (:label)"), {"label": label}
            )
    finally:
        engine.dispose()


class TestEndToEndRotationAndRevocation:
    def test_updated_url_takes_effect_without_a_restart(self, live_stack):
        """Rotating a connection must change what queries actually hit.

        Before the fix the cached engine kept serving the original target and
        the operator saw ``{"status": "updated"}`` for a change that no-oped.
        """
        _vault, _manager, tmp = live_stack
        first, second = tmp / "first.db", tmp / "second.db"
        seed_sqlite(first, "first-db")
        seed_sqlite(second, "second-db")

        registered = srv.vault_register_connection(
            "rot", f"sqlite:///{first}", skip_check=True
        )
        assert registered["status"] == "registered"
        assert "first-db" in srv.query("rot", "SELECT label FROM marker")

        updated = srv.vault_update_connection("rot", jdbc_url=f"sqlite:///{second}")
        assert updated["status"] == "updated"
        assert "second-db" in srv.query("rot", "SELECT label FROM marker")

    def test_revoked_alias_stops_resolving(self, live_stack):
        """Issue #22 probe 2d: revoke must end access, not just de-list."""
        _vault, manager, tmp = live_stack
        target = tmp / "target.db"
        seed_sqlite(target, "here")

        srv.vault_register_connection("gone", f"sqlite:///{target}", skip_check=True)
        assert "here" in srv.query("gone", "SELECT label FROM marker")

        revoked = srv.vault_revoke("gone")
        assert revoked["status"] == "revoked"
        assert manager._vault_engines == {}

        with pytest.raises(ValueError, match="not found"):
            srv.query("gone", "SELECT label FROM marker")

    def test_reregister_after_revoke_works(self, live_stack):
        """Issue #22 probe 3a: reuse of a revoked name must recover."""
        _vault, _manager, tmp = live_stack
        target = tmp / "reuse.db"
        seed_sqlite(target, "reused")

        srv.vault_register_connection("a", f"sqlite:///{target}", skip_check=True)
        assert "reused" in srv.query("a", "SELECT label FROM marker")

        srv.vault_revoke("a")
        srv.vault_register_connection("a", f"sqlite:///{target}", skip_check=True)
        assert "reused" in srv.query("a", "SELECT label FROM marker")

    def test_overwrite_registration_takes_effect(self, live_stack):
        """The overwrite=true path from probe 1b, exercised end to end."""
        _vault, _manager, tmp = live_stack
        first, second = tmp / "one.db", tmp / "two.db"
        seed_sqlite(first, "original")
        seed_sqlite(second, "replaced")

        srv.vault_register_connection("ow", f"sqlite:///{first}", skip_check=True)
        assert "original" in srv.query("ow", "SELECT label FROM marker")

        again = srv.vault_register_connection(
            "ow", f"sqlite:///{second}", skip_check=True, overwrite=True
        )
        assert again["status"] == "registered"
        assert "replaced" in srv.query("ow", "SELECT label FROM marker")

    def test_revoke_disposes_the_pool_of_a_live_connection(self, live_stack):
        """Closing the pool is what actually cuts off access at the database."""
        _vault, manager, tmp = live_stack
        target = tmp / "pooled.db"
        seed_sqlite(target, "live")

        srv.vault_register_connection("p", f"sqlite:///{target}", skip_check=True)
        srv.query("p", "SELECT label FROM marker")
        engine = manager._vault_engines["p"]

        with patch.object(engine, "dispose", wraps=engine.dispose) as spy:
            srv.vault_revoke("p")

        spy.assert_called_once()
