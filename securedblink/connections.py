"""Database connection manager.

Reads connection URLs from environment variables prefixed with DB_:
    DB_PROD=postgresql://user:pass@host:5432/mydb
    DB_LOCAL=sqlite:///./local.db
    DB_WAREHOUSE=oracle+oracledb://user:pass@host:1521/service

Connection names are the suffix after DB_, lowercased (e.g. DB_PROD -> 'prod').

For Oracle URLs, a bare path segment is treated as a service name (matching
JDBC thin convention) and promoted to the explicit ``service_name`` query
parameter. Pass ``?sid=<name>`` to force legacy SID resolution instead.

Also supports vault-based connections registered via the credential vault.
Use ConnectionManager.get_engine_by_alias() to retrieve vault-stored connections.
"""

import hashlib
import json
import os
import secrets
import threading
from typing import TYPE_CHECKING, Any

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, Engine, make_url

from securedblink.log import get_logger

if TYPE_CHECKING:
    from securedblink.vault.store import VaultStore

log = get_logger(__name__)

_PREFIX = "DB_"
_RESERVED = {"MAX_ROWS"}  # env vars that are config, not connections

# Config fields that determine a cached engine's identity. A change to any of
# them means the cached engine is holding credentials that no longer exist.
_FINGERPRINT_FIELDS = ("driver", "jdbc_url", "password", "username")


class VaultUnreadableError(ValueError):
    """The vault lists the alias but its stored config could not be read.

    Subclasses ``ValueError`` so existing handlers keep working. It exists so
    :meth:`ConnectionManager.engine` can tell a locked credential manager apart
    from a revoked alias instead of falling through to env vars and reporting a
    confusing "not found" for an alias the index says is registered.
    """


def _dispose_all(engines: list[Engine]) -> None:
    """Close every engine's connection pool, best effort.

    Runs outside the cache lock because closing pooled connections can block on
    the network. A failure here must not mask the caller's own error, so it is
    logged and swallowed.
    """
    for engine in engines:
        try:
            engine.dispose()
        except Exception as exc:
            log.warning("engine_dispose_failed", error=type(exc).__name__)


def _load_urls() -> dict[str, str]:
    prefix_upper = _PREFIX.upper()
    return {
        key[len(_PREFIX) :].lower(): val
        for key, val in os.environ.items()
        if key.upper().startswith(prefix_upper)
        and key[len(_PREFIX) :].upper() not in _RESERVED
    }


def _normalize_oracle_url(url: URL) -> URL:
    """Promote an Oracle URL path segment to the ``service_name`` parameter.

    JDBC thin URLs and Spring-style configurations place a service name in
    the path segment (``//host:port/service``), but SQLAlchemy's Oracle
    dialects interpret that segment as a SID. Promote it to the explicit
    ``service_name`` query parameter so connections resolve against the
    service registered with the listener. Callers needing legacy SID
    semantics pass ``?sid=<name>``; explicit ``service_name`` or ``sid``
    parameters are always respected. Non-Oracle URLs pass through unchanged.
    """
    if not (url.drivername == "oracle" or url.drivername.startswith("oracle+")):
        return url
    if not url.database:
        return url
    if {"service_name", "sid"} & set(url.query):
        return url
    return url.set(database="").update_query_dict({"service_name": url.database})


class ConnectionManager:
    """Resolve connection names to cached SQLAlchemy engines.

    Engines are cached per name because building one is cheap but connecting is
    not. The cache is the reason credential rotation and revocation need active
    invalidation: a cached engine keeps the credentials it was built with, so
    without eviction it serves secrets that no longer exist in the vault.

    Two mechanisms keep it honest:

    - :meth:`invalidate` is called by every tool that mutates the vault, so
      pooled connections built from old credentials are closed immediately.
    - Vault engines are revalidated against a fingerprint of the stored config
      on every lookup, so a mutation that bypassed :meth:`invalidate` - a new
      tool that forgot it, or a change made by another process such as the CLI -
      is still picked up on next use instead of being served stale.
    """

    def __init__(self) -> None:
        self._urls: dict[str, str] = _load_urls()
        self._engines: dict[str, Engine] = {}
        self._vault_engines: dict[str, Engine] = {}
        self._vault_fingerprints: dict[str, str] = {}
        # Keyed digest, so a fingerprint that escapes into a repr or a debug
        # dump cannot be brute-forced back into the password it came from.
        self._fingerprint_key = secrets.token_bytes(32)
        self._lock = threading.RLock()

    def names(self) -> list[str]:
        """Return sorted list of configured connection names (env vars only).

        For vault aliases, use vault_names() or all_names().
        """
        return sorted(self._urls.keys())

    def vault_names(self) -> list[str]:
        """Return sorted list of vault alias names."""
        from securedblink.vault import get_vault_store

        vault = get_vault_store()
        return vault.list_aliases()

    def all_names(self) -> list[str]:
        """Return sorted list of all connection names (env vars + vault)."""
        env_names = set(self.names())
        vault_names = set(self.vault_names())
        return sorted(env_names | vault_names)

    def invalidate(self, alias: str | None = None) -> int:
        """Dispose cached engines so credential changes take effect at once.

        Revocation is only real once the pooled connections built from the old
        credentials are closed, so evicting the cache entry is not enough on its
        own: every detached engine is disposed here.

        The fingerprint check in :meth:`engine` already catches mutations that
        never call this. Call it anyway on every vault mutation so access is cut
        off at the moment of the change rather than on next use.

        Args:
            alias: Connection name or vault alias to evict. ``None`` evicts
                every cached engine.

        Returns:
            The number of engines whose connection pools were closed.
        """
        with self._lock:
            targets = (
                list(self._engines) + list(self._vault_engines)
                if alias is None
                else [alias.lower()]
            )
            stale: list[Engine] = []
            for name in targets:
                stale.extend(self._pop_all_locked(name))

        _dispose_all(stale)
        if stale:
            log.info("engine_cache_invalidated", alias=alias, disposed=len(stale))
        return len(stale)

    def _fingerprint(self, config: dict[str, Any]) -> str:
        """Return a keyed digest of the credential-bearing config fields."""
        canonical = json.dumps(
            {field: config.get(field) for field in _FINGERPRINT_FIELDS},
            sort_keys=True,
            default=str,
        )
        return hashlib.blake2b(
            canonical.encode("utf-8"),
            digest_size=32,
            key=self._fingerprint_key,
        ).hexdigest()

    def _pop_all_locked(self, name: str) -> list[Engine]:
        """Detach every cached engine for ``name``. The caller holds the lock.

        Env-var and vault engines are separate namespaces that can share a name,
        so an explicit flush drops both.

        Detaching under the lock and disposing after releasing it keeps a slow
        ``dispose()`` from blocking concurrent lookups.

        Args:
            name: The lowercased connection name or vault alias

        Returns:
            The engines that were cached under that name, now unregistered
        """
        engines = self._pop_vault_locked(name)
        env_engine = self._engines.pop(name, None)
        if env_engine is not None:
            engines.append(env_engine)
        return engines

    def _pop_vault_locked(self, alias: str) -> list[Engine]:
        """Detach only the cached vault engine. The caller holds the lock.

        Env-var engines are built from ``os.environ``, which does not change at
        runtime, so a vault miss must never evict or dispose them. Popping both
        namespaces here would tear down a live env pool on every lookup.

        Args:
            alias: The lowercased vault alias

        Returns:
            A one-item list if a vault engine was cached, otherwise empty
        """
        self._vault_fingerprints.pop(alias, None)
        engine = self._vault_engines.pop(alias, None)
        return [] if engine is None else [engine]

    def _build_vault_engine(self, alias: str, config: dict[str, Any]) -> Engine:
        """Create an engine from a stored vault config.

        Args:
            alias: The vault alias, used in error messages
            config: The stored connection config

        Returns:
            A new, uncached SQLAlchemy engine

        Raises:
            ValueError: If the config carries no connection URL
        """
        jdbc_url = config.get("jdbc_url")
        if not jdbc_url:
            raise ValueError(f"Vault alias '{alias}' has no connection URL.")

        url = make_url(jdbc_url)
        username = config.get("username")
        password = config.get("password")
        if username:
            url = url.set(username=username)
        if password:
            url = url.set(password=password)
        return create_engine(_normalize_oracle_url(url))

    def _resolve_vault_engine(
        self, vault: "VaultStore", alias: str, stale: list[Engine]
    ) -> tuple[Engine, bool]:
        """Return the engine for ``alias``, refreshing the cache under the lock.

        Args:
            vault: The vault store to read the current config from
            alias: The lowercased vault alias
            stale: Output list. Engines detached here must be disposed by the
                caller once the lock is released.

        Returns:
            The engine to use, and whether it replaced a stale cached one

        Raises:
            ValueError: If the vault has no config for the alias, or the config
                has no connection URL
            VaultUnreadableError: If the alias is still registered but its
                secret could not be read, and a cached engine was dropped
        """
        with self._lock:
            config = vault.get(alias)
            if config is None:
                # Fail closed. Serving a cached engine here is exactly what made
                # revocation ineffective: the secret is gone from the vault but
                # the pool would still be authenticated and usable.
                evicted = self._pop_vault_locked(alias)
                stale.extend(evicted)
                # Only spend an index read on disambiguation when a working
                # engine is actually being dropped. A plain miss - an env-var
                # name, or an alias that was never registered - needs none, and
                # this path runs on every env lookup.
                if evicted and vault.exists(alias):
                    raise VaultUnreadableError(
                        f"Vault alias '{alias}' is registered, but its stored "
                        f"credentials could not be read from the credential "
                        f"manager. The cached connection pool was closed, so "
                        f"this alias is unavailable until the credential "
                        f"manager is readable again."
                    )
                raise ValueError(f"Vault alias '{alias}' not found.")

            fingerprint = self._fingerprint(config)
            cached = self._vault_engines.get(alias)
            if (
                cached is not None
                and self._vault_fingerprints.get(alias) == fingerprint
            ):
                return cached, False

            stale.extend(self._pop_vault_locked(alias))
            engine = self._build_vault_engine(alias, config)
            self._vault_engines[alias] = engine
            self._vault_fingerprints[alias] = fingerprint
            return engine, cached is not None

    def engine(self, name: str) -> Engine:
        """Return (cached) SQLAlchemy engine for the named connection.

        First checks environment variable connections, then vault aliases.
        """
        key = name.lower()

        # First try vault
        try:
            return self._get_vault_engine(key)
        except VaultUnreadableError:
            # The alias is registered but its secret could not be read. Falling
            # back to env vars would report "not found" for an alias the index
            # says exists, which sends the operator looking for a missing
            # connection instead of a locked credential manager.
            raise
        except ValueError:
            pass

        # Then try environment variables
        if key not in self._engines:
            if key not in self._urls:
                avail_env = (
                    ", ".join(f"'{n}'" for n in sorted(self._urls)) or "none configured"
                )
                avail_vault = self.vault_names()
                vault_list = (
                    ", ".join(f"'{n}'" for n in avail_vault) if avail_vault else "none"
                )
                raise ValueError(
                    f"Connection '{name}' not found.\n"
                    f"Available env connections: {avail_env}\n"
                    f"Available vault aliases: {vault_list}\n"
                    f"Set DB_{name.upper()}=<connection_url> to add via env, "
                    f"or use vault_register_connection to add via vault."
                )
            self._engines[key] = create_engine(
                _normalize_oracle_url(make_url(self._urls[key]))
            )
        return self._engines[key]

    def _get_vault_engine(self, alias: str) -> Engine:
        """Get engine for a vault alias, rebuilt whenever credentials change.

        The stored config is read on every call and compared against the
        fingerprint recorded when the cached engine was built, so a rotation or
        a revocation is picked up on the next lookup even when it came from a
        code path that never called :meth:`invalidate`.

        Credentials stored separately in the vault are applied onto the parsed
        URL. Vault-stored username/password take precedence over any credentials
        embedded in the URL itself.

        Args:
            alias: The vault alias

        Returns:
            SQLAlchemy engine built from the currently stored credentials

        Raises:
            ValueError: If the alias is not in the vault or the stored config
                has no connection URL
            VaultUnreadableError: If the alias is registered but the credential
                manager could not be read
        """
        from securedblink.vault import get_vault_store

        vault = get_vault_store()
        alias = alias.lower()

        stale: list[Engine] = []
        try:
            engine, rotated = self._resolve_vault_engine(vault, alias, stale)
        finally:
            # Outside the lock: dispose() closes live sockets and can block.
            _dispose_all(stale)

        if rotated:
            log.info("vault_engine_rebuilt", alias=alias)
        return engine

    def get_engine_by_alias(self, alias: str) -> Engine:
        """Get engine for a vault alias.

        This is a convenience method that explicitly looks up a vault alias.

        Args:
            alias: The vault alias

        Returns:
            SQLAlchemy engine

        Raises:
            ValueError: If the alias is not found in the vault
        """
        return self._get_vault_engine(alias)

    def is_vault_alias(self, name: str) -> bool:
        """Check if a connection name is a vault alias.

        Args:
            name: The connection name to check

        Returns:
            True if the name is a registered vault alias
        """
        from securedblink.vault import get_vault_store

        vault = get_vault_store()
        return vault.exists(name.lower())
