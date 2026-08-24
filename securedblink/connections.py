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

import os

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, Engine, make_url

_PREFIX = "DB_"
_RESERVED = {"MAX_ROWS"}  # env vars that are config, not connections


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
    def __init__(self) -> None:
        self._urls: dict[str, str] = _load_urls()
        self._engines: dict[str, Engine] = {}
        self._vault_engines: dict[str, Engine] = {}

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

    def engine(self, name: str) -> Engine:
        """Return (cached) SQLAlchemy engine for the named connection.

        First checks environment variable connections, then vault aliases.
        """
        key = name.lower()

        # First try vault
        try:
            return self._get_vault_engine(key)
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
        """Get engine for a vault alias.

        Credentials stored separately in the vault are applied onto the
        parsed URL. Vault-stored username/password take precedence over
        any credentials embedded in the URL itself.

        Args:
            alias: The vault alias

        Returns:
            SQLAlchemy engine

        Raises:
            ValueError: If the alias is not found in the vault
        """
        from securedblink.vault import get_vault_store

        vault = get_vault_store()
        alias = alias.lower()

        if alias not in self._vault_engines:
            config = vault.get(alias)
            if config is None:
                raise ValueError(f"Vault alias '{alias}' not found.")

            # Extract the URL from the vault config
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

            self._vault_engines[alias] = create_engine(_normalize_oracle_url(url))

        return self._vault_engines[alias]

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
