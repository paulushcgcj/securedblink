"""Connection resolver for the credential vault.

This module provides functionality to resolve connection configurations
from vault aliases, with fallback to environment variables.
"""

from typing import Any

from dbbridge.vault.store import get_vault_store


class ConnectionResolver:
    """Resolves connection configurations from vault aliases and env vars.

    This class provides a unified interface for retrieving database connection
    configurations, first checking the vault for an alias, then falling back
    to environment variables.
    """

    def __init__(self) -> None:
        self._vault = get_vault_store()

    def resolve(
        self, alias: str | None = None, url: str | None = None
    ) -> dict[str, Any]:
        """Resolve a connection configuration.

        This method attempts to resolve a connection in the following order:
        1. If alias is provided, look it up in the vault
        2. If url is provided, use it directly (for backward compatibility)
        3. If neither is provided, raise an error

        Args:
            alias: The vault alias to resolve (optional)
            url: A direct connection URL (optional, for backward compatibility)

        Returns:
            Dictionary with connection configuration:
            - jdbc_url: The connection URL
            - username: Username (optional)
            - password: Password (optional)
            - driver: Driver class (optional)
            - source: Either "vault" or "direct"

        Raises:
            ValueError: If neither alias nor url is provided, or if the alias is not found
        """
        if alias:
            # Try to resolve from vault
            config = self._vault.get(alias)
            if config:
                # Add source marker
                config = dict(config)
                config["_source"] = "vault"
                config["_alias"] = alias
                return config
            else:
                raise ValueError(
                    f"Alias '{alias}' not found in vault. Use vault_list to see available aliases."
                )

        if url:
            # Direct URL provided
            return {
                "jdbc_url": url,
                "_source": "direct",
            }

        raise ValueError("Either alias or url must be provided")

    def resolve_alias(self, alias: str) -> dict[str, Any]:
        """Resolve a connection configuration from a vault alias.

        Args:
            alias: The vault alias to resolve

        Returns:
            Dictionary with connection configuration

        Raises:
            ValueError: If the alias is not found
        """
        config = self._vault.get(alias)
        if config is None:
            raise ValueError(
                f"Alias '{alias}' not found in vault. Use vault_list to see available aliases."
            )

        result = dict(config)
        result["_source"] = "vault"
        result["_alias"] = alias
        return result

    def resolve_url(self, url: str) -> dict[str, Any]:
        """Resolve a connection configuration from a direct URL.

        Args:
            url: The connection URL

        Returns:
            Dictionary with connection configuration
        """
        return {
            "jdbc_url": url,
            "_source": "direct",
        }

    def get_all_vault_aliases(self) -> list[str]:
        """Get all registered vault aliases.

        Returns:
            List of alias names
        """
        return self._vault.list_aliases()

    def get_vault_metadata(self, alias: str) -> dict[str, Any] | None:
        """Get metadata for a vault alias.

        Args:
            alias: The alias to get metadata for

        Returns:
            Dictionary with metadata (created_at, source), or None if not found
        """
        return self._vault.get_metadata(alias)

    def alias_exists(self, alias: str) -> bool:
        """Check if a vault alias exists.

        Args:
            alias: The alias to check

        Returns:
            True if the alias exists in the vault
        """
        return self._vault.exists(alias)


# Global resolver instance
_resolver: ConnectionResolver | None = None


def get_resolver() -> ConnectionResolver:
    """Get the global connection resolver instance.

    Returns:
        The global ConnectionResolver instance
    """
    global _resolver
    if _resolver is None:
        _resolver = ConnectionResolver()
    return _resolver
