"""Secure credential storage using the keyring library.

This module provides the storage backend for the credential vault, using
keyring for secure storage and a local index file for alias management.
"""

import datetime
import json
from pathlib import Path
from typing import Any

import keyring.backends

# Service name for keyring
_SERVICE_NAME = "db-mcp"

# Index file to track aliases (no secrets, just metadata)
INDEX_DIR = Path.home() / ".db-mcp"
INDEX_FILE = INDEX_DIR / "aliases.json"


class InsecureKeyringError(Exception):
    """Raised when the detected keyring backend is insecure."""


class VaultStoreError(Exception):
    """Base exception for vault storage errors."""


def _get_keyring_backend_name() -> str:
    """Get the name of the current keyring backend."""
    try:
        backend = keyring.get_keyring()
        return type(backend).__module__ + "." + type(backend).__name__
    except (keyring.errors.KeyringError, ImportError, OSError):
        return "unknown"


def _is_backend_secure() -> bool:
    """Check if the current keyring backend is secure.

    Insecure backends include:
    - keyring.backends.fail.Keyring (fallback that stores plaintext)
    - keyring.backends.chainer.ChainerKeyring (may chain to insecure)
    - Any backend that stores in plaintext files

    Returns:
        True if the backend is secure, False otherwise
    """
    try:
        backend = keyring.get_keyring()
        backend_name = type(backend).__name__

        # These backends are known to be insecure
        insecure_backends = {
            "Keyring",  # fail.Keyring - plaintext fallback
            "ChainerKeyring",  # May chain to insecure
        }

        if backend_name in insecure_backends:
            return False

        # Check the module path for fail backend
        if "fail" in type(backend).__module__:
            return False

        # On Linux, check if using SecretService (secure) vs plaintext
        if "linux" in type(backend).__module__.lower():
            # Linux: libsecret/SecretService is secure
            if (
                "SecretService" in backend_name
                or "secretstorage" in type(backend).__module__
            ):
                return True
            # Other Linux backends may be insecure
            return False

        # macOS Keychain and Windows Credential Manager are secure
        if "Keychain" in backend_name or "Win" in backend_name:
            return True

        # Default to assuming secure if we can't determine
        return True

    except (keyring.errors.KeyringError, ImportError, OSError):
        # If we can't determine, be safe and assume insecure
        return False


def _is_credentials_manager_available() -> bool:
    """Check if a secure credentials manager is available.

    This tries to detect if we're on a system with a working
    credentials manager (Keychain, Secret Service, Credential Manager).
    """
    import platform

    system = platform.system().lower()

    try:
        # Try to detect the actual backend being used
        backend = keyring.get_keyring()

        # On macOS, Keychain should be available
        if system == "darwin":
            from keyring.backends import macOS

            return isinstance(backend, macOS.Keychain)  # type: ignore[attr-defined]

        # On Linux, check for SecretService
        if system == "linux":
            try:
                from keyring.backends import Linux  # type: ignore[attr-defined]

                return isinstance(backend, Linux.SecretService)
            except ImportError:
                pass
            # Try to import the libsecret backend
            try:
                __import__("keyring.backends.secretstorage")
                return True
            except ImportError:
                pass

        # On Windows, check for Credential Manager
        if system == "windows":
            from keyring.backends import Windows

            return isinstance(backend, Windows.WinVaultKeyring)

    except (keyring.errors.KeyringError, ImportError, AttributeError):
        pass

    return False


def verify_secure_backend() -> None:
    """Verify that a secure keyring backend is available.

    This should be called during startup to ensure we don't silently
    store credentials in an insecure backend.

    Raises:
        InsecureKeyringError: If no secure backend is available
    """
    import platform

    system = platform.system().lower()

    # First, check if we have a known secure backend
    if _is_credentials_manager_available():
        return

    # If we can't determine but the backend seems to be working,
    # try to detect insecure fallbacks
    if not _is_backend_secure():
        # Get the backend name for the error message
        backend_name = _get_keyring_backend_name()

        # Build platform-specific help message
        help_messages = {
            "darwin": (
                "On macOS, ensure the Keychain is accessible. "
                "This is typically available by default."
            ),
            "linux": (
                "On Linux, install and run a Secret Service daemon: "
                "sudo apt-get install gnome-keyring libsecret-1-0 libsecret-1-dev "
                "(or equivalent for your distribution). "
                "Then ensure dbus-daemon or gnome-keyring-daemon is running."
            ),
            "windows": (
                "On Windows, the Credential Manager should be available by default."
            ),
        }

        platform_help = help_messages.get(
            system, "Check your system's credential manager."
        )

        raise InsecureKeyringError(
            f"Insecure keyring backend detected: {backend_name}. "
            f"db-mcp refuses to store credentials without a secure backend.\n\n"
            f"{platform_help}\n\n"
            f"If you're in a headless environment without a credential manager, "
            f"consider using the environment variable-based connection method instead "
            f"(DB_<NAME>=<url>)."
        )


def _ensure_index_dir() -> None:
    """Ensure the .db-mcp directory exists."""
    INDEX_DIR.mkdir(parents=True, exist_ok=True)


def _load_index() -> dict[str, Any]:
    """Load the alias index file.

    Returns:
        Dictionary with alias metadata, or empty dict if file doesn't exist
    """
    if not INDEX_FILE.exists():
        return {}

    try:
        with open(INDEX_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_index(data: dict[str, Any]) -> None:
    """Save the alias index file.

    Args:
        data: The index data to save
    """
    _ensure_index_dir()

    # Write atomically using a temp file
    temp_file = INDEX_FILE.with_suffix(".tmp")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        # Atomic rename
        temp_file.replace(INDEX_FILE)
    except OSError as e:
        if temp_file.exists():
            temp_file.unlink()
        raise VaultStoreError(f"Failed to save index file: {e}") from e


class VaultStore:
    """Secure credential storage using keyring.

    This class provides methods to store, retrieve, and delete credentials
    using the keyring library. It also maintains a local index of aliases
    for listing purposes.
    """

    def __init__(self) -> None:
        self._index = _load_index()

    def _ensure_index_loaded(self) -> None:
        """Ensure the index is loaded from disk."""
        self._index = _load_index()

    def _save_index(self) -> None:
        """Save the current index to disk."""
        _save_index(self._index)

    def get(self, alias: str) -> dict[str, Any] | None:
        """Get connection configuration for an alias.

        Args:
            alias: The alias to retrieve

        Returns:
            Dictionary with connection config (jdbc_url, username, password, driver),
            or None if the alias doesn't exist
        """
        try:
            creds_json = keyring.get_password(_SERVICE_NAME, alias)
            if creds_json is None:
                return None

            creds = json.loads(creds_json)
            return dict(creds)
        except (json.JSONDecodeError, keyring.errors.KeyringError):
            # If we can't read the stored data, treat as not found
            return None

    def set(
        self,
        alias: str,
        jdbc_url: str,
        username: str | None = None,
        password: str | None = None,
        driver: str | None = None,
        source: str = "direct",
        overwrite: bool = False,
    ) -> None:
        """Store connection configuration for an alias.

        Args:
            alias: The alias to store under
            jdbc_url: The JDBC connection URL
            username: The database username (optional)
            password: The database password (optional)
            driver: The JDBC driver class (optional)
            source: Source of the connection ("direct" or "path")
            overwrite: If True, overwrite existing alias

        Raises:
            VaultStoreError: If the alias already exists and overwrite is False
        """
        # Normalize alias to lowercase
        alias = alias.lower()

        # Check if alias exists
        if not overwrite and self._index.get(alias):
            raise VaultStoreError(
                f"Alias '{alias}' already exists. Use overwrite=True to replace."
            )

        # Build the connection config
        config = {
            "jdbc_url": jdbc_url,
        }
        if username:
            config["username"] = username
        if password:
            config["password"] = password
        if driver:
            config["driver"] = driver

        # Store in keyring as JSON
        creds_json = json.dumps(config)
        keyring.set_password(_SERVICE_NAME, alias, creds_json)

        # Update index
        self._index[alias] = {
            "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "source": source,
        }
        self._save_index()

    def delete(self, alias: str) -> bool:
        """Delete a connection configuration.

        Args:
            alias: The alias to delete

        Returns:
            True if the alias was deleted, False if it didn't exist
        """
        alias = alias.lower()

        # Delete from keyring
        deleted_keyring = False
        try:
            keyring.delete_password(_SERVICE_NAME, alias)
            deleted_keyring = True
        except keyring.errors.KeyringError:
            pass

        # Delete from index
        deleted_index = alias in self._index
        if deleted_index:
            del self._index[alias]
            self._save_index()

        return deleted_keyring or deleted_index

    def list_aliases(self) -> list[str]:
        """List all registered aliases.

        Returns:
            List of alias names (sorted)
        """
        self._ensure_index_loaded()
        return sorted(self._index.keys())

    def get_metadata(self, alias: str) -> dict[str, Any] | None:
        """Get metadata for an alias.

        Args:
            alias: The alias to get metadata for

        Returns:
            Dictionary with metadata (created_at, source), or None if not found
        """
        alias = alias.lower()
        self._ensure_index_loaded()
        return self._index.get(alias)

    def list_all_metadata(self) -> dict[str, dict[str, Any]]:
        """Get metadata for all aliases.

        Returns:
            Dictionary mapping alias names to their metadata
        """
        self._ensure_index_loaded()
        return dict(self._index)

    def exists(self, alias: str) -> bool:
        """Check if an alias exists.

        Args:
            alias: The alias to check

        Returns:
            True if the alias exists
        """
        alias = alias.lower()
        self._ensure_index_loaded()
        return alias in self._index


# Global vault store instance
_vault_store: VaultStore | None = None


def get_vault_store() -> VaultStore:
    """Get the global vault store instance.

    Returns:
        The global VaultStore instance
    """
    global _vault_store
    if _vault_store is None:
        _vault_store = VaultStore()
    return _vault_store
