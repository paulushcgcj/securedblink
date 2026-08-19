"""securedblink credential vault.

This module provides a secure credential vault for storing database connection
configuration. It uses the keyring library for secure storage and maintains
a local index file for alias management.

The vault allows:
- Storing credentials with an alias via vault_register_connection
- Registering connections from config files via vault_register_from_path
- Listing all registered aliases via vault_list
- Revoking connections via vault_revoke
- Using aliases in query tools as an alternative to environment variables

Security features:
- Credentials are stored using the system's secure credential manager
- No plaintext credentials are ever returned in tool responses
- Path-based registration validates against allow-listed roots
- All logging and exception messages are redacted to prevent credential leaks

Configuration:
- Set SECUREDBLINK_ALLOWED_ROOTS to a colon-separated list of directories for
  path-based registration: SECUREDBLINK_ALLOWED_ROOTS=/path/to/configs:/another/path
"""

from securedblink.vault.parsers import (
    ConnectionConfig,
    parse_config_file,
)
from securedblink.vault.pathguard import (
    get_allowed_roots,
    is_path_allowed,
    validate_and_get_absolute_path,
)
from securedblink.vault.redact import (
    redact_connection_dict,
    redact_exception,
    redact_for_logging,
    redact_string,
)
from securedblink.vault.resolver import (
    ConnectionResolver,
    get_resolver,
)
from securedblink.vault.store import (
    InsecureKeyringError,
    VaultStore,
    VaultStoreError,
    get_vault_store,
    verify_secure_backend,
)

__all__ = [
    # Parsers
    "ConnectionConfig",
    # Resolver
    "ConnectionResolver",
    "InsecureKeyringError",
    # Store
    "VaultStore",
    "VaultStoreError",
    # Path guard
    "get_allowed_roots",
    "get_resolver",
    "get_vault_store",
    "is_path_allowed",
    "parse_config_file",
    # Redaction
    "redact_connection_dict",
    "redact_exception",
    "redact_for_logging",
    "redact_string",
    "validate_and_get_absolute_path",
    "verify_secure_backend",
]
