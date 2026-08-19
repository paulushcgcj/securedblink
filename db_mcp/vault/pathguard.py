"""Path validation utilities for the credential vault.

This module ensures that file paths used for registering connections
via vault_register_from_path are within allow-listed directories,
preventing directory traversal attacks.
"""

import os


def get_allowed_roots() -> list[str]:
    """Get the list of allow-listed root directories from environment variable.

    The DB_MCP_ALLOWED_ROOTS environment variable should contain a
    colon-separated list of directory paths.

    Returns:
        List of absolute path strings, or empty list if not configured.
    """
    roots_env = os.environ.get("DB_MCP_ALLOWED_ROOTS", "")
    if not roots_env:
        return []

    roots = []
    for root in roots_env.split(":"):
        root = root.strip()
        if root:
            # Expand ~ and environment variables
            root = os.path.expanduser(root)
            root = os.path.expandvars(root)
            # Normalize to absolute path
            root = os.path.abspath(root)
            roots.append(root)

    return roots


def is_path_allowed(file_path: str) -> bool:
    """Check if a file path is within any of the allow-listed roots.

    Args:
        file_path: The path to validate

    Returns:
        True if the path is within an allow-listed root, False otherwise

    Raises:
        ValueError: If DB_MCP_ALLOWED_ROOTS is not configured
    """
    allowed_roots = get_allowed_roots()

    if not allowed_roots:
        raise ValueError(
            "DB_MCP_ALLOWED_ROOTS environment variable is not configured. "
            "Cannot register connections from file paths without allow-listed roots. "
            "Set DB_MCP_ALLOWED_ROOTS to a colon-separated list of directories."
        )

    # Normalize the input path
    normalized_path = os.path.abspath(os.path.expanduser(os.path.expandvars(file_path)))

    # Check if the path is a file that exists
    if not os.path.isfile(normalized_path):
        raise ValueError(f"File not found: {normalized_path}")

    # Get the absolute path of the file (resolving symlinks)
    try:
        real_path = os.path.realpath(normalized_path)
    except OSError:
        # On some systems, realpath may fail
        real_path = normalized_path

    # Check if the real path is within any allowed root
    for root in allowed_roots:
        # Ensure root ends with separator for proper prefix matching
        if not root.endswith(os.sep):
            root = root + os.sep

        # Use os.path.commonpath to check if real_path starts with root
        try:
            common = os.path.commonpath([real_path, root])
            if common == root.rstrip(os.sep):
                return True
        except ValueError:
            # Different drives on Windows
            continue

    return False


def validate_and_get_absolute_path(file_path: str) -> str:
    """Validate a file path and return its absolute, resolved path.

    This function:
    1. Checks that DB_MCP_ALLOWED_ROOTS is configured
    2. Validates the path is within an allow-listed root
    3. Returns the resolved absolute path

    Args:
        file_path: The path to validate

    Returns:
        The resolved absolute path

    Raises:
        ValueError: If the path is not allowed or DB_MCP_ALLOWED_ROOTS not configured
        FileNotFoundError: If the file doesn't exist
    """
    if not is_path_allowed(file_path):
        raise ValueError(
            f"Path '{file_path}' is not within an allow-listed root directory. "
            f"Allowed roots: {get_allowed_roots()}. "
            "Set DB_MCP_ALLOWED_ROOTS to include the parent directory of this file."
        )

    # Return the resolved absolute path
    return os.path.realpath(
        os.path.abspath(os.path.expanduser(os.path.expandvars(file_path)))
    )


def check_traversal_safety(file_path: str, allowed_root: str) -> bool:
    """Explicitly check for directory traversal attempts.

    This is a more strict check that looks for '..' patterns in the path
    relative to the allowed root.

    Args:
        file_path: The file path to check
        allowed_root: The root directory it should be within

    Returns:
        True if the path is safe, False if it contains traversal
    """
    # Normalize paths
    root = os.path.abspath(os.path.expanduser(os.path.expandvars(allowed_root)))
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(file_path)))

    # Check if path starts with root
    if not path.startswith(root):
        return False

    # Check for '..' in the relative path
    relative = os.path.relpath(path, root)
    return not (relative.startswith("..") or os.sep + ".." + os.sep in relative)
