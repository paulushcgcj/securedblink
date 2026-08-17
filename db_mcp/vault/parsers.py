"""Parsers for various configuration file formats.

This module parses connection configuration from .env, .properties,
and .yml/.yaml files to extract JDBC connection details.
"""

import os
import re
from typing import Any, Optional

# For YAML parsing
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


class ConnectionConfig:
    """Container for parsed connection configuration."""
    
    def __init__(
        self,
        jdbc_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        driver: Optional[str] = None,
        source_format: Optional[str] = None
    ):
        self.jdbc_url = jdbc_url
        self.username = username
        self.password = password
        self.driver = driver
        self.source_format = source_format
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {}
        if self.jdbc_url:
            result["jdbc_url"] = self.jdbc_url
        if self.username:
            result["username"] = self.username
        if self.password:
            result["password"] = self.password
        if self.driver:
            result["driver"] = self.driver
        return result
    
    def is_valid(self) -> bool:
        """Check if the configuration has the minimum required fields."""
        return self.jdbc_url is not None and bool(self.jdbc_url.strip())


def _parse_env_file(file_path: str) -> ConnectionConfig:
    """Parse a .env file for database connection configuration.
    
    Supports standard .env format:
    DB_URL=jdbc:postgresql://user:pass@host:5432/db
    DB_USERNAME=user
    DB_PASSWORD=pass
    
    Or with DB_ prefix:
    DB_PROD_URL=jdbc:postgresql://...
    DB_PROD_USERNAME=user
    DB_PROD_PASSWORD=pass
    
    Args:
        file_path: Path to the .env file
        
    Returns:
        ConnectionConfig with extracted values
    """
    config = ConnectionConfig(source_format=".env")
    
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    # First pass: look for DB_URL or similar
    url_patterns = [
        r"^DB_URL\s*=\s*(.+)$",
        r"^DB_JDBC_URL\s*=\s*(.+)$",
        r"^DATABASE_URL\s*=\s*(.+)$",
        r"^JDBC_URL\s*=\s*(.+)$",
    ]
    
    for line in lines:
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue
        
        # Check for URL patterns
        for pattern in url_patterns:
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                config.jdbc_url = match.group(1).strip().strip('"\'')
                break
    
    # Second pass: look for username and password
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Match username
        if not config.username:
            match = re.match(r"^DB_USERNAME\s*=\s*(.+)$", line, re.IGNORECASE)
            if match:
                config.username = match.group(1).strip().strip('"\'')
        
        # Match password
        if not config.password:
            match = re.match(r"^DB_PASSWORD\s*=\s*(.+)$", line, re.IGNORECASE)
            if match:
                config.password = match.group(1).strip().strip('"\'')
    
    return config


def _parse_properties_file(file_path: str) -> ConnectionConfig:
    """Parse a .properties file for database connection configuration.
    
    Supports Java properties format:
    jdbc.url=jdbc:postgresql://user:pass@host:5432/db
    jdbc.username=user
    jdbc.password=pass
    
    Or Spring Boot style:
    spring.datasource.url=jdbc:postgresql://user:pass@host:5432/db
    spring.datasource.username=user
    spring.datasource.password=pass
    
    Args:
        file_path: Path to the .properties file
        
    Returns:
        ConnectionConfig with extracted values
    """
    config = ConnectionConfig(source_format=".properties")
    
    with open(file_path, "r", encoding="iso-8859-1") as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        
        # Split on first = or : (properties format allows both)
        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            continue
        
        key = key.strip().lower()
        value = value.strip().strip('"\'')
        
        # Match various URL keys
        url_keys = ["jdbc.url", "jdbcurl", "url", "spring.datasource.url", 
                    "datasource.url", "database.url", "db.url"]
        if any(k in key for k in url_keys) and not config.jdbc_url:
            config.jdbc_url = value
        
        # Match username
        username_keys = ["jdbc.username", "jdbcuser", "username", 
                        "spring.datasource.username", "datasource.username",
                        "database.username", "db.username", "user"]
        if any(k in key for k in username_keys) and not config.username:
            config.username = value
        
        # Match password
        password_keys = ["jdbc.password", "jdbcpassword", "password",
                        "spring.datasource.password", "datasource.password",
                        "database.password", "db.password", "passwd", "pwd"]
        if any(k in key for k in password_keys) and not config.password:
            config.password = value
        
        # Match driver (optional)
        driver_keys = ["jdbc.driver", "driver", "spring.datasource.driver-class-name",
                       "datasource.driver", "database.driver", "db.driver"]
        if any(k in key for k in driver_keys) and not config.driver:
            config.driver = value
    
    return config


def _parse_yaml_file(file_path: str) -> ConnectionConfig:
    """Parse a .yml or .yaml file for database connection configuration.
    
    Supports Spring Boot application.yml format:
    spring:
      datasource:
        url: jdbc:postgresql://user:pass@host:5432/db
        username: user
        password: pass
        driver-class-name: org.postgresql.Driver
    
    Also supports simple YAML:
    database:
      url: jdbc:postgresql://...
      username: user
      password: pass
    
    Args:
        file_path: Path to the .yml/.yaml file
        
    Returns:
        ConnectionConfig with extracted values
        
    Raises:
        ImportError: If PyYAML is not installed
    """
    if not _HAS_YAML:
        raise ImportError(
            "PyYAML is required to parse YAML files. "
            "Install it with: uv pip install pyyaml"
        )
    
    config = ConnectionConfig(source_format=".yaml")
    
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    if not data or not isinstance(data, dict):
        return config
    
    # Helper to extract values from nested dicts
    def get_nested(data: dict[str, Any], keys: list[str]) -> Optional[str]:
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current if isinstance(current, str) else None
    
    # Try Spring Boot style: spring.datasource.*
    if "spring" in data and isinstance(data["spring"], dict):
        ds = data["spring"].get("datasource", {})
        if isinstance(ds, dict):
            if not config.jdbc_url:
                config.jdbc_url = ds.get("url") or ds.get("jdbc-url") or ds.get("jdbcUrl")
            if not config.username:
                config.username = ds.get("username") or ds.get("user")
            if not config.password:
                config.password = ds.get("password") or ds.get("passwd")
            if not config.driver:
                config.driver = ds.get("driver-class-name") or ds.get("driverClassName")
    
    # Try database/datasource top-level
    for top_key in ["database", "datasource", "db"]:
        if top_key in data and isinstance(data[top_key], dict):
            db_config = data[top_key]
            if not config.jdbc_url:
                config.jdbc_url = db_config.get("url") or db_config.get("jdbc_url")
            if not config.username:
                config.username = db_config.get("username") or db_config.get("user")
            if not config.password:
                config.password = db_config.get("password") or db_config.get("passwd")
            if not config.driver:
                config.driver = db_config.get("driver")
    
    # Try direct top-level keys
    if not config.jdbc_url:
        config.jdbc_url = data.get("url") or data.get("jdbc_url") or data.get("database_url")
    if not config.username:
        config.username = data.get("username") or data.get("user")
    if not config.password:
        config.password = data.get("password") or data.get("passwd")
    if not config.driver:
        config.driver = data.get("driver")
    
    return config


def parse_config_file(file_path: str) -> ConnectionConfig:
    """Parse a configuration file based on its extension.
    
    Supports .env, .properties, .yml, and .yaml files.
    
    Args:
        file_path: Path to the configuration file
        
    Returns:
        ConnectionConfig with extracted values
        
    Raises:
        ValueError: If the file extension is not supported
        FileNotFoundError: If the file doesn't exist
        ImportError: If required dependencies are missing (e.g., PyYAML for .yml)
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in (".env",):
        return _parse_env_file(file_path)
    elif ext in (".properties",):
        return _parse_properties_file(file_path)
    elif ext in (".yml", ".yaml"):
        return _parse_yaml_file(file_path)
    else:
        raise ValueError(
            f"Unsupported configuration file format: {ext}. "
            "Supported formats: .env, .properties, .yml, .yaml"
        )
