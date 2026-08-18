"""Typed project settings using Pydantic‑Settings.

All configuration is read from environment variables prefixed with ``DB_``.
Missing required variables cause a fast‑fail at import time.
"""

from pydantic import Field, SettingsConfigDict
from pydantic_settings import BaseSettings


class DbSettings(BaseSettings):
    """Database connection URLs."""

    model_config = SettingsConfigDict(env_prefix="DB_", extra="forbid")

    prod: str = Field(..., description="PostgreSQL connection URL for production")
    local: str = Field(..., description="SQLite connection URL for local development")
    warehouse: str = Field(
        ..., description="Oracle (or other) connection URL for data warehouse"
    )
    max_rows: int = Field(
        default=500, description="Maximum rows returned by a read query"
    )


# Single instance used by the rest of the application.
settings = DbSettings()  # will raise if any required env var is missing
