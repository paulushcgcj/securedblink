"""securedblink: MCP server for multi-database access with LLM permission gating.

Provides tools for database connection management, vault-backed credential storage,
SQL classification, and safe execution of read/write operations through the MCP protocol.
"""

__all__ = ["classifier", "connections", "server", "vault"]
