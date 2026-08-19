"""Structured logging configuration for db-mcp.

All log output is written to **stderr**.  stdout is reserved for the MCP
stdio protocol — writing anything else there corrupts the protocol channel
that clients (IDE MCP integrations, the ``mcp`` CLI) read from.
"""

from __future__ import annotations

import logging
import sys
from typing import cast

import structlog
from structlog.typing import FilteringBoundLogger

LOG_LEVEL = logging.INFO


class _StderrLogger:
    """Minimal structlog logger writing to the *current* ``sys.stderr``.

    structlog only requires an object with ``msg()``; all log-level aliases
    are bound to it here. Resolving ``sys.stderr`` at call time (instead of
    capturing a file object when the logger is configured) keeps output
    visible to test capture fixtures such as pytest's ``capsys``/``capfd``.
    """

    def msg(self, message: str) -> None:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()

    log = debug = info = warn = warning = msg
    fatal = failure = err = error = critical = exception = msg


def configure_logging(level: int = LOG_LEVEL) -> None:
    """Configure structlog to emit human-readable logs on stderr.

    Uses a plain console renderer (no ANSI colors) so output is identical
    in terminals, CI logs, and captured test streams.

    Args:
        level: Minimum log level to emit. Defaults to ``logging.INFO``.
    """
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=lambda *_: _StderrLogger(),
        cache_logger_on_first_use=False,
    )


configure_logging()


def get_logger(name: str | None = None) -> FilteringBoundLogger:
    """Return a module-scoped structlog logger.

    Args:
        name: Logger name (typically ``"db_mcp.<module>"``). Used only for
            debugging context; the console renderer shows it in the output.

    Returns:
        A bound logger writing to stderr at the configured level.
    """
    return cast(FilteringBoundLogger, structlog.get_logger(name))
