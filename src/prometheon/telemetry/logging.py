"""Structured logging configuration for the validator runtime.

Provides one place to configure :mod:`logging` for the whole package so
operators see consistent formats across the CLI, the validator runner,
and any background helpers. The format is plain text by default
(``%(asctime)s %(levelname)s %(name)s %(message)s``) — a single line per
record, easy to grep, easy to feed into existing log shippers.

A separate :func:`configure_structlog` wires a richer JSON-line format
for operators who prefer machine-readable logs.
"""

from __future__ import annotations

import logging
import sys
from typing import Literal

import structlog

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def configure_stdlib_logging(*, level: LogLevel = "INFO") -> None:
    """Configure stdlib :mod:`logging` to write to stderr in plain format.

    Idempotent: re-calling reconfigures cleanly.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    root.addHandler(handler)
    root.setLevel(getattr(logging, level))


def configure_structlog(*, level: LogLevel = "INFO") -> None:
    """Configure :mod:`structlog` to emit one JSON line per record.

    JSON output keys: ``timestamp``, ``level``, ``logger``, ``event``,
    plus any structured fields the caller adds via ``log.info(...)``.
    """
    configure_stdlib_logging(level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        cache_logger_on_first_use=True,
    )


__all__ = ["LogLevel", "configure_stdlib_logging", "configure_structlog"]
