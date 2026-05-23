"""Structured reporting helpers for the validator runtime.

A thin layer over :mod:`logging` that:

- Emits redacted, structured log records (no raw API tokens, no raw
  signatures, no raw hotkeys beyond a short fingerprint).
- Appends NDJSON events to the runtime log via
  :func:`prometheon.validator.state.append_event`.

The runner uses these helpers instead of calling :mod:`logging` directly
so every operationally significant event passes through one place that
enforces the redaction list from consolidated specification §16.1 /
§24.3.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from prometheon.validator.state import append_event

_logger = logging.getLogger("prometheon.validator")


def hotkey_fingerprint(hotkey: str, *, prefix_len: int = 6, suffix_len: int = 6) -> str:
    """Return a short, redacted representation of an SS58 hotkey for logs.

    Format: ``"<prefix>…<suffix>"``. Logs include this short form rather
    than the full SS58 to keep grepability without bloating output.
    """
    if len(hotkey) <= prefix_len + suffix_len + 1:
        return hotkey
    return f"{hotkey[:prefix_len]}…{hotkey[-suffix_len:]}"


def report_event(
    *,
    event_type: str,
    state_directory: Path | str | None,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit a structured event to both the Python logger and the NDJSON log.

    Parameters
    ----------
    event_type:
        Short string identifier (e.g. ``"snapshot_accepted"``,
        ``"submission_failed"``).
    state_directory:
        Where the NDJSON event log lives. ``None`` disables the file
        append (used in unit tests).
    level:
        Python logging level for the in-process log record.
    **fields:
        Additional structured fields. Caller is responsible for ensuring
        nothing in here is a raw credential.
    """
    payload: dict[str, Any] = {"event_type": event_type, **fields}
    _logger.log(level, "%s %s", event_type, payload)
    if state_directory is not None:
        append_event(payload, directory=state_directory)


__all__ = ["hotkey_fingerprint", "report_event"]
