"""Validator local state persistence.

The validator runtime persists a small JSON document at
``.validator-state/state.json`` capturing the last successful cycle:
which snapshot was accepted, which weight plan was produced, what
extrinsic was submitted, and any error from the most recent attempt.

The write is atomic per consolidated specification §24.2: write to a
temporary file in the same directory, ``flush`` and ``fsync``, then
``rename`` into place. The rename is atomic on POSIX filesystems; the
``fsync`` makes the state durable across an unclean shutdown.

An optional append-only NDJSON event log under
``.validator-state/events.ndjson`` complements the single state file for
operators who want a richer history.

This module deliberately does **not** depend on the validator config or
the chain adapter. It is a small, isolated I/O layer that other modules
inject paths into.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

# Default sub-directory and filenames; tests may override.
DEFAULT_STATE_DIR = Path(".validator-state")
STATE_FILE_NAME = "state.json"
EVENTS_FILE_NAME = "events.ndjson"


class ValidatorState(BaseModel):
    """Persisted snapshot of the last successful validator cycle."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    chain_network: str
    platform_instance_id: str
    netuid: int = Field(ge=0)
    validator_hotkey: str = Field(min_length=1)
    mode: str = Field(min_length=1)
    last_accepted_snapshot_id: str | None = None
    last_accepted_snapshot_hash: str | None = None
    last_weight_plan_hash: str | None = None
    last_metagraph_block: int | None = None
    last_submitted_block: int | None = None
    last_extrinsic_hash: str | None = None
    last_submit_status: str | None = None
    last_error: str | None = None
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    def with_update(self, **fields: Any) -> ValidatorState:
        """Return a copy with the given fields overwritten and a fresh timestamp."""
        merged = self.model_dump()
        merged.update(fields)
        merged["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return ValidatorState.model_validate(merged)


def state_path(directory: Path | str = DEFAULT_STATE_DIR) -> Path:
    """Return the absolute path to the state file under ``directory``."""
    return Path(directory) / STATE_FILE_NAME


def events_path(directory: Path | str = DEFAULT_STATE_DIR) -> Path:
    """Return the absolute path to the NDJSON event log under ``directory``."""
    return Path(directory) / EVENTS_FILE_NAME


def write_state(state: ValidatorState, *, directory: Path | str = DEFAULT_STATE_DIR) -> None:
    """Atomically persist ``state`` to ``{directory}/state.json``.

    The temp file lives in the same directory as the target so the rename
    is on the same filesystem. ``fsync`` is called on both the temp file
    and (best-effort) the directory before the rename.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = state_path(directory)

    payload = json.dumps(state.model_dump(), sort_keys=True, indent=2).encode("utf-8")

    # Write to a temp file in the same directory so the rename is atomic.
    fd, tmp_path_str = tempfile.mkstemp(prefix=".state-", suffix=".json.tmp", dir=str(directory))
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
        # Best-effort directory sync so the rename is durable too.
        try:
            dir_fd = os.open(str(directory), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)
    except Exception:
        # Clean up the temp file if anything went wrong before the rename.
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()
        raise


def read_state(*, directory: Path | str = DEFAULT_STATE_DIR) -> ValidatorState | None:
    """Read and parse the persisted state.

    Returns ``None`` when no state file exists yet (typical on first
    run). Raises if the file exists but is malformed; the runner treats
    that as a startup-blocking error so operators can investigate.
    """
    path = state_path(directory)
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8")
    return ValidatorState.model_validate(json.loads(raw))


def append_event(event: dict[str, Any], *, directory: Path | str = DEFAULT_STATE_DIR) -> None:
    """Append one NDJSON event to the runtime log.

    Each event is JSON-serialised on a single line; missing
    ``timestamp`` is auto-added in the canonical UTC profile.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if "timestamp" not in event:
        event = {
            **event,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    line = json.dumps(event, sort_keys=True) + "\n"
    with events_path(directory).open("a", encoding="utf-8") as fh:
        fh.write(line)


__all__ = [
    "DEFAULT_STATE_DIR",
    "EVENTS_FILE_NAME",
    "STATE_FILE_NAME",
    "ValidatorState",
    "append_event",
    "events_path",
    "read_state",
    "state_path",
    "write_state",
]
