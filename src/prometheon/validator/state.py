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
from typing import Any, ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

# Default sub-directory and filenames; tests may override.
DEFAULT_STATE_DIR = Path(".validator-state")
STATE_FILE_NAME = "state.json"
EVENTS_FILE_NAME = "events.ndjson"

# Bounds on the append-only runtime log. 32 MiB holds well over a month of
# cycle events at a 15-minute cadence; five generations keep roughly half a
# year of history available for forensics without unbounded growth.
EVENTS_MAX_BYTES: Final[int] = 32 * 1024 * 1024
EVENTS_KEEP_ROTATIONS: Final[int] = 5


class ValidatorState(BaseModel):
    """Persisted snapshot of the last successful validator cycle."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    chain_network: str
    platform_instance_id: str
    netuid: int = Field(ge=0)
    validator_hotkey: str = Field(min_length=1)
    mode: str = Field(min_length=1)
    weight_source: str | None = None
    last_scored_epoch: str | None = None
    last_scores_hash: str | None = None
    last_engine_version: str | None = None
    last_stream_cursors: dict[str, int] | None = None
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
    path = events_path(directory)
    _rotate_if_oversized(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)


def _rotate_if_oversized(
    path: Path,
    *,
    max_bytes: int | None = None,
    keep: int | None = None,
) -> None:
    """Roll the event log over once it passes ``max_bytes``.

    The validator appends here every cycle, forever. Without a bound the
    file is a slow disk-full incident on a host whose only job is to keep
    submitting weights — and the failure would arrive as a write error in
    the middle of a cycle rather than as anything diagnosable.

    Rotation is by rename, so a reader tailing the live file keeps its
    handle and simply stops seeing new lines; ``keep`` older generations
    survive for post-incident forensics and the rest are dropped.

    The bounds resolve from the module constants at call time rather than
    as default arguments, so an operator (or a test) can retune them
    without the values having been frozen at import.
    """
    max_bytes = EVENTS_MAX_BYTES if max_bytes is None else max_bytes
    keep = EVENTS_KEEP_ROTATIONS if keep is None else keep

    try:
        if path.stat().st_size < max_bytes:
            return
    except FileNotFoundError:
        return

    # Rotation is best-effort: losing a log line is acceptable, failing a
    # scoring cycle because a rotation slot was occupied or another process
    # rotated first is not. Any OS error here leaves the live file in place
    # and the append proceeds.
    with contextlib.suppress(OSError):
        oldest = path.with_suffix(path.suffix + f".{keep}")
        if oldest.exists():
            oldest.unlink()
        for index in range(keep - 1, 0, -1):
            source = path.with_suffix(path.suffix + f".{index}")
            if source.exists():
                source.rename(path.with_suffix(path.suffix + f".{index + 1}"))
        path.rename(path.with_suffix(path.suffix + ".1"))


__all__ = [
    "DEFAULT_STATE_DIR",
    "EVENTS_FILE_NAME",
    "EVENTS_KEEP_ROTATIONS",
    "EVENTS_MAX_BYTES",
    "STATE_FILE_NAME",
    "ValidatorState",
    "append_event",
    "events_path",
    "read_state",
    "state_path",
    "write_state",
]
