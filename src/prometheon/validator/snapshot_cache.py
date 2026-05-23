"""Disk-backed cache for verified snapshots.

The validator currently re-fetches the latest snapshot on every cycle
even when the platform has not produced a new one. Each fetch costs an
HTTP round-trip plus Ed25519 verification of the body. For a validator
that ticks every 15 minutes and a platform that publishes once a day,
that is ~96 redundant verifications per day per validator.

This module is the WIP scaffold for a disk-backed cache keyed by
``(activity_date, snapshot_id)``. The runner will check the cache
before issuing a fetch; on a hit, the cached signed bytes go straight
to ``verify_aggregate_snapshot`` (or the equivalent detailed path) and
the runner skips the network call entirely.

Not wired into the runner yet — that integration is intentionally a
follow-up PR so the cache shape can be reviewed in isolation first.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SnapshotCacheEntry:
    """A single cached snapshot keyed by ``(activity_date, snapshot_id)``."""

    activity_date: str
    snapshot_id: str
    payload: dict[str, Any]


class SnapshotCache:
    """Filesystem-backed cache for verified snapshot payloads.

    Entries are stored as ``<cache_dir>/<activity_date>__<snapshot_id>.json``
    so they can be inspected and pruned with standard filesystem tools.
    Atomicity is provided by ``Path.replace`` after a temp-file write.

    The cache is intentionally *not* size-bounded in this initial scaffold;
    a follow-up PR will add LRU eviction once the cache is wired into the
    runner and we know typical sizes per validator deployment.
    """

    def __init__(self, cache_dir: Path | str) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _entry_filename(activity_date: str, snapshot_id: str) -> str:
        # snapshot_id may contain ':' (e.g. "phase1:2026-05-18:aggregate");
        # use a path-safe substitute so the filename round-trips on every
        # filesystem we run on.
        safe_id = snapshot_id.replace(":", "_").replace("/", "_")
        return f"{activity_date}__{safe_id}.json"

    def get(self, activity_date: str, snapshot_id: str) -> SnapshotCacheEntry | None:
        """Return the cached entry, or ``None`` if absent."""
        path = self._cache_dir / self._entry_filename(activity_date, snapshot_id)
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return None
        return SnapshotCacheEntry(
            activity_date=activity_date,
            snapshot_id=snapshot_id,
            payload=payload,
        )

    def put(self, entry: SnapshotCacheEntry) -> None:
        """Write the entry atomically."""
        path = self._cache_dir / self._entry_filename(entry.activity_date, entry.snapshot_id)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(entry.payload, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    def clear(self) -> int:
        """Remove all cached entries; return the number deleted."""
        count = 0
        for entry in self._cache_dir.iterdir():
            if entry.is_file() and entry.suffix == ".json":
                entry.unlink()
                count += 1
        return count


__all__ = ["SnapshotCache", "SnapshotCacheEntry"]
