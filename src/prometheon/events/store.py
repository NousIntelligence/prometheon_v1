"""Durable event-stream store (SQLite).

The validator's local copy of the four-family signed stream. Guarantees the
properties the ingest contract builds on:

- **Contiguity at rest** — :meth:`EventStore.append` accepts only a batch
  whose seqs continue exactly from ``last_stored_seq(family) + 1``; the
  records and the cursor update commit in one transaction, so a crash can
  never leave the cursor ahead of (or behind) the rows.
- **Permanent dedup** — ``event_id`` is globally unique; a violation rolls
  the whole batch back.
- **Byte stability** — each record persists as its exact
  ``EVENT_RECORD_V1`` canonical bytes (the unit day digests hash and
  backfill re-delivers). Reloading parses those bytes back through the
  strict parser, so a stored record can never drift from the wire.
- **Retention** — window families (``activity``, ``exclusion``) prune by
  ``epoch_id`` at the caller-supplied cutoff (contract: 23 days); state
  families (``identity``, ``group``) are never pruned. Pruning never
  touches the cursor: stream position and retention are independent.
- **Replay defence persistence** — the ingest nonce set survives restarts
  and prunes on the caller's clock.

The store never reads a wall clock; callers pass cutoffs and timestamps
explicitly (deterministic tests, no hidden time coupling). Instances are
not thread-safe — the ingest service serializes access.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from prometheon.events.records import (
    EventFamily,
    EventRecord,
    record_canonical_bytes,
    validate_event_record,
)
from prometheon.security.canonical import parse_canonical_json

_RECORD_DOMAIN_PREFIX: Final[bytes] = b"PROMETHEON_EVENT_RECORD_V1\n"

# Families pruned by the retention janitor; identity/group are state
# families and keep full history (attribution + device-key windows replay
# from genesis).
WINDOW_FAMILIES: Final[frozenset[EventFamily]] = frozenset(
    {EventFamily.ACTIVITY, EventFamily.EXCLUSION}
)

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS event_records (
    family          TEXT    NOT NULL,
    seq             INTEGER NOT NULL,
    event_id        TEXT    NOT NULL,
    epoch_id        TEXT    NOT NULL,
    user_ref_evt    TEXT,
    canonical_bytes BLOB    NOT NULL,
    PRIMARY KEY (family, seq)
) WITHOUT ROWID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_event_records_event_id
    ON event_records (event_id);
CREATE INDEX IF NOT EXISTS idx_event_records_family_epoch
    ON event_records (family, epoch_id, seq);

CREATE TABLE IF NOT EXISTS event_cursors (
    family          TEXT    PRIMARY KEY,
    last_stored_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_nonces (
    nonce   TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);
"""


class EventStoreError(RuntimeError):
    """A store invariant was violated (contiguity, dedup, family mismatch)."""


@dataclass(frozen=True)
class PreparedRecord:
    """One record ready for storage: validated view + exact wire bytes."""

    family: EventFamily
    seq: int
    event_id: str
    epoch_id: str
    user_ref_evt: str | None
    canonical_bytes: bytes

    @classmethod
    def from_mapping(cls, raw: dict[str, Any], view: EventRecord) -> PreparedRecord:
        return cls(
            family=view.family,
            seq=view.seq,
            event_id=view.event_id,
            epoch_id=view.epoch_id,
            user_ref_evt=view.user_ref_evt,
            canonical_bytes=record_canonical_bytes(raw),
        )


def load_record_mapping(canonical_bytes: bytes) -> dict[str, Any]:
    """Parse stored canonical bytes back into the raw record mapping."""
    if not canonical_bytes.startswith(_RECORD_DOMAIN_PREFIX):
        raise EventStoreError("stored bytes do not carry the EVENT_RECORD_V1 domain prefix")
    parsed = parse_canonical_json(canonical_bytes[len(_RECORD_DOMAIN_PREFIX) :])
    if not isinstance(parsed, dict):
        raise EventStoreError("stored canonical bytes did not decode to an object")
    return parsed


class EventStore:
    """SQLite-backed store; one instance per process, callers serialize."""

    def __init__(self, path: Path | str) -> None:
        # check_same_thread=False: the ingest app runs store calls on a
        # threadpool worker while holding an asyncio lock — access is
        # serialized by contract, so cross-thread use is safe.
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript(_SCHEMA)
        self._connection.commit()

    # -- lifecycle ------------------------------------------------------

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- cursors --------------------------------------------------------

    def last_stored_seq(self, family: EventFamily) -> int:
        row = self._connection.execute(
            "SELECT last_stored_seq FROM event_cursors WHERE family = ?",
            (family.value,),
        ).fetchone()
        return int(row[0]) if row is not None else 0

    # -- writes ---------------------------------------------------------

    def append(self, family: EventFamily, records: Sequence[PreparedRecord]) -> int:
        """Append a strictly-contiguous batch; returns the new cursor.

        Every record must belong to ``family`` and the seqs must run
        ``last_stored + 1, last_stored + 2, …`` with no gaps. The rows and
        the cursor update commit atomically; any violation (including an
        ``event_id`` already stored) rolls the entire batch back.
        """
        if not records:
            return self.last_stored_seq(family)

        expected = self.last_stored_seq(family) + 1
        for record in records:
            if record.family is not family:
                raise EventStoreError(
                    f"record seq {record.seq} belongs to family "
                    f"{record.family.value!r}, not {family.value!r}"
                )
            if record.seq != expected:
                raise EventStoreError(
                    f"non-contiguous append for {family.value}: expected seq "
                    f"{expected}, got {record.seq}"
                )
            expected += 1

        try:
            with self._connection:
                self._connection.executemany(
                    "INSERT INTO event_records "
                    "(family, seq, event_id, epoch_id, user_ref_evt, canonical_bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            record.family.value,
                            record.seq,
                            record.event_id,
                            record.epoch_id,
                            record.user_ref_evt,
                            record.canonical_bytes,
                        )
                        for record in records
                    ],
                )
                self._connection.execute(
                    "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?) "
                    "ON CONFLICT(family) DO UPDATE SET last_stored_seq = excluded.last_stored_seq",
                    (family.value, records[-1].seq),
                )
        except sqlite3.IntegrityError as exc:
            raise EventStoreError(f"append rejected by integrity constraint: {exc}") from exc
        return records[-1].seq

    # -- reads ----------------------------------------------------------

    def has_event_id(self, event_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM event_records WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row is not None

    def iter_family(self, family: EventFamily, *, start_seq: int = 1) -> Iterator[dict[str, Any]]:
        """Yield raw record mappings for ``family`` in ascending seq order."""
        cursor = self._connection.execute(
            "SELECT canonical_bytes FROM event_records WHERE family = ? AND seq >= ? ORDER BY seq",
            (family.value, start_seq),
        )
        for (blob,) in cursor:
            yield load_record_mapping(bytes(blob))

    def canonical_bytes_for_epoch(self, family: EventFamily, epoch_id: str) -> list[bytes]:
        """Stored canonical bytes for (family, epoch) in seq order.

        This is exactly the input of the day-digest recompute:
        ``records_hash = SHA-256(concat(result))``.
        """
        cursor = self._connection.execute(
            "SELECT canonical_bytes FROM event_records "
            "WHERE family = ? AND epoch_id = ? ORDER BY seq",
            (family.value, epoch_id),
        )
        return [bytes(blob) for (blob,) in cursor]

    def record_count_for_epoch(self, family: EventFamily, epoch_id: str) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) FROM event_records WHERE family = ? AND epoch_id = ?",
            (family.value, epoch_id),
        ).fetchone()
        return int(row[0])

    # -- retention ------------------------------------------------------

    def prune_window_families(self, *, before_epoch: str) -> int:
        """Delete window-family records with ``epoch_id < before_epoch``.

        State families are never touched, and cursors are never modified —
        the stream position is independent of retention. Returns the number
        of rows removed.
        """
        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM event_records WHERE epoch_id < ? AND family IN (?, ?)",
                (before_epoch, *sorted(family.value for family in WINDOW_FAMILIES)),
            )
        return int(cursor.rowcount)

    # -- ingest replay defence -----------------------------------------

    def nonce_seen(self, nonce: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM ingest_nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
        return row is not None

    def record_nonce(self, nonce: str, *, seen_at: str) -> None:
        with self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO ingest_nonces (nonce, seen_at) VALUES (?, ?)",
                (nonce, seen_at),
            )

    def prune_nonces(self, *, before: str) -> int:
        """Delete nonces with ``seen_at < before`` (lexicographic ISO order)."""
        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM ingest_nonces WHERE seen_at < ?", (before,)
            )
        return int(cursor.rowcount)


def prepare_wire_records(
    family: EventFamily, wire_records: Sequence[dict[str, Any]]
) -> list[PreparedRecord]:
    """Validate a push batch's records and prepare them for storage.

    Each record is envelope-validated (:func:`validate_event_record`) and
    checked against the batch family before canonical bytes are computed.
    """
    prepared: list[PreparedRecord] = []
    for wire_record in wire_records:
        raw, view = validate_event_record(wire_record)
        if view.family is not family:
            raise EventStoreError(
                f"batch family {family.value!r} does not match record family "
                f"{view.family.value!r} at seq {view.seq}"
            )
        prepared.append(PreparedRecord.from_mapping(raw, view))
    return prepared


__all__ = [
    "WINDOW_FAMILIES",
    "EventStore",
    "EventStoreError",
    "PreparedRecord",
    "load_record_mapping",
    "prepare_wire_records",
]
