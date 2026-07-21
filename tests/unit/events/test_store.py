"""Unit tests for the SQLite event store's invariants."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from prometheon.events.records import EventFamily
from prometheon.events.store import (
    EventStore,
    EventStoreError,
    PreparedRecord,
    load_record_mapping,
    prepare_wire_records,
)

pytestmark = pytest.mark.unit

USER = "usr_evt_" + "ab" * 32


def _wire_record(
    seq: int, *, family: str = "identity", epoch: str = "2026-07-10"
) -> dict[str, Any]:
    return {
        "domain": "PROMETHEON_EVENT_RECORD_V1",
        "family": family,
        "seq": seq,
        "epoch_id": epoch,
        "event_id": "0x" + f"{seq:064x}",
        "user_ref_evt": USER,
        "group_id": None,
        "received_ts": f"{epoch}T09:00:00Z",
        "category_id": None,
        "core": {"kind": "device_key_register", "public_key": "0x04" + "ee" * 64},
        "device_pubkey": None,
        "user_sig": None,
    }


def _prepared(seq: int, *, family: str = "identity", epoch: str = "2026-07-10") -> PreparedRecord:
    return prepare_wire_records(
        EventFamily(family), [_wire_record(seq, family=family, epoch=epoch)]
    )[0]


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    with EventStore(tmp_path / "events.sqlite") as opened:
        yield opened


class TestCursorsAndAppend:
    def test_fresh_store_cursors_are_zero(self, store: EventStore) -> None:
        for family in EventFamily:
            assert store.last_stored_seq(family) == 0

    def test_contiguous_append_advances_cursor(self, store: EventStore) -> None:
        new_cursor = store.append(EventFamily.IDENTITY, [_prepared(1), _prepared(2), _prepared(3)])
        assert new_cursor == 3
        assert store.last_stored_seq(EventFamily.IDENTITY) == 3

    def test_round_trip_preserves_mapping(self, store: EventStore) -> None:
        original = _wire_record(1)
        prepared = prepare_wire_records(EventFamily.IDENTITY, [original])
        store.append(EventFamily.IDENTITY, prepared)
        loaded = list(store.iter_family(EventFamily.IDENTITY))
        assert loaded == [original]

    def test_gap_append_rejected_atomically(self, store: EventStore) -> None:
        store.append(EventFamily.IDENTITY, [_prepared(1)])
        with pytest.raises(EventStoreError, match="non-contiguous"):
            store.append(EventFamily.IDENTITY, [_prepared(3)])
        assert store.last_stored_seq(EventFamily.IDENTITY) == 1

    def test_internal_gap_in_batch_rejected(self, store: EventStore) -> None:
        with pytest.raises(EventStoreError, match="non-contiguous"):
            store.append(EventFamily.IDENTITY, [_prepared(1), _prepared(3)])
        assert store.last_stored_seq(EventFamily.IDENTITY) == 0

    def test_duplicate_event_id_rolls_back_whole_batch(self, store: EventStore) -> None:
        first = _prepared(1)
        store.append(EventFamily.IDENTITY, [first])
        duplicate = PreparedRecord(
            family=first.family,
            seq=2,
            event_id=first.event_id,
            epoch_id=first.epoch_id,
            user_ref_evt=first.user_ref_evt,
            canonical_bytes=first.canonical_bytes,
        )
        with pytest.raises(EventStoreError, match="integrity"):
            store.append(EventFamily.IDENTITY, [duplicate])
        assert store.last_stored_seq(EventFamily.IDENTITY) == 1
        assert len(list(store.iter_family(EventFamily.IDENTITY))) == 1

    def test_family_mismatch_rejected(self, store: EventStore) -> None:
        with pytest.raises(EventStoreError, match="family"):
            store.append(EventFamily.GROUP, [_prepared(1, family="identity")])

    def test_families_have_independent_seqs(self, store: EventStore) -> None:
        store.append(EventFamily.IDENTITY, [_prepared(1)])
        group_record = _wire_record(1, family="group")
        group_record["event_id"] = "0x" + "9" * 64
        group_record["core"] = {"kind": "member_joined", "fan_group_id": "g1"}
        store.append(EventFamily.GROUP, prepare_wire_records(EventFamily.GROUP, [group_record]))
        assert store.last_stored_seq(EventFamily.IDENTITY) == 1
        assert store.last_stored_seq(EventFamily.GROUP) == 1

    def test_empty_append_is_a_noop(self, store: EventStore) -> None:
        assert store.append(EventFamily.IDENTITY, []) == 0


class TestPersistence:
    def test_reopen_preserves_cursor_and_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "events.sqlite"
        with EventStore(path) as store:
            store.append(EventFamily.IDENTITY, [_prepared(1), _prepared(2)])
        with EventStore(path) as reopened:
            assert reopened.last_stored_seq(EventFamily.IDENTITY) == 2
            assert len(list(reopened.iter_family(EventFamily.IDENTITY))) == 2

    def test_iter_family_start_seq(self, store: EventStore) -> None:
        store.append(EventFamily.IDENTITY, [_prepared(1), _prepared(2), _prepared(3)])
        tail = list(store.iter_family(EventFamily.IDENTITY, start_seq=3))
        assert [record["seq"] for record in tail] == [3]

    def test_has_event_id(self, store: EventStore) -> None:
        prepared = _prepared(1)
        assert not store.has_event_id(prepared.event_id)
        store.append(EventFamily.IDENTITY, [prepared])
        assert store.has_event_id(prepared.event_id)


class TestRetention:
    def test_prune_removes_window_families_only(self, store: EventStore) -> None:
        activity = _wire_record(1, family="activity", epoch="2026-06-01")
        activity["core"] = {
            "domain": "PROMETHEON_EVENT_V1",
            "kind": "login",
            "target": {},
            "scoring_fields": {},
            "client_ts": "2026-06-01T08:00:00Z",
            "client_nonce": "0x0000000000000001",
        }
        activity["event_id"] = "0x" + "1" * 64
        store.append(EventFamily.ACTIVITY, prepare_wire_records(EventFamily.ACTIVITY, [activity]))
        store.append(EventFamily.IDENTITY, [_prepared(1, epoch="2026-06-01")])

        removed = store.prune_window_families(before_epoch="2026-07-01")
        assert removed == 1
        assert list(store.iter_family(EventFamily.ACTIVITY)) == []
        assert len(list(store.iter_family(EventFamily.IDENTITY))) == 1

    def test_prune_keeps_cursor(self, store: EventStore) -> None:
        activity = _wire_record(1, family="activity", epoch="2026-06-01")
        activity["core"] = {
            "domain": "PROMETHEON_EVENT_V1",
            "kind": "login",
            "target": {},
            "scoring_fields": {},
            "client_ts": "2026-06-01T08:00:00Z",
            "client_nonce": "0x0000000000000001",
        }
        activity["event_id"] = "0x" + "1" * 64
        store.append(EventFamily.ACTIVITY, prepare_wire_records(EventFamily.ACTIVITY, [activity]))
        store.prune_window_families(before_epoch="2026-07-01")
        # Retention never rewinds the stream position.
        assert store.last_stored_seq(EventFamily.ACTIVITY) == 1

    def test_prune_boundary_is_exclusive(self, store: EventStore) -> None:
        store.append(EventFamily.IDENTITY, [_prepared(1, epoch="2026-07-01")])
        exclusion = _wire_record(1, family="exclusion", epoch="2026-07-01")
        exclusion["event_id"] = "0x" + "2" * 64
        exclusion["core"] = {
            "kind": "verdict",
            "applies_to_epoch": "2026-06-30",
            "weight_bp": 2500,
            "reason_codes": ["device_cluster"],
        }
        store.append(
            EventFamily.EXCLUSION, prepare_wire_records(EventFamily.EXCLUSION, [exclusion])
        )
        removed = store.prune_window_families(before_epoch="2026-07-01")
        assert removed == 0
        assert len(list(store.iter_family(EventFamily.EXCLUSION))) == 1


class TestNonces:
    def test_nonce_lifecycle(self, store: EventStore) -> None:
        assert not store.nonce_seen("n-1")
        store.record_nonce("n-1", seen_at="2026-07-10T09:00:00Z")
        assert store.nonce_seen("n-1")

    def test_prune_nonces(self, store: EventStore) -> None:
        store.record_nonce("old", seen_at="2026-07-09T00:00:00Z")
        store.record_nonce("new", seen_at="2026-07-10T12:00:00Z")
        removed = store.prune_nonces(before="2026-07-10T00:00:00Z")
        assert removed == 1
        assert not store.nonce_seen("old")
        assert store.nonce_seen("new")


class TestLoadRecordMapping:
    def test_rejects_foreign_bytes(self) -> None:
        with pytest.raises(EventStoreError):
            load_record_mapping(b"NOT_A_DOMAIN\n{}")
