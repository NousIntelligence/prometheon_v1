"""The r5 multi-tightening day, replayed through the production path.

Continuous emission makes several verdicts for one ``(user, epoch)`` the
normal case: a user's weight can only worsen within a day, so a verdict
emitted before day close may be superseded by a tighter one. ``event_id`` is
keyed on ``(applies_to_epoch, user_id, weight_bp)``, which makes each
distinct weight its own record instead of a duplicate that would wedge the
family's stream.

Everything here runs against the real store and the real scoring pipeline —
``prepare_wire_records`` validates and canonicalises exactly as the ingest
service does, so a record the platform could not deliver cannot pass here
either.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prometheon.events.pipeline import score_event_stream
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore, prepare_wire_records

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"
SCENARIO: dict[str, Any] = json.loads(
    (FIXTURES / "exclusion-tightening" / "01-multi-tightening-day" / "scenario.json").read_text()
)
EXPECTED: dict[str, Any] = SCENARIO["expected"]
EPOCH: str = SCENARIO["applies_to_epoch"]


def _store(records: list[dict[str, Any]], path: Path) -> EventStore:
    """Store a batch the way a conforming ingest must.

    Sorted by ``seq`` first: contiguity requires exact-next, so a validator
    cannot store 503 before 501 whatever order the platform hands them over.
    That is itself part of what makes the outcome order-independent.
    """
    ordered = sorted(records, key=lambda record: record["seq"])
    store = EventStore(path)
    store._connection.execute(
        "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
        (EventFamily.EXCLUSION.value, ordered[0]["seq"] - 1),
    )
    store._connection.commit()
    store.append(EventFamily.EXCLUSION, prepare_wire_records(EventFamily.EXCLUSION, ordered))
    return store


def _effective_weights(records: list[dict[str, Any]]) -> dict[str, int]:
    """Minimum weight per user, computed over the array in the given order."""
    weights: dict[str, int] = {}
    for record in records:
        core = record["core"]
        if core.get("kind") != "verdict":
            continue
        user = record["user_ref_evt"]
        weight = core.get("weight_bp", 10000)
        weights[user] = weight if user not in weights else min(weights[user], weight)
    return weights


class TestMultiTighteningDay:
    def test_each_tightening_is_its_own_record(self, tmp_path: Path) -> None:
        """Four verdicts, four distinct ids — three users, one tightened.

        Under the previous derivation the tightening collided with the
        verdict it supersedes, which our store rejects on the unique
        constraint, failing the whole batch and stalling the family.
        """
        with _store(SCENARIO["records"], tmp_path / "e.sqlite") as store:
            stored = list(store.iter_family(EventFamily.EXCLUSION))

        verdicts = [r for r in stored if r["core"].get("kind") == "verdict"]
        assert len(verdicts) == EXPECTED["verdict_records"]
        assert len({r["event_id"] for r in verdicts}) == EXPECTED["distinct_event_ids"]

    def test_a_post_midnight_verdict_lands_in_the_next_bucket(self, tmp_path: Path) -> None:
        """`epoch_id` is when it was sequenced; `applies_to_epoch` is what it affects.

        A verdict adjudicated at 00:02 on D+1 for day D sits in D+1's digest
        while applying to D — routine once emission is continuous.
        """
        with _store(SCENARIO["records"], tmp_path / "e.sqlite") as store:
            for bucket, count in EXPECTED["records_in_epoch_bucket"].items():
                assert store.record_count_for_epoch(EventFamily.EXCLUSION, bucket) == count

    def test_marker_count_matches_ours_across_buckets(self, tmp_path: Path) -> None:
        """Marker says 4 records for 3 users, and we agree.

        Counting distinct users would read 3 and mismatch; counting by
        `epoch_id` bucket would miss the post-midnight verdict entirely.
        """
        assert EXPECTED["marker_verdict_count"] == 4
        assert len(EXPECTED["effective_weight_bp"]) == 3

        with _store(SCENARIO["records"], tmp_path / "e.sqlite") as store:
            result = score_event_stream(store, scoring_date=EPOCH, allow_missing_marker=True)

        assert result.verdict_count_mismatch == {}

    @pytest.mark.parametrize("array", ["records", "records_arrival_tightest_first"])
    def test_arrival_order_does_not_change_the_outcome(self, tmp_path: Path, array: str) -> None:
        """The same five records, presented tightest-first, score identically."""
        with _store(SCENARIO[array], tmp_path / f"{array}.sqlite") as store:
            result = score_event_stream(store, scoring_date=EPOCH, allow_missing_marker=True)

        assert result.verdict_count_mismatch == {}
        assert _effective_weights(SCENARIO[array]) == EXPECTED["effective_weight_bp"]

    def test_min_wins_is_what_the_fixture_encodes(self) -> None:
        """The tightened user scores at the lower weight, not the first seen."""
        weights = _effective_weights(SCENARIO["records"])
        tightened = [
            r["user_ref_evt"] for r in SCENARIO["records"] if r["core"].get("weight_bp") == 2500
        ]
        assert tightened, "fixture must contain a tightening"
        assert weights[tightened[0]] == 2500
