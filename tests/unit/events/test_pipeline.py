"""Unit tests for the store-to-MinerRecords scoring pipeline.

Builds a small but complete synthetic stream (all four families) in a
real EventStore and asserts the composed output: verdict gating, weight
application, attribution, MinerRecord shape, and the alarm surfaces.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from prometheon.events.pipeline import (
    SCORING_WINDOW_DAYS,
    MissingVerdictsError,
    build_parity_report,
    current_epoch,
    diff_miner_records,
    score_event_stream,
    window_epochs,
)
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore, prepare_wire_records
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord

pytestmark = pytest.mark.unit

LEADER = "usr_evt_" + "1a" * 32
USER = "usr_evt_" + "2b" * 32
HOTKEY = "5F9MHZ78mgGtgAkYBAmj6KiCaK6tJphh75R4rmUWJT6cjoPS"
SCORING_DATE = "2026-07-14"


def _envelope(
    family: str, seq: int, epoch: str, core: dict[str, Any], **overrides: Any
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "domain": "PROMETHEON_EVENT_RECORD_V1",
        "family": family,
        "seq": seq,
        "epoch_id": epoch,
        "event_id": "0x" + hashlib.sha256(f"{family}-{seq}".encode()).hexdigest(),
        "user_ref_evt": USER,
        "group_id": None,
        "received_ts": f"{epoch}T09:00:00Z",
        "category_id": None,
        "core": core,
        "device_pubkey": None,
        "user_sig": None,
    }
    record.update(overrides)
    return record


def _activity_core(kind: str, seq: int, epoch: str) -> dict[str, Any]:
    core: dict[str, Any] = {
        "domain": "PROMETHEON_EVENT_V1",
        "kind": kind,
        "target": {"service_id": f"svc-{seq}"},
        "scoring_fields": {"dwell_seconds": 30, "scroll_percent": 80, "outbound_clicks": 1},
        "client_ts": f"{epoch}T08:59:59Z",
        "client_nonce": "0x" + f"{seq:016x}",
    }
    if kind == "login":
        # A login carries no target and no metrics; both are empty by
        # contract, not by omission.
        core["target"] = {}
        core["scoring_fields"] = {}
    return core


def _populate(
    store: EventStore,
    *,
    with_marker: bool = True,
    weight_bp: int | None = None,
    activity_kind: str = "service_detail_view",
) -> None:
    # Group family: leader creates the group, user joins before the window.
    group_records = [
        _envelope(
            "group",
            1,
            "2026-06-01",
            {"kind": "group_created", "slug": "g", "display_name": "G"},
            user_ref_evt=LEADER,
            group_id="grp-1",
        ),
        _envelope(
            "group",
            2,
            "2026-06-02",
            {"kind": "member_joined", "fan_group_id": "grp-1"},
        ),
    ]
    store.append(EventFamily.GROUP, prepare_wire_records(EventFamily.GROUP, group_records))

    # Identity family: leader's hotkey bound well before the window.
    identity_records = [
        _envelope(
            "identity",
            1,
            "2026-06-01",
            {
                "kind": "miner_hotkey_bind",
                "miner_profile_id": "mp-1",
                "hotkey_ss58": HOTKEY,
                "bound_at": "2026-06-01T00:00:00Z",
            },
            user_ref_evt=LEADER,
        ),
    ]
    store.append(EventFamily.IDENTITY, prepare_wire_records(EventFamily.IDENTITY, identity_records))

    # Activity family: four counted views on the scoring date (raw = 8),
    # or a single login (raw = 1 — the daily cap for logins is 1).
    activity_seqs = range(1, 2) if activity_kind == "login" else range(1, 5)
    activity_records = [
        _envelope(
            "activity",
            seq,
            SCORING_DATE,
            _activity_core(activity_kind, seq, SCORING_DATE),
            received_ts=f"{SCORING_DATE}T09:{seq:02d}:00Z",
        )
        for seq in activity_seqs
    ]
    store.append(EventFamily.ACTIVITY, prepare_wire_records(EventFamily.ACTIVITY, activity_records))

    # Exclusion family: optional verdict + the epoch-close marker.
    exclusion_records = []
    seq = 1
    verdict_count = 0
    if weight_bp is not None:
        exclusion_records.append(
            _envelope(
                "exclusion",
                seq,
                "2026-07-15",
                {
                    "kind": "verdict",
                    "applies_to_epoch": SCORING_DATE,
                    "weight_bp": weight_bp,
                    "reason_codes": ["device_cluster"],
                },
                received_ts="2026-07-15T00:05:00Z",
            )
        )
        seq += 1
        verdict_count = 1
    if with_marker:
        exclusion_records.append(
            _envelope(
                "exclusion",
                seq,
                "2026-07-15",
                {
                    "kind": "verdicts_complete",
                    "applies_to_epoch": SCORING_DATE,
                    "verdict_count": verdict_count,
                },
                user_ref_evt=None,
                received_ts="2026-07-15T00:05:01Z",
            )
        )
    if exclusion_records:
        store.append(
            EventFamily.EXCLUSION,
            prepare_wire_records(EventFamily.EXCLUSION, exclusion_records),
        )


class TestScoringPipeline:
    def test_window_epochs_shape(self) -> None:
        epochs = window_epochs(SCORING_DATE)
        assert len(epochs) == 14
        assert epochs[-1] == SCORING_DATE
        assert epochs[0] == "2026-07-01"

    def test_full_stack_scores_and_attributes(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store)
            result = score_event_stream(store, scoring_date=SCORING_DATE)
        # Four counted views at +2 each = raw 8; no streak history; full weight.
        assert result.daily_scores == {(USER, SCORING_DATE): 8}
        assert result.miner_records == [
            MinerRecord(miner_hotkey=HOTKEY, miner_score_points=8, active_member_count=0)
        ]
        assert not result.marker_missing
        assert result.verdict_count_mismatch == {}
        assert result.excluded_signature_verdicts == []

    def test_verdict_weight_applies(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, weight_bp=2500)
            result = score_event_stream(store, scoring_date=SCORING_DATE)
        # floor(8 * 2500 / 10000) = 2.
        assert result.daily_scores == {(USER, SCORING_DATE): 2}
        assert result.miner_records[0].miner_score_points == 2

    def test_missing_marker_blocks_by_default(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, with_marker=False)
            with pytest.raises(MissingVerdictsError):
                score_event_stream(store, scoring_date=SCORING_DATE)

    def test_missing_marker_opt_in_flags_alarm(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, with_marker=False)
            result = score_event_stream(store, scoring_date=SCORING_DATE, allow_missing_marker=True)
        assert result.marker_missing
        assert result.daily_scores == {(USER, SCORING_DATE): 8}

    def test_a_single_login_scores_one_point(self, tmp_path: Path) -> None:
        """A login carries no metrics; an empty scoring_fields is correct.

        Pinned end-to-end because a hand-rolled extraction once reported
        this case as 0 and it was read as a scoring defect. The kernel is
        already fixture-gated on it (score-kernel/02-qualification); this
        asserts the whole store→weights path agrees.
        """
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, activity_kind="login")
            result = score_event_stream(store, scoring_date=SCORING_DATE)

        assert result.daily_scores == {(USER, SCORING_DATE): 1}
        assert result.miner_records[0].miner_score_points == 1


class TestParityReport:
    def test_report_shape_and_ordering(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store)
            result = score_event_stream(store, scoring_date=SCORING_DATE)

        report = build_parity_report(result)
        assert report["epoch"] == SCORING_DATE
        assert report["scores"] == [{"user_ref_evt": USER, "daily_score": 8}]
        assert report["scores_hash"].startswith("0x")
        assert len(report["scores_hash"]) == 66

    def test_report_covers_only_the_scored_epoch(self, tmp_path: Path) -> None:
        """The window spans 14 days; a parity report is about one of them."""
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store)
            result = score_event_stream(store, scoring_date=SCORING_DATE)

        other_day = (USER, "2026-07-10")
        mutated = replace(result, daily_scores={**result.daily_scores, other_day: 5})
        report = build_parity_report(mutated)

        assert [row["user_ref_evt"] for row in report["scores"]] == [USER]
        assert report["scores"][0]["daily_score"] == 8

    def test_hash_is_stable_and_order_independent(self, tmp_path: Path) -> None:
        """Two implementations that agree must produce the same hash."""
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store)
            result = score_event_stream(store, scoring_date=SCORING_DATE)

        other = "usr_evt_" + "9f" * 32
        forward = replace(result, daily_scores={**result.daily_scores, (other, SCORING_DATE): 3})
        reversed_insert = replace(
            result,
            daily_scores={(other, SCORING_DATE): 3, **result.daily_scores},
        )

        assert build_parity_report(forward) == build_parity_report(reversed_insert)
        assert [row["user_ref_evt"] for row in build_parity_report(forward)["scores"]] == sorted(
            [USER, other]
        )

    def test_empty_day_still_reports(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store)
            result = score_event_stream(store, scoring_date=SCORING_DATE)

        report = build_parity_report(replace(result, daily_scores={}))
        assert report["scores"] == []
        assert report["scores_hash"].startswith("0x")

    def test_unregistered_signature_is_excluded_and_surfaced(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store)
            injected = _envelope(
                "activity",
                5,
                SCORING_DATE,
                _activity_core("service_detail_view", 5, SCORING_DATE),
                received_ts=f"{SCORING_DATE}T10:00:00Z",
                device_pubkey="0x04" + "ab" * 64,
                user_sig="0x" + "cd" * 64,
            )
            store.append(
                EventFamily.ACTIVITY,
                prepare_wire_records(EventFamily.ACTIVITY, [injected]),
            )
            result = score_event_stream(store, scoring_date=SCORING_DATE)
        assert len(result.excluded_signature_verdicts) == 1
        assert result.excluded_signature_verdicts[0].seq == 5
        # Score unchanged: the injected record contributed nothing.
        assert result.daily_scores == {(USER, SCORING_DATE): 8}


class TestShadowDiff:
    def test_parity(self) -> None:
        records = [MinerRecord(miner_hotkey=HOTKEY, miner_score_points=8, active_member_count=0)]
        diff = diff_miner_records(records, list(records))
        assert diff.matches
        assert diff.report_lines() == ["shadow diff: PARITY (all miners match)"]

    def test_score_delta_reported(self) -> None:
        snapshot = [MinerRecord(miner_hotkey=HOTKEY, miner_score_points=9, active_member_count=0)]
        events = [MinerRecord(miner_hotkey=HOTKEY, miner_score_points=8, active_member_count=0)]
        diff = diff_miner_records(snapshot, events)
        assert not diff.matches
        assert diff.score_deltas == {HOTKEY: (8, 9)}

    def test_membership_asymmetry_reported(self) -> None:
        other = "5E9XqbLCgv86mP66SmFUv9MAomPVd2GQjQdAH4rf45ymwngY"
        snapshot = [MinerRecord(miner_hotkey=HOTKEY, miner_score_points=8, active_member_count=0)]
        events = [MinerRecord(miner_hotkey=other, miner_score_points=8, active_member_count=0)]
        diff = diff_miner_records(snapshot, events)
        assert diff.only_in_snapshot == [HOTKEY]
        assert diff.only_in_events == [other]


class TestLiveRollingWindow:
    """The validator runtime's mode: score the in-progress day.

    Rankings move continuously as activity arrives, so the last window
    bucket is today so far. Today cannot have a ``verdicts_complete``
    marker — the platform seals a day the morning after — and treating
    that absence as an error would make a real-time window impossible.
    """

    def test_live_scores_without_a_marker_and_does_not_alarm(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, with_marker=False)
            result = score_event_stream(store, scoring_date=SCORING_DATE, live=True)

        assert result.daily_scores == {(USER, SCORING_DATE): 8}
        assert result.marker_missing is False  # expected absence, not an alarm
        assert result.live is True

    def test_sealed_mode_still_refuses_a_day_without_its_marker(self, tmp_path: Path) -> None:
        """The parity path must keep its guard; only the live path relaxes."""
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, with_marker=False)
            with pytest.raises(MissingVerdictsError):
                score_event_stream(store, scoring_date=SCORING_DATE)

    def test_window_is_fourteen_buckets_ending_today(self) -> None:
        epochs = window_epochs(SCORING_DATE)
        assert len(epochs) == SCORING_WINDOW_DAYS
        assert epochs[-1] == SCORING_DATE  # the in-progress day
        assert epochs[0] == "2026-07-01"  # 13 whole days before it

    def test_verdicts_still_apply_to_the_days_that_have_them(self, tmp_path: Path) -> None:
        """A verdict for an earlier day keeps its weight in live mode.

        Only *today's* verdicts are missing; the rest of the window is
        weighted exactly as in sealed mode.
        """
        with EventStore(tmp_path / "e.sqlite") as store:
            _populate(store, with_marker=False, weight_bp=2500)
            result = score_event_stream(store, scoring_date=SCORING_DATE, live=True)

        # floor(8 * 2500 / 10000) = 2 — the verdict applied.
        assert result.daily_scores == {(USER, SCORING_DATE): 2}

    def test_current_epoch_is_todays_utc_date(self) -> None:
        from datetime import datetime, timezone

        moment = datetime(2026, 8, 3, 23, 59, 59, tzinfo=timezone.utc)
        assert current_epoch(moment) == "2026-08-03"
        assert current_epoch() == datetime.now(timezone.utc).strftime("%Y-%m-%d")
