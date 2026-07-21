"""Event-stream scoring pipeline — store to MinerRecords.

Composes the whole recomputation stack over a local :class:`EventStore`:

    identity family  → DeviceKeyRegistry + BindingLedger
    group family     → GroupLedger
    exclusion family → verdict weights + ``verdicts_complete`` markers
    activity family  → EventScoringEngine → per-(user, day) daily scores
    attribution      → per-miner sums → the existing engine's MinerRecords

The scoring cutoff is enforced here: the window ending epoch ``D`` is
scored only after ``verdicts_complete(D)`` has been stored (the platform
seals D's verdict set once, ~00:05 UTC on D+1). The documented fallback —
score without D's verdicts after the grace period and alarm — is an
explicit opt-in (``allow_missing_marker``), never a silent default.

Alarm evidence is surfaced, not swallowed: records excluded for bad
signatures, a missing marker, or a verdict-count mismatch all ride the
result object for the caller to report.

Shadow-mode support: :func:`diff_miner_records` compares event-derived
MinerRecords against a snapshot-derived list and produces the per-miner
evidence the parity gate (14 consecutive clean days) is judged on.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from prometheon.events.device_signatures import DeviceKeyRegistry
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore
from prometheon.mechanisms.phase1_growth.event_attribution import (
    BindingLedger,
    GroupLedger,
    MinerAttributionResult,
    aggregate_miner_scores,
)
from prometheon.mechanisms.phase1_growth.event_scoring import (
    FULL_WEIGHT_BP,
    EventScoringEngine,
    EventVerdict,
    VerdictStatus,
)
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord

SCORING_WINDOW_DAYS: Final[int] = 14


class MissingVerdictsError(RuntimeError):
    """``verdicts_complete`` for the scoring epoch has not arrived."""


@dataclass(frozen=True)
class EventStreamScores:
    """Everything one scoring run produces."""

    scoring_date: str
    miner_records: list[MinerRecord]
    attribution: MinerAttributionResult
    daily_scores: dict[tuple[str, str], int]
    excluded_signature_verdicts: list[EventVerdict]
    marker_missing: bool
    verdict_count_mismatch: dict[str, tuple[int, int]]


@dataclass(frozen=True)
class ShadowDiff:
    """Per-miner comparison between snapshot- and event-derived records."""

    matches: bool
    score_deltas: dict[str, tuple[int, int]]
    member_deltas: dict[str, tuple[int, int]]
    only_in_snapshot: list[str]
    only_in_events: list[str]

    def report_lines(self) -> list[str]:
        lines: list[str] = []
        if self.matches:
            lines.append("shadow diff: PARITY (all miners match)")
            return lines
        lines.append("shadow diff: MISMATCH")
        for hotkey, (ours, theirs) in sorted(self.score_deltas.items()):
            lines.append(f"  score {hotkey}: events={ours} snapshot={theirs}")
        for hotkey, (ours, theirs) in sorted(self.member_deltas.items()):
            lines.append(f"  active_members {hotkey}: events={ours} snapshot={theirs}")
        for hotkey in self.only_in_snapshot:
            lines.append(f"  only in snapshot: {hotkey}")
        for hotkey in self.only_in_events:
            lines.append(f"  only in events: {hotkey}")
        return lines


def window_epochs(scoring_date: str) -> list[str]:
    """The 14 epoch ids ending at (and including) ``scoring_date``."""
    end = datetime.strptime(scoring_date, "%Y-%m-%d")
    return [
        (end - timedelta(days=offset)).strftime("%Y-%m-%d")
        for offset in range(SCORING_WINDOW_DAYS - 1, -1, -1)
    ]


def score_event_stream(
    store: EventStore,
    *,
    scoring_date: str,
    allow_missing_marker: bool = False,
) -> EventStreamScores:
    """Recompute miner records for the window ending ``scoring_date``."""
    registry = DeviceKeyRegistry()
    bindings = BindingLedger()
    for identity_record in store.iter_family(EventFamily.IDENTITY):
        registry.apply_identity_record(identity_record)
        bindings.apply_identity_record(identity_record)

    groups = GroupLedger()
    for group_record in store.iter_family(EventFamily.GROUP):
        groups.apply_group_record(group_record)

    weights: dict[tuple[str, str], int] = {}
    markers: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    for exclusion_record in store.iter_family(EventFamily.EXCLUSION):
        core = exclusion_record["core"]
        if core.get("kind") == "verdict":
            applies_to = core["applies_to_epoch"]
            user = exclusion_record["user_ref_evt"]
            weight = core["weight_bp"]
            existing = weights.get((user, applies_to))
            # At-most-one verdict per (user, epoch) is guaranteed; if a
            # duplicate ever appears, the lowest weight wins (and the
            # count mismatch below raises the alarm).
            weights[(user, applies_to)] = weight if existing is None else min(existing, weight)
            verdict_counts[applies_to] = verdict_counts.get(applies_to, 0) + 1
        elif core.get("kind") == "verdicts_complete":
            markers[core["applies_to_epoch"]] = core["verdict_count"]

    marker_missing = scoring_date not in markers
    if marker_missing and not allow_missing_marker:
        raise MissingVerdictsError(
            f"verdicts_complete({scoring_date}) has not been stored; "
            "score later or pass allow_missing_marker after the grace period"
        )

    verdict_count_mismatch = {
        epoch: (verdict_counts.get(epoch, 0), expected)
        for epoch, expected in markers.items()
        if verdict_counts.get(epoch, 0) != expected
    }

    engine = EventScoringEngine(registry)
    excluded: list[EventVerdict] = []
    for activity_record in store.iter_family(EventFamily.ACTIVITY):
        verdict = engine.process(activity_record)
        if verdict.status is VerdictStatus.EXCLUDED_SIGNATURE:
            excluded.append(verdict)

    epochs = window_epochs(scoring_date)
    users = {user for (user, _epoch) in engine.raw_scores()}
    daily_scores: dict[tuple[str, str], int] = {}
    for user in users:
        for epoch in epochs:
            weight = weights.get((user, epoch), FULL_WEIGHT_BP)
            day = engine.compose_day(user, epoch, weight)
            if day.raw > 0 or day.daily_score > 0:
                daily_scores[(user, epoch)] = day.daily_score

    attribution = aggregate_miner_scores(daily_scores, groups, bindings)
    miner_records = [
        MinerRecord(
            miner_hotkey=hotkey,
            miner_score_points=score,
            active_member_count=attribution.active_members.get(hotkey, 0),
        )
        for hotkey, score in sorted(attribution.miner_scores.items())
    ]

    return EventStreamScores(
        scoring_date=scoring_date,
        miner_records=miner_records,
        attribution=attribution,
        daily_scores=daily_scores,
        excluded_signature_verdicts=excluded,
        marker_missing=marker_missing,
        verdict_count_mismatch=verdict_count_mismatch,
    )


def diff_miner_records(
    snapshot_records: list[MinerRecord],
    event_records: list[MinerRecord],
) -> ShadowDiff:
    """Compare the two derivations of the same scoring window."""
    snapshot_by_hotkey = {record.miner_hotkey: record for record in snapshot_records}
    events_by_hotkey = {record.miner_hotkey: record for record in event_records}

    score_deltas: dict[str, tuple[int, int]] = {}
    member_deltas: dict[str, tuple[int, int]] = {}
    for hotkey in snapshot_by_hotkey.keys() & events_by_hotkey.keys():
        ours = events_by_hotkey[hotkey]
        theirs = snapshot_by_hotkey[hotkey]
        if ours.miner_score_points != theirs.miner_score_points:
            score_deltas[hotkey] = (ours.miner_score_points, theirs.miner_score_points)
        if ours.active_member_count != theirs.active_member_count:
            member_deltas[hotkey] = (ours.active_member_count, theirs.active_member_count)

    only_in_snapshot = sorted(snapshot_by_hotkey.keys() - events_by_hotkey.keys())
    only_in_events = sorted(events_by_hotkey.keys() - snapshot_by_hotkey.keys())
    matches = not (score_deltas or member_deltas or only_in_snapshot or only_in_events)
    return ShadowDiff(
        matches=matches,
        score_deltas=score_deltas,
        member_deltas=member_deltas,
        only_in_snapshot=only_in_snapshot,
        only_in_events=only_in_events,
    )


__all__ = [
    "SCORING_WINDOW_DAYS",
    "EventStreamScores",
    "MissingVerdictsError",
    "ShadowDiff",
    "diff_miner_records",
    "score_event_stream",
    "window_epochs",
]
