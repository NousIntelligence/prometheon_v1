"""Event-stream scoring pipeline — store to MinerRecords.

Composes the whole recomputation stack over a local :class:`EventStore`:

    identity family  → DeviceKeyRegistry + BindingLedger
    group family     → GroupLedger
    exclusion family → verdict weights + ``verdicts_complete`` markers
    activity family  → EventScoringEngine → per-(user, day) daily scores
    attribution      → per-miner sums → the existing engine's MinerRecords

Two modes, one code path:

- **live** (the validator runtime): score the rolling window ending on the
  in-progress day. Rankings move continuously as activity arrives. Today
  has no ``verdicts_complete`` marker and is not expected to.
- **sealed** (``ingest score``, parity reports): score a completed day,
  which must carry its marker. The documented fallback — score without it
  after the grace period and alarm — stays an explicit opt-in
  (``allow_missing_marker``), never a silent default.

Alarm evidence is surfaced, not swallowed: records excluded for bad
signatures, a missing marker, or a verdict-count mismatch all ride the
result object for the caller to report.

Shadow-mode support: :func:`diff_miner_records` compares event-derived
MinerRecords against a snapshot-derived list and produces the per-miner
evidence the parity gate is judged on (>= 30 consecutive days of zero
unexplained divergence across >= 3 validators, measured by the platform
through the advisory parity-report endpoint).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final

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
from prometheon.security.canonical import to_canonical_bytes

SCORING_WINDOW_DAYS: Final[int] = 14

# scoring-port-contract §5: "ENGINE_VERSION stamps every computed score; a
# rule change is an explicit, coordinated version bump — never silent." It
# names the frozen rule set, so it tracks the contract revision the engine
# implements — NOT this repo's version, which moves for unrelated reasons.
ENGINE_VERSION: Final[str] = "scoring-port-r4/2a36285f"

_EPOCH_RE: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
    live: bool = False


def build_parity_report(scores: EventStreamScores) -> dict[str, Any]:
    """Per-user daily scores for the scored epoch, as a comparable artifact.

    The pipeline has always computed these; only miner totals were ever
    surfaced, so anyone who needed the per-user numbers reconstructed them
    with throwaway library code. That is how a scoring run that was
    correct at every step still got reported wrong. This is the same
    values, produced by the same code path that feeds the weights, in a
    shape both sides can compare mechanically:

    ``{epoch, scores: [{user_ref_evt, daily_score}], scores_hash}``

    Rows are sorted by ``user_ref_evt``, so two implementations that agree
    produce byte-identical output. ``scores_hash`` is SHA-256 over the
    canonical bytes of ``{epoch, scores}``, which reduces "was this day
    clean?" to one equality check instead of a row-by-row read.
    """
    parse_epoch(scores.scoring_date)
    rows: list[dict[str, Any]] = sorted(
        (
            {"user_ref_evt": user, "daily_score": score}
            for (user, epoch), score in scores.daily_scores.items()
            if epoch == scores.scoring_date
        ),
        key=lambda row: str(row["user_ref_evt"]),
    )
    payload: dict[str, Any] = {"epoch": scores.scoring_date, "scores": rows}
    return {
        **payload,
        "scores_hash": "0x" + hashlib.sha256(to_canonical_bytes(payload)).hexdigest(),
        # Stamped for the audit trail, deliberately OUTSIDE the hashed
        # payload: scores_hash covers {epoch, scores} exactly, and the
        # platform recomputes it. Submission drops this field.
        "engine_version": ENGINE_VERSION,
    }


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


def current_epoch(now: datetime | None = None) -> str:
    """Today's UTC date — the last bucket of the live rolling window.

    ``epoch_id`` is stamped by the platform's database clock, so this is a
    local approximation of it. Around midnight two validators can briefly
    disagree on which day is current and submit different vectors; that is
    inherent to a real-time window and is resolved by chain consensus, not
    by us pretending to know a clock we cannot read.
    """
    moment = now or datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%d")


def parse_epoch(value: str) -> str:
    """Validate a ``YYYY-MM-DD`` epoch id and return it unchanged.

    ``strptime`` alone accepts ``2026-7-4`` and hands back a date, so an
    unpadded ``--date`` used to flow through scoring and come out as an
    ``epoch`` string no platform record could ever match — an empty report
    that looked like a clean one. The shape is part of the contract, so it
    is checked as such.
    """
    if not _EPOCH_RE.match(value):
        raise ValueError(f"epoch must be YYYY-MM-DD with zero padding, got {value!r}")
    datetime.strptime(value, "%Y-%m-%d")  # rejects impossible dates
    return value


def window_epochs(scoring_date: str) -> list[str]:
    """The 14 epoch ids ending at (and including) ``scoring_date``."""
    end = datetime.strptime(parse_epoch(scoring_date), "%Y-%m-%d")
    return [
        (end - timedelta(days=offset)).strftime("%Y-%m-%d")
        for offset in range(SCORING_WINDOW_DAYS - 1, -1, -1)
    ]


def score_event_stream(
    store: EventStore,
    *,
    scoring_date: str,
    allow_missing_marker: bool = False,
    live: bool = False,
) -> EventStreamScores:
    """Recompute miner records for the window ending ``scoring_date``.

    ``live=True`` scores the **in-progress** day: the window's last bucket
    is today so far, and today's ``verdicts_complete`` marker is neither
    expected nor alarmed (the platform seals a day the morning after). This
    is the mode the validator runtime uses — rankings move continuously as
    activity accumulates, rather than stepping once a day.

    The consequence to understand: today's anti-fraud verdicts do not exist
    yet, so today's activity scores at full weight until verdicts arrive.
    The rolling window then corrects it — every later recompute uses the
    verdict, for as long as that day stays in the window. Exposure is
    bounded by the platform's verdict latency, not by anything here.

    ``live=False`` (the default) keeps the sealed-day behaviour used by
    ``ingest score`` for parity reports, where a day without its marker is
    genuinely incomplete.
    """
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
            # ingest-contract §5: "weight_bp ∈ {0,1250,2500,5000,10000};
            # absent ⇒ 10000". Reading it as required turned a legal
            # verdict into a KeyError that aborted the whole scoring run.
            weight = core.get("weight_bp", FULL_WEIGHT_BP)
            existing = weights.get((user, applies_to))
            # At-most-one verdict per (user, epoch) is guaranteed; if a
            # duplicate ever appears, the lowest weight wins (and the
            # count mismatch below raises the alarm).
            weights[(user, applies_to)] = weight if existing is None else min(existing, weight)
            verdict_counts[applies_to] = verdict_counts.get(applies_to, 0) + 1
        elif core.get("kind") == "verdicts_complete":
            markers[core["applies_to_epoch"]] = core["verdict_count"]

    # In live mode the scored day is still in progress, so its
    # verdicts_complete marker cannot exist yet — the platform seals a day
    # once, the morning after. Absence is the expected state, not an alarm,
    # and blocking on it would make a real-time window impossible.
    marker_missing = not live and scoring_date not in markers
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
        live=live,
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
    "ENGINE_VERSION",
    "SCORING_WINDOW_DAYS",
    "EventStreamScores",
    "MissingVerdictsError",
    "ShadowDiff",
    "build_parity_report",
    "current_epoch",
    "diff_miner_records",
    "parse_epoch",
    "score_event_stream",
    "window_epochs",
]
