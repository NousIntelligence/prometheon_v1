"""Scheduling decisions for the validator runtime.

Encapsulates the small set of "should I do X now?" questions the runner
answers on every tick:

- Should I refresh the snapshot from the platform?
- Should I re-sync the metagraph?
- Should I attempt a weight submission?

Each decision is a pure function of (configured interval, last action time,
current time). Pure-function design keeps the runner unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from prometheon.validator.config import SchedulerConfig


@dataclass(frozen=True)
class ScheduleTicks:
    """The 'last time we did X' record for scheduling decisions.

    All fields default to ``None`` for first-run; once a step has run,
    its corresponding timestamp moves forward.
    """

    last_snapshot_refresh_at: datetime | None = None
    last_metagraph_refresh_at: datetime | None = None
    last_submission_attempt_at: datetime | None = None


def now_utc() -> datetime:
    """Return current UTC datetime; centralised so tests can monkey-patch."""
    return datetime.now(timezone.utc)


def _should_run(last: datetime | None, *, interval_minutes: int, now: datetime) -> bool:
    """Return ``True`` if ``last`` is unset or older than ``interval_minutes`` ago.

    Used as the building block for every scheduling decision.
    """
    if last is None:
        return True
    return now - last >= timedelta(minutes=interval_minutes)


def should_refresh_snapshot(
    ticks: ScheduleTicks, *, config: SchedulerConfig, now: datetime | None = None
) -> bool:
    """Decide whether to fetch a fresh snapshot from the platform now."""
    return _should_run(
        ticks.last_snapshot_refresh_at,
        interval_minutes=config.snapshot_refresh_interval_minutes,
        now=now if now is not None else now_utc(),
    )


def should_refresh_metagraph(
    ticks: ScheduleTicks, *, config: SchedulerConfig, now: datetime | None = None
) -> bool:
    """Decide whether to re-sync the metagraph now.

    The runner always re-syncs immediately before any submission; this
    decision drives the standalone background refresh that keeps the
    in-memory view fresh between submissions.
    """
    return _should_run(
        ticks.last_metagraph_refresh_at,
        interval_minutes=config.metagraph_refresh_interval_minutes,
        now=now if now is not None else now_utc(),
    )


def should_attempt_submission(
    ticks: ScheduleTicks, *, config: SchedulerConfig, now: datetime | None = None
) -> bool:
    """Decide whether to attempt a weight submission now.

    Coarse-grained timer: chain-side ``weights_rate_limit`` enforcement
    runs at submission time inside the chain adapter; this check is the
    cheap upstream filter that keeps the runner from spinning on
    repeated rejections.
    """
    return _should_run(
        ticks.last_submission_attempt_at,
        interval_minutes=config.weight_submission_check_interval_minutes,
        now=now if now is not None else now_utc(),
    )


__all__ = [
    "ScheduleTicks",
    "now_utc",
    "should_attempt_submission",
    "should_refresh_metagraph",
    "should_refresh_snapshot",
]
