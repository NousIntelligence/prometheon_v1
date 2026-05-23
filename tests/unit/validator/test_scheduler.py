"""Unit tests for ``prometheon.validator.scheduler``."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from prometheon.validator.config import SchedulerConfig
from prometheon.validator.scheduler import (
    ScheduleTicks,
    should_attempt_submission,
    should_refresh_metagraph,
    should_refresh_snapshot,
)

pytestmark = pytest.mark.unit


def _config(**overrides: int) -> SchedulerConfig:
    defaults = {
        "snapshot_refresh_interval_minutes": 60,
        "metagraph_refresh_interval_minutes": 10,
        "weight_submission_check_interval_minutes": 15,
    }
    defaults.update(overrides)
    return SchedulerConfig.model_validate(defaults)


NOW = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)


class TestShouldRefreshSnapshot:
    def test_runs_on_first_call_when_last_is_none(self) -> None:
        ticks = ScheduleTicks()
        assert should_refresh_snapshot(ticks, config=_config(), now=NOW)

    def test_skips_within_interval(self) -> None:
        ticks = ScheduleTicks(last_snapshot_refresh_at=NOW - timedelta(minutes=30))
        # 30 minutes < 60-minute interval.
        assert not should_refresh_snapshot(ticks, config=_config(), now=NOW)

    def test_runs_at_interval_boundary(self) -> None:
        ticks = ScheduleTicks(last_snapshot_refresh_at=NOW - timedelta(minutes=60))
        assert should_refresh_snapshot(ticks, config=_config(), now=NOW)


class TestShouldRefreshMetagraph:
    def test_default_10_minute_interval(self) -> None:
        ticks = ScheduleTicks(last_metagraph_refresh_at=NOW - timedelta(minutes=9))
        assert not should_refresh_metagraph(ticks, config=_config(), now=NOW)
        ticks_at_boundary = ScheduleTicks(last_metagraph_refresh_at=NOW - timedelta(minutes=10))
        assert should_refresh_metagraph(ticks_at_boundary, config=_config(), now=NOW)


class TestShouldAttemptSubmission:
    def test_default_15_minute_interval(self) -> None:
        ticks = ScheduleTicks(last_submission_attempt_at=NOW - timedelta(minutes=14))
        assert not should_attempt_submission(ticks, config=_config(), now=NOW)
        ticks_at_boundary = ScheduleTicks(last_submission_attempt_at=NOW - timedelta(minutes=15))
        assert should_attempt_submission(ticks_at_boundary, config=_config(), now=NOW)

    def test_first_call_always_runs(self) -> None:
        assert should_attempt_submission(ScheduleTicks(), config=_config(), now=NOW)
