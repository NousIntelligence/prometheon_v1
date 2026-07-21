"""Unit tests for the event-scoring engine's per-kind boundary rules.

The contract suite replays the full fixture scenario; these tests pin each
qualification boundary in isolation so a regression names the exact rule.
All records are unsigned (signature classification has its own suites).
"""

from __future__ import annotations

from typing import Any

import pytest

from prometheon.events.device_signatures import DeviceKeyRegistry
from prometheon.mechanisms.phase1_growth.event_scoring import (
    EventScoringEngine,
    EventScoringError,
    VerdictStatus,
    kernel_daily_score,
    streak_bonus_for,
)

pytestmark = pytest.mark.unit

USER = "usr_evt_" + "aa" * 32


def _engine() -> EventScoringEngine:
    return EventScoringEngine(DeviceKeyRegistry())


class _Feed:
    """Tiny helper assigning ascending seqs and shared defaults."""

    def __init__(self) -> None:
        self.engine = _engine()
        self._seq = 0

    def send(
        self,
        kind: str,
        *,
        ts: str,
        target: dict[str, Any] | None = None,
        fields: dict[str, Any] | None = None,
        category_id: str | None = None,
        user: str = USER,
    ) -> VerdictStatus:
        self._seq += 1
        record = {
            "seq": self._seq,
            "epoch_id": ts[:10],
            "user_ref_evt": user,
            "received_ts": ts,
            "category_id": category_id,
            "core": {
                "domain": "PROMETHEON_EVENT_V1",
                "kind": kind,
                "target": target or {},
                "scoring_fields": fields or {},
                "client_ts": ts,
                "client_nonce": "0x0000000000000001",
            },
            "device_pubkey": None,
            "user_sig": None,
        }
        return self.engine.process(record).status


def _view_fields() -> dict[str, Any]:
    return {"dwell_seconds": 30, "scroll_percent": 0, "outbound_clicks": 0}


class TestKernelAndStreaks:
    def test_kernel_rejects_unknown_weight(self) -> None:
        with pytest.raises(EventScoringError):
            kernel_daily_score(10, 0, 9999)

    def test_streak_break_on_missing_day(self) -> None:
        assert streak_bonus_for([4, 0, 4, 4, 4, 4, 4]) == 0

    def test_streak_caps_at_lookback(self) -> None:
        assert streak_bonus_for([20] * 10) == 3


class TestViewRules:
    def test_threshold_is_a_disjunction(self) -> None:
        feed = _Feed()
        below = {"dwell_seconds": 11, "scroll_percent": 59, "outbound_clicks": 0}
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "s1"},
                fields=below,
            )
            is VerdictStatus.REJECTED
        )
        one_click = {"dwell_seconds": 0, "scroll_percent": 0, "outbound_clicks": 1}
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-01T10:01:00Z",
                target={"service_id": "s1"},
                fields=one_click,
            )
            is VerdictStatus.COUNTED
        )

    def test_same_service_blocked_at_exactly_24h(self) -> None:
        feed = _Feed()
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "s1"},
                fields=_view_fields(),
            )
            is VerdictStatus.COUNTED
        )
        # Exactly t-24h is inside the window: still blocked.
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-02T10:00:00Z",
                target={"service_id": "s1"},
                fields=_view_fields(),
            )
            is VerdictStatus.REJECTED
        )
        # One second past the window: counts again.
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-02T10:00:01Z",
                target={"service_id": "s1"},
                fields=_view_fields(),
            )
            is VerdictStatus.COUNTED
        )

    def test_rejected_view_does_not_block_dedup(self) -> None:
        feed = _Feed()
        below = {"dwell_seconds": 1, "scroll_percent": 1, "outbound_clicks": 0}
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "s1"},
                fields=below,
            )
            is VerdictStatus.REJECTED
        )
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-01T10:05:00Z",
                target={"service_id": "s1"},
                fields=_view_fields(),
            )
            is VerdictStatus.COUNTED
        )

    def test_max_four_distinct_services_per_day(self) -> None:
        feed = _Feed()
        for index in range(4):
            assert (
                feed.send(
                    "service_detail_view",
                    ts=f"2026-07-01T1{index}:00:00Z",
                    target={"service_id": f"s{index}"},
                    fields=_view_fields(),
                )
                is VerdictStatus.COUNTED
            )
        assert (
            feed.send(
                "service_detail_view",
                ts="2026-07-01T15:00:00Z",
                target={"service_id": "s-fifth"},
                fields=_view_fields(),
            )
            is VerdictStatus.REJECTED
        )


class TestExplorationRules:
    def test_requires_three_distinct_views_in_window_inclusive_edge(self) -> None:
        feed = _Feed()
        for index, minute in enumerate(("00", "10", "20")):
            feed.send(
                "service_detail_view",
                ts=f"2026-07-01T10:{minute}:00Z",
                target={"service_id": f"s{index}"},
                fields=_view_fields(),
                category_id="cat-1",
            )
        # The 10:00 view sits at exactly t-30min: inclusive, so it counts.
        assert (
            feed.send("category_exploration", ts="2026-07-01T10:30:00Z", category_id="cat-1")
            is VerdictStatus.COUNTED
        )

    def test_two_views_insufficient(self) -> None:
        feed = _Feed()
        for index in range(2):
            feed.send(
                "service_detail_view",
                ts=f"2026-07-01T10:0{index}:00Z",
                target={"service_id": f"s{index}"},
                fields=_view_fields(),
                category_id="cat-1",
            )
        assert (
            feed.send("category_exploration", ts="2026-07-01T10:15:00Z", category_id="cat-1")
            is VerdictStatus.REJECTED
        )


class TestLifetimeAndNewsRules:
    def test_watchlist_duplicate_service_rejected(self) -> None:
        feed = _Feed()
        assert (
            feed.send("watchlist_add", ts="2026-07-01T10:00:00Z", target={"service_id": "s1"})
            is VerdictStatus.COUNTED
        )
        assert (
            feed.send("watchlist_add", ts="2026-07-01T10:05:00Z", target={"service_id": "s1"})
            is VerdictStatus.REJECTED
        )

    def test_news_requires_item_id_and_is_lifetime_once(self) -> None:
        feed = _Feed()
        assert (
            feed.send("service_news_click", ts="2026-07-01T10:00:00Z", target={})
            is VerdictStatus.REJECTED
        )
        assert (
            feed.send(
                "service_news_click",
                ts="2026-07-01T10:01:00Z",
                target={"news_item_id": "n1"},
            )
            is VerdictStatus.COUNTED
        )
        assert (
            feed.send(
                "service_news_click",
                ts="2026-07-02T10:00:00Z",
                target={"news_item_id": "n1"},
            )
            is VerdictStatus.REJECTED
        )


class TestCompareRules:
    def test_pair_dedup_is_order_insensitive_within_7d(self) -> None:
        feed = _Feed()
        assert (
            feed.send(
                "compare_session",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "a", "other_service_id": "b"},
                fields={"dwell_seconds": 45},
            )
            is VerdictStatus.COUNTED
        )
        assert (
            feed.send(
                "compare_session",
                ts="2026-07-03T10:00:00Z",
                target={"service_id": "b", "other_service_id": "a"},
                fields={"dwell_seconds": 45},
            )
            is VerdictStatus.REJECTED
        )

    def test_absent_other_id_skips_pair_dedup(self) -> None:
        feed = _Feed()
        assert (
            feed.send(
                "compare_session",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "a"},
                fields={"dwell_seconds": 45},
            )
            is VerdictStatus.COUNTED
        )
        assert (
            feed.send(
                "compare_session",
                ts="2026-07-02T10:00:00Z",
                target={"service_id": "a"},
                fields={"dwell_seconds": 45},
            )
            is VerdictStatus.COUNTED
        )

    def test_short_dwell_rejected(self) -> None:
        feed = _Feed()
        assert (
            feed.send(
                "compare_session",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "a", "other_service_id": "b"},
                fields={"dwell_seconds": 29},
            )
            is VerdictStatus.REJECTED
        )


class TestDemoRules:
    @staticmethod
    def _l1_fields(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "watch_permille": 900,
            "seek_count": 1,
            "watched_seconds": 100,
            "video_duration_seconds": 110,
            "tab_hidden_seconds": 5,
        }
        base.update(overrides)
        return base

    def test_permille_boundary(self) -> None:
        feed = _Feed()
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=self._l1_fields(watch_permille=849),
            )
            is VerdictStatus.REJECTED
        )
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:01:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=self._l1_fields(watch_permille=850),
            )
            is VerdictStatus.COUNTED
        )

    def test_seek_count_absent_or_excessive_rejected(self) -> None:
        feed = _Feed()
        fields = self._l1_fields()
        del fields["seek_count"]
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=fields,
            )
            is VerdictStatus.REJECTED
        )
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:01:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=self._l1_fields(seek_count=4),
            )
            is VerdictStatus.REJECTED
        )

    def test_tab_hidden_rule_and_watched_fallback(self) -> None:
        feed = _Feed()
        # 5 * 20 >= 100 -> rejected.
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:00:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=self._l1_fields(tab_hidden_seconds=20),
            )
            is VerdictStatus.REJECTED
        )
        # Absent tab_hidden_seconds with positive play -> rejected.
        fields = self._l1_fields()
        del fields["tab_hidden_seconds"]
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:01:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=fields,
            )
            is VerdictStatus.REJECTED
        )
        # watched_seconds == 0 falls back to video_duration_seconds.
        assert (
            feed.send(
                "demo_l1",
                ts="2026-07-01T10:02:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
                fields=self._l1_fields(watched_seconds=0, tab_hidden_seconds=10),
            )
            is VerdictStatus.COUNTED
        )

    def test_l2_requires_demo_id_and_7d_dedup_is_per_level(self) -> None:
        feed = _Feed()
        assert (
            feed.send("demo_l2", ts="2026-07-01T10:00:00Z", target={"service_id": "s1"})
            is VerdictStatus.REJECTED
        )
        assert (
            feed.send(
                "demo_l2",
                ts="2026-07-01T10:01:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
            )
            is VerdictStatus.COUNTED
        )
        # Same demo, same level, inside 7d: rejected.
        assert (
            feed.send(
                "demo_l2",
                ts="2026-07-04T10:00:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
            )
            is VerdictStatus.REJECTED
        )
        # Same demo id at a DIFFERENT level: its own dedup lane.
        assert (
            feed.send(
                "demo_l3",
                ts="2026-07-04T10:01:00Z",
                target={"service_id": "s1", "demo_id": "d1"},
            )
            is VerdictStatus.COUNTED
        )

    def test_max_two_distinct_demo_services_per_day(self) -> None:
        feed = _Feed()
        for index in range(2):
            assert (
                feed.send(
                    "demo_l2",
                    ts=f"2026-07-01T1{index}:00:00Z",
                    target={"service_id": f"s{index}", "demo_id": f"d{index}"},
                )
                is VerdictStatus.COUNTED
            )
        assert (
            feed.send(
                "demo_l2",
                ts="2026-07-01T12:00:00Z",
                target={"service_id": "s-third", "demo_id": "d-third"},
            )
            is VerdictStatus.REJECTED
        )


class TestEngineGuards:
    def test_out_of_order_seq_fails_loud(self) -> None:
        feed = _Feed()
        feed.send("login", ts="2026-07-01T10:00:00Z")
        record = {
            "seq": 1,
            "epoch_id": "2026-07-01",
            "user_ref_evt": USER,
            "received_ts": "2026-07-01T11:00:00Z",
            "category_id": None,
            "core": {
                "domain": "PROMETHEON_EVENT_V1",
                "kind": "login",
                "target": {},
                "scoring_fields": {},
                "client_ts": "2026-07-01T11:00:00Z",
                "client_nonce": "0x0000000000000002",
            },
            "device_pubkey": None,
            "user_sig": None,
        }
        with pytest.raises(EventScoringError):
            feed.engine.process(record)

    def test_login_daily_cap(self) -> None:
        feed = _Feed()
        assert feed.send("login", ts="2026-07-01T08:00:00Z") is VerdictStatus.COUNTED
        assert feed.send("login", ts="2026-07-01T09:00:00Z") is VerdictStatus.REJECTED
        assert feed.send("login", ts="2026-07-02T08:00:00Z") is VerdictStatus.COUNTED
