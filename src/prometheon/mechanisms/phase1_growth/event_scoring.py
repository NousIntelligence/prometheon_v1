"""Open recomputation of per-user daily scores from the event stream.

Implements the frozen scoring-port contract: per-kind qualification (§2),
the daily kernel (§1), and streak derivation — the validator-side half of
the "honest postman" model. Given the same stored stream, every compliant
validator produces bit-identical ``daily_score`` values; the exhaustive
fixture suites (``score-kernel/01..03``) gate this module in CI.

Layering:

- :class:`EventScoringEngine` consumes **activity-family records in seq
  order** plus a :class:`~prometheon.events.device_signatures.DeviceKeyRegistry`
  (identity-family state complete through the scored epochs) and produces a
  per-event :class:`EventVerdict` stream and per-(user, day) raw sums.
- :func:`compose_day` applies the kernel: raw cap 20, streak bonus from the
  seven prior epochs, pre cap 22, then the exclusion-family
  ``weight_bp`` multiplier (absent verdict = full weight).
- Records classified ``invalid`` / ``unregistered`` by the signature layer
  are **excluded before qualification** and never enter any dedup window;
  their presence in the publisher-signed stream is injection evidence the
  caller must alarm on (:attr:`EventVerdict.status` is
  ``excluded_signature``).

Everything is integer arithmetic. Sliding windows run on ``received_ts``
(second precision); daily caps bucket on ``epoch_id``. Exact boundary
semantics (inclusive/exclusive edges) follow §2 and are fixture-pinned.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Final

from prometheon.events.device_signatures import (
    DeviceKeyRegistry,
    SignatureStatus,
    classify_signature,
)

# ---------------------------------------------------------------------------
# Frozen constants (scoring-port contract sections 1 and 2)
# ---------------------------------------------------------------------------

EVENT_POINTS: Final[dict[str, int]] = {
    "login": 1,
    "service_detail_view": 2,
    "category_exploration": 1,
    "watchlist_add": 3,
    "service_follow_add": 2,
    "service_news_click": 2,
    "compare_session": 4,
    "demo_l1": 2,
    "demo_l2": 4,
    "demo_l3": 6,
}

DAILY_KIND_CAPS: Final[dict[str, int]] = {
    "login": 1,
    "category_exploration": 2,
    "watchlist_add": 2,
    "service_follow_add": 2,
    "service_news_click": 2,
    "compare_session": 1,
}

DAILY_RAW_CAP: Final[int] = 20
DAILY_PRE_CAP: Final[int] = 22
ACTIVE_DAY_THRESHOLD: Final[int] = 4
FULL_WEIGHT_BP: Final[int] = 10000
VERDICT_WEIGHT_BP_VALUES: Final[frozenset[int]] = frozenset({0, 1250, 2500, 5000, 10000})

_VIEW_DEDUP_WINDOW: Final[timedelta] = timedelta(hours=24)
_PAIR_DEDUP_WINDOW: Final[timedelta] = timedelta(days=7)
_EXPLORATION_WINDOW: Final[timedelta] = timedelta(minutes=30)
_STREAK_LOOKBACK_DAYS: Final[int] = 7
_MAX_VIEW_SERVICES_PER_DAY: Final[int] = 4
_MAX_DEMO_SERVICES_PER_DAY: Final[int] = 2
_EXPLORATION_MIN_DISTINCT_VIEWS: Final[int] = 3
_DEMO_L1_MIN_WATCH_PERMILLE: Final[int] = 850
_DEMO_L1_MAX_SEEKS: Final[int] = 3


class VerdictStatus(str, Enum):
    """Outcome of processing one activity record."""

    COUNTED = "counted"
    REJECTED = "rejected"
    EXCLUDED_SIGNATURE = "excluded_signature"


@dataclass(frozen=True)
class EventVerdict:
    """Per-event qualification outcome, in the fixture-pinned shape."""

    seq: int
    kind: str
    signature_status: SignatureStatus
    status: VerdictStatus
    points: int

    def as_mapping(self) -> dict[str, Any]:
        """The exact mapping shape the qualification fixtures assert."""
        return {
            "seq": self.seq,
            "kind": self.kind,
            "signature_status": self.signature_status.value,
            "status": self.status.value,
            "points": self.points,
        }


@dataclass(frozen=True)
class DayScore:
    """One (user, epoch) row after kernel composition."""

    epoch_id: str
    raw: int
    active: bool
    streak_bonus: int
    weight_bp: int
    daily_score: int

    def as_mapping(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "raw": self.raw,
            "active": self.active,
            "streak_bonus": self.streak_bonus,
            "weight_bp": self.weight_bp,
            "daily_score": self.daily_score,
        }


class EventScoringError(ValueError):
    """A scoring input violated the frozen contract's preconditions."""


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _parse_day(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d")


# ---------------------------------------------------------------------------
# Kernel + streaks (§1)
# ---------------------------------------------------------------------------


def streak_bonus_for(prior_raw_desc: list[int]) -> int:
    """Bonus from prior consecutive active days, most recent first.

    Look-back is exactly seven epochs; a missing epoch is inactive and
    breaks the streak (the genesis boundary therefore counts as inactive).
    Thresholds: >= 6 -> +3, >= 4 -> +2, >= 2 -> +1, else 0.
    """
    streak = 0
    for raw in prior_raw_desc[:_STREAK_LOOKBACK_DAYS]:
        if raw >= ACTIVE_DAY_THRESHOLD:
            streak += 1
        else:
            break
    if streak >= 6:
        return 3
    if streak >= 4:
        return 2
    if streak >= 2:
        return 1
    return 0


def kernel_daily_score(raw: int, streak: int, weight_bp: int) -> int:
    """``floor(min(22, raw + streak) * weight_bp / 10000)`` — integer only."""
    if weight_bp not in VERDICT_WEIGHT_BP_VALUES:
        raise EventScoringError(f"weight_bp {weight_bp!r} outside the locked verdict value set")
    return (min(DAILY_PRE_CAP, raw + streak) * weight_bp) // FULL_WEIGHT_BP


# ---------------------------------------------------------------------------
# Qualification (§2)
# ---------------------------------------------------------------------------


class _UserWindows:
    """Per-user qualification state. Only COUNTED events enter any window."""

    __slots__ = (
        "compare_pairs",
        "counted_views",
        "demo_services_by_day",
        "demo_uses",
        "kind_count_by_day",
        "lifetime_once",
        "news_seen",
        "view_services_by_day",
    )

    def __init__(self) -> None:
        self.counted_views: list[tuple[datetime, str, str | None]] = []
        self.view_services_by_day: dict[str, set[str]] = {}
        self.kind_count_by_day: dict[tuple[str, str], int] = {}
        self.news_seen: set[str] = set()
        self.lifetime_once: set[tuple[str, str]] = set()
        self.compare_pairs: list[tuple[datetime, tuple[str, str]]] = []
        self.demo_uses: list[tuple[datetime, str, str]] = []
        self.demo_services_by_day: dict[str, set[str]] = {}


class EventScoringEngine:
    """Replays an activity-family stream into verdicts and raw day sums.

    Feed records via :meth:`process` strictly in seq order (the engine
    enforces monotonicity — an out-of-order feed indicates a store bug and
    fails loud rather than silently diverging from other validators).
    """

    def __init__(self, registry: DeviceKeyRegistry) -> None:
        self._registry = registry
        self._windows: dict[str, _UserWindows] = {}
        self._raw_by_user_day: dict[tuple[str, str], int] = {}
        self._last_seq: int | None = None

    def process(self, record: dict[str, Any]) -> EventVerdict:
        """Classify, qualify, and accumulate one activity record."""
        seq = record["seq"]
        if self._last_seq is not None and seq <= self._last_seq:
            raise EventScoringError(
                f"activity records must be fed in ascending seq order "
                f"(got {seq} after {self._last_seq})"
            )
        self._last_seq = seq
        kind = record["core"]["kind"] if "core" in record else record["kind"]

        signature = classify_signature(record, self._registry)
        if signature in (SignatureStatus.INVALID, SignatureStatus.UNREGISTERED):
            return EventVerdict(
                seq=seq,
                kind=kind,
                signature_status=signature,
                status=VerdictStatus.EXCLUDED_SIGNATURE,
                points=0,
            )

        user = record["user_ref_evt"]
        windows = self._windows.setdefault(user, _UserWindows())
        counted = self._qualify(record, kind, windows)
        points = EVENT_POINTS[kind] if counted else 0
        if counted:
            key = (user, record["epoch_id"])
            self._raw_by_user_day[key] = self._raw_by_user_day.get(key, 0) + points
        return EventVerdict(
            seq=seq,
            kind=kind,
            signature_status=signature,
            status=VerdictStatus.COUNTED if counted else VerdictStatus.REJECTED,
            points=points,
        )

    def raw_scores(self) -> dict[tuple[str, str], int]:
        """Accumulated pre-cap raw sums keyed by ``(user_ref_evt, epoch_id)``."""
        return dict(self._raw_by_user_day)

    def compose_day(self, user: str, epoch_id: str, weight_bp: int = FULL_WEIGHT_BP) -> DayScore:
        """Apply the kernel for one (user, epoch) against accumulated raws."""
        raw = min(DAILY_RAW_CAP, self._raw_by_user_day.get((user, epoch_id), 0))
        active = raw >= ACTIVE_DAY_THRESHOLD
        day = _parse_day(epoch_id)
        prior = [
            min(
                DAILY_RAW_CAP,
                self._raw_by_user_day.get(
                    (user, (day - timedelta(days=offset)).strftime("%Y-%m-%d")), 0
                ),
            )
            for offset in range(1, _STREAK_LOOKBACK_DAYS + 1)
        ]
        bonus = streak_bonus_for(prior) if active else 0
        return DayScore(
            epoch_id=epoch_id,
            raw=raw,
            active=active,
            streak_bonus=bonus,
            weight_bp=weight_bp,
            daily_score=kernel_daily_score(raw, bonus, weight_bp),
        )

    # ------------------------------------------------------------------
    # Per-kind rules (§2). State mutates only on a counted outcome.
    # ------------------------------------------------------------------

    def _qualify(self, record: dict[str, Any], kind: str, windows: _UserWindows) -> bool:
        epoch = record["epoch_id"]
        received = _parse_ts(record["received_ts"])
        core = record.get("core", record)
        fields = core.get("scoring_fields") or {}
        target = core.get("target") or {}

        cap = DAILY_KIND_CAPS.get(kind)
        if cap is not None and windows.kind_count_by_day.get((kind, epoch), 0) >= cap:
            return False

        if kind == "login":
            counted = True
        elif kind == "service_detail_view":
            counted = self._qualify_view(record, windows, epoch, received, fields, target)
        elif kind == "category_exploration":
            counted = self._qualify_exploration(record, windows, received)
        elif kind in ("watchlist_add", "service_follow_add"):
            counted = self._qualify_lifetime_once(kind, windows, target)
        elif kind == "service_news_click":
            counted = self._qualify_news(windows, target)
        elif kind == "compare_session":
            counted = self._qualify_compare(windows, received, fields, target)
        elif kind in ("demo_l1", "demo_l2", "demo_l3"):
            counted = self._qualify_demo(kind, windows, epoch, received, fields, target)
        else:
            raise EventScoringError(f"unknown activity kind {kind!r}")

        if counted:
            windows.kind_count_by_day[(kind, epoch)] = (
                windows.kind_count_by_day.get((kind, epoch), 0) + 1
            )
        return counted

    def _qualify_view(
        self,
        record: dict[str, Any],
        windows: _UserWindows,
        epoch: str,
        received: datetime,
        fields: dict[str, Any],
        target: dict[str, Any],
    ) -> bool:
        service = target.get("service_id")
        if service is None:
            return False
        # Metric threshold: dwell >= 12s OR scroll >= 60% OR >= 1 outbound click.
        if not (
            fields.get("dwell_seconds", 0) >= 12
            or fields.get("scroll_percent", 0) >= 60
            or fields.get("outbound_clicks", 0) >= 1
        ):
            return False
        # Same-service dedup over [t-24h, t): a counted view AT exactly
        # t-24h still blocks (inclusive lower edge).
        low = received - _VIEW_DEDUP_WINDOW
        if any(s == service and low <= t < received for t, s, _ in windows.counted_views):
            return False
        day_services = windows.view_services_by_day.setdefault(epoch, set())
        if service not in day_services and len(day_services) >= _MAX_VIEW_SERVICES_PER_DAY:
            return False
        windows.counted_views.append((received, service, record.get("category_id")))
        day_services.add(service)
        return True

    def _qualify_exploration(
        self, record: dict[str, Any], windows: _UserWindows, received: datetime
    ) -> bool:
        category = record.get("category_id")
        if category is None:
            return False
        # Bound-check: >= 3 distinct same-category counted views in
        # [t-30min, t] (inclusive upper edge).
        low = received - _EXPLORATION_WINDOW
        distinct = {
            service
            for t, service, cat in windows.counted_views
            if cat == category and low <= t <= received
        }
        return len(distinct) >= _EXPLORATION_MIN_DISTINCT_VIEWS

    def _qualify_lifetime_once(
        self, kind: str, windows: _UserWindows, target: dict[str, Any]
    ) -> bool:
        # Platform-enforced lifetime-once per service, defensively
        # re-enforced within the stored window (fixture-pinned behavior).
        service = target.get("service_id")
        if service is None or (kind, service) in windows.lifetime_once:
            return False
        windows.lifetime_once.add((kind, service))
        return True

    def _qualify_news(self, windows: _UserWindows, target: dict[str, Any]) -> bool:
        item = target.get("news_item_id")
        if item is None or item in windows.news_seen:
            return False
        windows.news_seen.add(item)
        return True

    def _qualify_compare(
        self,
        windows: _UserWindows,
        received: datetime,
        fields: dict[str, Any],
        target: dict[str, Any],
    ) -> bool:
        if fields.get("dwell_seconds", 0) < 30:
            return False
        other = target.get("other_service_id")
        if other is not None:
            # Pair = the two ids sorted; dedup over [t-7d, t). An absent
            # other_service_id means no pair dedup, mirroring the platform.
            first = target.get("service_id")
            if not isinstance(first, str):
                return False
            pair = (min(first, other), max(first, other))
            low = received - _PAIR_DEDUP_WINDOW
            if any(p == pair and low <= t < received for t, p in windows.compare_pairs):
                return False
            windows.compare_pairs.append((received, pair))
        return True

    def _qualify_demo(
        self,
        kind: str,
        windows: _UserWindows,
        epoch: str,
        received: datetime,
        fields: dict[str, Any],
        target: dict[str, Any],
    ) -> bool:
        demo_id = target.get("demo_id")
        if kind == "demo_l1":
            if not self._demo_l1_metrics_pass(fields):
                return False
        elif demo_id is None:
            # demo_l2 / demo_l3 require the dedup key.
            return False
        if demo_id is not None:
            # Same demo once per 7 days per level: [t-7d, t).
            low = received - _PAIR_DEDUP_WINDOW
            if any(
                level == kind and d == demo_id and low <= t < received
                for t, level, d in windows.demo_uses
            ):
                return False
        service = target.get("service_id")
        day_services = windows.demo_services_by_day.setdefault(epoch, set())
        if (
            service is not None
            and service not in day_services
            and len(day_services) >= _MAX_DEMO_SERVICES_PER_DAY
        ):
            return False
        if demo_id is not None:
            windows.demo_uses.append((received, kind, demo_id))
        if service is not None:
            day_services.add(service)
        return True

    @staticmethod
    def _demo_l1_metrics_pass(fields: dict[str, Any]) -> bool:
        """Integer-exact demo_l1 thresholds (scoring-port §2 amendment).

        ``watch_permille >= 850``; ``seek_count <= 3`` (absent rejects);
        with ``total_play = watched_seconds if > 0 else
        video_duration_seconds``: reject when ``total_play > 0`` and
        ``tab_hidden_seconds`` is absent or ``5 * hidden >= total_play``.
        """
        permille = fields.get("watch_permille")
        if permille is None or permille < _DEMO_L1_MIN_WATCH_PERMILLE:
            return False
        seeks = fields.get("seek_count")
        if seeks is None or seeks > _DEMO_L1_MAX_SEEKS:
            return False
        watched = fields.get("watched_seconds", 0)
        total_play = watched if watched > 0 else fields.get("video_duration_seconds", 0)
        hidden = fields.get("tab_hidden_seconds")
        return not (total_play > 0 and (hidden is None or 5 * hidden >= total_play))


__all__ = [
    "ACTIVE_DAY_THRESHOLD",
    "DAILY_KIND_CAPS",
    "DAILY_PRE_CAP",
    "DAILY_RAW_CAP",
    "EVENT_POINTS",
    "FULL_WEIGHT_BP",
    "VERDICT_WEIGHT_BP_VALUES",
    "DayScore",
    "EventScoringEngine",
    "EventScoringError",
    "EventVerdict",
    "VerdictStatus",
    "kernel_daily_score",
    "streak_bonus_for",
]
