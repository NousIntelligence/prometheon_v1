"""Reference scorer for the Decentralized Validation contract tests.

A deliberately compact, test-local implementation of the frozen
scoring-port contract: signature-status evaluation, per-kind qualification
(§2), the daily kernel, streak derivation, and the C2/C3 attribution rules.

It exists so the vendored vectors are gated from day one and stays as an
independent cross-check after the production engine lands — both are pinned
to the same fixtures, so any drift between them is a test failure, never a
silent divergence.

Scale note: state scans are linear per user because fixture scenarios are
small; the production engine indexes these windows properly.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

EVENT_DOMAIN = b"PROMETHEON_EVENT_V1\n"

POINTS = {
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

DAILY_CAPS = {
    "login": 1,
    "category_exploration": 2,
    "watchlist_add": 2,
    "service_follow_add": 2,
    "service_news_click": 2,
    "compare_session": 1,
}

DAILY_RAW_CAP = 20
DAILY_PRE_CAP = 22
ACTIVE_THRESHOLD = 4
FULL_WEIGHT_BP = 10000
ATTRIBUTION_DAY_CLAMP = 20


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _day(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d")


# ---------------------------------------------------------------------------
# Signature status (R2 rule)
# ---------------------------------------------------------------------------


def signature_status(record: dict[str, Any], key_events: list[dict[str, Any]]) -> str:
    """Classify a record: unsigned / verified / invalid / unregistered.

    A key attests for events whose epoch falls inside
    ``register.epoch_id <= e <= revoke.epoch_id`` (revoke-epoch inclusive;
    unbounded if never revoked), for the matching (user, pubkey).
    """
    if record.get("device_pubkey") is None and record.get("user_sig") is None:
        return "unsigned"
    pub = record["device_pubkey"]
    epoch = _day(record["epoch_id"])
    covered = False
    for reg in key_events:
        if (
            reg["kind"] != "device_key_register"
            or reg["user_ref_evt"] != record["user_ref_evt"]
            or reg["public_key"] != pub
        ):
            continue
        revoke = next(
            (
                k
                for k in key_events
                if k["kind"] == "device_key_revoke"
                and k["user_ref_evt"] == record["user_ref_evt"]
                and k["public_key"] == pub
            ),
            None,
        )
        if _day(reg["epoch_id"]) <= epoch and (revoke is None or epoch <= _day(revoke["epoch_id"])):
            covered = True
            break
    if not covered:
        return "unregistered"
    try:
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(pub[2:])
        )
        sig = bytes.fromhex(record["user_sig"][2:])
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pubkey.verify(der, EVENT_DOMAIN + rfc8785.dumps(record["core"]), ec.ECDSA(hashes.SHA256()))
        return "verified"
    except (InvalidSignature, ValueError):
        return "invalid"


# ---------------------------------------------------------------------------
# Qualification (§2)
# ---------------------------------------------------------------------------


class UserQualificationState:
    """Per-user window state. Only COUNTED events enter any window."""

    def __init__(self) -> None:
        self.counted_views: list[tuple[datetime, str, str | None]] = []
        self.view_services_by_day: dict[str, set[str]] = {}
        self.kind_count_by_day: dict[tuple[str, str], int] = {}
        self.news_seen: set[str] = set()
        self.lifetime_once: set[tuple[str, str]] = set()
        self.compare_pairs: list[tuple[datetime, tuple[str, str]]] = []
        self.demo_uses: list[tuple[datetime, str, str]] = []
        self.demo_services_by_day: dict[str, set[str]] = {}


def qualify(record: dict[str, Any], state: UserQualificationState) -> bool:
    """Apply the §2 rule for the record's kind; update state only if counted."""
    kind = record["kind"]
    epoch = record["epoch_id"]
    at = _ts(record["received_ts"])
    fields = record.get("scoring_fields") or {}
    target = record.get("target") or {}

    cap = DAILY_CAPS.get(kind)
    if cap is not None and state.kind_count_by_day.get((kind, epoch), 0) >= cap:
        return False

    if kind == "login":
        pass

    elif kind == "service_detail_view":
        service = target.get("service_id")
        if service is None:
            return False
        if not (
            fields.get("dwell_seconds", 0) >= 12
            or fields.get("scroll_percent", 0) >= 60
            or fields.get("outbound_clicks", 0) >= 1
        ):
            return False
        # Same-service dedup [t-24h, t): a counted view AT exactly t-24h blocks.
        low = at - timedelta(hours=24)
        if any(s == service and low <= t < at for t, s, _ in state.counted_views):
            return False
        day_services = state.view_services_by_day.setdefault(epoch, set())
        if service not in day_services and len(day_services) >= 4:
            return False
        state.counted_views.append((at, service, record.get("category_id")))
        day_services.add(service)

    elif kind == "category_exploration":
        category = record.get("category_id")
        if category is None:
            return False
        # >= 3 distinct same-category counted views in [t-30min, t] (inclusive).
        low = at - timedelta(minutes=30)
        distinct = {s for t, s, c in state.counted_views if c == category and low <= t <= at}
        if len(distinct) < 3:
            return False

    elif kind in ("watchlist_add", "service_follow_add"):
        # Lifetime-once per service: platform-enforced upstream AND
        # validator-enforced within the stored window (fixture-pinned).
        service = target.get("service_id")
        if service is None or (kind, service) in state.lifetime_once:
            return False
        state.lifetime_once.add((kind, service))

    elif kind == "service_news_click":
        item = target.get("news_item_id")
        if item is None or item in state.news_seen:
            return False
        state.news_seen.add(item)

    elif kind == "compare_session":
        if fields.get("dwell_seconds", 0) < 30:
            return False
        other = target.get("other_service_id")
        if other is not None:
            pair = tuple(sorted([target.get("service_id"), other]))
            low = at - timedelta(days=7)
            if any(p == pair and low <= t < at for t, p in state.compare_pairs):
                return False
            state.compare_pairs.append((at, pair))

    elif kind in ("demo_l1", "demo_l2", "demo_l3"):
        demo_id = target.get("demo_id")
        if kind == "demo_l1":
            permille = fields.get("watch_permille")
            if permille is None or permille < 850:
                return False
            seeks = fields.get("seek_count")
            if seeks is None or seeks > 3:
                return False
            watched = fields.get("watched_seconds", 0)
            total_play = watched if watched > 0 else fields.get("video_duration_seconds", 0)
            hidden = fields.get("tab_hidden_seconds")
            if total_play > 0 and (hidden is None or 5 * hidden >= total_play):
                return False
        elif demo_id is None:
            return False
        if demo_id is not None:
            low = at - timedelta(days=7)
            if any(
                level == kind and d == demo_id and low <= t < at for t, level, d in state.demo_uses
            ):
                return False
        service = target.get("service_id")
        day_services = state.demo_services_by_day.setdefault(epoch, set())
        if service is not None and service not in day_services and len(day_services) >= 2:
            return False
        if demo_id is not None:
            state.demo_uses.append((at, kind, demo_id))
        if service is not None:
            day_services.add(service)

    else:
        return False

    state.kind_count_by_day[(kind, epoch)] = state.kind_count_by_day.get((kind, epoch), 0) + 1
    return True


# ---------------------------------------------------------------------------
# Kernel + streaks
# ---------------------------------------------------------------------------


def streak_bonus(prior_raw_desc: list[int]) -> int:
    """Bonus from prior consecutive active days, most recent first, look-back 7."""
    streak = 0
    for raw in prior_raw_desc[:7]:
        if raw >= ACTIVE_THRESHOLD:
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


def daily_score(raw: int, bonus: int, weight_bp: int) -> int:
    return (min(DAILY_PRE_CAP, raw + bonus) * weight_bp) // FULL_WEIGHT_BP


def replay_qualification(
    scenario: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], int]]:
    """Replay a qualification scenario; return (per-event verdicts, raw sums)."""
    states: dict[str, UserQualificationState] = {}
    raw_by_user_day: dict[tuple[str, str], int] = {}
    verdicts: list[dict[str, Any]] = []
    for record in sorted(scenario["records"], key=lambda r: r["seq"]):
        status_sig = signature_status(record, scenario["device_key_events"])
        if status_sig in ("invalid", "unregistered"):
            counted, points, status = False, 0, "excluded_signature"
        else:
            state = states.setdefault(record["user_ref_evt"], UserQualificationState())
            counted = qualify(record, state)
            points = POINTS[record["kind"]] if counted else 0
            status = "counted" if counted else "rejected"
        if counted:
            key = (record["user_ref_evt"], record["epoch_id"])
            raw_by_user_day[key] = raw_by_user_day.get(key, 0) + points
        verdicts.append(
            {
                "seq": record["seq"],
                "kind": record["kind"],
                "signature_status": status_sig,
                "status": status,
                "points": points,
            }
        )
    return verdicts, raw_by_user_day


def compose_day(
    user: str,
    epoch: str,
    raw_by_user_day: dict[tuple[str, str], int],
    weights: dict[tuple[str, str], int],
) -> dict[str, Any]:
    """Compose one (user, day) row exactly as the expected fixtures shape it."""
    raw = min(DAILY_RAW_CAP, raw_by_user_day.get((user, epoch), 0))
    active = raw >= ACTIVE_THRESHOLD
    prior = [
        min(
            DAILY_RAW_CAP,
            raw_by_user_day.get((user, (_day(epoch) - timedelta(days=i)).strftime("%Y-%m-%d")), 0),
        )
        for i in range(1, 8)
    ]
    bonus = streak_bonus(prior) if active else 0
    weight = weights.get((user, epoch), FULL_WEIGHT_BP)
    return {
        "epoch_id": epoch,
        "raw": raw,
        "active": active,
        "streak_bonus": bonus,
        "weight_bp": weight,
        "daily_score": daily_score(raw, bonus, weight),
    }


# ---------------------------------------------------------------------------
# Attribution (C2 start-of-day binding, C3 day-close membership)
# ---------------------------------------------------------------------------


def membership_at_day_close(user: str, epoch: str, joins: list[dict[str, Any]]) -> str | None:
    """C3: the group of the user's LAST member_joined with epoch_id <= d."""
    group: str | None = None
    for join in sorted(joins, key=lambda j: j["seq"]):
        if join["user_ref_evt"] == user and join["epoch_id"] <= epoch:
            group = join["group_id"]
    return group


def binding_at_day_start(
    leader: str, epoch: str, binding_events: list[dict[str, Any]]
) -> str | None:
    """C2/§3.1: the leader's MINER hotkey at d@00:00:00Z.

    Miner bindings only — a leader may also hold a validator hotkey, and a
    validator bind (before, after, or while the miner binding is unbound)
    never attributes group mass. Derived independently of the production
    ledger, so agreement between the two is evidence rather than a tautology.
    """
    day_start = _day(epoch)
    per_hotkey: dict[str, datetime | None] = {}
    for event in sorted(
        (b for b in binding_events if b["user_ref_evt"] == leader and b.get("role") == "miner"),
        key=lambda b: b["at"],
    ):
        if _ts(event["at"]) > day_start:
            continue
        per_hotkey[event["hotkey_ss58"]] = _ts(event["at"]) if event["kind"] == "bind" else None

    active = [(bound_at, hotkey) for hotkey, bound_at in per_hotkey.items() if bound_at]
    if not active:
        return None
    # Determinism guard: greatest bound_at, ties on ascending hotkey_ss58.
    active.sort(key=lambda item: item[1])
    active.sort(key=lambda item: item[0], reverse=True)
    return active[0][1]
