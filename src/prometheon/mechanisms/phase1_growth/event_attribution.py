"""Attribution of per-user daily scores to miners (event-stream source).

Implements the scoring-port contract §3 with the two rules the r3
attribution vectors pin:

- **Day-close membership (C3):** a user's whole epoch-``d`` score belongs
  to the group of their *last* ``member_joined`` record with
  ``epoch_id <= d`` (seq order breaks same-day ties). The per-event
  ``group_id`` stamp is context/audit only. A user with no membership at
  day close scores but attributes to no miner.
- **Start-of-day binding (C2):** the leader's hotkey for epoch ``d`` is
  the binding state at ``d @ 00:00:00Z`` computed from the **core
  timestamps** (``bound_at`` / ``unbound_at``), never epoch granularity:
  a mid-day-``d`` bind attributes from ``d+1``; a mid-day-``d`` unbind
  still attributes ``d``; an exact-midnight bind attributes ``d``.

Aggregation applies the per-day clamp: attribution sums
``min(20, max(0, daily_score))`` per (user, day), so ``user_score_14d``
is bounded at 280 by construction even though ``daily_score`` itself
reaches 22. Active membership is strict (``> 50``); eligibility requires
at least three active members. The output feeds the existing Phase 1
ranking/burn engine unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

ATTRIBUTION_DAY_CLAMP: Final[int] = 20
ACTIVE_MEMBER_THRESHOLD: Final[int] = 50
MIN_ACTIVE_MEMBERS: Final[int] = 3

# Attribution resolves the leader's MINER binding only. A leader may also
# hold a validator role with its own hotkey (the platform supports both per
# account); validator bind/unbind records must never enter this state lane,
# or a later validator bind would steal the group's attribution.
_BIND_KINDS: Final[frozenset[str]] = frozenset({"miner_hotkey_bind"})
_UNBIND_KINDS: Final[frozenset[str]] = frozenset({"miner_hotkey_unbind"})


class EventAttributionError(ValueError):
    """An attribution input violated the contract's preconditions."""


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _day_start(epoch_id: str) -> datetime:
    return datetime.strptime(epoch_id, "%Y-%m-%d")


class GroupLedger:
    """Group-family state: leaders and day-close memberships.

    Feed group-family records in seq order via :meth:`apply_group_record`;
    ``genesis_import`` wrappers are unwrapped.
    """

    def __init__(self) -> None:
        self._leader_by_group: dict[str, str] = {}
        # Per user: ordered (epoch_id, group_id) joins, seq order preserved.
        self._joins_by_user: dict[str, list[tuple[str, str]]] = {}

    def apply_group_record(self, record: dict[str, Any]) -> None:
        core = record.get("core", record)
        kind = core.get("kind")
        if kind == "genesis_import":
            kind = core.get("genesis_kind")

        if kind == "group_created":
            group_id = record.get("group_id") or core.get("group_id")
            leader = record.get("user_ref_evt")
            if isinstance(group_id, str) and isinstance(leader, str):
                self._leader_by_group[group_id] = leader
        elif kind == "member_joined":
            group_id = core.get("fan_group_id") or record.get("group_id") or core.get("group_id")
            user = record.get("user_ref_evt")
            epoch = record.get("epoch_id")
            if isinstance(group_id, str) and isinstance(user, str) and isinstance(epoch, str):
                self._joins_by_user.setdefault(user, []).append((epoch, group_id))

    def leader_of(self, group_id: str) -> str | None:
        return self._leader_by_group.get(group_id)

    def membership_at_day_close(self, user_ref_evt: str, epoch_id: str) -> str | None:
        """The group of the user's LAST join with ``epoch_id <= d``."""
        group: str | None = None
        for join_epoch, group_id in self._joins_by_user.get(user_ref_evt, []):
            if join_epoch <= epoch_id:
                group = group_id
        return group


class BindingLedger:
    """Identity-family hotkey-binding state, from the core timestamps.

    Feed identity-family bind/unbind records (or their ``genesis_import``
    wrappers) in seq order via :meth:`apply_identity_record`. State is kept
    per hotkey so the contract's rule can be evaluated literally: a hotkey
    is bound at ``t0`` when ``bound_at <= t0`` and no unbind for it falls
    in ``(bound_at, t0]``.
    """

    def __init__(self) -> None:
        # Per leader, per hotkey: (at, is_bind) events, sorted lazily.
        self._events_by_user: dict[str, dict[str, list[tuple[datetime, bool]]]] = {}
        # Unbinds that name no hotkey clear whatever was bound at the time.
        self._wildcard_unbinds: dict[str, list[datetime]] = {}

    def apply_identity_record(self, record: dict[str, Any]) -> None:
        core = record.get("core", record)
        kind = core.get("kind")
        if kind == "genesis_import":
            kind = core.get("genesis_kind")
        if kind in _BIND_KINDS:
            is_bind = True
            timestamp = core.get("bound_at") or core.get("at")
        elif kind in _UNBIND_KINDS:
            is_bind = False
            timestamp = core.get("unbound_at") or core.get("at")
        else:
            return

        user = record.get("user_ref_evt")
        hotkey = core.get("hotkey_ss58")
        if not (isinstance(user, str) and isinstance(timestamp, str)):
            return
        at = _parse_ts(timestamp)
        if not isinstance(hotkey, str):
            if not is_bind:
                self._wildcard_unbinds.setdefault(user, []).append(at)
            return
        self._events_by_user.setdefault(user, {}).setdefault(hotkey, []).append((at, is_bind))

    def binding_at_day_start(self, user_ref_evt: str, epoch_id: str) -> str | None:
        """The miner hotkey bound at ``epoch_id @ 00:00:00Z``, if any.

        Applies the scoring-port §3.1 determinism guard: where more than one
        miner binding is somehow active at ``t0`` — the platform keeps at
        most one, so this should be unreachable — the greatest ``bound_at``
        wins, and a remaining tie is broken on ascending ``hotkey_ss58``.
        The guard exists so that two implementations reading the same
        records in different orders cannot disagree; never let arrival
        order decide.
        """
        t0 = _day_start(epoch_id)
        cleared = [at for at in self._wildcard_unbinds.get(user_ref_evt, []) if at <= t0]

        active: list[tuple[datetime, str]] = []
        for hotkey, events in self._events_by_user.get(user_ref_evt, {}).items():
            bound_at: datetime | None = None
            for at, is_bind in sorted(events, key=lambda item: item[0]):
                if at > t0:
                    break
                bound_at = at if is_bind else None
            if bound_at is not None and not any(bound_at < at for at in cleared):
                active.append((bound_at, hotkey))

        if not active:
            return None
        # Two stable sorts express the rule directly: ascending hotkey
        # first, then descending bound_at, so the head is the greatest
        # bound_at and — among equal ones — the smallest hotkey.
        active.sort(key=lambda item: item[1])
        active.sort(key=lambda item: item[0], reverse=True)
        return active[0][1]


@dataclass(frozen=True)
class MinerAttributionResult:
    """Aggregated attribution output for the ranking layer."""

    miner_scores: dict[str, int]
    active_members: dict[str, int]
    eligible: dict[str, bool]
    per_user_day_hotkey: dict[tuple[str, str], str | None]


def attribute_user_day(
    user_ref_evt: str,
    epoch_id: str,
    groups: GroupLedger,
    bindings: BindingLedger,
) -> str | None:
    """The miner hotkey epoch-``d`` of this user attributes to, or ``None``."""
    group = groups.membership_at_day_close(user_ref_evt, epoch_id)
    if group is None:
        return None
    leader = groups.leader_of(group)
    if leader is None:
        return None
    return bindings.binding_at_day_start(leader, epoch_id)


def aggregate_miner_scores(
    daily_scores: dict[tuple[str, str], int],
    groups: GroupLedger,
    bindings: BindingLedger,
) -> MinerAttributionResult:
    """Attribute per-(user, day) scores and aggregate to miner totals.

    ``daily_scores`` maps ``(user_ref_evt, epoch_id)`` to the kernel's
    ``daily_score`` for every (user, day) inside the scoring window. The
    per-day clamp at :data:`ATTRIBUTION_DAY_CLAMP` is applied here — never
    upstream — so ``daily_score`` values above 20 (streak days) still
    contribute exactly 20.
    """
    per_user_day_hotkey: dict[tuple[str, str], str | None] = {}
    miner_scores: dict[str, int] = {}
    per_member_totals: dict[tuple[str, str], int] = {}

    for (user, epoch), score in sorted(daily_scores.items()):
        hotkey = attribute_user_day(user, epoch, groups, bindings)
        per_user_day_hotkey[(user, epoch)] = hotkey
        if hotkey is None:
            continue
        clamped = min(ATTRIBUTION_DAY_CLAMP, max(0, score))
        miner_scores[hotkey] = miner_scores.get(hotkey, 0) + clamped
        per_member_totals[(hotkey, user)] = per_member_totals.get((hotkey, user), 0) + clamped

    active_members: dict[str, int] = dict.fromkeys(miner_scores, 0)
    for (hotkey, _user), total in per_member_totals.items():
        if total > ACTIVE_MEMBER_THRESHOLD:
            active_members[hotkey] = active_members.get(hotkey, 0) + 1

    eligible = {hotkey: count >= MIN_ACTIVE_MEMBERS for hotkey, count in active_members.items()}
    return MinerAttributionResult(
        miner_scores=miner_scores,
        active_members=active_members,
        eligible=eligible,
        per_user_day_hotkey=per_user_day_hotkey,
    )


__all__ = [
    "ACTIVE_MEMBER_THRESHOLD",
    "ATTRIBUTION_DAY_CLAMP",
    "MIN_ACTIVE_MEMBERS",
    "BindingLedger",
    "EventAttributionError",
    "GroupLedger",
    "MinerAttributionResult",
    "aggregate_miner_scores",
    "attribute_user_day",
]
