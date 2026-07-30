"""Unit tests pinning each attribution rule in isolation."""

from __future__ import annotations

from typing import Any

import pytest

from prometheon.mechanisms.phase1_growth.event_attribution import (
    BindingLedger,
    GroupLedger,
    aggregate_miner_scores,
    attribute_user_day,
)

pytestmark = pytest.mark.unit

LEADER = "usr_evt_" + "1a" * 32
USER = "usr_evt_" + "2b" * 32
HOTKEY = "5F9MHZ78mgGtgAkYBAmj6KiCaK6tJphh75R4rmUWJT6cjoPS"
HOTKEY_B = "5E9XqbLCgv86mP66SmFUv9MAomPVd2GQjQdAH4rf45ymwngY"


def _groups(*records: dict[str, Any]) -> GroupLedger:
    ledger = GroupLedger()
    for record in records:
        ledger.apply_group_record(record)
    return ledger


def _bindings(*records: dict[str, Any]) -> BindingLedger:
    ledger = BindingLedger()
    for record in records:
        ledger.apply_identity_record(record)
    return ledger


def _created(group: str, leader: str, seq: int = 1) -> dict[str, Any]:
    return {
        "seq": seq,
        "epoch_id": "2026-07-01",
        "group_id": group,
        "user_ref_evt": leader,
        "core": {"kind": "group_created"},
    }


def _joined(user: str, group: str, epoch: str, seq: int) -> dict[str, Any]:
    return {
        "seq": seq,
        "epoch_id": epoch,
        "user_ref_evt": user,
        "core": {"kind": "member_joined", "fan_group_id": group},
    }


def _bind(leader: str, hotkey: str, at: str) -> dict[str, Any]:
    return {
        "user_ref_evt": leader,
        "core": {"kind": "miner_hotkey_bind", "hotkey_ss58": hotkey, "bound_at": at},
    }


def _unbind(leader: str, at: str) -> dict[str, Any]:
    return {
        "user_ref_evt": leader,
        "core": {"kind": "miner_hotkey_unbind", "unbound_at": at},
    }


class TestBindingStartOfDay:
    def test_mid_day_bind_attributes_from_next_day(self) -> None:
        bindings = _bindings(_bind(LEADER, HOTKEY, "2026-07-01T12:00:00Z"))
        assert bindings.binding_at_day_start(LEADER, "2026-07-01") is None
        assert bindings.binding_at_day_start(LEADER, "2026-07-02") == HOTKEY

    def test_exact_midnight_bind_attributes_that_day(self) -> None:
        bindings = _bindings(_bind(LEADER, HOTKEY, "2026-07-01T00:00:00Z"))
        assert bindings.binding_at_day_start(LEADER, "2026-07-01") == HOTKEY

    def test_mid_day_unbind_still_attributes_that_day(self) -> None:
        bindings = _bindings(
            _bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"),
            _unbind(LEADER, "2026-07-03T12:00:00Z"),
        )
        assert bindings.binding_at_day_start(LEADER, "2026-07-03") == HOTKEY
        assert bindings.binding_at_day_start(LEADER, "2026-07-04") is None

    def test_rebind_after_unbind(self) -> None:
        bindings = _bindings(
            _bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"),
            _unbind(LEADER, "2026-06-10T08:00:00Z"),
            _bind(LEADER, HOTKEY_B, "2026-06-20T00:00:00Z"),
        )
        assert bindings.binding_at_day_start(LEADER, "2026-06-05") == HOTKEY
        assert bindings.binding_at_day_start(LEADER, "2026-06-15") is None
        assert bindings.binding_at_day_start(LEADER, "2026-06-20") == HOTKEY_B

    def test_genesis_import_bind_unwraps(self) -> None:
        bindings = _bindings(
            {
                "user_ref_evt": LEADER,
                "core": {
                    "kind": "genesis_import",
                    "genesis_kind": "miner_hotkey_bind",
                    "hotkey_ss58": HOTKEY,
                    "bound_at": "2026-06-01T00:00:00Z",
                },
            }
        )
        assert bindings.binding_at_day_start(LEADER, "2026-07-01") == HOTKEY


class TestMembershipDayClose:
    def test_last_join_wins_for_the_whole_day(self) -> None:
        groups = _groups(
            _created("g1", LEADER, seq=1),
            _created("g2", LEADER, seq=2),
            _joined(USER, "g1", "2026-07-01", seq=3),
            _joined(USER, "g2", "2026-07-05", seq=4),
        )
        assert groups.membership_at_day_close(USER, "2026-07-04") == "g1"
        # A switch on day d gives the WHOLE day to the day-close group.
        assert groups.membership_at_day_close(USER, "2026-07-05") == "g2"

    def test_same_day_double_switch_resolves_by_seq(self) -> None:
        groups = _groups(
            _created("g1", LEADER, seq=1),
            _created("g2", LEADER, seq=2),
            _joined(USER, "g2", "2026-07-01", seq=3),
            _joined(USER, "g1", "2026-07-01", seq=4),
        )
        assert groups.membership_at_day_close(USER, "2026-07-01") == "g1"

    def test_no_membership_attributes_nowhere(self) -> None:
        groups = _groups(_created("g1", LEADER))
        bindings = _bindings(_bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"))
        assert attribute_user_day(USER, "2026-07-01", groups, bindings) is None


class TestAggregation:
    def _fixture(self) -> tuple[GroupLedger, BindingLedger]:
        groups = _groups(
            _created("g1", LEADER),
            _joined(USER, "g1", "2026-07-01", seq=2),
        )
        bindings = _bindings(_bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"))
        return groups, bindings

    def test_per_day_clamp_applies(self) -> None:
        groups, bindings = self._fixture()
        result = aggregate_miner_scores({(USER, "2026-07-01"): 22}, groups, bindings)
        assert result.miner_scores == {HOTKEY: 20}

    def test_active_member_threshold_is_strict(self) -> None:
        groups, bindings = self._fixture()
        # Three clamped days of 20 minus 10 = exactly 50: NOT active.
        exactly_fifty = {
            (USER, "2026-07-01"): 20,
            (USER, "2026-07-02"): 20,
            (USER, "2026-07-03"): 10,
        }
        result = aggregate_miner_scores(exactly_fifty, groups, bindings)
        assert result.miner_scores == {HOTKEY: 50}
        assert result.active_members == {HOTKEY: 0}

        over_fifty = dict(exactly_fifty)
        over_fifty[(USER, "2026-07-04")] = 1
        result = aggregate_miner_scores(over_fifty, groups, bindings)
        assert result.active_members == {HOTKEY: 1}

    def test_eligibility_requires_three_active_members(self) -> None:
        groups = _groups(_created("g1", LEADER))
        bindings = _bindings(_bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"))
        scores: dict[tuple[str, str], int] = {}
        for index in range(3):
            member = f"usr_evt_{index:02d}" + "00" * 31
            groups.apply_group_record(_joined(member, "g1", "2026-07-01", seq=10 + index))
            for day in range(1, 5):
                scores[(member, f"2026-07-0{day}")] = 20
        result = aggregate_miner_scores(scores, groups, bindings)
        assert result.active_members == {HOTKEY: 3}
        assert result.eligible == {HOTKEY: True}

    def test_negative_scores_clamp_to_zero(self) -> None:
        groups, bindings = self._fixture()
        result = aggregate_miner_scores({(USER, "2026-07-01"): -5}, groups, bindings)
        assert result.miner_scores == {HOTKEY: 0}


class TestRoleIsolation:
    def test_validator_bind_never_steals_miner_attribution(self) -> None:
        # A leader holding BOTH roles: the miner hotkey is bound first, a
        # validator hotkey later. Attribution must keep the miner hotkey —
        # a validator bind is a different role lane entirely.
        bindings = _bindings(
            _bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"),
            {
                "user_ref_evt": LEADER,
                "core": {
                    "kind": "validator_hotkey_bind",
                    "hotkey_ss58": HOTKEY_B,
                    "bound_at": "2026-06-10T00:00:00Z",
                },
            },
        )
        assert bindings.binding_at_day_start(LEADER, "2026-06-15") == HOTKEY

    def test_validator_unbind_does_not_clear_miner_binding(self) -> None:
        bindings = _bindings(
            _bind(LEADER, HOTKEY, "2026-06-01T00:00:00Z"),
            {
                "user_ref_evt": LEADER,
                "core": {
                    "kind": "validator_hotkey_unbind",
                    "unbound_at": "2026-06-10T00:00:00Z",
                },
            },
        )
        assert bindings.binding_at_day_start(LEADER, "2026-06-15") == HOTKEY


class TestDeterminismGuard:
    """scoring-port §3.1 — input order must never decide the outcome.

    The platform keeps at most one active miner binding, so these states
    should be unreachable; the guard exists precisely so that two
    implementations reading the same records in different orders cannot
    disagree if one ever occurs. The r4 fixture cannot exercise it (its
    dual-role leader never has two miner bindings active at once), so it
    is pinned here.
    """

    HOTKEY_LOW = "5AAA" + "a" * 44
    HOTKEY_HIGH = "5ZZZ" + "z" * 44

    def _bind(self, hotkey: str, at: str, user: str = "usr_leader") -> dict[str, object]:
        return {
            "user_ref_evt": user,
            "core": {
                "kind": "miner_hotkey_bind",
                "hotkey_ss58": hotkey,
                "bound_at": at,
            },
        }

    def _unbind(self, hotkey: str, at: str, user: str = "usr_leader") -> dict[str, object]:
        return {
            "user_ref_evt": user,
            "core": {
                "kind": "miner_hotkey_unbind",
                "hotkey_ss58": hotkey,
                "unbound_at": at,
            },
        }

    def _ledger(self, records: list[dict[str, object]]) -> BindingLedger:
        ledger = BindingLedger()
        for record in records:
            ledger.apply_identity_record(record)
        return ledger

    def test_greatest_bound_at_wins(self) -> None:
        records = [
            self._bind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
            self._bind(self.HOTKEY_HIGH, "2026-07-02T00:00:00Z"),
        ]
        for ordering in (records, list(reversed(records))):
            ledger = self._ledger(ordering)
            assert ledger.binding_at_day_start("usr_leader", "2026-07-05") == self.HOTKEY_HIGH

    def test_equal_bound_at_breaks_on_ascending_hotkey(self) -> None:
        records = [
            self._bind(self.HOTKEY_HIGH, "2026-07-01T00:00:00Z"),
            self._bind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
        ]
        for ordering in (records, list(reversed(records))):
            ledger = self._ledger(ordering)
            assert ledger.binding_at_day_start("usr_leader", "2026-07-05") == self.HOTKEY_LOW

    def test_unbind_sharing_its_binds_timestamp_does_not_undo_it(self) -> None:
        """The interval is (bound_at, t0] — open at the left."""
        records = [
            self._bind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
            self._unbind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
        ]
        for ordering in (records, list(reversed(records))):
            ledger = self._ledger(ordering)
            assert ledger.binding_at_day_start("usr_leader", "2026-07-05") == self.HOTKEY_LOW

    def test_later_unbind_does_undo_it(self) -> None:
        ledger = self._ledger(
            [
                self._bind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
                self._unbind(self.HOTKEY_LOW, "2026-07-01T00:00:01Z"),
            ]
        )
        assert ledger.binding_at_day_start("usr_leader", "2026-07-05") is None

    def test_a_rebind_after_an_unbind_is_active_again(self) -> None:
        ledger = self._ledger(
            [
                self._bind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
                self._unbind(self.HOTKEY_LOW, "2026-07-02T00:00:00Z"),
                self._bind(self.HOTKEY_LOW, "2026-07-03T00:00:00Z"),
            ]
        )
        assert ledger.binding_at_day_start("usr_leader", "2026-07-05") == self.HOTKEY_LOW

    def test_validator_bindings_never_participate(self) -> None:
        ledger = self._ledger(
            [
                self._bind(self.HOTKEY_LOW, "2026-07-01T00:00:00Z"),
                {
                    "user_ref_evt": "usr_leader",
                    "core": {
                        "kind": "validator_hotkey_bind",
                        "hotkey_ss58": self.HOTKEY_HIGH,
                        "bound_at": "2026-07-02T00:00:00Z",
                    },
                },
            ]
        )
        assert ledger.binding_at_day_start("usr_leader", "2026-07-05") == self.HOTKEY_LOW
