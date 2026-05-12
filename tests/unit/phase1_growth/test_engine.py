"""End-to-end tests for ``prometheon.mechanisms.phase1_growth.engine``.

This file covers the required fixture matrix from consolidated
specification §17.5 / §22.4. Each case is a single integration scenario
that exercises filter → rank → top-K → burn → allocation in one shot
against a hand-crafted snapshot + metagraph + policy.

The test cases are intentionally explicit rather than parameterised so
each one reads as an executable specification.
"""

from __future__ import annotations

import pytest
from bittensor_wallet import Keypair

from prometheon.chain.metagraph import MetagraphView
from prometheon.identity.roles import ChainNetwork
from prometheon.mechanisms.phase1_growth.engine import (
    WeightPlan,
    compute_phase1_weight_plan,
)
from prometheon.mechanisms.phase1_growth.policy import WEIGHT_UNITS, Phase1Policy
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


SNAPSHOT_ID = "phase1:2026-05-18:aggregate"
ACTIVITY_DATE = "2026-05-18"


def _ss58(uri: str) -> str:
    return Keypair.create_from_uri(uri).ss58_address


# A pool of 15 real SS58 addresses for engine inputs. ``//Burn`` is the
# burn target across the suite.
HOTKEYS: list[str] = [_ss58(f"//miner/{i}") for i in range(15)]
BURN_HOTKEY: str = _ss58("//Burn")


def _record(hotkey: str, score: int, active: int) -> MinerRecord:
    return MinerRecord(miner_hotkey=hotkey, miner_score_points=score, active_member_count=active)


def _metagraph(*hotkeys: str, block: int = 1234567) -> MetagraphView:
    by_uid = {i + 1: h for i, h in enumerate(hotkeys)}
    by_hotkey = {h: i for i, h in by_uid.items()}
    return MetagraphView(block_number=block, hotkeys_by_uid=by_uid, uids_by_hotkey=by_hotkey)


def _policy(*, burn_ppm: int = 150_000, burn_hotkey: str = BURN_HOTKEY) -> Phase1Policy:
    return Phase1Policy(burn_hotkey=burn_hotkey, manual_burn_rate_ppm=burn_ppm)


def _run(
    records: list[MinerRecord],
    *,
    metagraph: MetagraphView,
    policy: Phase1Policy | None = None,
) -> WeightPlan:
    return compute_phase1_weight_plan(
        records,
        metagraph=metagraph,
        policy=policy or _policy(),
        chain_network=ChainNetwork.FINNEY,
        platform_instance_id="bitfan-production",
        netuid=123,
        snapshot_id=SNAPSHOT_ID,
        activity_date=ACTIVITY_DATE,
    )


# ---------------------------------------------------------------------------
# Burn case A: winners exist AND burn hotkey is in metagraph
# ---------------------------------------------------------------------------


class TestCaseA:
    def test_one_winner_with_burn(self) -> None:
        records = [_record(HOTKEYS[0], score=500, active=5)]
        metagraph = _metagraph(HOTKEYS[0], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "A"
        assert plan.total_weight_units == WEIGHT_UNITS
        # Items: one miner + burn.
        roles = [i.role for i in plan.items]
        assert roles == ["miner", "burn"]
        # Burn slice = 15% of 1e9 = 1.5e8; miner gets the remainder.
        miner_item = plan.items[0]
        burn_item = plan.items[1]
        assert burn_item.weight_units == 150_000_000
        assert miner_item.weight_units == WEIGHT_UNITS - 150_000_000

    def test_two_winners_with_burn(self) -> None:
        records = [
            _record(HOTKEYS[0], score=300, active=5),
            _record(HOTKEYS[1], score=700, active=8),
        ]
        metagraph = _metagraph(HOTKEYS[0], HOTKEYS[1], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "A"
        assert plan.total_weight_units == WEIGHT_UNITS
        miners = [i for i in plan.items if i.role == "miner"]
        assert len(miners) == 2
        # Top miner is HOTKEYS[1] (higher score).
        assert miners[0].hotkey == HOTKEYS[1]
        assert miners[1].hotkey == HOTKEYS[0]
        # Burn slice unchanged.
        burn = next(i for i in plan.items if i.role == "burn")
        assert burn.weight_units == 150_000_000

    def test_three_winners_with_burn(self) -> None:
        records = [_record(HOTKEYS[i], score=100 + i * 10, active=5) for i in range(3)]
        metagraph = _metagraph(*HOTKEYS[:3], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "A"
        assert plan.total_weight_units == WEIGHT_UNITS

    def test_exactly_ten_winners_with_burn(self) -> None:
        records = [_record(HOTKEYS[i], score=100 + i, active=5) for i in range(10)]
        metagraph = _metagraph(*HOTKEYS[:10], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "A"
        # 10 miner items + 1 burn item.
        assert sum(1 for i in plan.items if i.role == "miner") == 10
        assert sum(1 for i in plan.items if i.role == "burn") == 1
        assert plan.total_weight_units == WEIGHT_UNITS

    def test_eleven_eligible_keeps_only_top_ten(self) -> None:
        # 11 candidates; top-K=10 keeps the top 10 by score.
        records = [_record(HOTKEYS[i], score=1000 + i, active=5) for i in range(11)]
        metagraph = _metagraph(*HOTKEYS[:11], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "A"
        miners = [i for i in plan.items if i.role == "miner"]
        assert len(miners) == 10
        # The dropped one is the lowest-scoring candidate (HOTKEYS[0]).
        miner_hotkeys = {i.hotkey for i in miners}
        assert HOTKEYS[0] not in miner_hotkeys
        # The dropped miner is in the exclusion list — actually no, it was
        # eligibility-pass, just top-K-out. The engine does not record
        # top-K losers in ``excluded``; only filter losers go there.

    def test_zero_burn_rate_gives_winners_full_pool(self) -> None:
        records = [_record(HOTKEYS[0], score=100, active=5)]
        metagraph = _metagraph(HOTKEYS[0], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph, policy=_policy(burn_ppm=0))
        assert plan.status == "ready"
        assert plan.burn_case == "A"
        # Burn case is still A (burn hotkey is registered), but the burn
        # slice is zero, so the items list contains only the miner row.
        assert plan.items[0].role == "miner"
        assert plan.items[0].weight_units == WEIGHT_UNITS
        assert all(i.role != "burn" for i in plan.items)


# ---------------------------------------------------------------------------
# Burn case B: winners exist AND burn hotkey is NOT in metagraph
# ---------------------------------------------------------------------------


class TestCaseB:
    def test_burn_hotkey_missing_winners_get_full_pool(self) -> None:
        records = [_record(HOTKEYS[0], score=100, active=5)]
        # Burn hotkey not in metagraph.
        metagraph = _metagraph(HOTKEYS[0])
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "B"
        assert plan.total_weight_units == WEIGHT_UNITS
        # No burn item; single miner gets everything.
        assert all(i.role == "miner" for i in plan.items)
        assert plan.items[0].weight_units == WEIGHT_UNITS

    def test_burn_hotkey_missing_with_multiple_winners(self) -> None:
        records = [
            _record(HOTKEYS[0], score=500, active=5),
            _record(HOTKEYS[1], score=500, active=5),
        ]
        metagraph = _metagraph(HOTKEYS[0], HOTKEYS[1])
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "B"
        assert plan.total_weight_units == WEIGHT_UNITS
        # Equal scores → equal allocation.
        weights = sorted(i.weight_units for i in plan.items)
        assert weights == [WEIGHT_UNITS // 2, WEIGHT_UNITS // 2]


# ---------------------------------------------------------------------------
# Burn case C: no winners AND burn hotkey IS in metagraph
# ---------------------------------------------------------------------------


class TestCaseC:
    def test_no_eligible_miners_burn_takes_full_pool(self) -> None:
        # All candidates have too few active members.
        records = [_record(HOTKEYS[0], score=100, active=1)]
        metagraph = _metagraph(HOTKEYS[0], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        assert plan.burn_case == "C"
        assert plan.total_weight_units == WEIGHT_UNITS
        assert len(plan.items) == 1
        assert plan.items[0].role == "burn"
        assert plan.items[0].weight_units == WEIGHT_UNITS

    def test_empty_input_with_burn_hotkey_present(self) -> None:
        plan = _run([], metagraph=_metagraph(BURN_HOTKEY))
        assert plan.status == "ready"
        assert plan.burn_case == "C"
        assert plan.items[0].role == "burn"
        assert plan.items[0].weight_units == WEIGHT_UNITS


# ---------------------------------------------------------------------------
# Burn case D: no winners AND burn hotkey is NOT in metagraph (fail closed)
# ---------------------------------------------------------------------------


class TestCaseD:
    def test_no_winners_no_burn_fails_closed(self) -> None:
        # No eligible miners and burn hotkey missing.
        plan = _run([], metagraph=_metagraph())
        assert plan.status == "no_valid_weight_target"
        assert plan.burn_case == "D"
        assert plan.items == []
        assert plan.total_weight_units == 0
        assert plan.failure_reason == "no_eligible_miners_and_burn_hotkey_missing"

    def test_ineligible_miners_and_no_burn_hotkey_fails_closed(self) -> None:
        # Records exist but every one fails eligibility, and burn is missing.
        records = [_record(HOTKEYS[0], score=100, active=2)]  # active too low
        metagraph = _metagraph(HOTKEYS[0])  # no burn
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "no_valid_weight_target"
        assert plan.burn_case == "D"


# ---------------------------------------------------------------------------
# Threshold filter happens BEFORE top-K selection
# ---------------------------------------------------------------------------


class TestThresholdBeforeTopK:
    def test_below_threshold_miner_excluded_even_with_high_score(self) -> None:
        # A miner with massive score but only 2 active members must not
        # crowd out a less-impressive but properly-active miner.
        records = [
            _record(HOTKEYS[0], score=999_999, active=2),  # ineligible
            _record(HOTKEYS[1], score=100, active=5),  # eligible
        ]
        metagraph = _metagraph(HOTKEYS[0], HOTKEYS[1], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        assert plan.status == "ready"
        miner_hotkeys = {i.hotkey for i in plan.items if i.role == "miner"}
        assert HOTKEYS[0] not in miner_hotkeys
        assert HOTKEYS[1] in miner_hotkeys


# ---------------------------------------------------------------------------
# Tie-breakers
# ---------------------------------------------------------------------------


class TestTieBreakers:
    def test_score_tie_resolved_by_active_member_count(self) -> None:
        records = [
            _record(HOTKEYS[0], score=100, active=5),
            _record(HOTKEYS[1], score=100, active=9),  # wins on active
            _record(HOTKEYS[2], score=100, active=3),
        ]
        metagraph = _metagraph(*HOTKEYS[:3], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        miners = [i for i in plan.items if i.role == "miner"]
        # Rank order by active DESC: HOTKEYS[1] (9), HOTKEYS[0] (5), HOTKEYS[2] (3).
        assert [m.hotkey for m in miners] == [HOTKEYS[1], HOTKEYS[0], HOTKEYS[2]]

    def test_score_and_active_tie_resolved_by_hotkey_ascending(self) -> None:
        # Identical score, identical active → alphabetical hotkey order.
        sorted_hotkeys = sorted(HOTKEYS[:3])
        records = [_record(h, score=100, active=5) for h in HOTKEYS[:3]]
        metagraph = _metagraph(*HOTKEYS[:3], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        miners = [i for i in plan.items if i.role == "miner"]
        assert [m.hotkey for m in miners] == sorted_hotkeys


# ---------------------------------------------------------------------------
# Unregistered miners excluded
# ---------------------------------------------------------------------------


class TestRegisteredAndUnregisteredMix:
    def test_unregistered_miner_excluded_audit_recorded(self) -> None:
        records = [
            _record(HOTKEYS[0], score=100, active=5),  # registered
            _record(HOTKEYS[1], score=200, active=5),  # NOT in metagraph
        ]
        metagraph = _metagraph(HOTKEYS[0], BURN_HOTKEY)  # HOTKEYS[1] missing
        plan = _run(records, metagraph=metagraph)
        miner_hotkeys = {i.hotkey for i in plan.items if i.role == "miner"}
        assert miner_hotkeys == {HOTKEYS[0]}
        assert any(
            e.hotkey == HOTKEYS[1] and e.reason == "not_registered_in_metagraph"
            for e in plan.excluded
        )


# ---------------------------------------------------------------------------
# Invariants and envelope identity
# ---------------------------------------------------------------------------


class TestInvariants:
    def test_ready_plans_always_sum_to_weight_units(self) -> None:
        # Five different scenarios — each must sum to exactly WEIGHT_UNITS.
        scenarios = [
            # (records, metagraph_hotkeys, ppm)
            ([_record(HOTKEYS[0], 100, 5)], (HOTKEYS[0], BURN_HOTKEY), 0),
            (
                [_record(HOTKEYS[i], 100 + i, 5) for i in range(3)],
                (*HOTKEYS[:3], BURN_HOTKEY),
                100_000,
            ),
            (
                [_record(HOTKEYS[i], 200, 5) for i in range(5)],
                (*HOTKEYS[:5], BURN_HOTKEY),
                500_000,
            ),
            ([_record(HOTKEYS[0], 100, 5)], (HOTKEYS[0],), 0),  # case B
            ([_record(HOTKEYS[0], 100, 1)], (HOTKEYS[0], BURN_HOTKEY), 0),  # case C
        ]
        for records, hotkeys, ppm in scenarios:
            plan = _run(
                records,
                metagraph=_metagraph(*hotkeys),
                policy=_policy(burn_ppm=ppm),
            )
            assert plan.status == "ready", f"unexpected status for {records}"
            assert plan.total_weight_units == WEIGHT_UNITS

    def test_envelope_identity_fields_carried_through(self) -> None:
        plan = _run(
            [_record(HOTKEYS[0], 100, 5)],
            metagraph=_metagraph(HOTKEYS[0], BURN_HOTKEY),
        )
        assert plan.domain == "PROMETHEON_WEIGHT_PLAN_V1"
        assert plan.schema_version == "1.0"
        assert plan.mechanism == "phase1_growth"
        assert plan.mechid == 0
        assert plan.chain_network == ChainNetwork.FINNEY
        assert plan.platform_instance_id == "bitfan-production"
        assert plan.netuid == 123
        assert plan.snapshot_id == SNAPSHOT_ID
        assert plan.activity_date == ACTIVITY_DATE
        assert plan.metagraph_block == 1234567

    def test_engine_is_deterministic_across_runs(self) -> None:
        records = [_record(HOTKEYS[i], score=100 + i, active=5 + (i % 3)) for i in range(7)]
        metagraph = _metagraph(*HOTKEYS[:7], BURN_HOTKEY)
        plan_a = _run(records, metagraph=metagraph)
        plan_b = _run(records, metagraph=metagraph)
        assert plan_a.model_dump(mode="json") == plan_b.model_dump(mode="json")

    def test_engine_does_not_mutate_inputs(self) -> None:
        records = [_record(HOTKEYS[i], score=100, active=5) for i in range(3)]
        snapshot = [r.model_copy() for r in records]
        _run(records, metagraph=_metagraph(*HOTKEYS[:3], BURN_HOTKEY))
        assert records == snapshot

    def test_top_k_dropouts_not_in_excluded(self) -> None:
        # The exclusion list captures eligibility losers only, not top-K losers.
        records = [_record(HOTKEYS[i], score=1000 + i, active=5) for i in range(11)]
        metagraph = _metagraph(*HOTKEYS[:11], BURN_HOTKEY)
        plan = _run(records, metagraph=metagraph)
        excluded_hotkeys = {e.hotkey for e in plan.excluded}
        # HOTKEYS[0] is the lowest-scoring of the 11 candidates and gets
        # dropped by top-K. It should NOT appear in plan.excluded because
        # it passed eligibility.
        assert HOTKEYS[0] not in excluded_hotkeys
