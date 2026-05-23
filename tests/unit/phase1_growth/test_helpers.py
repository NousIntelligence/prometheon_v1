"""Unit tests for the Phase 1 helper modules: eligibility, ranking, burn, allocation.

The engine orchestrator is exercised end-to-end in ``test_engine.py``;
this file pins the behaviour of each piece in isolation so failures
localise.
"""

from __future__ import annotations

import pytest
from bittensor_wallet import Keypair

from prometheon.chain.metagraph import MetagraphView
from prometheon.mechanisms.phase1_growth.allocation import allocate_winner_units
from prometheon.mechanisms.phase1_growth.burn import (
    BurnCase,
    compute_burn_units,
    resolve_burn,
)
from prometheon.mechanisms.phase1_growth.eligibility import (
    REASON_BELOW_ACTIVE_MEMBER_THRESHOLD,
    REASON_BURN_HOTKEY,
    REASON_NON_POSITIVE_SCORE,
    REASON_NOT_REGISTERED,
    filter_eligible,
)
from prometheon.mechanisms.phase1_growth.policy import (
    WEIGHT_UNITS,
    Phase1Policy,
)
from prometheon.mechanisms.phase1_growth.ranking import rank_candidates, select_top_k
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared SS58 fixtures (sorted ascending: A < B < C < BURN)
# ---------------------------------------------------------------------------

SS58_A = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
SS58_B = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
SS58_C = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
SS58_BURN = "5HpG9w8EBLe5XCrbczpwq5TSXvedjrBGCwqxK1iLpqEpkLB1"


def _ss58_pool(n: int) -> list[str]:
    """Generate ``n`` real SS58 addresses via Substrate test URIs.

    Uses ``//generated/<i>`` derivation paths to produce deterministic
    valid SS58 strings without bringing real wallet material into tests.
    """
    return [Keypair.create_from_uri(f"//generated/{i}").ss58_address for i in range(n)]


def _record(hotkey: str, score: int, active: int) -> MinerRecord:
    return MinerRecord(miner_hotkey=hotkey, miner_score_points=score, active_member_count=active)


def _metagraph(*hotkeys: str, block: int = 100) -> MetagraphView:
    """Build a MetagraphView with the given hotkeys, sequential UIDs from 0."""
    by_uid = dict(enumerate(hotkeys))
    by_hotkey = {h: i for i, h in by_uid.items()}
    return MetagraphView(block_number=block, hotkeys_by_uid=by_uid, uids_by_hotkey=by_hotkey)


def _policy(*, burn_hotkey: str = SS58_BURN, burn_ppm: int = 150_000) -> Phase1Policy:
    return Phase1Policy(burn_hotkey=burn_hotkey, manual_burn_rate_ppm=burn_ppm)


# ---------------------------------------------------------------------------
# Eligibility filter
# ---------------------------------------------------------------------------


class TestFilterEligible:
    def test_all_pass_when_everyone_qualifies(self) -> None:
        records = [
            _record(SS58_A, score=100, active=5),
            _record(SS58_B, score=200, active=8),
        ]
        metagraph = _metagraph(SS58_A, SS58_B, SS58_BURN)
        candidates, excluded = filter_eligible(records, metagraph=metagraph, policy=_policy())
        assert [c.miner_hotkey for c in candidates] == [SS58_A, SS58_B]
        assert excluded == []

    def test_unregistered_hotkey_excluded(self) -> None:
        records = [
            _record(SS58_A, score=100, active=5),
            _record(SS58_B, score=200, active=8),  # not in metagraph
        ]
        metagraph = _metagraph(SS58_A, SS58_BURN)  # B missing
        candidates, excluded = filter_eligible(records, metagraph=metagraph, policy=_policy())
        assert [c.miner_hotkey for c in candidates] == [SS58_A]
        assert len(excluded) == 1
        assert excluded[0].miner_hotkey == SS58_B
        assert excluded[0].reason == REASON_NOT_REGISTERED

    def test_burn_hotkey_excluded(self) -> None:
        records = [
            _record(SS58_A, score=100, active=5),
            _record(SS58_BURN, score=999, active=99),  # tries to mine as burn
        ]
        metagraph = _metagraph(SS58_A, SS58_BURN)
        candidates, excluded = filter_eligible(records, metagraph=metagraph, policy=_policy())
        assert [c.miner_hotkey for c in candidates] == [SS58_A]
        assert len(excluded) == 1
        assert excluded[0].reason == REASON_BURN_HOTKEY

    def test_below_active_member_threshold_excluded(self) -> None:
        records = [
            _record(SS58_A, score=100, active=2),  # below threshold
            _record(SS58_B, score=100, active=3),  # exactly at threshold
        ]
        metagraph = _metagraph(SS58_A, SS58_B, SS58_BURN)
        candidates, excluded = filter_eligible(records, metagraph=metagraph, policy=_policy())
        assert [c.miner_hotkey for c in candidates] == [SS58_B]
        assert len(excluded) == 1
        assert excluded[0].miner_hotkey == SS58_A
        assert excluded[0].reason == REASON_BELOW_ACTIVE_MEMBER_THRESHOLD

    def test_zero_score_excluded(self) -> None:
        records = [
            _record(SS58_A, score=0, active=10),
            _record(SS58_B, score=1, active=10),
        ]
        metagraph = _metagraph(SS58_A, SS58_B, SS58_BURN)
        candidates, excluded = filter_eligible(records, metagraph=metagraph, policy=_policy())
        assert [c.miner_hotkey for c in candidates] == [SS58_B]
        assert excluded[0].reason == REASON_NON_POSITIVE_SCORE

    def test_filter_preserves_input_order_among_candidates(self) -> None:
        records = [
            _record(SS58_B, score=200, active=8),
            _record(SS58_A, score=100, active=5),
        ]
        metagraph = _metagraph(SS58_A, SS58_B, SS58_BURN)
        candidates, _ = filter_eligible(records, metagraph=metagraph, policy=_policy())
        # Filter does not sort — that's the ranking step's job.
        assert [c.miner_hotkey for c in candidates] == [SS58_B, SS58_A]


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


class TestRankCandidates:
    def test_score_descending(self) -> None:
        records = [
            _record(SS58_A, score=100, active=5),
            _record(SS58_B, score=200, active=5),
            _record(SS58_C, score=150, active=5),
        ]
        ranked = rank_candidates(records)
        assert [r.miner_hotkey for r in ranked] == [SS58_B, SS58_C, SS58_A]

    def test_tie_on_score_resolved_by_active_count(self) -> None:
        records = [
            _record(SS58_A, score=100, active=3),
            _record(SS58_B, score=100, active=9),  # higher active
            _record(SS58_C, score=100, active=5),
        ]
        ranked = rank_candidates(records)
        assert [r.miner_hotkey for r in ranked] == [SS58_B, SS58_C, SS58_A]

    def test_tie_on_score_and_active_resolved_by_hotkey_ascending(self) -> None:
        records = [
            _record(SS58_C, score=100, active=5),
            _record(SS58_A, score=100, active=5),
            _record(SS58_B, score=100, active=5),
        ]
        ranked = rank_candidates(records)
        # All identical except hotkey → alphabetical order.
        assert [r.miner_hotkey for r in ranked] == [SS58_A, SS58_B, SS58_C]

    def test_empty_input(self) -> None:
        assert rank_candidates([]) == []

    def test_does_not_mutate_input(self) -> None:
        records = [_record(SS58_A, 100, 5), _record(SS58_B, 200, 5)]
        snapshot = list(records)
        rank_candidates(records)
        assert records == snapshot


class TestSelectTopK:
    def test_returns_all_when_fewer_than_k(self) -> None:
        records = [_record(SS58_A, 100, 5), _record(SS58_B, 200, 5)]
        assert select_top_k(records, top_k=10) == records

    def test_returns_only_k_when_more_than_k(self) -> None:
        hotkeys = _ss58_pool(15)
        records = [_record(hotkeys[i], 100 - i, 5) for i in range(15)]
        top = select_top_k(records, top_k=10)
        assert len(top) == 10

    def test_negative_k_rejected(self) -> None:
        with pytest.raises(ValueError):
            select_top_k([], top_k=-1)


# ---------------------------------------------------------------------------
# Burn case resolution
# ---------------------------------------------------------------------------


class TestComputeBurnUnits:
    def test_zero_ppm(self) -> None:
        assert compute_burn_units(0) == 0

    def test_full_million_ppm_equals_weight_units(self) -> None:
        assert compute_burn_units(1_000_000) == WEIGHT_UNITS

    def test_150k_ppm_yields_15_percent(self) -> None:
        # 150_000 ppm = 15% = 0.15 * 1_000_000_000 = 150_000_000.
        assert compute_burn_units(150_000) == 150_000_000

    @pytest.mark.parametrize("bad", [-1, 1_000_001, 2_000_000])
    def test_out_of_range_rejected(self, bad: int) -> None:
        with pytest.raises(ValueError):
            compute_burn_units(bad)

    def test_non_int_rejected(self) -> None:
        with pytest.raises(TypeError):
            compute_burn_units("100000")  # type: ignore[arg-type]


class TestResolveBurn:
    def test_case_a_winners_and_burn_registered(self) -> None:
        metagraph = _metagraph(SS58_A, SS58_BURN)
        result = resolve_burn(
            winners_exist=True, metagraph=metagraph, policy=_policy(burn_ppm=200_000)
        )
        assert result.case is BurnCase.A
        assert result.burn_uid == 1  # SS58_BURN is at UID 1
        assert result.burn_units == 200_000_000
        assert result.miner_pool_units == WEIGHT_UNITS - 200_000_000

    def test_case_b_winners_but_no_burn(self) -> None:
        metagraph = _metagraph(SS58_A)  # burn hotkey missing
        result = resolve_burn(winners_exist=True, metagraph=metagraph, policy=_policy())
        assert result.case is BurnCase.B
        assert result.burn_uid is None
        assert result.burn_units == 0
        assert result.miner_pool_units == WEIGHT_UNITS

    def test_case_c_no_winners_but_burn_registered(self) -> None:
        metagraph = _metagraph(SS58_A, SS58_BURN)
        result = resolve_burn(winners_exist=False, metagraph=metagraph, policy=_policy())
        assert result.case is BurnCase.C
        assert result.burn_uid == 1
        assert result.burn_units == WEIGHT_UNITS
        assert result.miner_pool_units == 0

    def test_case_d_no_winners_no_burn(self) -> None:
        metagraph = _metagraph(SS58_A)  # burn hotkey missing
        result = resolve_burn(winners_exist=False, metagraph=metagraph, policy=_policy())
        assert result.case is BurnCase.D
        assert result.burn_uid is None
        assert result.burn_units == 0
        assert result.miner_pool_units == 0


# ---------------------------------------------------------------------------
# Integer allocation
# ---------------------------------------------------------------------------


class TestAllocateWinnerUnits:
    def test_single_winner_takes_everything(self) -> None:
        winners = [_record(SS58_A, score=100, active=5)]
        allocation = allocate_winner_units(winners, miner_pool_units=WEIGHT_UNITS)
        assert allocation == {SS58_A: WEIGHT_UNITS}

    def test_equal_scores_split_evenly_when_divisible(self) -> None:
        winners = [
            _record(SS58_A, score=100, active=5),
            _record(SS58_B, score=100, active=5),
        ]
        allocation = allocate_winner_units(winners, miner_pool_units=1000)
        assert allocation == {SS58_A: 500, SS58_B: 500}

    def test_proportional_split(self) -> None:
        # Scores 100, 200, 700 split 1000 units as 100, 200, 700.
        winners = [
            _record(SS58_A, score=100, active=5),
            _record(SS58_B, score=200, active=5),
            _record(SS58_C, score=700, active=5),
        ]
        allocation = allocate_winner_units(winners, miner_pool_units=1000)
        assert allocation == {SS58_A: 100, SS58_B: 200, SS58_C: 700}

    def test_total_always_equals_budget(self) -> None:
        # Awkward sum that does not divide cleanly into the budget.
        winners = [
            _record(SS58_A, score=1, active=5),
            _record(SS58_B, score=1, active=5),
            _record(SS58_C, score=1, active=5),
        ]
        budget = WEIGHT_UNITS  # 1_000_000_000 not divisible by 3
        allocation = allocate_winner_units(winners, miner_pool_units=budget)
        assert sum(allocation.values()) == budget

    def test_remainder_distributed_by_priority_order(self) -> None:
        # With miner_pool_units=10 and scores (1, 1, 1), each gets 3 with
        # 1 leftover. The leftover goes to the highest remainder; ties on
        # remainder are broken by score, then active_count, then hotkey ASC.
        # All remainders are equal (10 % 3 = 1 each) so we fall through to
        # the score+active+hotkey tiebreakers. With equal score+active,
        # SS58_A (alphabetically first) wins the leftover.
        winners = [
            _record(SS58_C, score=1, active=5),
            _record(SS58_B, score=1, active=5),
            _record(SS58_A, score=1, active=5),
        ]
        allocation = allocate_winner_units(winners, miner_pool_units=10)
        assert allocation[SS58_A] == 4  # got the leftover
        assert allocation[SS58_B] == 3
        assert allocation[SS58_C] == 3
        assert sum(allocation.values()) == 10

    def test_zero_budget_yields_all_zeros(self) -> None:
        winners = [_record(SS58_A, 100, 5), _record(SS58_B, 200, 5)]
        allocation = allocate_winner_units(winners, miner_pool_units=0)
        assert allocation == {SS58_A: 0, SS58_B: 0}

    def test_empty_winners_with_zero_budget_returns_empty(self) -> None:
        assert allocate_winner_units([], miner_pool_units=0) == {}

    def test_empty_winners_with_nonzero_budget_raises(self) -> None:
        with pytest.raises(ValueError, match="callers must dispatch"):
            allocate_winner_units([], miner_pool_units=100)

    def test_negative_budget_rejected(self) -> None:
        winners = [_record(SS58_A, 100, 5)]
        with pytest.raises(ValueError, match="non-negative"):
            allocate_winner_units(winners, miner_pool_units=-1)

    def test_full_weight_units_with_realistic_scores_sums_correctly(self) -> None:
        # 10 winners with varied scores; total budget 1_000_000_000.
        hotkeys = _ss58_pool(10)
        winners = [_record(hotkeys[i], score=100 + i * 7, active=5) for i in range(10)]
        allocation = allocate_winner_units(winners, miner_pool_units=WEIGHT_UNITS)
        assert sum(allocation.values()) == WEIGHT_UNITS
        # Every winner gets a positive share (scores are all positive).
        assert all(v > 0 for v in allocation.values())
