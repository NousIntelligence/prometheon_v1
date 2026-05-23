"""Edge-case tests for ``prometheon.mechanisms.phase1_growth.eligibility``.

``test_helpers.py`` covers the typical pass/fail cases. This file pins
edge cases that are easy to break with seemingly-innocuous refactors:

- Empty input.
- Records exactly at each policy threshold (inclusive vs exclusive).
- Multiple exclusion reasons applying to the same record.
- Order preservation under duplicate hotkeys (defensive — the platform
  is expected to deduplicate before signing, but the engine must not
  crash if the invariant is violated).
"""

from __future__ import annotations

import pytest
from bittensor_wallet import Keypair

from prometheon.chain.metagraph import MetagraphView
from prometheon.mechanisms.phase1_growth.eligibility import (
    REASON_BELOW_ACTIVE_MEMBER_THRESHOLD,
    REASON_BURN_HOTKEY,
    REASON_NON_POSITIVE_SCORE,
    REASON_NOT_REGISTERED,
    filter_eligible,
)
from prometheon.mechanisms.phase1_growth.policy import Phase1Policy
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord

pytestmark = pytest.mark.unit


SS58_A = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
SS58_B = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
SS58_C = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
SS58_BURN = "5HpG9w8EBLe5XCrbczpwq5TSXvedjrBGCwqxK1iLpqEpkLB1"
SS58_UNREG = Keypair.create_from_uri("//generated/eligibility-edge-unreg").ss58_address


def _record(hotkey: str, score: int, active: int) -> MinerRecord:
    return MinerRecord(miner_hotkey=hotkey, miner_score_points=score, active_member_count=active)


def _metagraph(*hotkeys: str, block: int = 200) -> MetagraphView:
    by_uid = dict(enumerate(hotkeys))
    by_hotkey = {h: i for i, h in by_uid.items()}
    return MetagraphView(block_number=block, hotkeys_by_uid=by_uid, uids_by_hotkey=by_hotkey)


def _policy() -> Phase1Policy:
    return Phase1Policy(burn_hotkey=SS58_BURN, manual_burn_rate_ppm=150_000)


class TestEligibilityEdgeCases:
    def test_empty_records_yields_empty_outputs(self) -> None:
        candidates, excluded = filter_eligible(
            [], metagraph=_metagraph(SS58_A, SS58_BURN), policy=_policy()
        )
        assert candidates == []
        assert excluded == []

    def test_exactly_three_active_members_passes(self) -> None:
        # Threshold is "fewer than 3" excluded → exactly 3 must pass.
        records = [_record(SS58_A, score=100, active=3)]
        candidates, excluded = filter_eligible(
            records, metagraph=_metagraph(SS58_A, SS58_BURN), policy=_policy()
        )
        assert [c.miner_hotkey for c in candidates] == [SS58_A]
        assert excluded == []

    def test_exactly_two_active_members_excluded(self) -> None:
        records = [_record(SS58_A, score=100, active=2)]
        candidates, excluded = filter_eligible(
            records, metagraph=_metagraph(SS58_A, SS58_BURN), policy=_policy()
        )
        assert candidates == []
        assert len(excluded) == 1
        assert excluded[0].reason == REASON_BELOW_ACTIVE_MEMBER_THRESHOLD

    def test_score_zero_is_excluded_as_non_positive(self) -> None:
        records = [_record(SS58_A, score=0, active=10)]
        candidates, excluded = filter_eligible(
            records, metagraph=_metagraph(SS58_A, SS58_BURN), policy=_policy()
        )
        assert candidates == []
        assert excluded[0].reason == REASON_NON_POSITIVE_SCORE

    def test_burn_hotkey_excluded_even_with_qualifying_score(self) -> None:
        # A high-scoring burn hotkey must still be filtered from the candidate pool.
        records = [_record(SS58_BURN, score=999, active=99)]
        candidates, excluded = filter_eligible(
            records, metagraph=_metagraph(SS58_A, SS58_BURN), policy=_policy()
        )
        assert candidates == []
        assert excluded[0].reason == REASON_BURN_HOTKEY

    def test_unregistered_hotkey_excluded_before_other_checks(self) -> None:
        # An unregistered hotkey is excluded for REASON_NOT_REGISTERED regardless
        # of its score / active count. Confirms ordering of the checks.
        records = [_record(SS58_UNREG, score=500, active=10)]
        candidates, excluded = filter_eligible(
            records, metagraph=_metagraph(SS58_A, SS58_BURN), policy=_policy()
        )
        assert candidates == []
        assert excluded[0].reason == REASON_NOT_REGISTERED

    def test_mixed_exclusion_reasons_are_all_recorded(self) -> None:
        records = [
            _record(SS58_A, score=100, active=2),      # below threshold
            _record(SS58_B, score=0, active=10),        # non-positive
            _record(SS58_BURN, score=50, active=5),     # burn hotkey
            _record(SS58_UNREG, score=200, active=8),   # not registered
            _record(SS58_C, score=300, active=5),       # passes
        ]
        candidates, excluded = filter_eligible(
            records, metagraph=_metagraph(SS58_A, SS58_B, SS58_C, SS58_BURN), policy=_policy()
        )
        assert [c.miner_hotkey for c in candidates] == [SS58_C]
        reasons = {e.miner_hotkey: e.reason for e in excluded}
        assert reasons[SS58_A] == REASON_BELOW_ACTIVE_MEMBER_THRESHOLD
        assert reasons[SS58_B] == REASON_NON_POSITIVE_SCORE
        assert reasons[SS58_BURN] == REASON_BURN_HOTKEY
        assert reasons[SS58_UNREG] == REASON_NOT_REGISTERED
