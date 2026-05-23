"""Unit tests for ``prometheon.chain.uids``."""

from __future__ import annotations

import pytest
from bittensor_wallet import Keypair

from prometheon.chain.metagraph import MetagraphView
from prometheon.chain.uids import (
    UidResolutionError,
    partition_by_registration,
    resolve_plan_targets,
)
from prometheon.identity.roles import ChainNetwork
from prometheon.mechanisms.phase1_growth.engine import (
    WeightPlan,
    WeightPlanItem,
)

pytestmark = pytest.mark.unit


def _ss58(uri: str) -> str:
    return Keypair.create_from_uri(uri).ss58_address


HOTKEY_A = _ss58("//Alice")
HOTKEY_B = _ss58("//Bob")
HOTKEY_C = _ss58("//Charlie")


def _ready_plan(items: list[WeightPlanItem]) -> WeightPlan:
    return WeightPlan(
        chain_network=ChainNetwork.FINNEY,
        platform_instance_id="bitfan-test",
        netuid=123,
        snapshot_id="phase1:2026-05-18:aggregate",
        activity_date="2026-05-18",
        metagraph_block=100,
        status="ready",
        burn_case="A",
        items=items,
        excluded=[],
        total_weight_units=sum(i.weight_units for i in items),
    )


def _failure_plan() -> WeightPlan:
    return WeightPlan(
        chain_network=ChainNetwork.FINNEY,
        platform_instance_id="bitfan-test",
        netuid=123,
        snapshot_id="phase1:2026-05-18:aggregate",
        activity_date="2026-05-18",
        metagraph_block=100,
        status="no_valid_weight_target",
        burn_case="D",
        items=[],
        excluded=[],
        total_weight_units=0,
        failure_reason="no_eligible_miners_and_burn_hotkey_missing",
    )


class TestResolvePlanTargets:
    def test_happy_path(self) -> None:
        items = [
            WeightPlanItem(
                uid=1,
                hotkey=HOTKEY_A,
                role="miner",
                weight_units=600_000_000,
                reason="phase1_winner",
            ),
            WeightPlanItem(
                uid=2,
                hotkey=HOTKEY_B,
                role="burn",
                weight_units=400_000_000,
                reason="manual_burn_rate",
            ),
        ]
        metagraph = MetagraphView(
            block_number=200,
            hotkeys_by_uid={1: HOTKEY_A, 2: HOTKEY_B},
            uids_by_hotkey={HOTKEY_A: 1, HOTKEY_B: 2},
        )
        targets = resolve_plan_targets(_ready_plan(items), metagraph=metagraph)
        assert [(t.uid, t.hotkey, t.weight_units) for t in targets] == [
            (1, HOTKEY_A, 600_000_000),
            (2, HOTKEY_B, 400_000_000),
        ]

    def test_hotkey_no_longer_registered_raises(self) -> None:
        items = [
            WeightPlanItem(
                uid=1, hotkey=HOTKEY_A, role="miner", weight_units=10, reason="phase1_winner"
            ),
        ]
        # Metagraph has neither Alice nor anyone else.
        metagraph = MetagraphView(block_number=200)
        with pytest.raises(UidResolutionError, match="no longer registered"):
            resolve_plan_targets(_ready_plan(items), metagraph=metagraph)

    def test_uid_moved_raises(self) -> None:
        # Plan says Alice is UID 1; metagraph now puts her at UID 7.
        items = [
            WeightPlanItem(
                uid=1, hotkey=HOTKEY_A, role="miner", weight_units=10, reason="phase1_winner"
            ),
        ]
        metagraph = MetagraphView(
            block_number=200,
            hotkeys_by_uid={7: HOTKEY_A},
            uids_by_hotkey={HOTKEY_A: 7},
        )
        with pytest.raises(UidResolutionError, match="moved from UID 1 to UID 7"):
            resolve_plan_targets(_ready_plan(items), metagraph=metagraph)

    def test_failure_plan_rejected(self) -> None:
        with pytest.raises(UidResolutionError, match="cannot resolve UIDs"):
            resolve_plan_targets(_failure_plan(), metagraph=MetagraphView(block_number=0))


class TestPartitionByRegistration:
    def test_split(self) -> None:
        metagraph = MetagraphView(
            block_number=0,
            hotkeys_by_uid={1: HOTKEY_A},
            uids_by_hotkey={HOTKEY_A: 1},
        )
        registered, unregistered = partition_by_registration(
            [HOTKEY_A, HOTKEY_B, HOTKEY_C], metagraph=metagraph
        )
        assert registered == [HOTKEY_A]
        assert unregistered == [HOTKEY_B, HOTKEY_C]

    def test_empty(self) -> None:
        assert partition_by_registration([], metagraph=MetagraphView(block_number=0)) == (
            [],
            [],
        )
