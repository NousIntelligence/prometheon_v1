"""Phase 1 weight engine — orchestrator and output model.

Public API:

- :class:`WeightPlan` — the deterministic output of the engine.
- :class:`WeightPlanItem` — one ``(uid, hotkey, weight_units, reason)`` row
  inside a ready plan.
- :class:`WeightPlanStatus` — ``ready`` or ``no_valid_weight_target``.
- :class:`WeightPlanFailureReason` — closed set of failure reasons for
  ``status == "no_valid_weight_target"``.
- :func:`compute_phase1_weight_plan` — the single entry point. Pure
  function: no I/O, no clock, no random, no floats.

The engine consumes normalised :class:`MinerRecord` inputs (produced
either directly from an aggregate snapshot or from the detailed-mode
streaming accumulator), a :class:`MetagraphView`, a :class:`Phase1Policy`,
and a handful of identity strings carried into the output envelope so
downstream consumers can recognise the plan's provenance.

Algorithm (consolidated specification §21):

1. Filter eligibility (registered, not burn hotkey, ≥3 active members, score > 0).
2. Rank by (score DESC, active_count DESC, hotkey ASC).
3. Select top min(10, len(candidates)) winners.
4. Resolve burn case A/B/C/D from (winners exist, burn hotkey in metagraph).
5. Allocate WEIGHT_UNITS via largest-remainder.
6. Emit a deterministic WeightPlan with an explicit status.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from prometheon.chain.metagraph import MetagraphView
from prometheon.identity.roles import ChainNetwork
from prometheon.mechanisms.phase1_growth.allocation import allocate_winner_units
from prometheon.mechanisms.phase1_growth.burn import (
    BurnCase,
    BurnResolution,
    resolve_burn,
)
from prometheon.mechanisms.phase1_growth.eligibility import (
    ExclusionRecord,
    filter_eligible,
)
from prometheon.mechanisms.phase1_growth.policy import (
    WEIGHT_UNITS,
    Phase1Policy,
)
from prometheon.mechanisms.phase1_growth.ranking import rank_candidates, select_top_k
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord

WeightPlanStatus = Literal["ready", "no_valid_weight_target"]
WeightPlanItemRole = Literal["miner", "burn"]
BurnCaseLiteral = Literal["A", "B", "C", "D"]
WeightPlanFailureReason = Literal["no_eligible_miners_and_burn_hotkey_missing"]


class WeightPlanItem(BaseModel):
    """One non-zero allocation row inside a ready weight plan."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    uid: int = Field(ge=0)
    hotkey: str = Field(min_length=1)
    role: WeightPlanItemRole
    weight_units: int = Field(gt=0)
    reason: str = Field(min_length=1)


class WeightPlanExclusion(BaseModel):
    """One audit row recording why a miner was excluded from allocation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    hotkey: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class WeightPlan(BaseModel):
    """Output of the Phase 1 mechanism engine.

    A *ready* plan carries the integer allocation that the chain adapter
    will convert to u16 and submit. A *no_valid_weight_target* plan
    encodes the fail-closed case D (no eligible miners AND no burn
    hotkey in the metagraph) and must not be submitted; the validator
    runner persists it and logs a high-severity event.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    domain: Literal["PROMETHEON_WEIGHT_PLAN_V1"] = "PROMETHEON_WEIGHT_PLAN_V1"
    schema_version: Literal["1.0"] = "1.0"
    mechanism: Literal["phase1_growth"] = "phase1_growth"
    mechid: Literal[0] = 0
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    snapshot_id: str = Field(min_length=1)
    activity_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    metagraph_block: int = Field(ge=0)
    status: WeightPlanStatus
    burn_case: BurnCaseLiteral
    items: list[WeightPlanItem] = Field(default_factory=list)
    excluded: list[WeightPlanExclusion] = Field(default_factory=list)
    total_weight_units: int = Field(ge=0)
    failure_reason: WeightPlanFailureReason | None = None


def _exclusions_to_audit(exclusions: list[ExclusionRecord]) -> list[WeightPlanExclusion]:
    """Convert internal :class:`ExclusionRecord` items to the public model."""
    return [WeightPlanExclusion(hotkey=e.miner_hotkey, reason=e.reason) for e in exclusions]


def compute_phase1_weight_plan(
    miner_records: list[MinerRecord],
    *,
    metagraph: MetagraphView,
    policy: Phase1Policy,
    chain_network: ChainNetwork,
    platform_instance_id: str,
    netuid: int,
    snapshot_id: str,
    activity_date: str,
) -> WeightPlan:
    """Run the Phase 1 mechanism end-to-end.

    The function is **pure**:

    - No I/O of any kind.
    - No clock or random number access.
    - No floating-point arithmetic.
    - No mutation of input arguments.

    Parameters
    ----------
    miner_records:
        Normalised list of :class:`MinerRecord` (the same shape produced
        by aggregate-mode parsing or by the detailed-mode streaming
        accumulator).
    metagraph:
        Current chain :class:`MetagraphView`.
    policy:
        :class:`Phase1Policy` carrying the locked constants and the
        snapshot-controlled ``burn_hotkey`` / ``manual_burn_rate_ppm``.
    chain_network:
        Bittensor environment, embedded in the WeightPlan envelope.
    platform_instance_id:
        Platform environment identifier, embedded in the envelope.
    netuid:
        Subnet number, embedded in the envelope.
    snapshot_id:
        ``snapshot_id`` from the source snapshot, embedded in the envelope.
    activity_date:
        ``activity_date`` from the source snapshot, embedded in the envelope.

    Returns
    -------
    WeightPlan
        Either ``status == "ready"`` with an integer allocation that sums
        to :data:`WEIGHT_UNITS`, or ``status == "no_valid_weight_target"``
        with ``items == []``, ``total_weight_units == 0``, and
        ``failure_reason == "no_eligible_miners_and_burn_hotkey_missing"``.
    """
    candidates, exclusions = filter_eligible(miner_records, metagraph=metagraph, policy=policy)
    ranked = rank_candidates(candidates)
    winners = select_top_k(ranked, policy.top_k)
    burn = resolve_burn(winners_exist=bool(winners), metagraph=metagraph, policy=policy)

    audit_excluded = _exclusions_to_audit(exclusions)

    if burn.case is BurnCase.D:
        return WeightPlan(
            chain_network=chain_network,
            platform_instance_id=platform_instance_id,
            netuid=netuid,
            snapshot_id=snapshot_id,
            activity_date=activity_date,
            metagraph_block=metagraph.block_number,
            status="no_valid_weight_target",
            burn_case="D",
            items=[],
            excluded=audit_excluded,
            total_weight_units=0,
            failure_reason="no_eligible_miners_and_burn_hotkey_missing",
        )

    items = _build_items(winners, metagraph=metagraph, burn=burn)
    total = sum(item.weight_units for item in items)
    # Sanity invariant: ready plans must always sum to exactly WEIGHT_UNITS.
    # This is a programmer-error check; an upstream bug would manifest here.
    if total != WEIGHT_UNITS:
        raise AssertionError(
            f"ready plan total_weight_units={total} != WEIGHT_UNITS={WEIGHT_UNITS}"
        )

    return WeightPlan(
        chain_network=chain_network,
        platform_instance_id=platform_instance_id,
        netuid=netuid,
        snapshot_id=snapshot_id,
        activity_date=activity_date,
        metagraph_block=metagraph.block_number,
        status="ready",
        burn_case=burn.case.value,
        items=items,
        excluded=audit_excluded,
        total_weight_units=total,
        failure_reason=None,
    )


def _build_items(
    winners: list[MinerRecord],
    *,
    metagraph: MetagraphView,
    burn: BurnResolution,
) -> list[WeightPlanItem]:
    """Assemble :class:`WeightPlanItem` rows from the burn resolution.

    Cases:

    - **A** (winners + burn): burn slice plus per-winner allocation.
    - **B** (winners, no burn): full miner pool to winners.
    - **C** (no winners + burn): single burn-only row.
    - **D**: handled by the caller; never reaches this function.
    """
    items: list[WeightPlanItem] = []

    if burn.case is BurnCase.C:
        # Burn-only allocation: 100% of WEIGHT_UNITS to the burn UID.
        assert burn.burn_uid is not None
        return [
            WeightPlanItem(
                uid=burn.burn_uid,
                hotkey=_hotkey_for_uid(metagraph, burn.burn_uid),
                role="burn",
                weight_units=burn.burn_units,
                reason="all_burn_no_eligible_miners",
            )
        ]

    # Cases A and B both distribute miner_pool_units across winners.
    winner_units = allocate_winner_units(winners, miner_pool_units=burn.miner_pool_units)
    for record in winners:
        units = winner_units[record.miner_hotkey]
        if units == 0:
            # Zero-share winners are excluded from the wire envelope per
            # consolidated specification §15.2 ("items list must include
            # only non-zero weight targets").
            continue
        uid = metagraph.uid_for(record.miner_hotkey)
        assert uid is not None, (
            "winner must be registered in the metagraph (eligibility filter passed)"
        )
        items.append(
            WeightPlanItem(
                uid=uid,
                hotkey=record.miner_hotkey,
                role="miner",
                weight_units=units,
                reason="phase1_winner",
            )
        )

    if burn.case is BurnCase.A and burn.burn_units > 0:
        # Append burn row last so the items list reads as "miners, then burn".
        assert burn.burn_uid is not None
        items.append(
            WeightPlanItem(
                uid=burn.burn_uid,
                hotkey=_hotkey_for_uid(metagraph, burn.burn_uid),
                role="burn",
                weight_units=burn.burn_units,
                reason="manual_burn_rate",
            )
        )

    return items


def _hotkey_for_uid(metagraph: MetagraphView, uid: int) -> str:
    """Return the SS58 string for ``uid``; raise on programmer error."""
    hotkey = metagraph.hotkeys_by_uid.get(uid)
    if hotkey is None:
        raise AssertionError(f"UID {uid} not present in metagraph.hotkeys_by_uid")
    return hotkey


__all__ = [
    "WeightPlan",
    "WeightPlanExclusion",
    "WeightPlanFailureReason",
    "WeightPlanItem",
    "WeightPlanItemRole",
    "WeightPlanStatus",
    "compute_phase1_weight_plan",
]
