"""Phase 1 eligibility filtering — pure, deterministic, no I/O.

Given a normalised list of miner records, the current metagraph, and the
Phase 1 policy, this module drops every record that fails any of the
eligibility rules defined in consolidated specification §12.6 / §21:

1. ``miner_hotkey`` must be currently registered in the metagraph.
2. ``miner_hotkey`` must not equal the configured ``burn_hotkey`` (the
   burn target is handled separately in the burn module).
3. ``active_member_count >= 3``.
4. ``miner_score_points > 0``.

The function additionally returns an ordered list of exclusion records
explaining *why* each dropped record was dropped. The engine includes
that list in the ``WeightPlan`` so operators can audit how a particular
miner ended up out of the running.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheon.chain.metagraph import MetagraphView
from prometheon.mechanisms.phase1_growth.policy import Phase1Policy
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord


@dataclass(frozen=True)
class ExclusionRecord:
    """An immutable note explaining why a miner record was excluded.

    ``reason`` is a stable machine-readable string. The exclusion list
    surfaces in the final ``WeightPlan`` for transparency.
    """

    miner_hotkey: str
    reason: str


# Stable exclusion reason codes used in :class:`ExclusionRecord.reason`.
REASON_NOT_REGISTERED = "not_registered_in_metagraph"
REASON_BURN_HOTKEY = "is_burn_hotkey"
REASON_BELOW_ACTIVE_MEMBER_THRESHOLD = "below_active_member_threshold"
REASON_NON_POSITIVE_SCORE = "non_positive_score"


def filter_eligible(
    records: list[MinerRecord],
    *,
    metagraph: MetagraphView,
    policy: Phase1Policy,
) -> tuple[list[MinerRecord], list[ExclusionRecord]]:
    """Partition records into (candidates, exclusions).

    The filter is applied in the order specified by consolidated
    specification §21. The order matters for the reason attribution but
    not for the final candidate set: a record that fails multiple checks
    is recorded with the first failing reason it encounters, which keeps
    audit messages predictable.

    Parameters
    ----------
    records:
        The normalised miner records produced by aggregate-mode parsing
        or by the detailed-mode streaming accumulator.
    metagraph:
        The current :class:`prometheon.chain.metagraph.MetagraphView`.
    policy:
        The :class:`prometheon.mechanisms.phase1_growth.policy.Phase1Policy`.
        ``burn_hotkey`` and ``min_active_members_for_reward`` are read.

    Returns
    -------
    tuple
        ``(candidates, exclusions)`` — candidates preserves the input
        order; exclusions are appended in the order encountered.
    """
    candidates: list[MinerRecord] = []
    exclusions: list[ExclusionRecord] = []

    threshold = policy.min_active_members_for_reward
    burn_hotkey = policy.burn_hotkey

    for record in records:
        # Order matches the consolidated specification §21 algorithm.
        if not metagraph.is_registered(record.miner_hotkey):
            exclusions.append(
                ExclusionRecord(
                    miner_hotkey=record.miner_hotkey,
                    reason=REASON_NOT_REGISTERED,
                )
            )
            continue
        if record.miner_hotkey == burn_hotkey:
            exclusions.append(
                ExclusionRecord(
                    miner_hotkey=record.miner_hotkey,
                    reason=REASON_BURN_HOTKEY,
                )
            )
            continue
        if record.active_member_count < threshold:
            exclusions.append(
                ExclusionRecord(
                    miner_hotkey=record.miner_hotkey,
                    reason=REASON_BELOW_ACTIVE_MEMBER_THRESHOLD,
                )
            )
            continue
        if record.miner_score_points <= 0:
            exclusions.append(
                ExclusionRecord(
                    miner_hotkey=record.miner_hotkey,
                    reason=REASON_NON_POSITIVE_SCORE,
                )
            )
            continue
        candidates.append(record)

    return candidates, exclusions


__all__ = [
    "REASON_BELOW_ACTIVE_MEMBER_THRESHOLD",
    "REASON_BURN_HOTKEY",
    "REASON_NON_POSITIVE_SCORE",
    "REASON_NOT_REGISTERED",
    "ExclusionRecord",
    "filter_eligible",
]
