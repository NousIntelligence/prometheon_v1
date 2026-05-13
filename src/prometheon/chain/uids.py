"""Hotkey-to-UID resolution helpers.

The Phase 1 weight engine emits a :class:`WeightPlan` whose items carry
``(uid, hotkey)`` pairs already resolved against the metagraph snapshot
the engine was given. The validator runtime re-resolves every UID
**right before** each submission attempt because UIDs are not stable
identity (consolidated specification §13.3 / §19.6).

This module provides the small set of helpers the runner uses to:

- Re-verify that every hotkey in a plan still resolves to its expected UID.
- Detect hotkeys that left the metagraph between engine run and submission.

The actual ``set_weights`` call is in :mod:`prometheon.chain.weights`.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheon.chain.metagraph import MetagraphView
from prometheon.mechanisms.phase1_growth.engine import WeightPlan, WeightPlanItem


class UidResolutionError(Exception):
    """Raised when a plan's hotkey-to-UID resolution no longer matches the
    fresh metagraph."""

    code = "chain.uid_resolution_error"


@dataclass(frozen=True)
class ResolvedTarget:
    """One submission target with its freshly-resolved UID and unit count."""

    hotkey: str
    uid: int
    weight_units: int
    role: str


def resolve_plan_targets(plan: WeightPlan, *, metagraph: MetagraphView) -> list[ResolvedTarget]:
    """Re-resolve every plan item against ``metagraph`` and return the targets.

    Raises :class:`UidResolutionError` if any item's hotkey is no longer
    in the metagraph, or if its current UID differs from the value the
    engine recorded. The runner reacts by re-running the engine on the
    fresh metagraph rather than submitting stale UIDs.

    Parameters
    ----------
    plan:
        Ready :class:`WeightPlan` from the engine. Calling this function
        on a ``no_valid_weight_target`` plan is a programmer error
        (callers must check ``plan.status`` first); it raises
        :class:`UidResolutionError` in that case so the bug surfaces.
    metagraph:
        Current metagraph view at submission time.

    Returns
    -------
    list[ResolvedTarget]
        One entry per plan item, in input order, with fresh UID values.
    """
    if plan.status != "ready":
        raise UidResolutionError(f"cannot resolve UIDs for a plan with status={plan.status!r}")

    resolved: list[ResolvedTarget] = []
    for item in plan.items:
        current_uid = metagraph.uid_for(item.hotkey)
        if current_uid is None:
            raise UidResolutionError(
                f"hotkey {item.hotkey!r} was in the engine metagraph but is "
                f"no longer registered at block {metagraph.block_number}"
            )
        if current_uid != item.uid:
            raise UidResolutionError(
                f"hotkey {item.hotkey!r} moved from UID {item.uid} to "
                f"UID {current_uid} between engine run and submission"
            )
        resolved.append(
            ResolvedTarget(
                hotkey=item.hotkey,
                uid=current_uid,
                weight_units=item.weight_units,
                role=item.role,
            )
        )
    return resolved


def partition_by_registration(
    hotkeys: list[str], *, metagraph: MetagraphView
) -> tuple[list[str], list[str]]:
    """Split ``hotkeys`` into ``(registered, unregistered)`` ordered groups.

    The input order is preserved within each group. Useful when the
    runner needs to audit how many hotkeys vanished between the engine
    run and the submission attempt.
    """
    registered: list[str] = []
    unregistered: list[str] = []
    for hotkey in hotkeys:
        (registered if metagraph.is_registered(hotkey) else unregistered).append(hotkey)
    return registered, unregistered


__all__ = [
    "ResolvedTarget",
    "UidResolutionError",
    "WeightPlanItem",
    "partition_by_registration",
    "resolve_plan_targets",
]
