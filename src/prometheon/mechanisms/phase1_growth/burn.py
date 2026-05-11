"""Phase 1 burn-case resolution.

The Phase 1 spec defines four mutually exclusive burn cases (consolidated
specification §12.11 / §21):

- **Case A**: winners exist AND burn_hotkey is in the metagraph
  → ``effective_burn_units = burn_units``, remainder to winners.
- **Case B**: winners exist AND burn_hotkey is NOT in the metagraph
  → effective burn 0, 100% to winners.
- **Case C**: no winners AND burn_hotkey is in the metagraph
  → 100% to burn UID.
- **Case D**: no winners AND burn_hotkey is NOT in the metagraph
  → fail closed: ``no_valid_weight_target``, do not submit.

This module owns the discriminator and the integer ``burn_units``
conversion. The actual unit-distribution to winners lives in
:mod:`prometheon.mechanisms.phase1_growth.allocation`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from prometheon.chain.metagraph import MetagraphView
from prometheon.mechanisms.phase1_growth.policy import (
    MAX_BURN_RATE_PPM,
    WEIGHT_UNITS,
    Phase1Policy,
)

_PPM_DENOMINATOR: Final[int] = 1_000_000


class BurnCase(str, Enum):
    """Discrete burn-case identifier (consolidated specification §12.11)."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"


@dataclass(frozen=True)
class BurnResolution:
    """The outcome of evaluating the burn rules against the current state.

    Attributes
    ----------
    case:
        Which of A/B/C/D applies for this submission.
    burn_uid:
        Current UID for ``burn_hotkey``, or ``None`` if the hotkey is not
        registered (cases B and D).
    burn_units:
        Integer weight units allocated to the burn target. ``0`` when no
        burn target exists (cases B and D) or when the configured rate is
        zero. In case C this equals :data:`WEIGHT_UNITS`.
    miner_pool_units:
        Integer weight units left for the winners after the burn slice.
        In case A this is ``WEIGHT_UNITS - burn_units``; in case B it is
        :data:`WEIGHT_UNITS`; in cases C and D it is ``0``.
    """

    case: BurnCase
    burn_uid: int | None
    burn_units: int
    miner_pool_units: int


def compute_burn_units(manual_burn_rate_ppm: int) -> int:
    """Convert a ppm rate to integer weight units exactly.

    Because :data:`WEIGHT_UNITS` is 1_000_000_000 and the denominator is
    1_000_000, the multiplication is divisible whenever
    ``manual_burn_rate_ppm`` is a non-negative integer in the documented
    range, so the floor in the formula adds no rounding error.
    """
    if not isinstance(manual_burn_rate_ppm, int) or isinstance(manual_burn_rate_ppm, bool):
        raise TypeError(
            f"manual_burn_rate_ppm must be int, got {type(manual_burn_rate_ppm).__name__}"
        )
    if manual_burn_rate_ppm < 0 or manual_burn_rate_ppm > MAX_BURN_RATE_PPM:
        raise ValueError(
            f"manual_burn_rate_ppm must be in [0, {MAX_BURN_RATE_PPM}], got {manual_burn_rate_ppm}"
        )
    return (WEIGHT_UNITS * manual_burn_rate_ppm) // _PPM_DENOMINATOR


def resolve_burn(
    *,
    winners_exist: bool,
    metagraph: MetagraphView,
    policy: Phase1Policy,
) -> BurnResolution:
    """Discriminate which burn case applies and compute the integer pools.

    Parameters
    ----------
    winners_exist:
        ``True`` if at least one eligible miner remains after filtering
        and top-K selection.
    metagraph:
        Current :class:`prometheon.chain.metagraph.MetagraphView`.
    policy:
        :class:`prometheon.mechanisms.phase1_growth.policy.Phase1Policy`
        carrying the snapshot's burn fields.

    Returns
    -------
    BurnResolution
        ``case`` identifies the rule; the integer fields encode the
        deterministic allocation pools the engine will distribute next.
    """
    burn_uid = metagraph.uid_for(policy.burn_hotkey)
    burn_hotkey_registered = burn_uid is not None

    if winners_exist and burn_hotkey_registered:
        burn_units = compute_burn_units(policy.manual_burn_rate_ppm)
        return BurnResolution(
            case=BurnCase.A,
            burn_uid=burn_uid,
            burn_units=burn_units,
            miner_pool_units=WEIGHT_UNITS - burn_units,
        )

    if winners_exist and not burn_hotkey_registered:
        return BurnResolution(
            case=BurnCase.B,
            burn_uid=None,
            burn_units=0,
            miner_pool_units=WEIGHT_UNITS,
        )

    if not winners_exist and burn_hotkey_registered:
        return BurnResolution(
            case=BurnCase.C,
            burn_uid=burn_uid,
            burn_units=WEIGHT_UNITS,
            miner_pool_units=0,
        )

    # No winners AND burn hotkey missing → fail closed.
    return BurnResolution(
        case=BurnCase.D,
        burn_uid=None,
        burn_units=0,
        miner_pool_units=0,
    )


__all__ = ["BurnCase", "BurnResolution", "compute_burn_units", "resolve_burn"]
