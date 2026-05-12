"""Largest-remainder integer allocation for Phase 1.

The mechanism distributes an integer ``miner_pool_units`` budget across
the ranked winners so the per-winner shares:

- Are non-negative integers.
- Sum exactly to ``miner_pool_units`` (no off-by-one).
- Are reproducible bit-for-bit across any compliant implementation.

The algorithm is largest-remainder allocation (consolidated specification
§12.12 / §21.1):

1. Compute the ideal share ``score_i / total_score`` times ``miner_pool_units``.
2. Take the floor of each ideal share as the base allocation.
3. Distribute the remaining ``miner_pool_units - sum(base)`` units one at
   a time, in this priority order:
   - largest fractional remainder first
   - then largest ``miner_score_points``
   - then largest ``active_member_count``
   - then smallest ``miner_hotkey`` (lexicographic ascending)

The tie-breakers (especially the final hotkey ASC) make the output
deterministic even when multiple winners share identical scores and
remainders.
"""

from __future__ import annotations

from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord


def allocate_winner_units(
    winners: list[MinerRecord],
    *,
    miner_pool_units: int,
) -> dict[str, int]:
    """Distribute ``miner_pool_units`` across ``winners`` deterministically.

    Parameters
    ----------
    winners:
        Ranked candidate list. Must be non-empty unless
        ``miner_pool_units == 0``. Every record must have positive
        ``miner_score_points``; the engine guarantees this via the
        upstream eligibility filter.
    miner_pool_units:
        Non-negative integer budget. ``0`` is allowed and yields an
        all-zero allocation.

    Returns
    -------
    dict[str, int]
        Mapping of ``miner_hotkey`` to integer units. Sum equals
        ``miner_pool_units`` exactly. Hotkeys present in ``winners`` with
        a zero share are included in the mapping with value ``0``.

    Raises
    ------
    ValueError
        If ``miner_pool_units`` is negative, if ``winners`` is empty with
        a positive ``miner_pool_units``, or if any winner has a
        non-positive score (a programmer error — the eligibility filter
        should have removed them).
    """
    if miner_pool_units < 0:
        raise ValueError(f"miner_pool_units must be non-negative, got {miner_pool_units}")

    if not winners:
        if miner_pool_units > 0:
            raise ValueError(
                "winners list is empty but miner_pool_units is non-zero; "
                "callers must dispatch to a burn-only case instead"
            )
        return {}

    total_score = sum(r.miner_score_points for r in winners)
    if total_score <= 0:
        raise ValueError(
            "total_score must be positive after eligibility filtering; "
            "every winner must have miner_score_points > 0"
        )

    # First pass: integer floors plus exact integer remainders so the
    # second pass can compare without floating-point arithmetic.
    base: dict[str, int] = {}
    remainders: dict[str, int] = {}
    for record in winners:
        product = miner_pool_units * record.miner_score_points
        base[record.miner_hotkey] = product // total_score
        remainders[record.miner_hotkey] = product % total_score

    leftover = miner_pool_units - sum(base.values())

    if leftover == 0:
        return base
    # leftover is necessarily in [0, len(winners)) because the floor of
    # n_i exact-shares can fall short by at most one per winner.
    if leftover < 0 or leftover > len(winners):
        raise AssertionError(
            f"leftover {leftover} outside [0, {len(winners)}] — allocation invariant broken"
        )

    # Second pass: distribute leftover one unit at a time using the
    # deterministic priority order from the spec.
    ordered = sorted(
        winners,
        key=lambda r: (
            -remainders[r.miner_hotkey],  # largest fractional remainder first
            -r.miner_score_points,  # then largest score
            -r.active_member_count,  # then largest active count
            r.miner_hotkey,  # then hotkey ASC
        ),
    )

    for i in range(leftover):
        base[ordered[i].miner_hotkey] += 1

    return base


__all__ = ["allocate_winner_units"]
