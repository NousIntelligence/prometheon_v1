"""Phase 1 candidate ranking — deterministic sort with explicit tie-breakers.

The sort key from consolidated specification §12.7 is:

1. ``miner_score_points`` descending
2. ``active_member_count`` descending
3. ``miner_hotkey`` ascending lexicographic

The hotkey tie-breaker is the canonical SS58 string. The sort is total
under this key, so two compliant implementations always produce the same
ranking from the same inputs.
"""

from __future__ import annotations

from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord


def rank_candidates(candidates: list[MinerRecord]) -> list[MinerRecord]:
    """Return ``candidates`` sorted by the canonical Phase 1 ranking key.

    The function does not mutate its input. Two records that tie on every
    sort key produce a stable, predictable output (alphabetic on
    ``miner_hotkey``).

    Parameters
    ----------
    candidates:
        The post-eligibility-filter set of candidates.

    Returns
    -------
    list[MinerRecord]
        A new list sorted descending by score, then descending by active
        member count, then ascending by hotkey.
    """
    return sorted(
        candidates,
        key=lambda r: (
            -r.miner_score_points,  # primary: score DESC
            -r.active_member_count,  # secondary: active_count DESC
            r.miner_hotkey,  # tertiary: hotkey ASC
        ),
    )


def select_top_k(ranked: list[MinerRecord], top_k: int) -> list[MinerRecord]:
    """Return the first ``min(top_k, len(ranked))`` records.

    Implements the top-K selection step from consolidated specification
    §12.8: with fewer than ``top_k`` candidates, every candidate wins;
    with more, only the top ``top_k`` do.
    """
    if top_k < 0:
        raise ValueError(f"top_k must be non-negative, got {top_k}")
    return ranked[:top_k]


__all__ = ["rank_candidates", "select_top_k"]
