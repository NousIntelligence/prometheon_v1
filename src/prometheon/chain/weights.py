"""Weight submission adapter.

This module owns the boundary between the pure mechanism engine (which
emits integer weight units summing to ``WEIGHT_UNITS = 1_000_000_000``)
and the Bittensor chain (which expects u16 weight values summing to
``CHAIN_WEIGHT_UNITS = 65_535``).

The actual ``set_weights`` SDK call is wrapped behind a strategy
interface so the validator runtime can swap mock implementations in for
tests and a real Bittensor adapter in for production. The interface also
makes the policy decisions explicit:

- Plain ``set_weights`` only — no commit-reveal in Phase 1
  (consolidated specification §17).
- ``mechid=0`` must be passed when the SDK accepts it; outside local
  development a missing ``mechid`` argument fails closed
  (consolidated specification §19).
- ``version_key`` is always passed; the runner is responsible for
  comparing it to the chain's expected value and failing closed on
  mismatch where policy demands it (consolidated specification §18).

The u16 conversion uses the same largest-remainder approach as the
engine's miner-pool allocation, ensuring the chain values sum exactly
to :data:`CHAIN_WEIGHT_UNITS` for every ready plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Protocol

from prometheon.chain.uids import ResolvedTarget

# Sum of u16 chain weight values for any ready plan. Matches the
# ``CHAIN_WEIGHT_UNITS`` constant in the consolidated specification §20.2.
CHAIN_WEIGHT_UNITS: Final[int] = 65_535


class WeightSubmissionError(Exception):
    """Raised by any weight submission policy or SDK failure."""

    code: str = "chain.weight_submission_error"


class CommitRevealEnabledError(WeightSubmissionError):
    """Plain ``set_weights`` is unavailable because the chain has commit-reveal on."""

    code = "chain.commit_reveal_enabled"


class WeightsVersionMismatchError(WeightSubmissionError):
    """The chain's ``weights_version`` differs from the configured ``version_key``."""

    code = "chain.weights_version_mismatch"


class MechidMissingError(WeightSubmissionError):
    """The installed Bittensor SDK does not expose ``mechid`` and the operator
    has not allowed legacy SDKs on this network."""

    code = "chain.mechid_missing"


@dataclass(frozen=True)
class ChainWeightVector:
    """Resolved, u16-quantised submission vector ready for the SDK.

    Sums to :data:`CHAIN_WEIGHT_UNITS` for any ready plan. The
    ``hotkeys`` list mirrors ``uids`` and ``weights`` 1:1 so callers can
    log human-readable targets without re-resolving.
    """

    uids: list[int] = field(default_factory=list)
    weights: list[int] = field(default_factory=list)
    hotkeys: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not (len(self.uids) == len(self.weights) == len(self.hotkeys)):
            raise ValueError(
                f"length mismatch: uids={len(self.uids)}, "
                f"weights={len(self.weights)}, hotkeys={len(self.hotkeys)}"
            )


def to_u16_chain_vector(targets: list[ResolvedTarget]) -> ChainWeightVector:
    """Convert :class:`ResolvedTarget` rows to a u16 chain vector.

    Applies largest-remainder allocation against
    :data:`CHAIN_WEIGHT_UNITS` so the output values are non-negative
    integers ≤ 65_535 summing exactly to :data:`CHAIN_WEIGHT_UNITS` for
    any non-empty input whose unit total is positive.

    Raises
    ------
    ValueError
        If ``targets`` is empty (callers must dispatch the Case D /
        fail-closed path before reaching this function) or if any target
        carries a negative ``weight_units``.
    """
    if not targets:
        raise ValueError(
            "targets list is empty; the runner must not invoke u16 conversion "
            "for a no_valid_weight_target plan"
        )

    total_units = 0
    for target in targets:
        if target.weight_units < 0:
            raise ValueError(
                f"target {target.hotkey!r} has negative weight_units {target.weight_units}"
            )
        total_units += target.weight_units

    if total_units == 0:
        raise ValueError("all targets have zero weight_units; the runner must skip submission")

    # Largest-remainder allocation from 1_000_000_000-scale units down to
    # CHAIN_WEIGHT_UNITS-scale u16 values.
    base: list[int] = []
    remainders: list[int] = []
    for target in targets:
        product = CHAIN_WEIGHT_UNITS * target.weight_units
        base.append(product // total_units)
        remainders.append(product % total_units)

    leftover = CHAIN_WEIGHT_UNITS - sum(base)
    if leftover < 0 or leftover > len(targets):
        raise AssertionError(
            f"u16 leftover {leftover} outside [0, {len(targets)}] — allocation invariant broken"
        )

    if leftover > 0:
        # Priority: largest remainder, then largest weight_units, then
        # smallest hotkey (lexicographic) — same tie-breakers as the
        # engine's miner-pool allocation so the order is consistent.
        order = sorted(
            range(len(targets)),
            key=lambda i: (
                -remainders[i],
                -targets[i].weight_units,
                targets[i].hotkey,
            ),
        )
        for i in range(leftover):
            base[order[i]] += 1

    return ChainWeightVector(
        uids=[t.uid for t in targets],
        weights=base,
        hotkeys=[t.hotkey for t in targets],
    )


@dataclass(frozen=True)
class ChainHyperparameters:
    """The chain hyperparameters and feature flags the runner checks before
    submitting weights."""

    weights_version: int
    commit_reveal_enabled: bool


@dataclass(frozen=True)
class ChainAdapterCapabilities:
    """Static feature detection for the installed Bittensor SDK.

    Determined once at startup so the runner can fail closed early on
    networks where a missing ``mechid`` would mean an undetectable on-chain
    misconfiguration.
    """

    sdk_version: str
    python_version: str
    supports_mechid: bool


class WeightSubmissionStrategy(Protocol):
    """Pluggable submission backend.

    Phase 1 ships only :class:`PlainSetWeightsStrategy`. Commit-reveal
    has its own protocol slot reserved for a future phase; until then any
    ``commit_reveal_enabled == True`` detection causes the runner to fail
    closed.
    """

    def submit(
        self,
        *,
        netuid: int,
        vector: ChainWeightVector,
        version_key: int,
        mechid: int | None,
    ) -> str | None:
        """Submit the u16 vector to the chain.

        Returns the extrinsic hash on success, or ``None`` if the SDK
        does not surface one.
        """
        ...


def assert_phase1_compatible(
    *,
    hyperparams: ChainHyperparameters,
    capabilities: ChainAdapterCapabilities,
    configured_version_key: int,
    fail_on_weights_version_mismatch: bool,
    allow_legacy_sdk_without_mechid: bool,
) -> None:
    """Run the pre-submission policy checks.

    Raises the matching subclass of :class:`WeightSubmissionError` if any
    check fails. Returns ``None`` on success.

    Checks (in order):

    1. ``commit_reveal_enabled`` is False (Phase 1 ships plain set_weights
       only — see consolidated specification §17).
    2. The SDK supports ``mechid`` *or* the operator has explicitly
       allowed legacy SDKs on this network.
    3. The chain's ``weights_version`` matches ``configured_version_key``,
       *or* the operator has chosen to ignore the mismatch.
    """
    if hyperparams.commit_reveal_enabled:
        raise CommitRevealEnabledError(
            "subnet has commit-reveal enabled; Phase 1 ships plain set_weights only"
        )

    if not capabilities.supports_mechid and not allow_legacy_sdk_without_mechid:
        raise MechidMissingError(
            f"installed Bittensor SDK {capabilities.sdk_version!r} does not "
            "expose mechid; allow_legacy_sdk_without_mechid=True is required "
            "to proceed (local development only)"
        )

    if hyperparams.weights_version != configured_version_key and fail_on_weights_version_mismatch:
        raise WeightsVersionMismatchError(
            f"chain weights_version={hyperparams.weights_version} does not "
            f"match configured version_key={configured_version_key}"
        )


__all__ = [
    "CHAIN_WEIGHT_UNITS",
    "ChainAdapterCapabilities",
    "ChainHyperparameters",
    "ChainWeightVector",
    "CommitRevealEnabledError",
    "MechidMissingError",
    "WeightSubmissionError",
    "WeightSubmissionStrategy",
    "WeightsVersionMismatchError",
    "assert_phase1_compatible",
    "to_u16_chain_vector",
]
