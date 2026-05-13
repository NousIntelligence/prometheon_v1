"""Unit tests for ``prometheon.chain.weights``.

Covers u16 conversion, the pre-submission policy gate, and the
strategy-protocol shape (verified via a small in-test fake).
"""

from __future__ import annotations

import pytest

from prometheon.chain.uids import ResolvedTarget
from prometheon.chain.weights import (
    CHAIN_WEIGHT_UNITS,
    ChainAdapterCapabilities,
    ChainHyperparameters,
    ChainWeightVector,
    CommitRevealEnabledError,
    MechidMissingError,
    WeightsVersionMismatchError,
    assert_phase1_compatible,
    to_u16_chain_vector,
)

pytestmark = pytest.mark.unit


def _t(hotkey: str, uid: int, units: int, *, role: str = "miner") -> ResolvedTarget:
    return ResolvedTarget(hotkey=hotkey, uid=uid, weight_units=units, role=role)


# ---------------------------------------------------------------------------
# ChainWeightVector
# ---------------------------------------------------------------------------


class TestChainWeightVector:
    def test_balanced_lengths_accepted(self) -> None:
        v = ChainWeightVector(uids=[1, 2], weights=[100, 200], hotkeys=["a", "b"])
        assert len(v.uids) == 2

    def test_length_mismatch_rejected(self) -> None:
        with pytest.raises(ValueError, match="length mismatch"):
            ChainWeightVector(uids=[1], weights=[100, 200], hotkeys=["a"])


# ---------------------------------------------------------------------------
# to_u16_chain_vector
# ---------------------------------------------------------------------------


class TestToU16ChainVector:
    def test_single_target_takes_full_chain_units(self) -> None:
        vector = to_u16_chain_vector([_t("5A", 1, 1_000_000_000)])
        assert vector.weights == [CHAIN_WEIGHT_UNITS]
        assert vector.uids == [1]

    def test_two_equal_targets_split_evenly(self) -> None:
        vector = to_u16_chain_vector([_t("5A", 1, 500_000_000), _t("5B", 2, 500_000_000)])
        assert sum(vector.weights) == CHAIN_WEIGHT_UNITS
        # 65_535 is odd; equal scores split as (32768, 32767) with the
        # leftover going to the smaller-hotkey target by tie-break.
        assert vector.weights == [32768, 32767]

    def test_proportional_split_of_three(self) -> None:
        vector = to_u16_chain_vector(
            [
                _t("5A", 1, 100_000_000),
                _t("5B", 2, 200_000_000),
                _t("5C", 3, 700_000_000),
            ]
        )
        assert sum(vector.weights) == CHAIN_WEIGHT_UNITS
        # Approximately 6553, 13107, 45875.
        a, b, c = vector.weights
        assert b > a and c > b

    def test_total_equals_chain_weight_units_for_realistic_plan(self) -> None:
        targets = [_t(f"5h_{i:02d}", uid=i + 1, units=100 + i * 7) for i in range(11)]
        vector = to_u16_chain_vector(targets)
        assert sum(vector.weights) == CHAIN_WEIGHT_UNITS

    def test_empty_targets_rejected(self) -> None:
        with pytest.raises(ValueError, match="targets list is empty"):
            to_u16_chain_vector([])

    def test_all_zero_units_rejected(self) -> None:
        with pytest.raises(ValueError, match="zero weight_units"):
            to_u16_chain_vector([_t("5A", 1, 0)])

    def test_negative_units_rejected(self) -> None:
        with pytest.raises(ValueError, match="negative weight_units"):
            to_u16_chain_vector([_t("5A", 1, -1)])


# ---------------------------------------------------------------------------
# assert_phase1_compatible
# ---------------------------------------------------------------------------


def _hyperparams(*, weights_version: int = 0, commit_reveal: bool = False) -> ChainHyperparameters:
    return ChainHyperparameters(
        weights_version=weights_version, commit_reveal_enabled=commit_reveal
    )


def _capabilities(*, supports_mechid: bool = True) -> ChainAdapterCapabilities:
    return ChainAdapterCapabilities(
        sdk_version="10.3.2",
        python_version="3.11",
        supports_mechid=supports_mechid,
    )


class TestAssertPhase1Compatible:
    def test_happy_path(self) -> None:
        assert_phase1_compatible(
            hyperparams=_hyperparams(),
            capabilities=_capabilities(),
            configured_version_key=0,
            fail_on_weights_version_mismatch=True,
            allow_legacy_sdk_without_mechid=False,
        )

    def test_commit_reveal_enabled_rejected(self) -> None:
        with pytest.raises(CommitRevealEnabledError):
            assert_phase1_compatible(
                hyperparams=_hyperparams(commit_reveal=True),
                capabilities=_capabilities(),
                configured_version_key=0,
                fail_on_weights_version_mismatch=True,
                allow_legacy_sdk_without_mechid=False,
            )

    def test_missing_mechid_rejected_when_legacy_not_allowed(self) -> None:
        with pytest.raises(MechidMissingError):
            assert_phase1_compatible(
                hyperparams=_hyperparams(),
                capabilities=_capabilities(supports_mechid=False),
                configured_version_key=0,
                fail_on_weights_version_mismatch=True,
                allow_legacy_sdk_without_mechid=False,
            )

    def test_missing_mechid_accepted_when_legacy_allowed(self) -> None:
        assert_phase1_compatible(
            hyperparams=_hyperparams(),
            capabilities=_capabilities(supports_mechid=False),
            configured_version_key=0,
            fail_on_weights_version_mismatch=True,
            allow_legacy_sdk_without_mechid=True,
        )

    def test_weights_version_mismatch_rejected_when_strict(self) -> None:
        with pytest.raises(WeightsVersionMismatchError):
            assert_phase1_compatible(
                hyperparams=_hyperparams(weights_version=5),
                capabilities=_capabilities(),
                configured_version_key=4,
                fail_on_weights_version_mismatch=True,
                allow_legacy_sdk_without_mechid=False,
            )

    def test_weights_version_mismatch_tolerated_when_relaxed(self) -> None:
        assert_phase1_compatible(
            hyperparams=_hyperparams(weights_version=5),
            capabilities=_capabilities(),
            configured_version_key=4,
            fail_on_weights_version_mismatch=False,
            allow_legacy_sdk_without_mechid=False,
        )
