"""Unit tests for ``prometheon.chain.subtensor``.

Pins:

- The return-shape handling of ``_parse_set_weights_result`` because the
  Bittensor SDK has historically shifted between bare tuples, bools, and
  dataclass-shaped responses, and silently swallowing a failure in this
  layer would let a validator believe it submitted weights when it did
  not.
- The ``read_hyperparameters`` contract against the SDK's
  :class:`SubnetHyperparameters` accessor — the previous revision called
  two non-existent convenience methods
  (``get_commit_reveal_weights_enabled`` and ``weights_version``) and
  silently fell through to "commit-reveal off, weights_version=0", which
  caused the validator to miss a subnet-owner-enabled commit-reveal
  flip and jam on ``TooManyUnrevealedCommits``. Tests below pin the
  new single-call contract on both happy and SDK-drift paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from prometheon.chain.subtensor import (
    SubtensorError,
    _parse_set_weights_result,
    read_hyperparameters,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Duck-typed ExtrinsicResponse stand-ins (so the test suite does not need
# to import bittensor's real dataclass).
# ---------------------------------------------------------------------------


@dataclass
class _Receipt:
    extrinsic_hash: str | None = None

    def __str__(self) -> str:
        return f"<Receipt extrinsic_hash={self.extrinsic_hash}>"


@dataclass
class _Response:
    success: bool
    message: str | None = None
    error: object | None = None
    extrinsic_function: str | None = None
    extrinsic_fee: object | None = None
    extrinsic_receipt: _Receipt | None = None


# ---------------------------------------------------------------------------
# Bittensor 10.x ExtrinsicResponse shape (dataclass with .success / .message)
# ---------------------------------------------------------------------------


class TestExtrinsicResponseShape:
    def test_success_with_hash_returns_extrinsic_hash(self) -> None:
        # Realistic happy path: SDK returns an extrinsic_hash inside the receipt.
        receipt = _Receipt(extrinsic_hash="0xabc123")
        response = _Response(success=True, message="Finalized.", extrinsic_receipt=receipt)
        assert _parse_set_weights_result(response) == "0xabc123"

    def test_success_without_receipt_falls_back_to_message(self) -> None:
        # SDK reports success but doesn't surface a receipt yet (common
        # when wait_for_inclusion is False, or with older 10.x patches).
        response = _Response(success=True, message="Submitted.")
        assert _parse_set_weights_result(response) == "Submitted."

    def test_success_with_empty_message_returns_none(self) -> None:
        # Edge case the old code already handled — keep behaviour consistent.
        response = _Response(success=True, message="")
        assert _parse_set_weights_result(response) is None

    def test_failure_raises_with_message(self) -> None:
        # The bug an earlier PR fixes: the old code silently treated this
        # as a successful submission. Now it must raise.
        response = _Response(success=False, message="set_weights rate limit exceeded")
        with pytest.raises(SubtensorError, match="set_weights rate limit exceeded"):
            _parse_set_weights_result(response)

    def test_failure_with_empty_message_includes_other_diagnostic_fields(self) -> None:
        # The chain sometimes rejects with .message=None but populates
        # .error / .extrinsic_function / .extrinsic_receipt. Operator must
        # see something more useful than `set_weights returned failure: None`.
        receipt = _Receipt(extrinsic_hash="0xdeadbeef")
        response = _Response(
            success=False,
            message=None,
            error=RuntimeError("weights_set_rate_limit_exceeded"),
            extrinsic_function="set_weights_extrinsic",
            extrinsic_fee=42,
            extrinsic_receipt=receipt,
        )
        with pytest.raises(SubtensorError) as exc_info:
            _parse_set_weights_result(response)
        msg = str(exc_info.value)
        assert "weights_set_rate_limit_exceeded" in msg
        assert "set_weights_extrinsic" in msg
        assert "0xdeadbeef" in msg
        assert "fee=42" in msg

    def test_failure_with_no_diagnostic_fields_has_clear_fallback(self) -> None:
        # Pathological case: SDK returns a failure with literally no fields
        # set. The error message must still tell the operator what we know.
        response = _Response(success=False)
        with pytest.raises(SubtensorError, match="no detail provided by SDK"):
            _parse_set_weights_result(response)


# ---------------------------------------------------------------------------
# Legacy SDK shapes
# ---------------------------------------------------------------------------


class TestLegacyTupleShape:
    def test_success_tuple_returns_message(self) -> None:
        assert _parse_set_weights_result((True, "ok")) == "ok"

    def test_success_tuple_with_empty_message_returns_none(self) -> None:
        assert _parse_set_weights_result((True, "")) is None

    def test_failure_tuple_raises(self) -> None:
        with pytest.raises(SubtensorError, match="quota"):
            _parse_set_weights_result((False, "quota exceeded"))


class TestLegacyBoolShape:
    def test_bare_true_returns_none(self) -> None:
        assert _parse_set_weights_result(True) is None

    def test_bare_false_raises(self) -> None:
        with pytest.raises(SubtensorError, match="returned False"):
            _parse_set_weights_result(False)


class TestLegacyStringAndUnknown:
    def test_bare_string_returns_string(self) -> None:
        # Very old SDKs returned the extrinsic hash directly.
        assert _parse_set_weights_result("0xdeadbeef") == "0xdeadbeef"

    def test_unknown_shape_returns_none(self) -> None:
        # Unknown shape but no exception from the SDK — treat as success
        # without a receipt rather than dropping a potential failure signal.
        assert _parse_set_weights_result({"unknown": "shape"}) is None


# ---------------------------------------------------------------------------
# read_hyperparameters — duck-typed SubnetHyperparameters stand-in.
#
# The pre-PR-#66 revision called ``subtensor.get_commit_reveal_weights_enabled``
# and ``subtensor.weights_version`` — two methods that do not exist on
# ``bittensor.Subtensor`` in either 10.3.x or 10.5.x. The ``except
# AttributeError`` fallbacks silently treated the missing methods as
# "commit-reveal disabled, weights_version=0", so a real subnet-owner
# commit-reveal toggle on netuid 481 was invisible to the validator and
# the SDK silently routed set_weights through the commit-reveal
# extrinsic, jamming on TooManyUnrevealedCommits. The new revision uses
# ``get_subnet_hyperparameters`` (present on both SDK versions) and
# refuses to swallow shape-drift — failure surfaces as SubtensorError.
# ---------------------------------------------------------------------------


@dataclass
class _SubnetHyperparametersStub:
    """Minimal duck-typed stand-in for bittensor's SubnetHyperparameters."""

    commit_reveal_weights_enabled: bool
    weights_version: int | None


class _FakeSubtensor:
    """Routes ``get_subnet_hyperparameters`` to the supplied factory.

    The factory is a callable so individual tests can either return a
    stub or raise to exercise the error paths.
    """

    def __init__(self, factory: Any) -> None:
        self._factory = factory
        self.calls: list[int] = []

    def get_subnet_hyperparameters(self, *, netuid: int) -> Any:
        self.calls.append(netuid)
        return self._factory(netuid)


class TestReadHyperparametersHappyPath:
    def test_commit_reveal_disabled_normal_subnet(self) -> None:
        stub = _SubnetHyperparametersStub(
            commit_reveal_weights_enabled=False,
            weights_version=10005000,
        )
        subtensor = _FakeSubtensor(lambda _netuid: stub)
        result = read_hyperparameters(subtensor, netuid=481)
        assert result.commit_reveal_enabled is False
        assert result.weights_version == 10005000
        assert subtensor.calls == [481]

    def test_commit_reveal_enabled_surfaces_to_caller(self) -> None:
        # The case the production incident exposed: subnet owner enabled
        # commit-reveal. The runner's pre-submission policy gate
        # (assert_phase1_compatible) must see True and raise
        # CommitRevealEnabledError; the silent fail-open default of False
        # caused the original jam.
        stub = _SubnetHyperparametersStub(
            commit_reveal_weights_enabled=True,
            weights_version=10005000,
        )
        subtensor = _FakeSubtensor(lambda _netuid: stub)
        result = read_hyperparameters(subtensor, netuid=481)
        assert result.commit_reveal_enabled is True

    def test_weights_version_none_collapses_to_zero(self) -> None:
        # SubnetHyperparameters.weights_version is typed Optional[int];
        # the chain returns None when no version has been set. Collapse
        # to 0 explicitly rather than letting None propagate into the
        # policy gate.
        stub = _SubnetHyperparametersStub(
            commit_reveal_weights_enabled=False,
            weights_version=None,
        )
        subtensor = _FakeSubtensor(lambda _netuid: stub)
        result = read_hyperparameters(subtensor, netuid=1)
        assert result.weights_version == 0


class TestReadHyperparametersErrorPaths:
    def test_subtensor_raises_wraps_in_subtensor_error(self) -> None:
        def _raise(_netuid: int) -> Any:
            raise RuntimeError("connection refused")

        subtensor = _FakeSubtensor(_raise)
        with pytest.raises(SubtensorError, match="connection refused"):
            read_hyperparameters(subtensor, netuid=481)

    def test_subtensor_returns_none_raises_with_clear_message(self) -> None:
        # The SDK returns None when the subnet does not exist on the
        # current network — a real operator error worth surfacing
        # loudly, not silently defaulting.
        subtensor = _FakeSubtensor(lambda _netuid: None)
        with pytest.raises(SubtensorError, match="no hyperparameters"):
            read_hyperparameters(subtensor, netuid=99999)

    def test_missing_commit_reveal_field_raises_compatibility_error(self) -> None:
        # Defence-in-depth: if a future SDK ever drops or renames the
        # field, we want a loud SubtensorError at startup naming the
        # field, not a silent fall-through.
        class _BadStub:
            weights_version = 0
            # No commit_reveal_weights_enabled attribute.

        subtensor = _FakeSubtensor(lambda _netuid: _BadStub())
        with pytest.raises(SubtensorError, match="commit_reveal_weights_enabled"):
            read_hyperparameters(subtensor, netuid=481)

    def test_missing_weights_version_field_raises_compatibility_error(self) -> None:
        class _BadStub:
            commit_reveal_weights_enabled = False
            # No weights_version attribute.

        subtensor = _FakeSubtensor(lambda _netuid: _BadStub())
        with pytest.raises(SubtensorError, match="weights_version"):
            read_hyperparameters(subtensor, netuid=481)

    def test_no_attribute_error_fallback_remains(self) -> None:
        # Regression guard: the previous revision had
        # ``except AttributeError: commit_reveal_enabled = False`` which
        # silently masked the missing-method bug. A method-missing
        # condition must now bubble up as SubtensorError, not be turned
        # into a False default.
        class _NoMethod:
            pass

        subtensor = _NoMethod()
        with pytest.raises(SubtensorError):
            # AttributeError from the missing method surfaces as
            # SubtensorError via the outer ``except Exception`` guard.
            read_hyperparameters(subtensor, netuid=481)  # type: ignore[arg-type]
