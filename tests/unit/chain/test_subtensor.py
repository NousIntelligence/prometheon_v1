"""Unit tests for ``prometheon.chain.subtensor``.

Specifically pins the return-shape handling of ``_parse_set_weights_result``
because the Bittensor SDK has historically shifted between bare tuples,
bools, and dataclass-shaped responses, and silently swallowing a failure
in this layer would let a validator believe it submitted weights when it
did not.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from prometheon.chain.subtensor import SubtensorError, _parse_set_weights_result

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Duck-typed ExtrinsicResponse stand-ins (so the test suite does not need
# to import bittensor's real dataclass).
# ---------------------------------------------------------------------------


@dataclass
class _Receipt:
    extrinsic_hash: str | None


@dataclass
class _Response:
    success: bool
    message: str
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
        # The bug this PR fixes: the old code silently treated this as
        # a successful submission. Now it must raise.
        response = _Response(success=False, message="set_weights rate limit exceeded")
        with pytest.raises(SubtensorError, match="set_weights rate limit exceeded"):
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
