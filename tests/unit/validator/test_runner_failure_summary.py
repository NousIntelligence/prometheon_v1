"""Unit tests for the on-disk failure-summary builder.

The runner persists ``(code, message)`` to ``state.json`` and
``events.ndjson`` whenever a cycle raises. For platform-side errors, the
``message`` field is server-provided, so we never want to serialise the
raw exception (which could embed the typed ``details`` dict) — we want a
code + a control-char-stripped, length-bound rendering of the platform's
human message.

These tests pin the contract for :func:`_safe_failure_summary` so any
future regression (e.g., re-introducing ``str(exc)`` into the persistence
path) fails the suite.
"""

from __future__ import annotations

import pytest

from prometheon.platform.errors import (
    HotkeyAlreadyLinkedError,
    NonceExpiredError,
    PlatformError,
    ProfileAlreadyHasHotkeyError,
)
from prometheon.validator.runner import _safe_failure_summary

pytestmark = pytest.mark.unit


class TestSafeFailureSummary:
    def test_platform_error_uses_wire_code_and_detail(self) -> None:
        exc = NonceExpiredError(status_code=401, detail="Nonce TTL elapsed.")
        code, message = _safe_failure_summary(exc)
        assert code == "NONCE_EXPIRED"
        assert message == "Nonce TTL elapsed."

    def test_platform_error_without_detail_uses_code_in_message(self) -> None:
        exc = HotkeyAlreadyLinkedError(status_code=409)
        code, message = _safe_failure_summary(exc)
        assert code == "HOTKEY_ALREADY_LINKED"
        # Default message must still be informative.
        assert "HOTKEY_ALREADY_LINKED" in message

    def test_typed_details_dict_is_not_serialised_into_message(self) -> None:
        # Even when the platform sends a structured details payload, only
        # the human-readable detail goes to disk — the dict stays on the
        # exception instance for the renderer to display interactively.
        exc = ProfileAlreadyHasHotkeyError(
            status_code=409,
            detail="Profile already has a hotkey.",
            details={"recommended_action": "rotate"},
        )
        code, message = _safe_failure_summary(exc)
        assert code == "PROFILE_ALREADY_HAS_HOTKEY"
        assert message == "Profile already has a hotkey."
        assert "recommended_action" not in message
        assert "rotate" not in message

    def test_strips_c0_control_characters(self) -> None:
        # A malicious or buggy server cannot embed terminal control
        # sequences in the operator-facing trailer via the persisted
        # message.
        exc = PlatformError(
            status_code=400,
            detail="hello\x1b[31mworld\x00trailing\x07bell",
        )
        _code, message = _safe_failure_summary(exc)
        assert "\x1b" not in message
        assert "\x00" not in message
        assert "\x07" not in message
        # Visible characters survive.
        assert "hello" in message
        assert "world" in message

    def test_preserves_tab(self) -> None:
        # Tab is the only C0 control we keep — it's harmless in logs and
        # operators sometimes use it for alignment in detail messages.
        exc = PlatformError(status_code=400, detail="col1\tcol2")
        _code, message = _safe_failure_summary(exc)
        assert message == "col1\tcol2"

    def test_truncates_long_detail(self) -> None:
        exc = PlatformError(status_code=400, detail="x" * 5000)
        _code, message = _safe_failure_summary(exc)
        assert len(message) <= 300
        assert message.endswith("...")

    def test_non_platform_exception_falls_back_to_str(self) -> None:
        exc = ValueError("internal config bug")
        code, message = _safe_failure_summary(exc)
        assert code == "ValueError"
        assert message == "internal config bug"

    def test_non_platform_exception_with_code_attribute(self) -> None:
        # Subnet-internal exceptions that carry a ``code`` attribute (e.g.,
        # the engine's domain errors) preserve it.
        class FakeDomainError(Exception):
            code = "engine.no_eligible_miners"

        exc = FakeDomainError("no miners met the threshold")
        code, message = _safe_failure_summary(exc)
        assert code == "engine.no_eligible_miners"
        assert message == "no miners met the threshold"
