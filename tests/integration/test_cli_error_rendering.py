"""End-to-end tests of the CLI error-rendering boundary.

These tests drive the ``prometheon`` CLI through :class:`click.testing.CliRunner`,
mocking only the two outermost dependencies (wallet loading and the
BitFan client) so that every layer of the renderer pipeline is exercised:

  argv → Click parser → sub-command body → PlatformError raised by the
  fake client → bubbles up through Click's ``standalone_mode=False`` →
  caught in ``cli.main.main`` → routed to ``cli.renderer.render_error`` →
  written to stderr → ``sys.exit(1)``.

The fakes are deliberately tiny: a ``FakeKeypair`` that has only the
``ss58_address`` attribute the CLI reads before the platform call, and
a ``FakeClient`` that satisfies the context-manager protocol and raises
the chosen exception on the first method call. Every command we test
fails at the first network method, so neither signing nor envelope
construction is ever exercised — that keeps the test surface narrow to
"does the renderer fire?" rather than "do all the upstream layers
work?" (which is the unit-test suite's concern).

PR #62 in the error-rendering handoff. Pairs the unit suite in
``tests/unit/cli/test_renderer.py`` with full CLI-boundary coverage
across four error-bearing sub-commands.
"""

from __future__ import annotations

from typing import Any

import pytest

from prometheon.cli import main as main_module
from prometheon.cli import (
    recover_hotkey as recover_hotkey_module,
)
from prometheon.cli import (
    rotate_hotkey as rotate_hotkey_module,
)
from prometheon.cli import (
    verify_miner as verify_miner_module,
)
from prometheon.cli import (
    verify_validator as verify_validator_module,
)
from prometheon.platform.errors import (
    AccountNotVerifiedError,
    HotkeyAlreadyLinkedError,
    NonceExpiredError,
    PlatformError,
    RecoveryCooldownActiveError,
    RotationCooldownActiveError,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


# Shape-valid SS58 address. No corresponding private key exists; the CLI
# only reads this string and passes it to the platform body validator,
# which accepts any value matching the base58 pattern. The fake client
# never reaches the signing step in these tests.
_FAKE_SS58: str = "5DNNS3vUaoCM3GZuFRDKfNNYTuMzBnDqdjUSepFijozaXAa6"


class _FakeKeypair:
    """The minimum surface the CLI reads from a Bittensor keypair before
    the first platform call. The CLI never reaches the signing step in
    these tests because the fake client raises before then.
    """

    def __init__(self, ss58_address: str = _FAKE_SS58) -> None:
        self.ss58_address: str = ss58_address


class _FakeClient:
    """Context-manager-compatible fake :class:`BitFanClient`.

    Records the exception to raise and which method should raise it. All
    fixture commands in this module fail at the first call
    (``request_nonce``), so the dispatch dict is just a guard against
    test author error.
    """

    def __init__(self, *, raise_on: str, exception: PlatformError) -> None:
        self._raise_on = raise_on
        self._exception = exception
        self.calls: list[str] = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        return None

    def request_nonce(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("request_nonce")
        if self._raise_on == "request_nonce":
            raise self._exception
        raise AssertionError("fake client method called past the raise point")

    def post_verify_envelope(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("post_verify_envelope")
        if self._raise_on == "post_verify_envelope":
            raise self._exception
        raise AssertionError("fake client method called past the raise point")

    def post_rotation_envelope(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("post_rotation_envelope")
        if self._raise_on == "post_rotation_envelope":
            raise self._exception
        raise AssertionError("fake client method called past the raise point")

    def post_recovery_envelope(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("post_recovery_envelope")
        if self._raise_on == "post_recovery_envelope":
            raise self._exception
        raise AssertionError("fake client method called past the raise point")


# ---------------------------------------------------------------------------
# Shared injection helper
# ---------------------------------------------------------------------------


def _wire_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    module: Any,
    exception: PlatformError,
    raise_on: str = "request_nonce",
) -> _FakeClient:
    """Patch wallet loading and client construction in the given command
    module so the CLI proceeds past argument parsing and immediately
    raises ``exception`` from inside the ``with make_client(...)`` block.
    """
    fake_client = _FakeClient(raise_on=raise_on, exception=exception)

    def _fake_load_hotkey(**kwargs: Any) -> _FakeKeypair:
        return _FakeKeypair()

    def _fake_load_coldkey(**kwargs: Any) -> _FakeKeypair:
        return _FakeKeypair()

    def _fake_make_client(**kwargs: Any) -> _FakeClient:
        return fake_client

    monkeypatch.setattr(module, "load_hotkey_or_exit", _fake_load_hotkey)
    if hasattr(module, "load_coldkey_or_exit"):
        monkeypatch.setattr(module, "load_coldkey_or_exit", _fake_load_coldkey)
    monkeypatch.setattr(module, "make_client", _fake_make_client)
    return fake_client


# ---------------------------------------------------------------------------
# Shared command-line skeletons
# ---------------------------------------------------------------------------


_VERIFY_COMMON_ARGS = [
    "--username",
    "alice",
    "--email",
    "alice@example.com",
    "--wallet-name",
    "default",
    "--wallet-hotkey",
    "hk1",
    "--platform-base-url",
    "https://api.bitfan.example",
    "--platform-instance-id",
    "bitfan-staging",
    "--chain-network",
    "test",
    "--netuid",
    "481",
]

_ROTATE_COMMON_ARGS = [
    "--role",
    "miner",
    "--username",
    "alice",
    "--email",
    "alice@example.com",
    "--wallet-name",
    "default",
    "--old-hotkey-name",
    "old",
    "--new-hotkey-name",
    "new",
    "--platform-base-url",
    "https://api.bitfan.example",
    "--platform-instance-id",
    "bitfan-staging",
    "--chain-network",
    "test",
    "--netuid",
    "481",
]

_RECOVER_COMMON_ARGS = [
    "--recovery-method",
    "manual_2fa_ops",
    "--role",
    "miner",
    "--username",
    "alice",
    "--email",
    "alice@example.com",
    "--wallet-name",
    "default",
    "--old-hotkey-name",
    "old",
    "--new-hotkey-name",
    "new",
    "--platform-base-url",
    "https://api.bitfan.example",
    "--platform-instance-id",
    "bitfan-staging",
    "--chain-network",
    "test",
    "--netuid",
    "481",
]


# ---------------------------------------------------------------------------
# verify-miner
# ---------------------------------------------------------------------------


class TestVerifyMinerErrorRendering:
    def test_main_dispatch_emits_renderer_block_for_nonce_expired(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=verify_miner_module,
            exception=NonceExpiredError(status_code=401, detail="ttl expired"),
        )
        monkeypatch.setenv("PROMETHEON_MINER_API_TOKEN", "bootstrap-token-fixture")
        with pytest.raises(SystemExit) as excinfo:
            main_module.main(["verify-miner", *_VERIFY_COMMON_ARGS])
        captured = capsys.readouterr()
        assert excinfo.value.code == 1
        assert "Error: NONCE_EXPIRED" in captured.err
        assert "(platform, HTTP 401)" in captured.err
        assert "Remediation:" in captured.err
        # The renderer's docs link uses the canonical docs root.
        assert "github.com/NousIntelligence/prometheon_v1/blob/main/docs" in captured.err

    def test_renderer_block_does_not_include_verbose_trailer_without_flag(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=verify_miner_module,
            exception=NonceExpiredError(status_code=401, detail="ttl expired"),
        )
        monkeypatch.setenv("PROMETHEON_MINER_API_TOKEN", "bootstrap-token-fixture")
        with pytest.raises(SystemExit):
            main_module.main(["verify-miner", *_VERIFY_COMMON_ARGS])
        captured = capsys.readouterr()
        assert "[verbose]" not in captured.err


# ---------------------------------------------------------------------------
# verify-validator
# ---------------------------------------------------------------------------


class TestVerifyValidatorErrorRendering:
    def test_renderer_block_for_account_not_verified(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=verify_validator_module,
            exception=AccountNotVerifiedError(status_code=403, detail="role not yet verified"),
        )
        monkeypatch.setenv("PROMETHEON_VALIDATOR_API_TOKEN", "bootstrap-token-fixture")
        with pytest.raises(SystemExit) as excinfo:
            main_module.main(["verify-validator", *_VERIFY_COMMON_ARGS])
        captured = capsys.readouterr()
        assert excinfo.value.code == 1
        assert "Error: ACCOUNT_NOT_VERIFIED" in captured.err
        assert "verify-" in captured.err  # remediation references verify-{miner,validator}


# ---------------------------------------------------------------------------
# rotate-hotkey
# ---------------------------------------------------------------------------


class TestRotateHotkeyErrorRendering:
    def test_renderer_surfaces_cooldown_until_from_typed_details(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=rotate_hotkey_module,
            exception=RotationCooldownActiveError(
                status_code=409,
                detail="Rotation cooldown active.",
                details={"cooldown_until": "2026-05-30T00:00:00Z"},
            ),
        )
        monkeypatch.setenv("PROMETHEON_API_TOKEN", "operational-token-fixture")
        with pytest.raises(SystemExit) as excinfo:
            main_module.main(["rotate-hotkey", *_ROTATE_COMMON_ARGS])
        captured = capsys.readouterr()
        assert excinfo.value.code == 1
        assert "Error: ROTATION_COOLDOWN_ACTIVE" in captured.err
        # The typed details renderer surfaces the cooldown timestamp.
        assert "Cooldown clears at: 2026-05-30T00:00:00Z" in captured.err

    def test_hotkey_already_linked_renders_remediation_referencing_recover(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=rotate_hotkey_module,
            exception=HotkeyAlreadyLinkedError(status_code=409, detail="bound to another account"),
        )
        monkeypatch.setenv("PROMETHEON_API_TOKEN", "operational-token-fixture")
        with pytest.raises(SystemExit):
            main_module.main(["rotate-hotkey", *_ROTATE_COMMON_ARGS])
        captured = capsys.readouterr()
        assert "Error: HOTKEY_ALREADY_LINKED" in captured.err
        assert "recover-hotkey" in captured.err


# ---------------------------------------------------------------------------
# recover-hotkey
# ---------------------------------------------------------------------------


class TestRecoverHotkeyErrorRendering:
    def test_renderer_block_for_recovery_cooldown_active_with_details(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=recover_hotkey_module,
            exception=RecoveryCooldownActiveError(
                status_code=409,
                detail="Recovery cooldown active.",
                details={"cooldown_until": "2026-06-01T00:00:00Z"},
            ),
        )
        monkeypatch.setenv("PROMETHEON_API_TOKEN", "operational-token-fixture")
        with pytest.raises(SystemExit) as excinfo:
            main_module.main(["recover-hotkey", *_RECOVER_COMMON_ARGS])
        captured = capsys.readouterr()
        assert excinfo.value.code == 1
        assert "Error: RECOVERY_COOLDOWN_ACTIVE" in captured.err
        assert "Cooldown clears at: 2026-06-01T00:00:00Z" in captured.err
        # Recovery remediation references the Ops Console manual flow.
        assert "Ops Console" in captured.err


# ---------------------------------------------------------------------------
# Cross-cutting: --verbose flag, unknown codes, Click usage errors
# ---------------------------------------------------------------------------


class TestVerboseFlag:
    def test_verbose_flag_adds_diagnostic_trailer(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=verify_miner_module,
            exception=NonceExpiredError(status_code=401, detail="ttl expired"),
        )
        monkeypatch.setenv("PROMETHEON_MINER_API_TOKEN", "bootstrap-token-fixture")
        with pytest.raises(SystemExit):
            main_module.main(["--verbose", "verify-miner", *_VERIFY_COMMON_ARGS])
        captured = capsys.readouterr()
        assert "[verbose]" in captured.err
        assert "NONCE_EXPIRED" in captured.err

    def test_short_verbose_flag_works(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _wire_fakes(
            monkeypatch,
            module=verify_miner_module,
            exception=NonceExpiredError(status_code=401, detail="ttl expired"),
        )
        monkeypatch.setenv("PROMETHEON_MINER_API_TOKEN", "bootstrap-token-fixture")
        with pytest.raises(SystemExit):
            main_module.main(["-v", "verify-miner", *_VERIFY_COMMON_ARGS])
        captured = capsys.readouterr()
        assert "[verbose]" in captured.err


class TestUnknownPlatformCode:
    def test_unknown_wire_code_routes_through_issue_template_path(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _FutureCodeError(PlatformError):
            code = "FUTURE_FANCY_ERROR"

        _wire_fakes(
            monkeypatch,
            module=verify_miner_module,
            exception=_FutureCodeError(
                status_code=400,
                detail="server is ahead of this CLI build",
                wire_code="FUTURE_FANCY_ERROR",
            ),
        )
        monkeypatch.setenv("PROMETHEON_MINER_API_TOKEN", "bootstrap-token-fixture")
        with pytest.raises(SystemExit) as excinfo:
            main_module.main(["verify-miner", *_VERIFY_COMMON_ARGS])
        captured = capsys.readouterr()
        assert excinfo.value.code == 1
        assert "FUTURE_FANCY_ERROR" in captured.err
        assert "does not recognise" in captured.err.lower()
        # Issue-template URL is present in the operator-facing block.
        assert "unrecognised-platform-code.md" in captured.err
        assert "issues/new" in captured.err


class TestClickUsageErrorsBypassRenderer:
    """A missing required Click option must keep its native Click rendering
    (with the help banner), not be routed through the platform renderer.
    """

    def test_missing_required_option_shows_click_help(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main_module.main(["verify-miner"])
        captured = capsys.readouterr()
        # Click's UsageError exit code (2) — not the renderer's 1.
        assert excinfo.value.code == 2
        # The standard Click "Missing option" / "Usage:" affordance.
        assert "Usage" in captured.err or "Missing" in captured.err
        # No renderer artifacts in this path.
        assert "[verbose]" not in captured.err
        assert "Remediation:" not in captured.err
