"""Unit tests for how ``recover-hotkey`` accepts the *old* hotkey.

The old hotkey never signs a recovery — only the coldkey and the new hotkey
do. Its address is carried in the payload purely so the platform knows which
binding is being replaced. Requiring the old key *file* therefore made the
command unusable in the one situation it exists for: the key is gone. These
tests pin the two ways to name it, their mutual exclusion, and that a
malformed address is rejected before any network call consumes a nonce.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from prometheon.cli.recover_hotkey import recover_hotkey

pytestmark = pytest.mark.unit

VALID_SS58 = "5F9MHZ78mgGtgAkYBAmj6KiCaK6tJphh75R4rmUWJT6cjoPS"

BASE_ARGS = [
    "--recovery-method",
    "coldkey",
    "--role",
    "miner",
    "--username",
    "operator",
    "--email",
    "operator@example.invalid",
    "--api-token",
    "token",
    "--wallet-name",
    "wallet",
    "--new-hotkey-name",
    "new",
    "--platform-base-url",
    "https://platform.invalid",
    "--platform-instance-id",
    "bitfan-staging",
    "--chain-network",
    "test",
    "--netuid",
    "481",
]


def _invoke(*extra: str) -> tuple[int, str]:
    result = CliRunner().invoke(recover_hotkey, [*BASE_ARGS, *extra])
    return result.exit_code, result.output


def test_neither_old_hotkey_option_is_a_usage_error() -> None:
    code, output = _invoke()
    assert code == 2
    assert "--old-hotkey-ss58" in output
    assert "--old-hotkey-name" in output


def test_both_old_hotkey_options_is_a_usage_error() -> None:
    code, output = _invoke("--old-hotkey-ss58", VALID_SS58, "--old-hotkey-name", "old")
    assert code == 2
    assert "not both" in output


def test_malformed_ss58_is_rejected_before_any_platform_call() -> None:
    # No client is stubbed here on purpose: if the check moved after the
    # nonce request, this would fail on a connection error rather than a
    # usage error, which is exactly the regression being guarded.
    code, output = _invoke("--old-hotkey-ss58", "not-an-address")
    assert code == 2
    assert "not an SS58 address" in output


def test_valid_ss58_gets_past_argument_handling_without_the_old_key_file() -> None:
    # The lost-hotkey path: no old key file exists, and the command must not
    # try to load one. It proceeds to the platform call and fails there.
    code, output = _invoke("--old-hotkey-ss58", VALID_SS58)
    assert code != 2, output
    assert "old-hotkey" not in output
