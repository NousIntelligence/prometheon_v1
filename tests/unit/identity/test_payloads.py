"""Unit tests for ``prometheon.identity.payloads``.

Covers all four canonical payload models plus the ``NonceResponse`` shape.
Each model is exercised for:

- Valid construction.
- Field-level validation (regex, range, type, literal).
- Immutability (``frozen=True``).
- Round-trip through ``to_canonical_dict`` and ``to_signed_bytes``.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from prometheon.identity.payloads import (
    ColdkeyRecoveryPayload,
    HotkeyRotationPayload,
    IdentityVerifyPayload,
    ManualRecoveryPayload,
    NonceResponse,
)
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.security.canonical import (
    DOMAIN_HOTKEY_RECOVERY,
    DOMAIN_HOTKEY_ROTATION,
    DOMAIN_IDENTITY_VERIFY,
    domain_prefixed_bytes,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared values used across multiple test classes
# ---------------------------------------------------------------------------

VALID_HEX32 = "0x" + "ab" * 32
VALID_TIMESTAMP = "2026-05-20T00:00:00Z"
VALID_EXPIRES = "2026-05-20T00:10:00Z"
VALID_SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"  # //Alice
VALID_NEW_SS58 = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"  # //Bob


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _verify_payload_kwargs(**overrides: Any) -> dict[str, Any]:
    base = {
        "role": Role.MINER,
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "platform_account_id": "acct_abc",
        "username_hash": VALID_HEX32,
        "email_hash": VALID_HEX32,
        "hotkey_ss58": VALID_SS58,
        "nonce": "nonce_abc_123",
        "issued_at": VALID_TIMESTAMP,
        "expires_at": VALID_EXPIRES,
        "api_token_hash": VALID_HEX32,
    }
    base.update(overrides)
    return base


def _rotation_payload_kwargs(**overrides: Any) -> dict[str, Any]:
    base = {
        "role": Role.MINER,
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "platform_account_id": "acct_abc",
        "old_hotkey_ss58": VALID_SS58,
        "new_hotkey_ss58": VALID_NEW_SS58,
        "nonce": "nonce_abc_123",
        "issued_at": VALID_TIMESTAMP,
        "expires_at": VALID_EXPIRES,
        "api_token_hash": VALID_HEX32,
    }
    base.update(overrides)
    return base


def _coldkey_recovery_kwargs(**overrides: Any) -> dict[str, Any]:
    base = {
        "role": Role.MINER,
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "platform_account_id": "acct_abc",
        "old_hotkey_ss58": VALID_SS58,
        "coldkey_ss58": VALID_NEW_SS58,
        "new_hotkey_ss58": VALID_NEW_SS58,
        "nonce": "nonce_abc_123",
        "issued_at": VALID_TIMESTAMP,
        "expires_at": VALID_EXPIRES,
        "api_token_hash": VALID_HEX32,
    }
    base.update(overrides)
    return base


def _manual_recovery_kwargs(**overrides: Any) -> dict[str, Any]:
    base = {
        "role": Role.MINER,
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "platform_account_id": "acct_abc",
        "old_hotkey_ss58": VALID_SS58,
        "new_hotkey_ss58": VALID_NEW_SS58,
        "discord_handle_hash": VALID_HEX32,
        "nonce": "nonce_abc_123",
        "issued_at": VALID_TIMESTAMP,
        "expires_at": VALID_EXPIRES,
        "api_token_hash": VALID_HEX32,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# NonceResponse
# ---------------------------------------------------------------------------


class TestNonceResponse:
    def test_constructs_with_valid_fields(self) -> None:
        nonce = NonceResponse(
            platform_account_id="acct_abc",
            username_hash=VALID_HEX32,
            email_hash=VALID_HEX32,
            nonce="nonce_abc_123",
            issued_at=VALID_TIMESTAMP,
            expires_at=VALID_EXPIRES,
        )
        assert nonce.platform_account_id == "acct_abc"

    def test_rejects_uppercase_hash(self) -> None:
        with pytest.raises(ValidationError):
            NonceResponse(
                platform_account_id="acct_abc",
                username_hash="0x" + "AB" * 32,
                email_hash=VALID_HEX32,
                nonce="nonce",
                issued_at=VALID_TIMESTAMP,
                expires_at=VALID_EXPIRES,
            )

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            NonceResponse(
                platform_account_id="acct_abc",
                username_hash=VALID_HEX32,
                email_hash=VALID_HEX32,
                nonce="nonce",
                issued_at=VALID_TIMESTAMP,
                expires_at=VALID_EXPIRES,
                surprise="not-allowed",  # type: ignore[call-arg]
            )

    def test_rejects_malformed_timestamp(self) -> None:
        with pytest.raises(ValidationError):
            NonceResponse(
                platform_account_id="acct_abc",
                username_hash=VALID_HEX32,
                email_hash=VALID_HEX32,
                nonce="nonce",
                issued_at="2026-05-20 00:00:00Z",  # space instead of T
                expires_at=VALID_EXPIRES,
            )


# ---------------------------------------------------------------------------
# IdentityVerifyPayload
# ---------------------------------------------------------------------------


class TestIdentityVerifyPayload:
    def test_constructs_with_valid_fields(self) -> None:
        p = IdentityVerifyPayload(**_verify_payload_kwargs())
        assert p.domain == "PROMETHEON_IDENTITY_VERIFY_V1"
        assert p.action == "verify_identity"
        assert p.role == Role.MINER

    def test_domain_locked_to_literal(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(domain="WRONG_DOMAIN"))

    def test_action_locked_to_literal(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(action="something_else"))

    def test_role_must_be_known(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(role="operator"))

    def test_chain_network_must_be_known(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(chain_network="mainnet"))

    def test_netuid_must_be_non_negative(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(netuid=-1))

    def test_hashes_must_be_canonical_hex(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(username_hash="abcd"))

    def test_timestamps_must_match_strict_profile(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(issued_at="2026-05-20T00:00:00.123Z"))

    def test_rejects_empty_platform_instance_id(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(platform_instance_id=""))

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifyPayload(**_verify_payload_kwargs(unexpected="field"))

    def test_is_immutable(self) -> None:
        p = IdentityVerifyPayload(**_verify_payload_kwargs())
        with pytest.raises(ValidationError):
            p.role = Role.VALIDATOR  # type: ignore[misc]

    def test_to_canonical_dict_emits_strings_for_enums(self) -> None:
        p = IdentityVerifyPayload(**_verify_payload_kwargs())
        d = p.to_canonical_dict()
        assert d["role"] == "miner"
        assert d["chain_network"] == "finney"
        assert isinstance(d["role"], str) and not isinstance(d["role"], Role)

    def test_to_signed_bytes_matches_manual_envelope(self) -> None:
        p = IdentityVerifyPayload(**_verify_payload_kwargs())
        manual = domain_prefixed_bytes(DOMAIN_IDENTITY_VERIFY, p.to_canonical_dict())
        assert p.to_signed_bytes() == manual

    def test_signed_bytes_change_when_field_changes(self) -> None:
        # Two payloads differing only in role must produce different signed
        # bytes — a sanity check that we are signing the whole envelope and
        # not a fixed string.
        p1 = IdentityVerifyPayload(**_verify_payload_kwargs(role=Role.MINER))
        p2 = IdentityVerifyPayload(**_verify_payload_kwargs(role=Role.VALIDATOR))
        assert p1.to_signed_bytes() != p2.to_signed_bytes()


# ---------------------------------------------------------------------------
# HotkeyRotationPayload
# ---------------------------------------------------------------------------


class TestHotkeyRotationPayload:
    def test_constructs_with_valid_fields(self) -> None:
        p = HotkeyRotationPayload(**_rotation_payload_kwargs())
        assert p.domain == "PROMETHEON_HOTKEY_ROTATION_V1"
        assert p.action == "rotate_hotkey"
        assert p.cooldown_days == 7  # locked

    def test_cooldown_days_cannot_be_changed(self) -> None:
        with pytest.raises(ValidationError):
            HotkeyRotationPayload(**_rotation_payload_kwargs(cooldown_days=14))

    def test_signed_bytes_under_rotation_domain(self) -> None:
        p = HotkeyRotationPayload(**_rotation_payload_kwargs())
        manual = domain_prefixed_bytes(DOMAIN_HOTKEY_ROTATION, p.to_canonical_dict())
        assert p.to_signed_bytes() == manual

    def test_old_and_new_hotkey_distinct_in_canonical_form(self) -> None:
        p = HotkeyRotationPayload(**_rotation_payload_kwargs())
        d = p.to_canonical_dict()
        assert d["old_hotkey_ss58"] != d["new_hotkey_ss58"]


# ---------------------------------------------------------------------------
# ColdkeyRecoveryPayload
# ---------------------------------------------------------------------------


class TestColdkeyRecoveryPayload:
    def test_constructs_with_valid_fields(self) -> None:
        p = ColdkeyRecoveryPayload(**_coldkey_recovery_kwargs())
        assert p.domain == "PROMETHEON_HOTKEY_RECOVERY_V1"
        assert p.recovery_method == "coldkey"
        assert p.pending_hours == 24
        assert p.recovery_cooldown_days == 14

    def test_recovery_method_locked_to_coldkey(self) -> None:
        with pytest.raises(ValidationError):
            ColdkeyRecoveryPayload(**_coldkey_recovery_kwargs(recovery_method="manual_2fa_ops"))

    def test_pending_hours_locked(self) -> None:
        with pytest.raises(ValidationError):
            ColdkeyRecoveryPayload(**_coldkey_recovery_kwargs(pending_hours=12))

    def test_cooldown_days_locked(self) -> None:
        with pytest.raises(ValidationError):
            ColdkeyRecoveryPayload(**_coldkey_recovery_kwargs(recovery_cooldown_days=7))

    def test_signed_bytes_under_recovery_domain(self) -> None:
        p = ColdkeyRecoveryPayload(**_coldkey_recovery_kwargs())
        manual = domain_prefixed_bytes(DOMAIN_HOTKEY_RECOVERY, p.to_canonical_dict())
        assert p.to_signed_bytes() == manual


# ---------------------------------------------------------------------------
# ManualRecoveryPayload
# ---------------------------------------------------------------------------


class TestManualRecoveryPayload:
    def test_constructs_with_valid_fields(self) -> None:
        p = ManualRecoveryPayload(**_manual_recovery_kwargs())
        assert p.recovery_method == "manual_2fa_ops"

    def test_recovery_method_locked_to_manual(self) -> None:
        with pytest.raises(ValidationError):
            ManualRecoveryPayload(**_manual_recovery_kwargs(recovery_method="coldkey"))

    def test_discord_handle_hash_must_be_canonical_hex(self) -> None:
        with pytest.raises(ValidationError):
            ManualRecoveryPayload(**_manual_recovery_kwargs(discord_handle_hash="not-hex"))

    def test_signed_bytes_under_recovery_domain(self) -> None:
        p = ManualRecoveryPayload(**_manual_recovery_kwargs())
        manual = domain_prefixed_bytes(DOMAIN_HOTKEY_RECOVERY, p.to_canonical_dict())
        assert p.to_signed_bytes() == manual

    def test_no_coldkey_field_present(self) -> None:
        # Manual recovery has no coldkey_ss58 — confirming the model rejects
        # it as an extra field.
        with pytest.raises(ValidationError):
            ManualRecoveryPayload(**_manual_recovery_kwargs(coldkey_ss58=VALID_SS58))

    def test_two_recovery_methods_under_same_domain_differ_in_signed_bytes(
        self,
    ) -> None:
        # Coldkey and manual recovery share the domain but differ in payload
        # shape; the signed bytes must therefore differ.
        coldkey = ColdkeyRecoveryPayload(**_coldkey_recovery_kwargs())
        manual = ManualRecoveryPayload(**_manual_recovery_kwargs())
        assert coldkey.to_signed_bytes() != manual.to_signed_bytes()
