"""Unit tests for ``prometheon.identity.verifier``.

Covers:

- ``ClientInfo`` and envelope structural validation.
- Shared helpers: domain match, environment match, expiry window.
- The full identity-verify pipeline, asserting both success and every
  specific failure path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from bittensor_wallet import Keypair
from pydantic import ValidationError

from prometheon.identity.errors import (
    EnvironmentMismatchError,
    IdentityDomainMismatchError,
    IdentityPayloadValidationError,
    PayloadExpiredError,
    PayloadNotYetValidError,
)
from prometheon.identity.payloads import IdentityVerifyPayload
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.identity.verifier import (
    ClientInfo,
    IdentityVerifyEnvelope,
    IdentityVerifySignatures,
    assert_domain_match,
    assert_environment_match,
    assert_payload_within_expiry,
    verify_identity_envelope,
)
from prometheon.security.canonical import DOMAIN_HOTKEY_ROTATION, DOMAIN_IDENTITY_VERIFY
from prometheon.security.signatures import (
    SignatureVerificationError,
    sign_with_bittensor_keypair,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


VALID_HEX32 = "0x" + "cd" * 32
EXPECTED_INSTANCE = "bitfan-production"
EXPECTED_NETWORK = ChainNetwork.FINNEY


@pytest.fixture
def alice_keypair() -> Keypair:
    return Keypair.create_from_uri("//Alice")


def _build_signed_envelope(
    keypair: Keypair,
    *,
    chain_network: ChainNetwork = EXPECTED_NETWORK,
    platform_instance_id: str = EXPECTED_INSTANCE,
    api_token_hash: str = VALID_HEX32,
    issued_at: str = "2026-05-20T00:00:00Z",
    expires_at: str = "2026-05-20T00:10:00Z",
) -> tuple[IdentityVerifyEnvelope, IdentityVerifyPayload]:
    """Construct a fully-signed envelope using a real SR25519 keypair."""
    payload = IdentityVerifyPayload(
        role=Role.MINER,
        chain_network=chain_network,
        platform_instance_id=platform_instance_id,
        netuid=123,
        platform_account_id="acct_abc",
        username_hash=VALID_HEX32,
        email_hash=VALID_HEX32,
        hotkey_ss58=keypair.ss58_address,
        nonce="nonce_abc_123",
        issued_at=issued_at,
        expires_at=expires_at,
        api_token_hash=api_token_hash,
    )
    sig_hex = sign_with_bittensor_keypair(
        keypair, DOMAIN_IDENTITY_VERIFY, payload.to_canonical_dict()
    )
    envelope = IdentityVerifyEnvelope(
        payload=payload,
        signatures=IdentityVerifySignatures(hotkey=sig_hex),
        client=ClientInfo(name="prometheon-cli", version="0.1.0"),
    )
    return envelope, payload


def _at(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# ClientInfo
# ---------------------------------------------------------------------------


class TestClientInfo:
    def test_constructs_with_name_and_version(self) -> None:
        ci = ClientInfo(name="prometheon-cli", version="0.1.0")
        assert ci.name == "prometheon-cli"
        assert ci.version == "0.1.0"

    def test_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            ClientInfo(name="", version="0.1.0")

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            ClientInfo(name="cli", version="0.1.0", platform="linux")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# IdentityVerifySignatures
# ---------------------------------------------------------------------------


class TestIdentityVerifySignatures:
    def test_rejects_uppercase_hex(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifySignatures(hotkey="0x" + "AB" * 64)

    def test_rejects_short_signature(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifySignatures(hotkey="0x" + "00" * 63)

    def test_rejects_extra_signature_field(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerifySignatures(  # type: ignore[call-arg]
                hotkey="0x" + "00" * 64, coldkey="0x" + "00" * 64
            )


# ---------------------------------------------------------------------------
# assert_domain_match
# ---------------------------------------------------------------------------


class TestAssertDomainMatch:
    def test_accepts_matching_domain(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(alice_keypair)
        assert_domain_match(payload, expected_domain=DOMAIN_IDENTITY_VERIFY)

    def test_rejects_wrong_expected_domain(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(alice_keypair)
        with pytest.raises(IdentityDomainMismatchError):
            assert_domain_match(payload, expected_domain=DOMAIN_HOTKEY_ROTATION)


# ---------------------------------------------------------------------------
# assert_environment_match
# ---------------------------------------------------------------------------


class TestAssertEnvironmentMatch:
    def test_accepts_matching_pair(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(alice_keypair)
        assert_environment_match(
            payload,
            expected_chain_network=EXPECTED_NETWORK,
            expected_platform_instance_id=EXPECTED_INSTANCE,
        )

    def test_rejects_chain_network_mismatch(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(alice_keypair, chain_network=ChainNetwork.TEST)
        with pytest.raises(EnvironmentMismatchError, match="chain_network mismatch"):
            assert_environment_match(
                payload,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
            )

    def test_rejects_platform_instance_mismatch(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(alice_keypair, platform_instance_id="bitfan-staging")
        with pytest.raises(EnvironmentMismatchError, match="platform_instance_id mismatch"):
            assert_environment_match(
                payload,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
            )


# ---------------------------------------------------------------------------
# assert_payload_within_expiry
# ---------------------------------------------------------------------------


class TestAssertPayloadWithinExpiry:
    def test_accepts_payload_inside_window(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(
            alice_keypair,
            issued_at="2026-05-20T00:00:00Z",
            expires_at="2026-05-20T00:10:00Z",
        )
        # now is between issued_at and expires_at
        assert_payload_within_expiry(payload, now=_at("2026-05-20T00:05:00Z"))

    def test_rejects_expired_payload(self, alice_keypair: Keypair) -> None:
        _, payload = _build_signed_envelope(
            alice_keypair,
            issued_at="2026-05-20T00:00:00Z",
            expires_at="2026-05-20T00:10:00Z",
        )
        with pytest.raises(PayloadExpiredError):
            assert_payload_within_expiry(payload, now=_at("2026-05-20T00:11:00Z"))

    def test_rejects_payload_too_far_in_future(self, alice_keypair: Keypair) -> None:
        # issued_at = 12:00, expires_at = 12:10. now = 11:50 → 600 seconds
        # before issued_at, well beyond the 300-second skew window.
        _, payload = _build_signed_envelope(
            alice_keypair,
            issued_at="2026-05-20T12:00:00Z",
            expires_at="2026-05-20T12:10:00Z",
        )
        with pytest.raises(PayloadNotYetValidError):
            assert_payload_within_expiry(payload, now=_at("2026-05-20T11:50:00Z"))

    def test_within_skew_window_is_accepted(self, alice_keypair: Keypair) -> None:
        # issued_at = 12:00, now = 11:58 → 120 seconds drift, within the
        # 300-second skew tolerance.
        _, payload = _build_signed_envelope(
            alice_keypair,
            issued_at="2026-05-20T12:00:00Z",
            expires_at="2026-05-20T12:10:00Z",
        )
        # We test by ensuring this does not raise.
        assert_payload_within_expiry(payload, now=_at("2026-05-20T11:58:00Z"))


# ---------------------------------------------------------------------------
# verify_identity_envelope — end-to-end
# ---------------------------------------------------------------------------


class TestVerifyIdentityEnvelope:
    def test_valid_envelope_verifies(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        verify_identity_envelope(
            envelope,
            expected_chain_network=EXPECTED_NETWORK,
            expected_platform_instance_id=EXPECTED_INSTANCE,
            expected_api_token_hash=VALID_HEX32,
            now=_at("2026-05-20T00:05:00Z"),
        )

    def test_chain_network_mismatch_rejected(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        with pytest.raises(EnvironmentMismatchError):
            verify_identity_envelope(
                envelope,
                expected_chain_network=ChainNetwork.TEST,  # wrong
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_platform_instance_mismatch_rejected(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        with pytest.raises(EnvironmentMismatchError):
            verify_identity_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id="bitfan-staging",
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_api_token_hash_mismatch_rejected(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        with pytest.raises(IdentityPayloadValidationError, match="api_token_hash"):
            verify_identity_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash="0x" + "ff" * 32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_expired_payload_rejected(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        with pytest.raises(PayloadExpiredError):
            verify_identity_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T01:00:00Z"),
            )

    def test_tampered_signature_rejected(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        # Construct a new envelope reusing every field except for a
        # corrupted hotkey signature. Flip the last hex character to keep
        # the length and lowercase-hex shape valid but invalidate the
        # signature crypto.
        original_sig = envelope.signatures.hotkey
        flipped_last = "f" if original_sig[-1] != "f" else "e"
        bad_sig = original_sig[:-1] + flipped_last
        tampered = IdentityVerifyEnvelope(
            payload=envelope.payload,
            signatures=IdentityVerifySignatures(hotkey=bad_sig),
            client=envelope.client,
        )
        with pytest.raises(SignatureVerificationError):
            verify_identity_envelope(
                tampered,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_uses_real_clock_when_now_not_supplied(self, alice_keypair: Keypair) -> None:
        # Build an envelope that is clearly outside any plausible "now"
        # window so the verification fails with PayloadExpiredError. This
        # exercises the default-clock path without relying on a frozen
        # time.
        now_real = datetime.now(timezone.utc)
        long_ago_issued = (now_real - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        long_ago_expires = (now_real - timedelta(hours=23)).strftime("%Y-%m-%dT%H:%M:%SZ")
        envelope, _ = _build_signed_envelope(
            alice_keypair,
            issued_at=long_ago_issued,
            expires_at=long_ago_expires,
        )
        with pytest.raises(PayloadExpiredError):
            verify_identity_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
            )


# ---------------------------------------------------------------------------
# Envelope structural validation
# ---------------------------------------------------------------------------


class TestEnvelopeStructure:
    def test_rejects_envelope_missing_signatures(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        # Reconstruct the envelope dict without the signatures block.
        raw: dict[str, Any] = envelope.model_dump(mode="json")
        raw.pop("signatures")
        with pytest.raises(ValidationError):
            IdentityVerifyEnvelope.model_validate(raw)

    def test_rejects_envelope_with_extra_top_level_field(self, alice_keypair: Keypair) -> None:
        envelope, _ = _build_signed_envelope(alice_keypair)
        raw: dict[str, Any] = envelope.model_dump(mode="json")
        raw["unexpected"] = "field"
        with pytest.raises(ValidationError):
            IdentityVerifyEnvelope.model_validate(raw)
