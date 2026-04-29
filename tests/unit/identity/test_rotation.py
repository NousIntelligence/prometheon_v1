"""Unit tests for ``prometheon.identity.rotation``.

Exercises the two-signature rotation envelope: both old and new hotkey
must sign the same canonical bytes, and verification fails if either
signature is missing, modified, or comes from the wrong key.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from bittensor_wallet import Keypair
from pydantic import ValidationError

from prometheon.identity.errors import (
    EnvironmentMismatchError,
    IdentityPayloadValidationError,
    PayloadExpiredError,
)
from prometheon.identity.payloads import HotkeyRotationPayload
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.identity.rotation import (
    HotkeyRotationEnvelope,
    HotkeyRotationSignatures,
    verify_rotation_envelope,
)
from prometheon.identity.verifier import ClientInfo
from prometheon.security.canonical import DOMAIN_HOTKEY_ROTATION
from prometheon.security.signatures import (
    SignatureVerificationError,
    sign_with_bittensor_keypair,
)

pytestmark = pytest.mark.unit


VALID_HEX32 = "0x" + "ef" * 32
EXPECTED_INSTANCE = "bitfan-production"
EXPECTED_NETWORK = ChainNetwork.FINNEY


@pytest.fixture
def old_keypair() -> Keypair:
    return Keypair.create_from_uri("//Alice")


@pytest.fixture
def new_keypair() -> Keypair:
    return Keypair.create_from_uri("//Bob")


@pytest.fixture
def other_keypair() -> Keypair:
    return Keypair.create_from_uri("//Charlie")


def _build_rotation_envelope(
    *,
    old_keypair: Keypair,
    new_keypair: Keypair,
    chain_network: ChainNetwork = EXPECTED_NETWORK,
    platform_instance_id: str = EXPECTED_INSTANCE,
    api_token_hash: str = VALID_HEX32,
    issued_at: str = "2026-05-20T00:00:00Z",
    expires_at: str = "2026-05-20T00:10:00Z",
) -> HotkeyRotationEnvelope:
    payload = HotkeyRotationPayload(
        role=Role.MINER,
        chain_network=chain_network,
        platform_instance_id=platform_instance_id,
        netuid=123,
        platform_account_id="acct_abc",
        old_hotkey_ss58=old_keypair.ss58_address,
        new_hotkey_ss58=new_keypair.ss58_address,
        nonce="nonce_abc_123",
        issued_at=issued_at,
        expires_at=expires_at,
        api_token_hash=api_token_hash,
    )
    canonical = payload.to_canonical_dict()
    old_sig = sign_with_bittensor_keypair(old_keypair, DOMAIN_HOTKEY_ROTATION, canonical)
    new_sig = sign_with_bittensor_keypair(new_keypair, DOMAIN_HOTKEY_ROTATION, canonical)
    return HotkeyRotationEnvelope(
        payload=payload,
        signatures=HotkeyRotationSignatures(old_hotkey=old_sig, new_hotkey=new_sig),
        client=ClientInfo(name="prometheon-cli", version="0.1.0"),
    )


def _at(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# HotkeyRotationSignatures
# ---------------------------------------------------------------------------


class TestHotkeyRotationSignatures:
    def test_rejects_missing_new_hotkey(self) -> None:
        with pytest.raises(ValidationError):
            HotkeyRotationSignatures(old_hotkey="0x" + "00" * 64)  # type: ignore[call-arg]

    def test_rejects_missing_old_hotkey(self) -> None:
        with pytest.raises(ValidationError):
            HotkeyRotationSignatures(new_hotkey="0x" + "00" * 64)  # type: ignore[call-arg]

    def test_rejects_extra_signature_field(self) -> None:
        with pytest.raises(ValidationError):
            HotkeyRotationSignatures(  # type: ignore[call-arg]
                old_hotkey="0x" + "00" * 64,
                new_hotkey="0x" + "00" * 64,
                coldkey="0x" + "00" * 64,
            )


# ---------------------------------------------------------------------------
# verify_rotation_envelope
# ---------------------------------------------------------------------------


class TestVerifyRotationEnvelope:
    def test_valid_two_signature_envelope_verifies(
        self, old_keypair: Keypair, new_keypair: Keypair
    ) -> None:
        envelope = _build_rotation_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        verify_rotation_envelope(
            envelope,
            expected_chain_network=EXPECTED_NETWORK,
            expected_platform_instance_id=EXPECTED_INSTANCE,
            expected_api_token_hash=VALID_HEX32,
            now=_at("2026-05-20T00:05:00Z"),
        )

    def test_chain_network_mismatch_rejected(
        self, old_keypair: Keypair, new_keypair: Keypair
    ) -> None:
        envelope = _build_rotation_envelope(
            old_keypair=old_keypair,
            new_keypair=new_keypair,
            chain_network=ChainNetwork.TEST,
        )
        with pytest.raises(EnvironmentMismatchError):
            verify_rotation_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_api_token_hash_mismatch_rejected(
        self, old_keypair: Keypair, new_keypair: Keypair
    ) -> None:
        envelope = _build_rotation_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        with pytest.raises(IdentityPayloadValidationError):
            verify_rotation_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash="0x" + "aa" * 32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_expired_payload_rejected(self, old_keypair: Keypair, new_keypair: Keypair) -> None:
        envelope = _build_rotation_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        with pytest.raises(PayloadExpiredError):
            verify_rotation_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T01:00:00Z"),
            )

    def test_old_hotkey_signature_signed_by_wrong_key_rejected(
        self,
        old_keypair: Keypair,
        new_keypair: Keypair,
        other_keypair: Keypair,
    ) -> None:
        # Build a valid envelope first to get a correct payload, then
        # rebuild it with the OLD signature produced by an unrelated key.
        good = _build_rotation_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        wrong_old_sig = sign_with_bittensor_keypair(
            other_keypair, DOMAIN_HOTKEY_ROTATION, good.payload.to_canonical_dict()
        )
        tampered = HotkeyRotationEnvelope(
            payload=good.payload,
            signatures=HotkeyRotationSignatures(
                old_hotkey=wrong_old_sig,
                new_hotkey=good.signatures.new_hotkey,
            ),
            client=good.client,
        )
        with pytest.raises(SignatureVerificationError):
            verify_rotation_envelope(
                tampered,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_new_hotkey_signature_signed_by_wrong_key_rejected(
        self,
        old_keypair: Keypair,
        new_keypair: Keypair,
        other_keypair: Keypair,
    ) -> None:
        good = _build_rotation_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        wrong_new_sig = sign_with_bittensor_keypair(
            other_keypair, DOMAIN_HOTKEY_ROTATION, good.payload.to_canonical_dict()
        )
        tampered = HotkeyRotationEnvelope(
            payload=good.payload,
            signatures=HotkeyRotationSignatures(
                old_hotkey=good.signatures.old_hotkey,
                new_hotkey=wrong_new_sig,
            ),
            client=good.client,
        )
        with pytest.raises(SignatureVerificationError):
            verify_rotation_envelope(
                tampered,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_swapping_old_and_new_signatures_is_rejected(
        self, old_keypair: Keypair, new_keypair: Keypair
    ) -> None:
        # An attacker who manages to flip the two signature slots in the
        # envelope cannot succeed: the old signature won't verify against
        # the new SS58, and the new signature won't verify against the old
        # SS58.
        good = _build_rotation_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        swapped = HotkeyRotationEnvelope(
            payload=good.payload,
            signatures=HotkeyRotationSignatures(
                old_hotkey=good.signatures.new_hotkey,
                new_hotkey=good.signatures.old_hotkey,
            ),
            client=good.client,
        )
        with pytest.raises(SignatureVerificationError):
            verify_rotation_envelope(
                swapped,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )
