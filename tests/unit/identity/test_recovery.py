"""Unit tests for ``prometheon.identity.recovery``.

Covers both flows (coldkey and manual) through the full verifier
pipeline, including the rejection paths every Platform check is
expected to catch.
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
from prometheon.identity.payloads import (
    ColdkeyRecoveryPayload,
    ManualRecoveryPayload,
)
from prometheon.identity.recovery import (
    ColdkeyRecoveryEnvelope,
    ColdkeyRecoverySignatures,
    ManualRecoveryEnvelope,
    ManualRecoverySignatures,
    verify_coldkey_recovery_envelope,
    verify_manual_recovery_envelope,
)
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.identity.verifier import ClientInfo
from prometheon.security.canonical import DOMAIN_HOTKEY_RECOVERY
from prometheon.security.signatures import (
    SignatureVerificationError,
    sign_with_bittensor_keypair,
)

pytestmark = pytest.mark.unit


VALID_HEX32 = "0x" + "12" * 32
EXPECTED_INSTANCE = "bitfan-production"
EXPECTED_NETWORK = ChainNetwork.FINNEY


@pytest.fixture
def old_keypair() -> Keypair:
    return Keypair.create_from_uri("//Alice")


@pytest.fixture
def coldkey_keypair() -> Keypair:
    return Keypair.create_from_uri("//Bob")


@pytest.fixture
def new_keypair() -> Keypair:
    return Keypair.create_from_uri("//Charlie")


@pytest.fixture
def other_keypair() -> Keypair:
    return Keypair.create_from_uri("//Dave")


def _at(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Coldkey recovery
# ---------------------------------------------------------------------------


def _build_coldkey_envelope(
    *,
    old_keypair: Keypair,
    coldkey_keypair: Keypair,
    new_keypair: Keypair,
    chain_network: ChainNetwork = EXPECTED_NETWORK,
    platform_instance_id: str = EXPECTED_INSTANCE,
    api_token_hash: str = VALID_HEX32,
    issued_at: str = "2026-05-20T00:00:00Z",
    expires_at: str = "2026-05-20T00:10:00Z",
) -> ColdkeyRecoveryEnvelope:
    payload = ColdkeyRecoveryPayload(
        role=Role.MINER,
        chain_network=chain_network,
        platform_instance_id=platform_instance_id,
        netuid=123,
        platform_account_id="acct_abc",
        old_hotkey_ss58=old_keypair.ss58_address,
        coldkey_ss58=coldkey_keypair.ss58_address,
        new_hotkey_ss58=new_keypair.ss58_address,
        nonce="nonce_abc_123",
        issued_at=issued_at,
        expires_at=expires_at,
        api_token_hash=api_token_hash,
    )
    canonical = payload.to_canonical_dict()
    coldkey_sig = sign_with_bittensor_keypair(coldkey_keypair, DOMAIN_HOTKEY_RECOVERY, canonical)
    new_sig = sign_with_bittensor_keypair(new_keypair, DOMAIN_HOTKEY_RECOVERY, canonical)
    return ColdkeyRecoveryEnvelope(
        payload=payload,
        signatures=ColdkeyRecoverySignatures(coldkey=coldkey_sig, new_hotkey=new_sig),
        client=ClientInfo(name="prometheon-cli", version="0.1.0"),
    )


class TestColdkeyRecoverySignatures:
    def test_rejects_missing_new_hotkey(self) -> None:
        with pytest.raises(ValidationError):
            ColdkeyRecoverySignatures(coldkey="0x" + "00" * 64)  # type: ignore[call-arg]

    def test_rejects_extra_signature_field(self) -> None:
        with pytest.raises(ValidationError):
            ColdkeyRecoverySignatures(  # type: ignore[call-arg]
                coldkey="0x" + "00" * 64,
                new_hotkey="0x" + "00" * 64,
                hotkey="0x" + "00" * 64,
            )


class TestVerifyColdkeyRecovery:
    def test_valid_envelope_verifies(
        self,
        old_keypair: Keypair,
        coldkey_keypair: Keypair,
        new_keypair: Keypair,
    ) -> None:
        envelope = _build_coldkey_envelope(
            old_keypair=old_keypair,
            coldkey_keypair=coldkey_keypair,
            new_keypair=new_keypair,
        )
        verify_coldkey_recovery_envelope(
            envelope,
            expected_chain_network=EXPECTED_NETWORK,
            expected_platform_instance_id=EXPECTED_INSTANCE,
            expected_api_token_hash=VALID_HEX32,
            now=_at("2026-05-20T00:05:00Z"),
        )

    def test_chain_network_mismatch_rejected(
        self,
        old_keypair: Keypair,
        coldkey_keypair: Keypair,
        new_keypair: Keypair,
    ) -> None:
        envelope = _build_coldkey_envelope(
            old_keypair=old_keypair,
            coldkey_keypair=coldkey_keypair,
            new_keypair=new_keypair,
            chain_network=ChainNetwork.TEST,
        )
        with pytest.raises(EnvironmentMismatchError):
            verify_coldkey_recovery_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_expired_payload_rejected(
        self,
        old_keypair: Keypair,
        coldkey_keypair: Keypair,
        new_keypair: Keypair,
    ) -> None:
        envelope = _build_coldkey_envelope(
            old_keypair=old_keypair,
            coldkey_keypair=coldkey_keypair,
            new_keypair=new_keypair,
        )
        with pytest.raises(PayloadExpiredError):
            verify_coldkey_recovery_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T01:00:00Z"),
            )

    def test_wrong_coldkey_signature_rejected(
        self,
        old_keypair: Keypair,
        coldkey_keypair: Keypair,
        new_keypair: Keypair,
        other_keypair: Keypair,
    ) -> None:
        good = _build_coldkey_envelope(
            old_keypair=old_keypair,
            coldkey_keypair=coldkey_keypair,
            new_keypair=new_keypair,
        )
        wrong_coldkey_sig = sign_with_bittensor_keypair(
            other_keypair, DOMAIN_HOTKEY_RECOVERY, good.payload.to_canonical_dict()
        )
        tampered = ColdkeyRecoveryEnvelope(
            payload=good.payload,
            signatures=ColdkeyRecoverySignatures(
                coldkey=wrong_coldkey_sig,
                new_hotkey=good.signatures.new_hotkey,
            ),
            client=good.client,
        )
        with pytest.raises(SignatureVerificationError):
            verify_coldkey_recovery_envelope(
                tampered,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )


# ---------------------------------------------------------------------------
# Manual recovery
# ---------------------------------------------------------------------------


def _build_manual_envelope(
    *,
    old_keypair: Keypair,
    new_keypair: Keypair,
    chain_network: ChainNetwork = EXPECTED_NETWORK,
    platform_instance_id: str = EXPECTED_INSTANCE,
    api_token_hash: str = VALID_HEX32,
    issued_at: str = "2026-05-20T00:00:00Z",
    expires_at: str = "2026-05-20T00:10:00Z",
) -> ManualRecoveryEnvelope:
    payload = ManualRecoveryPayload(
        role=Role.MINER,
        chain_network=chain_network,
        platform_instance_id=platform_instance_id,
        netuid=123,
        platform_account_id="acct_abc",
        old_hotkey_ss58=old_keypair.ss58_address,
        new_hotkey_ss58=new_keypair.ss58_address,
        discord_handle_hash=VALID_HEX32,
        nonce="nonce_abc_123",
        issued_at=issued_at,
        expires_at=expires_at,
        api_token_hash=api_token_hash,
    )
    canonical = payload.to_canonical_dict()
    new_sig = sign_with_bittensor_keypair(new_keypair, DOMAIN_HOTKEY_RECOVERY, canonical)
    return ManualRecoveryEnvelope(
        payload=payload,
        signatures=ManualRecoverySignatures(new_hotkey=new_sig),
        client=ClientInfo(name="prometheon-cli", version="0.1.0"),
    )


class TestManualRecoverySignatures:
    def test_rejects_extra_signature_field(self) -> None:
        with pytest.raises(ValidationError):
            ManualRecoverySignatures(  # type: ignore[call-arg]
                new_hotkey="0x" + "00" * 64,
                coldkey="0x" + "00" * 64,
            )


class TestVerifyManualRecovery:
    def test_valid_envelope_verifies(self, old_keypair: Keypair, new_keypair: Keypair) -> None:
        envelope = _build_manual_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        verify_manual_recovery_envelope(
            envelope,
            expected_chain_network=EXPECTED_NETWORK,
            expected_platform_instance_id=EXPECTED_INSTANCE,
            expected_api_token_hash=VALID_HEX32,
            now=_at("2026-05-20T00:05:00Z"),
        )

    def test_api_token_mismatch_rejected(self, old_keypair: Keypair, new_keypair: Keypair) -> None:
        envelope = _build_manual_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        with pytest.raises(IdentityPayloadValidationError):
            verify_manual_recovery_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash="0x" + "aa" * 32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_wrong_new_hotkey_signature_rejected(
        self,
        old_keypair: Keypair,
        new_keypair: Keypair,
        other_keypair: Keypair,
    ) -> None:
        good = _build_manual_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        wrong_sig = sign_with_bittensor_keypair(
            other_keypair, DOMAIN_HOTKEY_RECOVERY, good.payload.to_canonical_dict()
        )
        tampered = ManualRecoveryEnvelope(
            payload=good.payload,
            signatures=ManualRecoverySignatures(new_hotkey=wrong_sig),
            client=good.client,
        )
        with pytest.raises(SignatureVerificationError):
            verify_manual_recovery_envelope(
                tampered,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T00:05:00Z"),
            )

    def test_expired_payload_rejected(self, old_keypair: Keypair, new_keypair: Keypair) -> None:
        envelope = _build_manual_envelope(old_keypair=old_keypair, new_keypair=new_keypair)
        with pytest.raises(PayloadExpiredError):
            verify_manual_recovery_envelope(
                envelope,
                expected_chain_network=EXPECTED_NETWORK,
                expected_platform_instance_id=EXPECTED_INSTANCE,
                expected_api_token_hash=VALID_HEX32,
                now=_at("2026-05-20T01:00:00Z"),
            )
