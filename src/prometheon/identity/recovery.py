"""Hotkey recovery envelope models and end-to-end verifiers.

Two recovery flows live in this module, both sharing the
``PROMETHEON_HOTKEY_RECOVERY_V1`` domain:

- **Coldkey recovery** — used when the old hotkey is unavailable but the
  coldkey is. The coldkey and the new hotkey both sign the canonical
  payload.
- **Manual (2FA + Ops) recovery** — used when neither the old hotkey nor
  the coldkey is available. Only the new hotkey signs. Proof of identity
  comes from the Platform's 2FA flow plus Ops Console approval; the
  signed payload alone is *not* sufficient to authorize activation.

Both flows enter a 24-hour pending period on the Platform side after
acceptance and start a 14-day recovery cooldown after activation. Those
state transitions are tracked by the Platform; this module only verifies
the cryptographic and structural correctness of the envelope.
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from prometheon.identity.errors import IdentityPayloadValidationError
from prometheon.identity.payloads import (
    ColdkeyRecoveryPayload,
    ManualRecoveryPayload,
)
from prometheon.identity.roles import ChainNetwork
from prometheon.identity.verifier import (
    ClientInfo,
    assert_domain_match,
    assert_environment_match,
    assert_payload_within_expiry,
    now_utc,
)
from prometheon.security.canonical import DOMAIN_HOTKEY_RECOVERY
from prometheon.security.signatures import verify_bittensor_signature

# ---------------------------------------------------------------------------
# Coldkey recovery
# ---------------------------------------------------------------------------


class ColdkeyRecoverySignatures(BaseModel):
    """Signature pair for coldkey-backed recovery.

    The coldkey proves ownership of the historical hotkey-coldkey
    association (verified by the Platform via chain state or a previously
    captured ownership record); the new hotkey proves control of the
    rotation target.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    coldkey: str = Field(pattern=r"^0x[0-9a-f]{128}$")
    new_hotkey: str = Field(pattern=r"^0x[0-9a-f]{128}$")


class ColdkeyRecoveryEnvelope(BaseModel):
    """Wire envelope for coldkey recovery requests."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    payload: ColdkeyRecoveryPayload
    signatures: ColdkeyRecoverySignatures
    client: ClientInfo


def verify_coldkey_recovery_envelope(
    envelope: ColdkeyRecoveryEnvelope,
    *,
    expected_chain_network: ChainNetwork,
    expected_platform_instance_id: str,
    expected_api_token_hash: str,
    now: datetime | None = None,
) -> None:
    """Run every cryptographic check the Platform performs on a coldkey
    recovery envelope.

    The Platform performs additional non-cryptographic checks that this
    module deliberately does **not** duplicate: matching the coldkey to a
    historical hotkey-coldkey ownership record, enforcing the 14-day
    recovery cooldown, and creating the 24-hour pending recovery state.

    Order of operations:

    1. Domain binding.
    2. Environment binding.
    3. API-token binding.
    4. Validity window.
    5. Coldkey signature verifies against the canonical payload.
    6. New hotkey signature verifies against the canonical payload.
    """
    payload = envelope.payload
    current_time = now if now is not None else now_utc()
    canonical = payload.to_canonical_dict()

    assert_domain_match(payload, expected_domain=DOMAIN_HOTKEY_RECOVERY)
    assert_environment_match(
        payload,
        expected_chain_network=expected_chain_network,
        expected_platform_instance_id=expected_platform_instance_id,
    )
    if payload.api_token_hash != expected_api_token_hash:
        raise IdentityPayloadValidationError(
            "api_token_hash in payload does not match the presented API token"
        )
    assert_payload_within_expiry(payload, now=current_time)

    verify_bittensor_signature(
        ss58_address=payload.coldkey_ss58,
        signature_hex=envelope.signatures.coldkey,
        domain=DOMAIN_HOTKEY_RECOVERY,
        payload=canonical,
    )
    verify_bittensor_signature(
        ss58_address=payload.new_hotkey_ss58,
        signature_hex=envelope.signatures.new_hotkey,
        domain=DOMAIN_HOTKEY_RECOVERY,
        payload=canonical,
    )


# ---------------------------------------------------------------------------
# Manual (2FA + Ops) recovery
# ---------------------------------------------------------------------------


class ManualRecoverySignatures(BaseModel):
    """Single-signature container for manual (2FA + Ops) recovery.

    Only the new hotkey signs. The flow is deliberately *not* a
    cryptographic proof of old key ownership — it is a Platform-mediated
    administrative recovery gated by 2FA, Discord handle review, and
    Ops Console approval. The new hotkey signature simply proves that
    whoever requested the recovery actually controls the destination key.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    new_hotkey: str = Field(pattern=r"^0x[0-9a-f]{128}$")


class ManualRecoveryEnvelope(BaseModel):
    """Wire envelope for manual recovery requests."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    payload: ManualRecoveryPayload
    signatures: ManualRecoverySignatures
    client: ClientInfo


def verify_manual_recovery_envelope(
    envelope: ManualRecoveryEnvelope,
    *,
    expected_chain_network: ChainNetwork,
    expected_platform_instance_id: str,
    expected_api_token_hash: str,
    now: datetime | None = None,
) -> None:
    """Run every cryptographic check on a manual recovery envelope.

    The Platform additionally verifies 2FA, the Discord handle, Ops
    approval, and the 14-day cooldown — those checks are out of scope
    here. This module is responsible for envelope correctness only.

    Order of operations:

    1. Domain binding.
    2. Environment binding.
    3. API-token binding.
    4. Validity window.
    5. New hotkey signature verifies against the canonical payload.
    """
    payload = envelope.payload
    current_time = now if now is not None else now_utc()
    canonical = payload.to_canonical_dict()

    assert_domain_match(payload, expected_domain=DOMAIN_HOTKEY_RECOVERY)
    assert_environment_match(
        payload,
        expected_chain_network=expected_chain_network,
        expected_platform_instance_id=expected_platform_instance_id,
    )
    if payload.api_token_hash != expected_api_token_hash:
        raise IdentityPayloadValidationError(
            "api_token_hash in payload does not match the presented API token"
        )
    assert_payload_within_expiry(payload, now=current_time)

    verify_bittensor_signature(
        ss58_address=payload.new_hotkey_ss58,
        signature_hex=envelope.signatures.new_hotkey,
        domain=DOMAIN_HOTKEY_RECOVERY,
        payload=canonical,
    )


__all__ = [
    "ColdkeyRecoveryEnvelope",
    "ColdkeyRecoverySignatures",
    "ManualRecoveryEnvelope",
    "ManualRecoverySignatures",
    "verify_coldkey_recovery_envelope",
    "verify_manual_recovery_envelope",
]
