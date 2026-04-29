"""Hotkey rotation envelope models and end-to-end verifier.

Normal hotkey rotation requires signatures from **both** the old and the
new hotkey over the same canonical payload. This module owns:

- :class:`HotkeyRotationSignatures` — the two-signature container.
- :class:`HotkeyRotationEnvelope` — the wire shape for
  ``POST /v1/prometheon/identity/rotate-hotkey``.
- :func:`verify_rotation_envelope` — the full pipeline that mirrors the
  Platform-side checks for a rotation request.

Cooldown enforcement (7 days per role on the Platform account) is a
Platform-side concern; the subnet code surfaces it via a corresponding
``platform.errors.RotationCooldownActiveError`` when the Platform returns
that status, but this module does not duplicate the cooldown logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from prometheon.identity.errors import IdentityPayloadValidationError
from prometheon.identity.payloads import HotkeyRotationPayload
from prometheon.identity.roles import ChainNetwork
from prometheon.identity.verifier import (
    ClientInfo,
    assert_domain_match,
    assert_environment_match,
    assert_payload_within_expiry,
    now_utc,
)
from prometheon.security.canonical import DOMAIN_HOTKEY_ROTATION
from prometheon.security.signatures import verify_bittensor_signature


class HotkeyRotationSignatures(BaseModel):
    """Signature pair carried in a hotkey-rotation envelope.

    Both the old hotkey and the new hotkey sign the same canonical bytes;
    both signatures must verify for the rotation to be accepted.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    old_hotkey: str = Field(pattern=r"^0x[0-9a-f]{128}$")
    new_hotkey: str = Field(pattern=r"^0x[0-9a-f]{128}$")


class HotkeyRotationEnvelope(BaseModel):
    """Wire envelope for ``POST /v1/prometheon/identity/rotate-hotkey``."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    payload: HotkeyRotationPayload
    signatures: HotkeyRotationSignatures
    client: ClientInfo


def verify_rotation_envelope(
    envelope: HotkeyRotationEnvelope,
    *,
    expected_chain_network: ChainNetwork,
    expected_platform_instance_id: str,
    expected_api_token_hash: str,
    now: datetime | None = None,
) -> None:
    """Run every check the Platform performs on a hotkey-rotation envelope.

    Order of operations:

    1. Domain binding (``domain`` matches ``PROMETHEON_HOTKEY_ROTATION_V1``).
    2. Environment binding (``chain_network`` and ``platform_instance_id``).
    3. API-token binding.
    4. Validity window.
    5. SR25519 signature verification — **both** old and new hotkey
       signatures must verify against the canonical payload.

    The function returns ``None`` on success; on failure it raises the
    most specific exception that applies. Callers should catch
    :class:`prometheon.identity.errors.IdentityError` (or its specific
    subclass) and :class:`prometheon.security.signatures.SignatureError`.
    """
    payload = envelope.payload
    current_time = now if now is not None else now_utc()
    canonical = payload.to_canonical_dict()

    assert_domain_match(payload, expected_domain=DOMAIN_HOTKEY_ROTATION)
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

    # Both signatures cover the SAME canonical bytes. Verify each in turn;
    # either failure aborts the rotation.
    verify_bittensor_signature(
        ss58_address=payload.old_hotkey_ss58,
        signature_hex=envelope.signatures.old_hotkey,
        domain=DOMAIN_HOTKEY_ROTATION,
        payload=canonical,
    )
    verify_bittensor_signature(
        ss58_address=payload.new_hotkey_ss58,
        signature_hex=envelope.signatures.new_hotkey,
        domain=DOMAIN_HOTKEY_ROTATION,
        payload=canonical,
    )


__all__ = [
    "HotkeyRotationEnvelope",
    "HotkeyRotationSignatures",
    "verify_rotation_envelope",
]
