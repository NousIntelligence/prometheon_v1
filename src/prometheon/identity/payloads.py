"""Canonical identity payload models and signed-envelope helpers.

This module defines the Pydantic models for every canonical identity payload
in Phase 1:

- :class:`IdentityVerifyPayload`     — ``PROMETHEON_IDENTITY_VERIFY_V1``
- :class:`HotkeyRotationPayload`     — ``PROMETHEON_HOTKEY_ROTATION_V1``
- :class:`ColdkeyRecoveryPayload`    — ``PROMETHEON_HOTKEY_RECOVERY_V1`` (coldkey)
- :class:`ManualRecoveryPayload`     — ``PROMETHEON_HOTKEY_RECOVERY_V1`` (manual)

It also defines :class:`NonceResponse`, the parsed shape of the Platform's
``POST /v1/prometheon/identity/nonce`` reply. The hashes returned in that
response are signed verbatim by the CLI — neither the CLI nor the validator
re-normalize username or email locally, which removes the largest single
source of cross-implementation drift.

Every payload model has the same surface:

- It is immutable (``frozen=True``) and forbids extra fields.
- It validates every field at construction time with strict regexes and
  range checks.
- It exposes :meth:`to_canonical_dict` returning the dict that JCS will
  canonicalize.
- It exposes :meth:`to_signed_bytes` returning the exact byte sequence
  passed to the signer — ``ASCII(domain) + b"\\n" + JCS(payload_dict)``.

Field-level constraints are pinned by regex / range / Literal so that an
invalid input produces a precise validation error well before any signing
attempt.
"""

from __future__ import annotations

from typing import Any, ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from prometheon.identity.roles import ChainNetwork, Role
from prometheon.security.canonical import domain_prefixed_bytes

# ---------------------------------------------------------------------------
# Shared regex patterns
#
# Hex32: a SHA-256 digest in canonical 0x lowercase-hex form.
# ISO8601 UTC Z: the strict timestamp profile (no fractional seconds, no
#                offsets other than literal Z).
# SS58: loose check (base58 alphabet, 46-48 chars). Signature verification
#       performs the precise SS58 + crypto-type check, so this regex just
#       blocks obviously malformed addresses cheaply.
# ---------------------------------------------------------------------------

_HEX32_RE: Final[str] = r"^0x[0-9a-f]{64}$"
_ISO8601_UTC_Z_RE: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
_SS58_LOOSE_RE: Final[str] = r"^[1-9A-HJ-NP-Za-km-z]{46,48}$"


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class _PrometheonPayload(BaseModel):
    """Base class for every canonical identity payload.

    Subclasses declare their own fields plus a ``domain`` Literal default.
    The base provides the two serializer methods that every payload must
    expose, so callers never have to remember which canonical-domain
    constant matches which payload type.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=False,
    )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Return the dict that will be JCS-canonicalized for signing or hashing.

        Uses ``mode="json"`` so enum members are converted to their string
        values, matching the on-wire representation exactly.
        """
        return self.model_dump(mode="json")

    def to_signed_bytes(self) -> bytes:
        """Return the exact byte sequence to sign for this payload.

        The bytes are ``ASCII(domain) + b"\\n" + JCS(payload_dict)``. The
        ``domain`` value is taken from the payload itself (the ``domain``
        field on every payload subclass is declared as a Literal with the
        correct default, so subclassing a wrong-domain typo is a compile-
        time error).
        """
        payload_dict = self.to_canonical_dict()
        domain = payload_dict["domain"]
        return domain_prefixed_bytes(domain, payload_dict)


# ---------------------------------------------------------------------------
# NonceResponse — what the Platform returns from POST /identity/nonce
# ---------------------------------------------------------------------------


class NonceResponse(BaseModel):
    """The Platform's reply to ``POST /v1/prometheon/identity/nonce``.

    The Platform owns username and email canonicalization. It returns the
    canonical hashes in this response so the CLI can sign them verbatim.
    Re-normalizing on the CLI side is forbidden — the only correct
    behaviour is to embed these exact values into the canonical payload.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    platform_account_id: str = Field(min_length=1)
    username_hash: str = Field(pattern=_HEX32_RE)
    email_hash: str = Field(pattern=_HEX32_RE)
    nonce: str = Field(min_length=1)
    issued_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    expires_at: str = Field(pattern=_ISO8601_UTC_Z_RE)


# ---------------------------------------------------------------------------
# Identity verification — PROMETHEON_IDENTITY_VERIFY_V1
# ---------------------------------------------------------------------------


class IdentityVerifyPayload(_PrometheonPayload):
    """Canonical payload for miner / validator identity verification.

    The hotkey owner signs the domain-prefixed JCS bytes of this payload
    with their SR25519 hotkey. The Platform verifies the signature and
    consumes the nonce on success, setting ``<role>_verified = true`` for
    the linked Platform account.
    """

    domain: Literal["PROMETHEON_IDENTITY_VERIFY_V1"] = "PROMETHEON_IDENTITY_VERIFY_V1"
    action: Literal["verify_identity"] = "verify_identity"
    role: Role
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    platform_account_id: str = Field(min_length=1)
    username_hash: str = Field(pattern=_HEX32_RE)
    email_hash: str = Field(pattern=_HEX32_RE)
    hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    nonce: str = Field(min_length=1)
    issued_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    expires_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    api_token_hash: str = Field(pattern=_HEX32_RE)


# ---------------------------------------------------------------------------
# Normal hotkey rotation — PROMETHEON_HOTKEY_ROTATION_V1
# ---------------------------------------------------------------------------


class HotkeyRotationPayload(_PrometheonPayload):
    """Canonical payload for normal (old + new hotkey signature) rotation.

    Both the old and the new hotkey sign the same canonical bytes. A
    successful rotation starts a 7-day cooldown for that role on the
    linked Platform account; the ``cooldown_days`` field is locked to 7
    via a Literal default so the on-wire form is never ambiguous.
    """

    domain: Literal["PROMETHEON_HOTKEY_ROTATION_V1"] = "PROMETHEON_HOTKEY_ROTATION_V1"
    action: Literal["rotate_hotkey"] = "rotate_hotkey"
    role: Role
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    platform_account_id: str = Field(min_length=1)
    old_hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    new_hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    nonce: str = Field(min_length=1)
    issued_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    expires_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    api_token_hash: str = Field(pattern=_HEX32_RE)
    cooldown_days: Literal[7] = 7


# ---------------------------------------------------------------------------
# Hotkey recovery — PROMETHEON_HOTKEY_RECOVERY_V1
#
# Two flavours share the same domain string but use different
# recovery_method values and signature sets:
#
#   coldkey       : coldkey signature + new hotkey signature
#   manual_2fa_ops: new hotkey signature only (proof of identity comes from
#                    the Platform 2FA flow plus Ops Console approval)
# ---------------------------------------------------------------------------


class ColdkeyRecoveryPayload(_PrometheonPayload):
    """Canonical payload for coldkey-backed hotkey recovery.

    Used when the old hotkey is unavailable but the coldkey is. Both the
    coldkey and the new hotkey sign the same canonical bytes. The Platform
    enforces a 24-hour pending period before activation and a 14-day
    recovery cooldown after activation.
    """

    domain: Literal["PROMETHEON_HOTKEY_RECOVERY_V1"] = "PROMETHEON_HOTKEY_RECOVERY_V1"
    recovery_method: Literal["coldkey"] = "coldkey"
    action: Literal["recover_hotkey"] = "recover_hotkey"
    role: Role
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    platform_account_id: str = Field(min_length=1)
    old_hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    coldkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    new_hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    nonce: str = Field(min_length=1)
    issued_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    expires_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    api_token_hash: str = Field(pattern=_HEX32_RE)
    pending_hours: Literal[24] = 24
    recovery_cooldown_days: Literal[14] = 14


class ManualRecoveryPayload(_PrometheonPayload):
    """Canonical payload for manual (2FA + Ops-approved) hotkey recovery.

    Used when neither the old hotkey nor the coldkey is available. Only
    the new hotkey signs. Proof of identity comes from the Platform's 2FA
    flow plus Ops Console review; this is documented in audit logs as a
    non-cryptographic ownership recovery.

    The :attr:`discord_handle_hash` field carries a SHA-256 of the
    Discord handle the user submits during recovery; the raw handle is
    never written into a signed payload or any subnet log.
    """

    domain: Literal["PROMETHEON_HOTKEY_RECOVERY_V1"] = "PROMETHEON_HOTKEY_RECOVERY_V1"
    recovery_method: Literal["manual_2fa_ops"] = "manual_2fa_ops"
    action: Literal["recover_hotkey"] = "recover_hotkey"
    role: Role
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    platform_account_id: str = Field(min_length=1)
    old_hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    new_hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    discord_handle_hash: str = Field(pattern=_HEX32_RE)
    nonce: str = Field(min_length=1)
    issued_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    expires_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    api_token_hash: str = Field(pattern=_HEX32_RE)
    pending_hours: Literal[24] = 24
    recovery_cooldown_days: Literal[14] = 14


__all__ = [
    "ColdkeyRecoveryPayload",
    "HotkeyRotationPayload",
    "IdentityVerifyPayload",
    "ManualRecoveryPayload",
    "NonceResponse",
]
