"""Identity envelope models and full verification pipeline.

This module provides:

- :class:`ClientInfo` — common envelope metadata field.
- :class:`IdentityVerifySignatures` and :class:`IdentityVerifyEnvelope` —
  the wire shape for ``POST /v1/prometheon/identity/verify``.
- Shared verification helpers used by this module and by :mod:`prometheon.
  identity.rotation` and :mod:`prometheon.identity.recovery`.
- :func:`verify_identity_envelope` — full end-to-end verification of an
  identity-verify envelope. The check ordering matches what the Platform
  performs and what contract tests assert against.

The shared helpers are intentionally public:

- :func:`assert_domain_match`
- :func:`assert_environment_match`
- :func:`assert_payload_within_expiry`
- :func:`now_utc`

They are reused by rotation and recovery verifiers, and they are useful for
contract-level tests that want to inspect specific failure paths.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

from prometheon.identity.errors import (
    EnvironmentMismatchError,
    IdentityDomainMismatchError,
    IdentityPayloadValidationError,
    PayloadExpiredError,
    PayloadNotYetValidError,
)
from prometheon.identity.payloads import (
    IdentityVerifyPayload,
    PrometheonPayload,
)
from prometheon.identity.roles import ChainNetwork
from prometheon.security.canonical import DOMAIN_IDENTITY_VERIFY
from prometheon.security.signatures import verify_bittensor_signature

# Maximum allowed forward drift between the receiver's clock and the
# payload's ``issued_at``. Mirrors the consolidated specification's
# API_REQUEST_MAX_CLOCK_SKEW_SECONDS so identity payloads and API request
# signatures share the same skew tolerance.
_MAX_CLOCK_SKEW_SECONDS: Final[int] = 300


# ---------------------------------------------------------------------------
# Envelope sub-models
# ---------------------------------------------------------------------------


class ClientInfo(BaseModel):
    """Optional metadata identifying the CLI that produced an envelope.

    The Platform may log ``client.name`` and ``client.version`` for
    telemetry; the values are not security-critical and do not affect
    signature verification.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)


class IdentityVerifySignatures(BaseModel):
    """Signature set carried in an identity-verify envelope.

    Only the hotkey signature is present; identity verification proves
    control of a single key (the hotkey).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    hotkey: str = Field(pattern=r"^0x[0-9a-f]{128}$")


class IdentityVerifyEnvelope(BaseModel):
    """Wire envelope for ``POST /v1/prometheon/identity/verify``."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    payload: IdentityVerifyPayload
    signatures: IdentityVerifySignatures
    client: ClientInfo


# ---------------------------------------------------------------------------
# Shared verification helpers
# ---------------------------------------------------------------------------


def now_utc() -> datetime:
    """Return the current time as a timezone-aware UTC ``datetime``.

    Centralised so tests can monkey-patch a single function rather than
    sprinkling ``datetime.now`` calls across helpers.
    """
    return datetime.now(timezone.utc)


def _parse_iso8601_z(timestamp: str) -> datetime:
    """Parse a strict ``YYYY-MM-DDTHH:MM:SSZ`` string.

    The payload regexes guarantee the input shape; this helper just
    converts the validated string into a tz-aware ``datetime`` for
    arithmetic comparisons.
    """
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def assert_domain_match(payload: PrometheonPayload, *, expected_domain: str) -> None:
    """Raise if the payload's ``domain`` field does not equal ``expected_domain``.

    The domain field is also embedded in the signed bytes via the external
    envelope prefix; this check rejects mismatches before the more
    expensive signature verification step runs.
    """
    embedded = payload.to_canonical_dict().get("domain")
    if embedded != expected_domain:
        raise IdentityDomainMismatchError(
            f"payload domain {embedded!r} does not match expected {expected_domain!r}"
        )


def assert_environment_match(
    payload: PrometheonPayload,
    *,
    expected_chain_network: ChainNetwork,
    expected_platform_instance_id: str,
) -> None:
    """Raise if ``chain_network`` or ``platform_instance_id`` differs from config.

    This is the cross-environment replay defense: a payload that was
    signed for one Bittensor network and one Platform instance cannot be
    accepted on a different network or instance, even if the API token
    and base URL happen to match.
    """
    payload_dict = payload.to_canonical_dict()

    payload_chain = payload_dict.get("chain_network")
    expected_chain = expected_chain_network.value
    if payload_chain != expected_chain:
        raise EnvironmentMismatchError(
            f"chain_network mismatch: payload={payload_chain!r}, expected={expected_chain!r}"
        )

    payload_instance = payload_dict.get("platform_instance_id")
    if payload_instance != expected_platform_instance_id:
        raise EnvironmentMismatchError(
            f"platform_instance_id mismatch: payload={payload_instance!r}, "
            f"expected={expected_platform_instance_id!r}"
        )


def assert_payload_within_expiry(
    payload: PrometheonPayload,
    *,
    now: datetime,
) -> None:
    """Raise if the receiver's clock is outside ``[issued_at, expires_at]``.

    Allows up to :data:`_MAX_CLOCK_SKEW_SECONDS` of forward drift on
    ``issued_at`` so that benign clock-skew between the CLI host and the
    receiver does not reject otherwise-valid payloads.

    Parameters
    ----------
    payload:
        Any Prometheon canonical payload (all four carry ``issued_at`` and
        ``expires_at``).
    now:
        The current time as a tz-aware UTC ``datetime``. Injected so tests
        can supply a deterministic clock.
    """
    payload_dict = payload.to_canonical_dict()
    issued_at = _parse_iso8601_z(payload_dict["issued_at"])
    expires_at = _parse_iso8601_z(payload_dict["expires_at"])

    if (issued_at - now).total_seconds() > _MAX_CLOCK_SKEW_SECONDS:
        raise PayloadNotYetValidError(
            f"payload issued_at {issued_at.isoformat()} is in the future beyond "
            f"the {_MAX_CLOCK_SKEW_SECONDS}s skew window (now={now.isoformat()})"
        )
    if expires_at < now:
        raise PayloadExpiredError(
            f"payload expired at {expires_at.isoformat()} (now={now.isoformat()})"
        )


# ---------------------------------------------------------------------------
# Identity-verify envelope verifier
# ---------------------------------------------------------------------------


def verify_identity_envelope(
    envelope: IdentityVerifyEnvelope,
    *,
    expected_chain_network: ChainNetwork,
    expected_platform_instance_id: str,
    expected_api_token_hash: str,
    now: datetime | None = None,
) -> None:
    """Run every check the Platform performs on an identity-verify envelope.

    Order of operations matches the Platform's check sequence so contract
    tests cover identical paths:

    1. Domain binding (payload ``domain`` == expected).
    2. Environment binding (``chain_network`` and ``platform_instance_id``).
    3. API-token binding (``api_token_hash`` == hash of the presented token).
    4. Validity window (``issued_at`` not too far in the future,
       ``expires_at`` not in the past).
    5. SR25519 hotkey signature verifies against the canonical envelope.

    The function returns ``None`` on success; on failure it raises the
    most specific exception that applies. Callers should catch
    :class:`prometheon.identity.errors.IdentityError` (or its specific
    subclass) and :class:`prometheon.security.signatures.SignatureError`.
    """
    payload = envelope.payload
    current_time = now if now is not None else now_utc()

    assert_domain_match(payload, expected_domain=DOMAIN_IDENTITY_VERIFY)
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
        ss58_address=payload.hotkey_ss58,
        signature_hex=envelope.signatures.hotkey,
        domain=DOMAIN_IDENTITY_VERIFY,
        payload=payload.to_canonical_dict(),
    )


__all__ = [
    "ClientInfo",
    "IdentityVerifyEnvelope",
    "IdentityVerifySignatures",
    "assert_domain_match",
    "assert_environment_match",
    "assert_payload_within_expiry",
    "now_utc",
    "verify_identity_envelope",
]
