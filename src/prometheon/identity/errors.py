"""Identity-layer exceptions.

The errors raised by this module concern envelope structure, payload
validation, domain binding, environment binding, and payload expiry —
everything that can be checked on the subnet side without consulting the
Platform.

Signature errors bubble up from ``prometheon.security.signatures`` with
their own structured codes; Platform-side conditions (token validation,
nonce consumption, account lockout) surface as
``prometheon.platform.errors``. The identity errors below are the
in-between layer.
"""

from __future__ import annotations


class IdentityError(Exception):
    """Base exception for the identity layer.

    Each subclass carries a stable ``code`` attribute matching the failure
    code catalog in the consolidated specification §16.1 / §16.4.
    """

    code: str = "identity.error"


class IdentityPayloadValidationError(IdentityError):
    """A canonical payload fails the schema or field-level validation rules."""

    code = "identity.payload_invalid"


class IdentityEnvelopeStructureError(IdentityError):
    """The HTTP request envelope does not match the expected shape.

    For example, the ``signatures`` block is missing a required key, or
    contains a key that is not part of the contract.
    """

    code = "identity.envelope_invalid"


class IdentityDomainMismatchError(IdentityError):
    """The ``domain`` embedded inside the canonical payload does not match
    the domain expected for this endpoint or operation."""

    code = "signature.domain_mismatch"


class EnvironmentMismatchError(IdentityError):
    """The ``chain_network`` or ``platform_instance_id`` carried by the
    payload does not match the validator/CLI's configured environment.

    This is the cross-environment replay defense: a staging-signed payload
    cannot be consumed by a production validator even if the API token and
    base URL happen to match.
    """

    code = "ENVIRONMENT_MISMATCH"


class PayloadExpiredError(IdentityError):
    """The payload's ``expires_at`` is in the past.

    The check is performed against the receiver's clock immediately before
    signature verification, so the verifier rejects stale envelopes before
    spending cycles on crypto.
    """

    code = "identity.payload_expired"


class PayloadNotYetValidError(IdentityError):
    """The payload's ``issued_at`` is in the future beyond the allowed skew.

    Defensive against clock-skew attacks where a payload is constructed
    with a forward-dated timestamp.
    """

    code = "identity.payload_not_yet_valid"


__all__ = [
    "EnvironmentMismatchError",
    "IdentityDomainMismatchError",
    "IdentityEnvelopeStructureError",
    "IdentityError",
    "IdentityPayloadValidationError",
    "PayloadExpiredError",
    "PayloadNotYetValidError",
]
