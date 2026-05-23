"""Cryptographic signature primitives for Prometheon.

Phase 1 uses two distinct signing roles, each with its own algorithm:

- **SR25519** for Bittensor hotkey and coldkey signatures. Used for identity
  verification, hotkey rotation, coldkey recovery, manual recovery, and
  validator-to-Platform API request signing.
- **Ed25519** for Platform snapshot signatures. Used by the BitFan platform
  to sign daily snapshots and detailed-mode manifests.

These two trust roles are intentionally separated. A Bittensor hotkey must
never be used to sign a snapshot, and a Platform Ed25519 key must never be
used to sign an identity payload. The two algorithms make accidental misuse
impossible.

Wire encoding (consolidated specification §6.1):

- Signatures: ``"0x"`` + 128 lowercase hex characters (64 bytes).
- Ed25519 public keys: ``"0x"`` + 64 lowercase hex characters (32 bytes).

The verifier path is strict — any deviation in length, prefix, or case is
rejected with a structured failure code (see consolidated specification §16.4).
"""

from __future__ import annotations

import re
from typing import Any, Final

from bittensor_wallet import Keypair
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from prometheon.security.canonical import domain_prefixed_bytes

# Canonical hex format regexes. These enforce ``0x`` lowercase-hex form with
# the exact expected byte length. Any other shape (uppercase, base64, missing
# prefix, wrong length) is a format error.
_SIGNATURE_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-f]{128}$")
_PUBLIC_KEY_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-f]{64}$")

# Length of the raw byte forms after decoding the canonical hex.
_SIGNATURE_BYTE_LEN: Final[int] = 64
_PUBLIC_KEY_BYTE_LEN: Final[int] = 32


# ---------------------------------------------------------------------------
# Structured errors
#
# Every signature failure carries a stable ``code`` string. The codes match
# the catalog in the consolidated specification §16.4 so that CLI output,
# validator logs, and Platform error responses can use a single shared
# vocabulary.
# ---------------------------------------------------------------------------


class SignatureError(Exception):
    """Base exception for signature operations.

    Subclasses carry a stable ``code`` attribute identifying the specific
    failure mode. The ``code`` is suitable for use in structured logs,
    error responses, and CLI output.
    """

    code: str = "signature.error"


class SignatureFormatError(SignatureError):
    """The signature hex, public key hex, or other encoded value is malformed."""

    code = "signature.invalid_format"


class SignatureVerificationError(SignatureError):
    """The signature did not verify against the provided key and message."""

    code = "signature.verification_failed"


class SignatureAddressMismatchError(SignatureError):
    """The SS58 address could not be parsed or did not match the payload."""

    code = "signature.address_mismatch"


class UnsupportedKeyTypeError(SignatureError):
    """The keypair declared a crypto type that Phase 1 does not accept."""

    code = "signature.unsupported_key_type"


# ---------------------------------------------------------------------------
# Hex encoding and decoding helpers
# ---------------------------------------------------------------------------


def signature_bytes_to_hex(sig: bytes) -> str:
    """Encode a 64-byte signature as ``"0x"`` + 128 lowercase hex characters.

    Raises
    ------
    SignatureFormatError
        If ``sig`` is not exactly 64 bytes long.
    """
    if not isinstance(sig, (bytes, bytearray)):
        raise SignatureFormatError(f"signature bytes must be bytes, got {type(sig).__name__}")
    if len(sig) != _SIGNATURE_BYTE_LEN:
        raise SignatureFormatError(f"signature must be {_SIGNATURE_BYTE_LEN} bytes, got {len(sig)}")
    return "0x" + bytes(sig).hex()


def signature_hex_to_bytes(signature_hex: str) -> bytes:
    """Decode a canonical signature hex string into 64 raw bytes.

    Accepts only the strict canonical form ``^0x[0-9a-f]{128}$``. Any other
    representation (uppercase hex, missing prefix, base64, wrong length) is
    rejected with :class:`SignatureFormatError`.
    """
    if not isinstance(signature_hex, str):
        raise SignatureFormatError(f"signature hex must be str, got {type(signature_hex).__name__}")
    if not _SIGNATURE_HEX_RE.match(signature_hex):
        raise SignatureFormatError(
            "signature must match the canonical form "
            "'0x' + 128 lowercase hex characters; "
            f"got {signature_hex!r}"
        )
    return bytes.fromhex(signature_hex[2:])


def public_key_bytes_to_hex(pk: bytes) -> str:
    """Encode a 32-byte public key as ``"0x"`` + 64 lowercase hex characters."""
    if not isinstance(pk, (bytes, bytearray)):
        raise SignatureFormatError(f"public key bytes must be bytes, got {type(pk).__name__}")
    if len(pk) != _PUBLIC_KEY_BYTE_LEN:
        raise SignatureFormatError(
            f"public key must be {_PUBLIC_KEY_BYTE_LEN} bytes, got {len(pk)}"
        )
    return "0x" + bytes(pk).hex()


def public_key_hex_to_bytes(public_key_hex: str) -> bytes:
    """Decode a canonical public key hex string into 32 raw bytes.

    Accepts only the strict canonical form ``^0x[0-9a-f]{64}$``.
    """
    if not isinstance(public_key_hex, str):
        raise SignatureFormatError(
            f"public key hex must be str, got {type(public_key_hex).__name__}"
        )
    if not _PUBLIC_KEY_HEX_RE.match(public_key_hex):
        raise SignatureFormatError(
            "public key must match the canonical form "
            "'0x' + 64 lowercase hex characters; "
            f"got {public_key_hex!r}"
        )
    return bytes.fromhex(public_key_hex[2:])


# ---------------------------------------------------------------------------
# SR25519 — Bittensor hotkey and coldkey signatures
# ---------------------------------------------------------------------------


def sign_with_bittensor_keypair(keypair: Keypair, domain: str, payload: Any) -> str:
    """Sign the domain-prefixed JCS bytes of ``payload`` with a Bittensor keypair.

    The bytes that are signed are exactly:

        ASCII(domain) + b"\\n" + JCS(payload)

    so the returned signature is verifiable by any conforming implementation
    that constructs the same envelope.

    Parameters
    ----------
    keypair:
        A loaded :class:`bittensor_wallet.Keypair` with a private key. For
        hotkey signatures pass ``wallet.hotkey``; for coldkey signatures pass
        ``wallet.coldkey`` (the wallet must be unlocked).
    domain:
        One of the eight known Prometheon signing domains. Unknown domains
        are rejected by the underlying envelope builder.
    payload:
        A JSON-compatible Python object. Floats are rejected.

    Returns
    -------
    str
        ``"0x"`` + 128 lowercase hex characters representing the SR25519
        signature.

    Raises
    ------
    SignatureError
        If the envelope cannot be built or the underlying keypair rejects
        signing.
    """
    envelope = domain_prefixed_bytes(domain, payload)
    try:
        raw_signature = keypair.sign(envelope)
    except Exception as exc:
        raise SignatureError(f"keypair refused to sign Prometheon envelope: {exc}") from exc
    return signature_bytes_to_hex(raw_signature)


def verify_bittensor_signature(
    ss58_address: str,
    signature_hex: str,
    domain: str,
    payload: Any,
) -> None:
    """Verify an SR25519 signature against the domain-prefixed JCS bytes.

    Reconstructs a verify-only :class:`bittensor_wallet.Keypair` from the
    declared SS58 address, rebuilds the canonical envelope from ``domain``
    and ``payload``, and checks the signature.

    Parameters
    ----------
    ss58_address:
        The Bittensor SS58 address that claims to have produced the
        signature.
    signature_hex:
        ``"0x"`` + 128 lowercase hex characters.
    domain:
        The expected Prometheon signing domain.
    payload:
        The Python object whose canonical bytes were signed. Must contain
        the same ``"domain"`` field; double-binding is the caller's
        responsibility (the underlying envelope builder does not enforce
        it, but verifiers in this codebase always do).

    Raises
    ------
    SignatureFormatError
        If ``signature_hex`` is malformed.
    SignatureAddressMismatchError
        If the SS58 address cannot be parsed.
    SignatureVerificationError
        If the signature does not verify or the keypair raised an internal
        error during verification.
    """
    envelope = domain_prefixed_bytes(domain, payload)
    raw_signature = signature_hex_to_bytes(signature_hex)

    try:
        verify_keypair = Keypair(ss58_address=ss58_address)
    except Exception as exc:
        raise SignatureAddressMismatchError(
            f"could not construct verifier keypair from ss58_address {ss58_address!r}: {exc}"
        ) from exc

    try:
        ok = bool(verify_keypair.verify(envelope, raw_signature))
    except Exception as exc:
        raise SignatureVerificationError(f"SR25519 verification raised: {exc}") from exc

    if not ok:
        raise SignatureVerificationError(
            f"SR25519 signature does not verify for ss58 {ss58_address!r} under domain {domain!r}"
        )


# ---------------------------------------------------------------------------
# Ed25519 — Platform snapshot signatures
# ---------------------------------------------------------------------------


def verify_ed25519_signature(
    public_key_hex: str,
    signature_hex: str,
    message: bytes,
) -> None:
    """Verify an Ed25519 signature over arbitrary message bytes.

    For Prometheon snapshots the ``message`` argument is the domain-prefixed
    JCS envelope::

        b"PROMETHEON_SNAPSHOT_V1\\n" + JCS(snapshot_object_without_platform_signature)

    Callers are responsible for constructing the envelope (typically via
    :func:`prometheon.security.canonical.domain_prefixed_bytes`).

    Parameters
    ----------
    public_key_hex:
        ``"0x"`` + 64 lowercase hex characters identifying the Platform
        Ed25519 public key associated with the snapshot's
        ``platform_key_id``.
    signature_hex:
        ``"0x"`` + 128 lowercase hex characters.
    message:
        The byte sequence that was signed.

    Raises
    ------
    SignatureFormatError
        If the public key or signature hex is malformed, or the message is
        not bytes.
    SignatureVerificationError
        If the signature does not verify.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise SignatureFormatError(f"Ed25519 message must be bytes, got {type(message).__name__}")

    pk_bytes = public_key_hex_to_bytes(public_key_hex)
    sig_bytes = signature_hex_to_bytes(signature_hex)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(pk_bytes)
    except Exception as exc:
        raise SignatureFormatError(
            f"could not construct Ed25519 public key from {public_key_hex!r}: {exc}"
        ) from exc

    try:
        public_key.verify(sig_bytes, bytes(message))
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Ed25519 signature does not verify against the provided public key"
        ) from exc


__all__ = [
    "SignatureAddressMismatchError",
    "SignatureError",
    "SignatureFormatError",
    "SignatureVerificationError",
    "UnsupportedKeyTypeError",
    "public_key_bytes_to_hex",
    "public_key_hex_to_bytes",
    "sign_with_bittensor_keypair",
    "signature_bytes_to_hex",
    "signature_hex_to_bytes",
    "verify_bittensor_signature",
    "verify_ed25519_signature",
]
