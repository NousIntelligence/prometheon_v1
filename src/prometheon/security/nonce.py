"""Cryptographic nonce generation for client-side API requests.

For validator-to-Platform API requests (``PROMETHEON_API_REQUEST_V1``) the
client generates a fresh nonce per request. The nonce is included in the
signed request payload and in the ``X-Prometheon-Nonce`` header; the
Platform tracks consumed nonces per `(api_token, validator_hotkey)` to
prevent replay within the nonce TTL window.

Wire format (consolidated specification §9.2):

- 16 or more bytes of cryptographic randomness.
- Encoded as ``"0x"`` followed by lowercase hexadecimal.
- Validators must use 16-64 bytes (32-128 hex characters). The Platform may
  apply a tighter cap but Phase 1 client code does not.

Identity-flow nonces (verify, rotate, recover) are **not** generated here.
Those are issued by the Platform's nonce endpoint as opaque strings and
signed exactly as returned. This module is for client-side request nonces
only.
"""

from __future__ import annotations

import re
import secrets
from typing import Final

_MIN_NONCE_BYTES: Final[int] = 16
_MAX_NONCE_BYTES: Final[int] = 64
_DEFAULT_NONCE_BYTES: Final[int] = 16

# Canonical format regex for client-generated API request nonces. Identity
# nonces from the Platform are opaque strings and do not match this regex.
_NONCE_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-f]{32,128}$")


class NonceError(ValueError):
    """Raised on malformed nonce input or invalid generation parameters."""


def generate_api_request_nonce(byte_length: int = _DEFAULT_NONCE_BYTES) -> str:
    """Generate a cryptographically random API-request nonce.

    Uses :func:`secrets.token_hex` so the underlying entropy comes from the
    operating system's CSPRNG. The output is always ``"0x"`` followed by
    lowercase hexadecimal characters.

    Parameters
    ----------
    byte_length:
        Number of random bytes to draw. Must satisfy
        ``16 <= byte_length <= 64``. Defaults to 16 bytes (32 hex
        characters), which is sufficient for replay-window protection
        while keeping headers compact.

    Returns
    -------
    str
        ``"0x"`` + ``2 * byte_length`` lowercase hex characters.

    Raises
    ------
    NonceError
        If ``byte_length`` is not an ``int`` or is outside the
        ``[_MIN_NONCE_BYTES, _MAX_NONCE_BYTES]`` range.
    """
    # Reject ``bool`` explicitly because ``bool`` is an ``int`` subclass in
    # Python and would otherwise pass the range check with surprising results
    # (True == 1, False == 0).
    if isinstance(byte_length, bool) or not isinstance(byte_length, int):
        raise NonceError(f"byte_length must be int, got {type(byte_length).__name__}")
    if byte_length < _MIN_NONCE_BYTES or byte_length > _MAX_NONCE_BYTES:
        raise NonceError(
            f"byte_length must be in [{_MIN_NONCE_BYTES}, {_MAX_NONCE_BYTES}], got {byte_length}"
        )
    return "0x" + secrets.token_hex(byte_length)


def is_valid_api_request_nonce(nonce: object) -> bool:
    """Return ``True`` if ``nonce`` matches the canonical API-request format.

    Intentionally accepts ``object`` so the predicate is safe to call on
    arbitrary input — for example, on values just parsed from untrusted
    JSON. A non-``str`` argument always returns ``False`` without raising.
    For a raising variant, use :func:`assert_valid_api_request_nonce`.
    """
    if not isinstance(nonce, str):
        return False
    return bool(_NONCE_HEX_RE.match(nonce))


def assert_valid_api_request_nonce(nonce: object) -> None:
    """Raise :class:`NonceError` if ``nonce`` is not canonically formatted.

    Use this in code paths that should fail loudly on bad input — for
    example, when reconstructing the canonical request payload from
    user-provided values for signature verification.
    """
    if not isinstance(nonce, str):
        raise NonceError(f"nonce must be str, got {type(nonce).__name__}")
    if not _NONCE_HEX_RE.match(nonce):
        raise NonceError(
            "API request nonce must match the canonical form "
            "'0x' + 32 to 128 lowercase hex characters; "
            f"got {nonce!r}"
        )


__all__ = [
    "NonceError",
    "assert_valid_api_request_nonce",
    "generate_api_request_nonce",
    "is_valid_api_request_nonce",
]
