"""Hashing helpers used across the Prometheon protocol surface.

All hashes in Prometheon are SHA-256 and are wire-encoded as ``"0x"`` followed
by lowercase hexadecimal characters. This module provides the small set of
helpers every other module uses; no other code performs its own SHA-256
computation or hex formatting.

Exposed helpers:

- :func:`sha256_hex`             generic ``"0x" + sha256(bytes).hexdigest()``
- :func:`domain_prefixed_hash`   ``sha256`` over ``ASCII(domain) + b"\\n" + JCS(obj)``
- :func:`api_token_hash`         ``"0x" + sha256(token.encode("utf-8"))``
- :func:`body_hash`              ``"0x" + sha256(request_body_bytes)``
- :func:`query_hash`             ``"0x" + sha256(canonical_query_string)``

The query hash deserves special attention. Phase 1 snapshot endpoints
deliberately avoid query parameters and prefer path segments, but the
helper exists for completeness (and for any future endpoint that needs it).
Canonicalization rules follow the consolidated specification: sort by
key, then by value; RFC 3986 percent-encode keys and values; **uppercase
hex** for percent-encoded octets; join as ``key=value`` pairs with ``&``.

Reference: consolidated specification §10 (Encoding), §9.5–§9.7 (path/query/body
hashing for API requests), §11 (snapshot model where ``records_hash`` and
``page_hash`` are computed via :func:`domain_prefixed_hash`).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from prometheon.security.canonical import (
    CanonicalEncodingError,
    domain_prefixed_bytes,
)

# Canonical hex prefix on every encoded hash and signature in the protocol.
_HEX_PREFIX = "0x"

# Empty SHA-256 (precomputed) — used by callers that want a constant rather
# than a function call for the "no body" / "no query" cases.
EMPTY_SHA256_HEX = _HEX_PREFIX + hashlib.sha256(b"").hexdigest()


def sha256_hex(data: bytes) -> str:
    """Return ``"0x" + sha256(data).hexdigest()``.

    The output is always 66 characters: a two-character ``0x`` prefix
    followed by 64 lowercase hexadecimal characters.

    Parameters
    ----------
    data:
        The bytes to hash. Pass ``b""`` for an empty input.

    Returns
    -------
    str
        The ``"0x"``-prefixed lowercase-hex SHA-256 digest.
    """
    return _HEX_PREFIX + hashlib.sha256(data).hexdigest()


def domain_prefixed_hash(domain: str, obj: Any) -> str:
    """Return the SHA-256 hash of the standard Prometheon signing envelope.

    Delegates to :func:`prometheon.security.canonical.domain_prefixed_bytes`
    for envelope construction, so this helper enforces all the same
    Prometheon-specific rules (float rejection, known-domain check,
    RFC 8785 canonicalization).

    Parameters
    ----------
    domain:
        One of the eight known Prometheon signing domains. Unknown domains
        raise via the underlying envelope builder.
    obj:
        A JSON-compatible Python object (no floats, string keys only).

    Returns
    -------
    str
        ``"0x"`` + lowercase hex SHA-256 of the envelope bytes.

    Raises
    ------
    prometheon.security.canonical.CanonicalEncodingError
        If the domain is unknown or the object cannot be canonicalized.
    """
    envelope = domain_prefixed_bytes(domain, obj)
    return sha256_hex(envelope)


def api_token_hash(api_token: str) -> str:
    """Return the SHA-256 hash of an API token, encoded in the canonical form.

    The token itself is sent only through the ``Authorization: Bearer``
    header on individual requests; signed payloads embed *this hash* so the
    signature is bound to the token presented in the request. The Platform
    server independently hashes the bearer token and compares to the value
    inside the signed payload.

    Parameters
    ----------
    api_token:
        The raw API token string. **Never logged.**

    Returns
    -------
    str
        ``"0x"`` + lowercase hex SHA-256 of ``api_token.encode("utf-8")``.

    Raises
    ------
    TypeError
        If ``api_token`` is not a ``str``. Tokens must be passed as
        ``str``; if you have ``bytes`` decode them explicitly so the
        encoding choice is visible at the call site.
    """
    if not isinstance(api_token, str):
        raise TypeError(
            f"api_token must be a str, got {type(api_token).__name__}; "
            "decode bytes explicitly at the call site"
        )
    return sha256_hex(api_token.encode("utf-8"))


def body_hash(body: bytes) -> str:
    """Return the canonical hash of an HTTP request body.

    For GET requests with no body, callers may pass ``b""`` directly, or
    use :data:`EMPTY_SHA256_HEX`. Both produce the same value.

    Parameters
    ----------
    body:
        The raw bytes of the request body. Must be ``bytes``; ``str`` is
        rejected so the encoding choice is explicit.

    Returns
    -------
    str
        ``"0x"`` + lowercase hex SHA-256 of ``body``.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(
            f"body must be bytes, got {type(body).__name__}; "
            "encode str explicitly at the call site"
        )
    return sha256_hex(bytes(body))


def query_hash(query: Mapping[str, str | list[str] | tuple[str, ...]] | None) -> str:
    """Return the canonical hash of an HTTP query string.

    The hash is computed over the canonical-query-string ASCII bytes. The
    canonical form is built from the input mapping by:

    1. Sorting parameter names lexicographically by byte value.
    2. Within each name, sorting duplicate values lexicographically.
    3. RFC 3986 percent-encoding each name and each value, using
       **uppercase** hex for the percent-encoded octets.
    4. Joining as ``key=value`` pairs separated by ``&``.

    An empty or ``None`` query produces :data:`EMPTY_SHA256_HEX`.

    Parameters
    ----------
    query:
        Mapping of parameter name to value(s). A value may be a single
        string or a list/tuple of strings for repeated parameters.
        Pass ``None`` or an empty mapping for "no query parameters".

    Returns
    -------
    str
        ``"0x"`` + lowercase hex SHA-256 of the canonical query string.

    Raises
    ------
    CanonicalEncodingError
        If any value is not a string, or if multi-valued entries are
        provided for endpoints that disallow them. The caller is
        responsible for rejecting repeated keys where the endpoint
        contract forbids them; this helper accepts them and canonicalises
        the multi-value form deterministically.
    """
    if not query:
        return EMPTY_SHA256_HEX

    pairs: list[tuple[str, str]] = []
    for key, raw in query.items():
        if not isinstance(key, str):
            raise CanonicalEncodingError(
                f"query parameter name must be str, got {type(key).__name__}"
            )

        # Normalize to an iterable of string values so multi-valued and
        # single-valued entries take the same path.
        if isinstance(raw, str):
            values: list[str] = [raw]
        elif isinstance(raw, (list, tuple)):
            values = list(raw)
        else:
            raise CanonicalEncodingError(
                f"query parameter value for {key!r} must be str or list/tuple of str, "
                f"got {type(raw).__name__}"
            )

        for value in values:
            if not isinstance(value, str):
                raise CanonicalEncodingError(
                    f"query parameter value for {key!r} must be str, "
                    f"got {type(value).__name__}"
                )
            pairs.append((key, value))

    # Sort by (key, value) lexicographically by byte value. ``str`` comparison
    # is by code point, which for ASCII keys/values matches byte order; if
    # higher code points appear they sort consistently between Python
    # implementations because str comparison is unicode-codepoint-based and
    # the canonical query string is later encoded with percent-encoding.
    pairs.sort(key=lambda kv: (kv[0], kv[1]))

    # RFC 3986 percent-encode key and value. ``urllib.parse.quote`` emits
    # uppercase hex octets and leaves unreserved characters alone, which
    # matches the canonical form. ``safe=""`` ensures we also encode "/" and
    # the other typical query-safe characters.
    encoded_pairs = [f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs]
    canonical_query = "&".join(encoded_pairs)

    return sha256_hex(canonical_query.encode("ascii"))


__all__ = [
    "EMPTY_SHA256_HEX",
    "sha256_hex",
    "domain_prefixed_hash",
    "api_token_hash",
    "body_hash",
    "query_hash",
]
