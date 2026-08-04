"""Canonical JSON (RFC 8785) and domain-prefixed envelope helpers.

This module is the canonicalization trust root for Prometheon. Every signed or
internally hashed object in the protocol passes through ``to_canonical_bytes``
and ``domain_prefixed_bytes`` defined here. The implementation deliberately
restricts what may be canonicalized:

- Floats are rejected. All numeric fields in Prometheon signed payloads are
  integers (scores, counts, weight units, parts-per-million). Allowing floats
  even once opens a path to validator divergence.
- ``NaN``, ``+Infinity``, and ``-Infinity`` are rejected at parse time and
  cannot survive canonicalization.
- Duplicate JSON object keys are rejected at parse time. Two implementations
  that disagree on which duplicate "wins" would compute different signatures
  and different hashes from the same wire bytes.
- The twelve Prometheon signing domains are declared as module-level
  constants; arbitrary domain strings are not accepted by the envelope helper.

The envelope is the single byte sequence that is signed or hashed:

    ASCII(domain) + b"\\n" + JCS(payload_object)

The ``domain`` is also embedded inside ``payload_object["domain"]`` by the
caller. Verifiers check both. This double binding is intentional: it
defends against accidental cross-protocol reuse if a future implementer
forgets one layer.

Reference: RFC 8785 JSON Canonicalization Scheme.
"""

from __future__ import annotations

import json
from typing import Any, Final

import rfc8785

# ---------------------------------------------------------------------------
# Signing domains.
#
# Every signed payload in Prometheon Phase 1 carries one of these twelve
# domain strings, both as the external prefix in the signed bytes and as the
# ``domain`` field inside the payload object. The constants are exposed for
# direct comparison; the ``ALL_DOMAINS`` set is used by ``domain_prefixed_bytes``
# to reject typos and unknown domains.
# ---------------------------------------------------------------------------

DOMAIN_IDENTITY_VERIFY: Final[str] = "PROMETHEON_IDENTITY_VERIFY_V1"
DOMAIN_HOTKEY_ROTATION: Final[str] = "PROMETHEON_HOTKEY_ROTATION_V1"
DOMAIN_HOTKEY_RECOVERY: Final[str] = "PROMETHEON_HOTKEY_RECOVERY_V1"
DOMAIN_API_REQUEST: Final[str] = "PROMETHEON_API_REQUEST_V1"
DOMAIN_SNAPSHOT: Final[str] = "PROMETHEON_SNAPSHOT_V1"
DOMAIN_RECORD_SET: Final[str] = "PROMETHEON_RECORD_SET_V1"
DOMAIN_RECORD_PAGE: Final[str] = "PROMETHEON_RECORD_PAGE_V1"
DOMAIN_WEIGHT_PLAN: Final[str] = "PROMETHEON_WEIGHT_PLAN_V1"

# Decentralized Validation (event-stream) domains.
DOMAIN_INGEST_PUSH: Final[str] = "PROMETHEON_INGEST_PUSH_V1"
DOMAIN_EVENT_RECORD: Final[str] = "PROMETHEON_EVENT_RECORD_V1"
DOMAIN_EVENT: Final[str] = "PROMETHEON_EVENT_V1"
DOMAIN_DAY_DIGEST: Final[str] = "PROMETHEON_DAY_DIGEST_V1"
# A validator's countersignature over a day digest it has verified against
# its own stored records. Separate from DOMAIN_DAY_DIGEST so a platform
# signature can never be replayed as a validator attestation, or the reverse.
DOMAIN_DIGEST_ATTESTATION: Final[str] = "PROMETHEON_DIGEST_ATTESTATION_V1"

ALL_DOMAINS: Final[frozenset[str]] = frozenset(
    {
        DOMAIN_IDENTITY_VERIFY,
        DOMAIN_HOTKEY_ROTATION,
        DOMAIN_HOTKEY_RECOVERY,
        DOMAIN_API_REQUEST,
        DOMAIN_SNAPSHOT,
        DOMAIN_RECORD_SET,
        DOMAIN_RECORD_PAGE,
        DOMAIN_WEIGHT_PLAN,
        DOMAIN_INGEST_PUSH,
        DOMAIN_EVENT_RECORD,
        DOMAIN_EVENT,
        DOMAIN_DAY_DIGEST,
        DOMAIN_DIGEST_ATTESTATION,
    }
)

# Separator byte between the ASCII domain prefix and the JCS-canonicalized
# payload. The choice of ``\n`` matches the protocol specification and is
# deliberately a single byte to keep the prefix length predictable.
_DOMAIN_SEPARATOR: Final[bytes] = b"\n"


# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------


class CanonicalEncodingError(ValueError):
    """Raised when an object cannot be safely canonicalized or parsed.

    Subclasses ``ValueError`` so that callers handling generic input-validation
    errors continue to work, while specific handlers can dispatch on the
    Prometheon-specific exception type.

    ``code`` categorises the rejection with the vocabulary shared with the
    platform's strict parser (and pinned by the ``json-parser-rejection``
    fixture suite): ``duplicate_key``, ``forbidden_key``, ``float_literal``,
    ``invalid_json``, or the generic ``invalid``.
    """

    def __init__(self, message: str, *, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


# Keys rejected at parse time regardless of nesting depth. Prototype-poisoning
# escape hatches in JavaScript consumers; a Python validator never interprets
# them specially, but the wire contract forbids them everywhere so both
# implementations reject identical byte streams.
_FORBIDDEN_KEYS: Final[frozenset[str]] = frozenset({"__proto__", "prototype", "constructor"})


# ---------------------------------------------------------------------------
# Public helpers.
# ---------------------------------------------------------------------------


def to_canonical_bytes(obj: Any) -> bytes:
    """Return RFC 8785 JCS canonical bytes for ``obj``.

    Rejects any object that contains a float at any depth. Floats are
    forbidden in Prometheon signed payloads; allowing them would let two
    compliant implementations disagree on canonical output and therefore on
    signatures.

    Parameters
    ----------
    obj:
        A JSON-compatible structure (``None``, ``bool``, ``int``, ``str``,
        ``list``, ``dict[str, ...]``). Booleans are accepted (JSON ``true``
        and ``false`` are not numeric in JCS).

    Returns
    -------
    bytes
        The UTF-8 canonical encoding of ``obj``.

    Raises
    ------
    CanonicalEncodingError
        If a float is present, if a dict key is not a string, or if the
        underlying canonicalizer rejects the input (for example, NaN or
        Infinity).
    """
    _reject_floats(obj)
    try:
        return rfc8785.dumps(obj)
    except Exception as exc:  # rfc8785 raises various builtin exceptions
        raise CanonicalEncodingError(
            f"object cannot be canonicalized under RFC 8785: {exc}"
        ) from exc


def domain_prefixed_bytes(domain: str, obj: Any) -> bytes:
    """Return the bytes that are signed or hashed for a given domain.

    The output layout is::

        ASCII(domain) + b"\\n" + JCS(obj)

    The ``domain`` must be one of the known Prometheon signing domains
    declared at module level. An unrecognised domain raises rather than
    being silently encoded, to prevent accidental cross-protocol reuse.

    Parameters
    ----------
    domain:
        One of the constants in ``ALL_DOMAINS``.
    obj:
        The payload object. The caller is responsible for ensuring the
        ``"domain"`` field inside ``obj`` matches ``domain``; verifiers
        re-check this binding when consuming the bytes.

    Returns
    -------
    bytes
        The exact byte sequence to be passed to a signer or hasher.

    Raises
    ------
    CanonicalEncodingError
        If ``domain`` is not a known Prometheon domain, or if ``obj``
        cannot be canonicalized.
    """
    if domain not in ALL_DOMAINS:
        raise CanonicalEncodingError(f"unknown Prometheon signing domain: {domain!r}")

    # ASCII-encode the domain string. All Prometheon domain identifiers are
    # restricted to ASCII; this assertion makes a violation explicit instead
    # of producing a misleading UTF-8 multi-byte prefix.
    try:
        prefix = domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CanonicalEncodingError(f"signing domain must be pure ASCII: {domain!r}") from exc

    return prefix + _DOMAIN_SEPARATOR + to_canonical_bytes(obj)


def parse_canonical_json(raw: str | bytes) -> Any:
    """Parse a Prometheon-canonical JSON document into a Python object.

    Unlike :func:`json.loads`, this parser:

    - Rejects ``NaN``, ``Infinity``, and ``-Infinity``.
    - Rejects any number that the underlying parser would represent as a
      Python ``float`` (numbers containing ``.`` or an exponent).
    - Rejects duplicate object keys.
    - Rejects the prototype-poisoning keys ``__proto__``, ``prototype``,
      and ``constructor`` at any depth (wire-contract rule shared with the
      platform's strict parser).

    Use this parser when receiving JSON whose bytes will be hashed, signed,
    verified, or re-canonicalized. For best-effort parsing of non-canonical
    JSON (for example, untrusted external bodies that will not be re-hashed)
    use :func:`json.loads` directly.

    Parameters
    ----------
    raw:
        The JSON document, as ``str`` or ``bytes``.

    Returns
    -------
    Any
        The parsed Python object.

    Raises
    ------
    CanonicalEncodingError
        On any of the rejection conditions above, or on a JSON syntax error.
    """
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw

    try:
        return json.loads(
            text,
            parse_float=_reject_float_literal,
            parse_constant=_reject_constant_literal,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except CanonicalEncodingError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalEncodingError(f"invalid JSON: {exc}", code="invalid_json") from exc


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


def _reject_floats(obj: Any) -> None:
    """Walk ``obj`` and raise if any nested value is a Python ``float``.

    Note that ``bool`` is a subclass of ``int`` in Python; the isinstance
    check against ``bool`` therefore comes first to keep ``True`` and
    ``False`` from being classified as integers (they are not numeric in
    JSON either, so the distinction matters only for clarity).
    """
    if isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise CanonicalEncodingError(
            "float values are forbidden in Prometheon signed payloads; "
            "use integers (scores, counts, weight units, ppm)"
        )
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise CanonicalEncodingError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
            _reject_floats(value)
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_floats(item)


def _reject_float_literal(value: str) -> float:
    """``parse_float`` hook for :func:`json.loads` — always raises.

    Any number in the JSON source that contains ``.`` or an exponent passes
    through here. Prometheon forbids such values entirely, so we raise with
    the literal in the message for debuggability.
    """
    raise CanonicalEncodingError(
        f"float literal forbidden in Prometheon canonical JSON: {value!r}",
        code="float_literal",
    )


def _reject_constant_literal(value: str) -> float:
    """``parse_constant`` hook for :func:`json.loads` — always raises.

    Triggered for ``NaN``, ``Infinity``, and ``-Infinity``. None of these are
    valid JSON at all, so the shared rejection vocabulary classifies them as
    ``invalid_json`` rather than a Prometheon-specific restriction.
    """
    raise CanonicalEncodingError(
        f"non-canonical JSON token forbidden in Prometheon canonical JSON: {value!r}",
        code="invalid_json",
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` for :func:`json.loads` — strict key policy.

    Rejects duplicate keys (the default parser silently keeps the last
    value, which is incompatible with byte-stable canonicalization) and the
    prototype-poisoning keys, at every nesting depth. Unicode escapes in the
    source are already decoded by the time keys reach this hook, so escaped
    spellings of the same key are caught identically.
    """
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in _FORBIDDEN_KEYS:
            raise CanonicalEncodingError(
                f"forbidden object key in Prometheon canonical JSON: {key!r}",
                code="forbidden_key",
            )
        if key in seen:
            raise CanonicalEncodingError(
                f"duplicate JSON object key forbidden in Prometheon canonical JSON: {key!r}",
                code="duplicate_key",
            )
        seen.add(key)
        result[key] = value
    return result


__all__ = [
    "ALL_DOMAINS",
    "DOMAIN_API_REQUEST",
    "DOMAIN_DAY_DIGEST",
    "DOMAIN_DIGEST_ATTESTATION",
    "DOMAIN_EVENT",
    "DOMAIN_EVENT_RECORD",
    "DOMAIN_HOTKEY_RECOVERY",
    "DOMAIN_HOTKEY_ROTATION",
    "DOMAIN_IDENTITY_VERIFY",
    "DOMAIN_INGEST_PUSH",
    "DOMAIN_RECORD_PAGE",
    "DOMAIN_RECORD_SET",
    "DOMAIN_SNAPSHOT",
    "DOMAIN_WEIGHT_PLAN",
    "CanonicalEncodingError",
    "domain_prefixed_bytes",
    "parse_canonical_json",
    "to_canonical_bytes",
]
