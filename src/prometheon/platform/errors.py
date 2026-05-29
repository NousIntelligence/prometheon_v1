"""Platform-side error catalog and HTTP response mapping.

The BitFan platform returns errors as a small JSON envelope::

    {"code": "<CODE>", "message": "<human readable message>", "details": {...}}

This module defines:

- :class:`PlatformError` and its hierarchy — one Python exception class per
  error code the platform may return. Every exception carries a stable
  ``code`` string, an optional HTTP ``status_code``, an optional ``detail``
  message (the platform's ``message`` field), and an optional ``details``
  dict (the platform's typed ``details`` payload, scrubbed of cross-user
  PII at parse time).
- :func:`platform_error_from_response_body` — maps a decoded response body
  to the matching exception. Validates the ``code`` shape, sanitises the
  ``details`` dict against the privacy backstop key-pattern list, and
  routes unknown codes to the generic 4xx/5xx bucket while preserving the
  raw body in ``detail`` so debugging is never blind.

The exception hierarchy mirrors the 33-code platform contract. New codes
added by future additive platform releases fall through to the generic
base class until the catalog is extended; this is intentional so an older
CLI build never crashes on a code it does not yet know.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, ClassVar, cast

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Wire-code shape guard. Both UPPER_SNAKE (identity / snapshot) and
# dotted.lowercase (signature primitives) are valid; anything else is a
# protocol surprise we refuse to display verbatim. Length cap keeps the
# operator-facing trailer grep-friendly and immune to terminal-flood.
_CODE_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")

# Privacy backstop: any ``details`` key whose name matches one of these
# patterns is dropped at parse time before the exception is constructed.
# The platform commits never to emit cross-user information; this list is
# defence-in-depth in case a future platform regression slips one through.
_SENSITIVE_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^conflicting_"),
    re.compile(r".*_owner_id$"),
    re.compile(r".*_user_id$"),
    re.compile(r"^other_account_"),
    re.compile(r"^other_user_"),
    re.compile(r"^current_holder_"),
    re.compile(r"^current_owner_"),
)

# Track which sensitive-key drops we have already reported this process so
# we do not flood stderr when the same code repeats across a long-running
# validator loop. One warning per offending key name is enough signal.
_SANITISE_WARN_SEEN: set[str] = set()

_logger = logging.getLogger(__name__)


def _key_is_sensitive(key: str) -> bool:
    """Return ``True`` when ``key`` matches any privacy-backstop pattern."""
    return any(pattern.match(key) for pattern in _SENSITIVE_KEY_PATTERNS)


def _sanitise_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop cross-user keys from ``details`` before the exception is built.

    Returns ``None`` when input is ``None`` (the wire shape \"no details
    field\") and an empty dict when every key was dropped (so callers can
    still distinguish \"present but empty\" from \"absent\"). Emits one
    stderr warning per distinct dropped key name per process — repeated
    drops of the same key on subsequent errors do not re-warn.
    """
    if details is None:
        return None
    sanitised: dict[str, Any] = {}
    dropped: list[str] = []
    for key, value in details.items():
        if isinstance(key, str) and _key_is_sensitive(key):
            dropped.append(key)
            continue
        sanitised[key] = value
    if dropped:
        novel = [k for k in dropped if k not in _SANITISE_WARN_SEEN]
        for k in novel:
            _SANITISE_WARN_SEEN.add(k)
        if novel:
            sys.stderr.write(
                f"prometheon-cli: dropped sensitive detail key(s): {', '.join(novel)}\n"
            )
    return sanitised


# ---------------------------------------------------------------------------
# Base exception
# ---------------------------------------------------------------------------


class PlatformError(Exception):
    """Base exception for any error returned by the BitFan platform API.

    Subclasses carry a stable :attr:`code` matching the on-wire error
    string. :attr:`status_code` is filled in when constructed from an HTTP
    response; :attr:`detail` is the platform's human-readable ``message``
    field; :attr:`details` is the platform's typed ``details`` payload,
    already sanitised against the privacy backstop key-pattern list at
    construction time. :attr:`wire_code` carries the exact code string the
    platform returned — identical to :attr:`code` for catalogued classes,
    but distinct when an additive (forward-compatibility) code falls
    through to the generic :class:`PlatformError` base; the CLI renderer
    reads :attr:`wire_code` so an unknown code can still display verbatim
    and link to a tagged issue-template.
    """

    code: ClassVar[str] = "PLATFORM_ERROR"

    def __init__(
        self,
        message: str | None = None,
        *,
        status_code: int | None = None,
        detail: str | None = None,
        details: dict[str, Any] | None = None,
        wire_code: str | None = None,
    ) -> None:
        # Compose a clear default message if the caller passes nothing so
        # ``str(exc)`` is always useful in logs.
        display = message or detail or f"platform returned {wire_code or self.code}"
        super().__init__(display)
        self.status_code = status_code
        self.detail = detail
        self.details = details
        self.wire_code = wire_code or self.code


# ---------------------------------------------------------------------------
# Authentication and authorisation
# ---------------------------------------------------------------------------


class AuthInvalidTokenError(PlatformError):
    code = "AUTH_INVALID_TOKEN"


class AuthTokenScopeMissingError(PlatformError):
    """Wire ``details`` shape: ``{required_scope: str}``."""

    code = "AUTH_TOKEN_SCOPE_MISSING"


class AccountNotVerifiedError(PlatformError):
    code = "ACCOUNT_NOT_VERIFIED"


class AccountLockedOutError(PlatformError):
    """Future-additive wire ``details``: ``{locked_until: ISO8601Z}``."""

    code = "ACCOUNT_LOCKED_OUT"


# ---------------------------------------------------------------------------
# Nonce
# ---------------------------------------------------------------------------


class NonceMissingError(PlatformError):
    code = "NONCE_MISSING"


class NonceExpiredError(PlatformError):
    """Future-additive wire ``details``: ``{expired_at, server_time}``."""

    code = "NONCE_EXPIRED"


class NonceAlreadyUsedError(PlatformError):
    """Future-additive wire ``details``: ``{consumed_at}``."""

    code = "NONCE_ALREADY_USED"


class NonceContextMismatchError(PlatformError):
    code = "NONCE_CONTEXT_MISMATCH"


# ---------------------------------------------------------------------------
# Hotkey state
# ---------------------------------------------------------------------------


class HotkeyAlreadyLinkedError(PlatformError):
    code = "HOTKEY_ALREADY_LINKED"


class HotkeyNotLinkedError(PlatformError):
    code = "HOTKEY_NOT_LINKED"


class RotationCooldownActiveError(PlatformError):
    """Wire ``details`` shape: ``{cooldown_until: ISO8601Z}``."""

    code = "ROTATION_COOLDOWN_ACTIVE"


class RecoveryCooldownActiveError(PlatformError):
    """Wire ``details`` shape: ``{cooldown_until: ISO8601Z}``."""

    code = "RECOVERY_COOLDOWN_ACTIVE"


class RecoveryPendingError(PlatformError):
    """Future-additive wire ``details``: ``{activation_eligible_at}``."""

    code = "RECOVERY_PENDING"


# ---------------------------------------------------------------------------
# Binding-ledger codes (verify / rotate / recover guards)
# ---------------------------------------------------------------------------


class ProfileAlreadyHasHotkeyError(PlatformError):
    """Wire ``details`` shape: ``{recommended_action: 'rotate' | 'recover'}``."""

    code = "PROFILE_ALREADY_HAS_HOTKEY"


class MinerFanGroupRequiredError(PlatformError):
    """No details payload; rejection text is enough."""

    code = "MINER_FAN_GROUP_REQUIRED"


class ColdkeyOwnershipNotProvenError(PlatformError):
    code = "COLDKEY_OWNERSHIP_NOT_PROVEN"


class DiscordHandleMissingError(PlatformError):
    code = "DISCORD_HANDLE_MISSING"


class TwoFactorProofInvalidError(PlatformError):
    code = "TWO_FACTOR_PROOF_INVALID"


# ---------------------------------------------------------------------------
# Snapshot read
# ---------------------------------------------------------------------------


class SnapshotNotReadyError(PlatformError):
    code = "SNAPSHOT_NOT_READY"


class SnapshotModeInvalidError(PlatformError):
    code = "SNAPSHOT_MODE_INVALID"


class SnapshotDateInvalidError(PlatformError):
    code = "SNAPSHOT_DATE_INVALID"


class SnapshotAccessDeniedError(PlatformError):
    code = "SNAPSHOT_ACCESS_DENIED"


# ---------------------------------------------------------------------------
# Snapshot storage
# ---------------------------------------------------------------------------


class SnapshotPageNotFoundError(PlatformError):
    code = "SNAPSHOT_PAGE_NOT_FOUND"


class SnapshotStorageAccessDeniedError(PlatformError):
    code = "SNAPSHOT_STORAGE_ACCESS_DENIED"


class SnapshotStorageError(PlatformError):
    code = "SNAPSHOT_STORAGE_ERROR"


class SnapshotPageHashError(PlatformError):
    code = "SNAPSHOT_PAGE_HASH_ERROR"


# ---------------------------------------------------------------------------
# Cross-environment / path
# ---------------------------------------------------------------------------


class EnvironmentMismatchPlatformError(PlatformError):
    """Platform reported chain_network / platform_instance_id mismatch.

    Mirrors the subnet-side :class:`prometheon.identity.errors.EnvironmentMismatchError`
    but kept distinct so callers can distinguish "we caught it locally"
    from "the platform caught it". The renderer uses this distinction to
    pick the right remediation path.

    Wire ``details`` shape:
    ``{expected_chain_network: str, expected_platform_instance_id: str}``.
    """

    code = "ENVIRONMENT_MISMATCH"


class PathMismatchError(PlatformError):
    code = "PATH_MISMATCH"


# ---------------------------------------------------------------------------
# Signature primitives — the five granular codes that exhaustively cover
# every signature-failure path. Inherit from a shared abstract base so a
# caller can ``except SignaturePlatformError`` to catch the whole family
# without enumerating each concrete class.
# ---------------------------------------------------------------------------


class SignaturePlatformError(PlatformError):
    """Abstract base for every platform-side ``signature.*`` wire code.

    Never instantiated directly and intentionally absent from
    :data:`_CATALOG` (the catalog maps wire codes to concrete classes;
    this base has no wire code of its own). Exists only so callers can
    write ``except SignaturePlatformError`` to catch any signature-family
    error without enumerating the five concrete subclasses.
    """

    # Empty string keeps mypy happy without registering the base in the
    # catalog. ``platform_error_from_response_body`` resolves on the
    # concrete subclass codes; this base never matches a wire payload.
    code = ""


class SignatureInvalidFormatError(SignaturePlatformError):
    code = "signature.invalid_format"


class SignatureUnsupportedKeyTypeError(SignaturePlatformError):
    code = "signature.unsupported_key_type"


class SignatureVerificationFailedError(SignaturePlatformError):
    code = "signature.verification_failed"


class SignatureAddressMismatchError(SignaturePlatformError):
    code = "signature.address_mismatch"


class SignatureDomainMismatchError(SignaturePlatformError):
    """Wire ``details`` shape: ``{expected_domain: 'PROMETHEON_*_V1'}``."""

    code = "signature.domain_mismatch"


# ---------------------------------------------------------------------------
# Generic fall-throughs
# ---------------------------------------------------------------------------


class PlatformUnauthorizedError(PlatformError):
    """4xx that does not match a more specific catalogued code."""

    code = "PLATFORM_UNAUTHORIZED"


class PlatformBadRequestError(PlatformError):
    """4xx that the server reported without a known error code."""

    code = "PLATFORM_BAD_REQUEST"


class PlatformServerError(PlatformError):
    """5xx returned by the platform."""

    code = "PLATFORM_SERVER_ERROR"


# ---------------------------------------------------------------------------
# Catalog and response mapping
# ---------------------------------------------------------------------------


# Maps the wire ``code`` string to its concrete exception class. The
# abstract :class:`SignaturePlatformError` is intentionally omitted — only
# concrete codes that can appear on the wire are catalogued. The three
# generic bucket classes are also omitted; they are produced by
# :func:`_generic_for_status` directly when no specific code is available.
_CATALOG: dict[str, type[PlatformError]] = {
    cls.code: cls
    for cls in (
        # Identity / authn
        AuthInvalidTokenError,
        AuthTokenScopeMissingError,
        AccountNotVerifiedError,
        AccountLockedOutError,
        # Nonce
        NonceMissingError,
        NonceExpiredError,
        NonceAlreadyUsedError,
        NonceContextMismatchError,
        # Hotkey state
        HotkeyAlreadyLinkedError,
        HotkeyNotLinkedError,
        RotationCooldownActiveError,
        RecoveryCooldownActiveError,
        RecoveryPendingError,
        # Binding-ledger
        ProfileAlreadyHasHotkeyError,
        MinerFanGroupRequiredError,
        ColdkeyOwnershipNotProvenError,
        DiscordHandleMissingError,
        TwoFactorProofInvalidError,
        # Snapshot read
        SnapshotNotReadyError,
        SnapshotModeInvalidError,
        SnapshotDateInvalidError,
        SnapshotAccessDeniedError,
        # Snapshot storage
        SnapshotPageNotFoundError,
        SnapshotStorageAccessDeniedError,
        SnapshotStorageError,
        SnapshotPageHashError,
        # Cross-environment / path
        EnvironmentMismatchPlatformError,
        PathMismatchError,
        # Signature primitives
        SignatureInvalidFormatError,
        SignatureUnsupportedKeyTypeError,
        SignatureVerificationFailedError,
        SignatureAddressMismatchError,
        SignatureDomainMismatchError,
    )
}


def exception_for_code(code: str) -> type[PlatformError]:
    """Return the exception class for a given on-wire error code.

    Unknown codes fall through to :class:`PlatformError` so the caller
    still raises something useful.
    """
    return _CATALOG.get(code, PlatformError)


def platform_error_from_response_body(
    body: Any,
    *,
    status_code: int,
) -> PlatformError:
    """Build the matching :class:`PlatformError` from a decoded response body.

    The body is expected to be a dict with ``code`` and optional
    ``message`` / ``details`` keys, matching the platform's error
    envelope. The ``code`` is shape-validated against a strict regex
    before lookup so a malicious or buggy server cannot inject terminal
    control sequences via the operator-facing trailer; the ``details``
    dict is sanitised against the privacy backstop key list at parse
    time so cross-user PII can never reach the renderer (or the
    validator's on-disk event log).

    When the body does not match the envelope shape, the raw body is
    preserved in ``detail`` so debugging is never blind.
    """
    if isinstance(body, dict):
        body_dict = cast(dict[str, Any], body)
        code = body_dict.get("code")
        message = body_dict.get("message")
        details_raw = body_dict.get("details")
        if isinstance(code, str) and _CODE_PATTERN.match(code):
            cls = exception_for_code(code)
            return cls(
                status_code=status_code,
                detail=message if isinstance(message, str) else None,
                details=_sanitise_details(details_raw if isinstance(details_raw, dict) else None),
                wire_code=code,
            )
        if isinstance(code, str):
            # Wire returned a ``code`` whose shape we refuse to display
            # verbatim. Preserve it in ``detail`` (truncated) so the
            # operator can still see what the platform said.
            preview = code[:64]
            return _generic_for_status(
                status_code,
                detail=f"platform returned malformed code {preview!r}",
            )
        # Dict body but no ``code`` field — surface the raw body in detail
        # so debugging is not blind.
        raw = _stringify_body(body_dict)
        return _generic_for_status(status_code, detail=raw)

    if isinstance(body, str) and body:
        return _generic_for_status(status_code, detail=body[:500])

    return _generic_for_status(
        status_code,
        detail=f"empty {status_code} response from platform",
    )


def _stringify_body(body: dict[str, Any]) -> str:
    """Compact-stringify an arbitrary response body for inclusion in error detail."""
    text = repr(body)
    return text if len(text) <= 500 else text[:497] + "..."


def _generic_for_status(status_code: int, *, detail: str) -> PlatformError:
    """Return the generic 4xx / 5xx bucket exception with the given detail."""
    if 500 <= status_code < 600:
        return PlatformServerError(status_code=status_code, detail=detail)
    return PlatformBadRequestError(status_code=status_code, detail=detail)


__all__ = [
    "AccountLockedOutError",
    "AccountNotVerifiedError",
    "AuthInvalidTokenError",
    "AuthTokenScopeMissingError",
    "ColdkeyOwnershipNotProvenError",
    "DiscordHandleMissingError",
    "EnvironmentMismatchPlatformError",
    "HotkeyAlreadyLinkedError",
    "HotkeyNotLinkedError",
    "MinerFanGroupRequiredError",
    "NonceAlreadyUsedError",
    "NonceContextMismatchError",
    "NonceExpiredError",
    "NonceMissingError",
    "PathMismatchError",
    "PlatformBadRequestError",
    "PlatformError",
    "PlatformServerError",
    "PlatformUnauthorizedError",
    "ProfileAlreadyHasHotkeyError",
    "RecoveryCooldownActiveError",
    "RecoveryPendingError",
    "RotationCooldownActiveError",
    "SignatureAddressMismatchError",
    "SignatureDomainMismatchError",
    "SignatureInvalidFormatError",
    "SignaturePlatformError",
    "SignatureUnsupportedKeyTypeError",
    "SignatureVerificationFailedError",
    "SnapshotAccessDeniedError",
    "SnapshotDateInvalidError",
    "SnapshotModeInvalidError",
    "SnapshotNotReadyError",
    "SnapshotPageHashError",
    "SnapshotPageNotFoundError",
    "SnapshotStorageAccessDeniedError",
    "SnapshotStorageError",
    "TwoFactorProofInvalidError",
    "exception_for_code",
    "platform_error_from_response_body",
]
