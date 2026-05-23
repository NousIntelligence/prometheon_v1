"""Platform-side error catalog and HTTP response mapping.

The BitFan platform returns errors as a small JSON envelope::

    {"code": "<CODE>", "message": "<human readable message>"}

This module defines:

- :class:`PlatformError` and its hierarchy — a Python exception per error
  code the platform may return. Every exception carries a stable ``code``
  string, an optional HTTP ``status_code``, and an optional ``detail``
  message (the platform's ``message`` field).
- :func:`platform_error_from_response_body` — maps a decoded response
  body to the matching exception (or to a generic :class:`PlatformError`
  if the code is unknown). When the body does not match the canonical
  envelope, the raw body is preserved in ``detail`` so the operator
  still sees what the platform actually said.

The exception hierarchy follows the error catalog in the consolidated
specification §16.1. New codes added by future platform releases fall
through to the generic base class until the catalog is extended.
"""

from __future__ import annotations

from typing import Any, ClassVar, cast


class PlatformError(Exception):
    """Base exception for any error returned by the BitFan platform API.

    Subclasses carry a stable :attr:`code` matching the on-wire error
    string. The :attr:`status_code` is filled in when constructed from an
    HTTP response; the :attr:`detail` field carries the platform's
    human-readable message.
    """

    code: ClassVar[str] = "PLATFORM_ERROR"

    def __init__(
        self,
        message: str | None = None,
        *,
        status_code: int | None = None,
        detail: str | None = None,
    ) -> None:
        # Compose a clear default message if the caller passes nothing so
        # ``str(exc)`` is always useful in logs.
        display = message or detail or f"platform returned {self.code}"
        super().__init__(display)
        self.status_code = status_code
        self.detail = detail


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------


class AuthInvalidTokenError(PlatformError):
    code = "AUTH_INVALID_TOKEN"


class AuthTokenScopeMissingError(PlatformError):
    code = "AUTH_TOKEN_SCOPE_MISSING"


class AccountNotVerifiedError(PlatformError):
    code = "ACCOUNT_NOT_VERIFIED"


class AccountLockedOutError(PlatformError):
    code = "ACCOUNT_LOCKED_OUT"


# ---------------------------------------------------------------------------
# Nonce / signature
# ---------------------------------------------------------------------------


class NonceMissingError(PlatformError):
    code = "NONCE_MISSING"


class NonceExpiredError(PlatformError):
    code = "NONCE_EXPIRED"


class NonceAlreadyUsedError(PlatformError):
    code = "NONCE_ALREADY_USED"


class NonceContextMismatchError(PlatformError):
    code = "NONCE_CONTEXT_MISMATCH"


class SignatureInvalidError(PlatformError):
    code = "SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# Hotkey state
# ---------------------------------------------------------------------------


class HotkeyAlreadyLinkedError(PlatformError):
    code = "HOTKEY_ALREADY_LINKED"


class HotkeyNotLinkedError(PlatformError):
    code = "HOTKEY_NOT_LINKED"


class RotationCooldownActiveError(PlatformError):
    code = "ROTATION_COOLDOWN_ACTIVE"


class RecoveryCooldownActiveError(PlatformError):
    code = "RECOVERY_COOLDOWN_ACTIVE"


class RecoveryPendingError(PlatformError):
    code = "RECOVERY_PENDING"


# ---------------------------------------------------------------------------
# Snapshot
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
# Cross-environment / path
# ---------------------------------------------------------------------------


class EnvironmentMismatchPlatformError(PlatformError):
    """Platform reported chain_network / platform_instance_id mismatch.

    Mirrors the subnet-side ``EnvironmentMismatchError`` from
    :mod:`prometheon.identity.errors` but kept distinct so callers can
    distinguish "we caught it locally" from "the platform caught it".
    """

    code = "ENVIRONMENT_MISMATCH"


class PathMismatchError(PlatformError):
    code = "PATH_MISMATCH"


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


_CATALOG: dict[str, type[PlatformError]] = {
    cls.code: cls
    for cls in (
        AuthInvalidTokenError,
        AuthTokenScopeMissingError,
        AccountNotVerifiedError,
        AccountLockedOutError,
        NonceMissingError,
        NonceExpiredError,
        NonceAlreadyUsedError,
        NonceContextMismatchError,
        SignatureInvalidError,
        HotkeyAlreadyLinkedError,
        HotkeyNotLinkedError,
        RotationCooldownActiveError,
        RecoveryCooldownActiveError,
        RecoveryPendingError,
        SnapshotNotReadyError,
        SnapshotModeInvalidError,
        SnapshotDateInvalidError,
        SnapshotAccessDeniedError,
        EnvironmentMismatchPlatformError,
        PathMismatchError,
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
    ``message`` keys, matching the platform's error envelope. When the
    body does not match the envelope shape, the raw body is included in
    ``detail`` so operators can still see what the platform actually
    said instead of a generic ``"unexpected NNN"`` message.
    """
    if isinstance(body, dict):
        body_dict = cast(dict[str, Any], body)
        code = body_dict.get("code")
        message = body_dict.get("message")
        if isinstance(code, str):
            cls = exception_for_code(code)
            return cls(
                status_code=status_code,
                detail=message if isinstance(message, str) else None,
            )
        # Dict body but no canonical ``code`` field — surface the raw
        # body in detail so debugging is not blind.
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
    "EnvironmentMismatchPlatformError",
    "HotkeyAlreadyLinkedError",
    "HotkeyNotLinkedError",
    "NonceAlreadyUsedError",
    "NonceContextMismatchError",
    "NonceExpiredError",
    "NonceMissingError",
    "PathMismatchError",
    "PlatformBadRequestError",
    "PlatformError",
    "PlatformServerError",
    "PlatformUnauthorizedError",
    "RecoveryCooldownActiveError",
    "RecoveryPendingError",
    "RotationCooldownActiveError",
    "SignatureInvalidError",
    "SnapshotAccessDeniedError",
    "SnapshotDateInvalidError",
    "SnapshotModeInvalidError",
    "SnapshotNotReadyError",
    "exception_for_code",
    "platform_error_from_response_body",
]
