"""Platform-side error catalog and HTTP response mapping.

The BitFan platform returns errors as a small JSON envelope::

    {"error": "<CODE>", "detail": "<human readable message>"}

This module defines:

- :class:`PlatformError` and its hierarchy — a Python exception per error
  code the platform may return. Every exception carries a stable ``code``
  string, an optional HTTP ``status_code``, and an optional ``detail``
  message.
- :func:`platform_error_from_response` — maps an ``httpx.Response`` whose
  status is ``>= 400`` to the matching exception (or to a generic
  :class:`PlatformError` if the code is unknown).

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

    The body is expected to be a dict with ``error`` and optional
    ``detail`` keys, matching the platform's error envelope. Bodies that
    do not match the envelope shape are wrapped in a generic
    :class:`PlatformBadRequestError` (for 4xx) or
    :class:`PlatformServerError` (for 5xx).
    """
    if isinstance(body, dict):
        body_dict = cast(dict[str, Any], body)
        code = body_dict.get("error")
        detail = body_dict.get("detail")
        if isinstance(code, str):
            cls = exception_for_code(code)
            return cls(
                status_code=status_code,
                detail=detail if isinstance(detail, str) else None,
            )

    # The response did not match the canonical error envelope. Categorise
    # by status code so callers can still react meaningfully.
    if 500 <= status_code < 600:
        return PlatformServerError(
            status_code=status_code,
            detail=f"unexpected {status_code} response from platform",
        )
    return PlatformBadRequestError(
        status_code=status_code,
        detail=f"unexpected {status_code} response from platform",
    )


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
