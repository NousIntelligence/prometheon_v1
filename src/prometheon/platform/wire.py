"""The BitFan platform's two universal wire conventions, in one place.

Every module that speaks HTTP to the platform — whether through
:class:`~prometheon.platform.client.BitFanClient` or with its own injected
``httpx.Client`` — owes the API the same two things. They are collected
here so a new call site can adopt both by importing them, and so a
reviewer can grep one module to audit compliance.

**1. Environment binding.** Every *authenticated* request carries

- ``X-Prometheon-Chain-Network`` — ``test`` / ``finney`` / ``local``
- ``X-Prometheon-Platform-Instance-Id`` — ``bitfan-staging`` / …

The platform's env guard rejects a request that omits either with HTTP
400 ``ENVIRONMENT_MISMATCH``. The headers are what stop a testnet
validator from ever reading or writing production state.

The guard reads the binding from the request *body* when the body carries
it — the signed verify/rotate/recover envelopes each contain
``chain_network`` and ``platform_instance_id`` fields, which is why those
POSTs pass with a bearer header alone. Every other shape must supply the
headers: GETs have no body (snapshot API, event read API), and POSTs whose
body is not a signed envelope do not carry the fields (ingest-endpoint
registration). Default to sending them; the only endpoint that takes no
authentication at all today is ``GET /keys``.

Some endpoints additionally require the *signed-request* header set
(``X-Prometheon-Hotkey`` / ``-Nonce`` / ``-Timestamp`` /
``-Request-Signature``) — the snapshot API does. That signature is built
in :mod:`prometheon.platform.signing`; binding headers are needed either
way, and are covered by the signature when both are present.

**2. Response envelopes.** Every response body is wrapped:

- success — ``{"success": true, "data": {…}, "meta": {…}}``
- error — ``{"success": false, "error": {"code", "message", "details"?}}``

Payload fields are never at the top level. Read them through
:func:`unwrap_success_envelope`; render failures through
:func:`describe_error_body`, which keeps the platform's ``code`` in the
message — that string is usually the whole diagnosis for an operator.

Both conventions were learned the hard way: two separate modules shipped
with hand-rolled header dicts and ``response.json()`` used verbatim, and
both were dead on arrival against the live API while unit tests passed.
Mocked transports must therefore reproduce the envelope exactly and
assert the outgoing headers, or they certify nothing.
"""

from __future__ import annotations

from typing import Any, Final

CHAIN_NETWORK_HEADER: Final[str] = "X-Prometheon-Chain-Network"
PLATFORM_INSTANCE_ID_HEADER: Final[str] = "X-Prometheon-Platform-Instance-Id"

_ERROR_TEXT_LIMIT: Final[int] = 300


def environment_binding_headers(
    *,
    chain_network: str,
    platform_instance_id: str,
) -> dict[str, str]:
    """The two env-binding headers every authenticated call must carry."""
    return {
        CHAIN_NETWORK_HEADER: chain_network,
        PLATFORM_INSTANCE_ID_HEADER: platform_instance_id,
    }


def bearer_auth_headers(
    *,
    api_token: str,
    chain_network: str,
    platform_instance_id: str,
) -> dict[str, str]:
    """Header set for a token-authenticated call: bearer + env binding.

    Sufficient on its own for the endpoints that authenticate by token
    alone (ingest-endpoint registration, the event read API). Endpoints
    that also demand a request signature add those headers on top.
    """
    return {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        **environment_binding_headers(
            chain_network=chain_network,
            platform_instance_id=platform_instance_id,
        ),
    }


def unwrap_success_envelope(body: dict[str, Any]) -> Any:
    """Return ``body['data']`` if ``body`` is the platform's success envelope.

    A success envelope is ``{"success": True, "data": {...}, "meta": {...}}``.
    Bodies that do not match the envelope shape are returned unchanged so
    plain-shaped responses (if any future endpoint bypasses the
    interceptor) still flow through unmodified.
    """
    if body.get("success") is True and "data" in body:
        return body["data"]
    return body


def unwrap_error_envelope(body: dict[str, Any]) -> dict[str, Any]:
    """Return ``body['error']`` if ``body`` is the platform's error envelope.

    An error envelope is ``{"success": False, "error": {"code": "...", "message": "..."}}``.
    Bodies that do not match the envelope shape are returned unchanged so
    callers can still surface them.
    """
    error = body.get("error")
    if body.get("success") is False and isinstance(error, dict):
        return error
    return body


def is_error_envelope(body: Any) -> bool:
    """True when a body explicitly declares failure (``success: false``).

    Worth checking even on a 2xx: an envelope that says ``success: false``
    must never be mistaken for a payload just because the status line was
    friendly.
    """
    return isinstance(body, dict) and body.get("success") is False


def describe_error_body(body: Any, *, status_code: int) -> str:
    """One-line, operator-facing description of a failed platform call.

    Keeps the platform's error ``code`` in the message — ``ENVIRONMENT_MISMATCH``
    or ``INSUFFICIENT_SCOPE`` names the fix, where a bare status code sends
    the reader to a packet capture. Falls back to truncated body text for
    non-enveloped or non-JSON responses.
    """
    if isinstance(body, dict):
        error = unwrap_error_envelope(body)
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message")
            if isinstance(code, str) and isinstance(message, str):
                return f"HTTP {status_code} {code}: {message}"
            if isinstance(code, str):
                return f"HTTP {status_code} {code}"
    text = body if isinstance(body, str) else repr(body)
    return f"HTTP {status_code}: {text[:_ERROR_TEXT_LIMIT]}"


__all__ = [
    "CHAIN_NETWORK_HEADER",
    "PLATFORM_INSTANCE_ID_HEADER",
    "bearer_auth_headers",
    "describe_error_body",
    "environment_binding_headers",
    "is_error_envelope",
    "unwrap_error_envelope",
    "unwrap_success_envelope",
]
