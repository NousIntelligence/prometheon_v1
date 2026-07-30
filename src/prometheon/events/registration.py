"""Ingest-endpoint registration against the platform identity API.

One authenticated call (long-lived validator token carrying
``ingest:register``): ``POST /identity/ingest-endpoint`` with the public
HTTPS ingest URL. The platform binds the endpoint server-side to the
token's verified hotkey; re-registering the same URL is a no-op and a new
URL rotates atomically.

Both platform wire conventions apply here and are taken from
:mod:`prometheon.platform.wire`: the call carries the environment-binding
headers (without them the platform rejects with ``ENVIRONMENT_MISMATCH``)
and the response rides the success envelope, so ``endpoint_id`` lives
under ``data``, never at the top level. Staging bring-up on 2026-07-22
found this module violating both. The signed-request header set
(hotkey/nonce/timestamp/signature) is *not* required on this endpoint —
bearer token plus the two binding headers is sufficient.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import httpx

from prometheon.platform.wire import (
    bearer_auth_headers,
    describe_error_body,
    is_error_envelope,
    unwrap_success_envelope,
)

INGEST_ENDPOINT_PATH: Final[str] = "/api/v1/prometheon/identity/ingest-endpoint"


class RegistrationError(RuntimeError):
    """The registration call failed; carries the platform's response."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class RegistrationResult:
    endpoint_id: str
    rotated: bool
    unchanged: bool


def _error_description(response: httpx.Response) -> str:
    """Render a failed response, preserving the platform's error code."""
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text
    return describe_error_body(body, status_code=response.status_code)


def register_ingest_endpoint(
    *,
    base_url: str,
    api_token: str,
    ingest_endpoint_url: str,
    chain_network: str,
    platform_instance_id: str,
    http: httpx.Client,
) -> RegistrationResult:
    """Register (or rotate to) ``ingest_endpoint_url``; returns the outcome."""
    if not ingest_endpoint_url.startswith("https://"):
        raise RegistrationError(
            "ingest_endpoint_url must be public HTTPS; the platform's SSRF "
            f"guard refuses anything else (got {ingest_endpoint_url!r})"
        )
    response = http.post(
        base_url.rstrip("/") + INGEST_ENDPOINT_PATH,
        json={"ingest_endpoint_url": ingest_endpoint_url},
        headers=bearer_auth_headers(
            api_token=api_token,
            chain_network=chain_network,
            platform_instance_id=platform_instance_id,
        ),
    )
    if response.status_code not in (200, 201):
        raise RegistrationError(
            f"registration failed: {_error_description(response)}",
            status_code=response.status_code,
        )
    body: Any = response.json()
    if not isinstance(body, dict):
        raise RegistrationError("registration response is not an object")
    if is_error_envelope(body):
        raise RegistrationError(
            f"registration failed: {_error_description(response)}",
            status_code=response.status_code,
        )
    data = unwrap_success_envelope(body)
    if not isinstance(data, dict) or "endpoint_id" not in data:
        raise RegistrationError("registration response missing endpoint_id")
    return RegistrationResult(
        endpoint_id=str(data["endpoint_id"]),
        rotated=bool(data.get("rotated", False)),
        unchanged=bool(data.get("unchanged", False)),
    )


__all__ = [
    "INGEST_ENDPOINT_PATH",
    "RegistrationError",
    "RegistrationResult",
    "register_ingest_endpoint",
]
