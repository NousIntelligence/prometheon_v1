"""Ingest-endpoint registration against the platform identity API.

One authenticated call (long-lived validator token carrying
``ingest:register``): ``POST /identity/ingest-endpoint`` with the public
HTTPS ingest URL. The platform binds the endpoint server-side to the
token's verified hotkey; re-registering the same URL is a no-op and a new
URL rotates atomically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import httpx

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


def register_ingest_endpoint(
    *,
    base_url: str,
    api_token: str,
    ingest_endpoint_url: str,
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
        headers={"Authorization": f"Bearer {api_token}"},
    )
    if response.status_code not in (200, 201):
        raise RegistrationError(
            f"registration returned HTTP {response.status_code}: {response.text[:300]}",
            status_code=response.status_code,
        )
    body: Any = response.json()
    if not isinstance(body, dict) or "endpoint_id" not in body:
        raise RegistrationError("registration response missing endpoint_id")
    return RegistrationResult(
        endpoint_id=str(body["endpoint_id"]),
        rotated=bool(body.get("rotated", False)),
        unchanged=bool(body.get("unchanged", False)),
    )


__all__ = [
    "INGEST_ENDPOINT_PATH",
    "RegistrationError",
    "RegistrationResult",
    "register_ingest_endpoint",
]
