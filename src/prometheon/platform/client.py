"""Typed HTTP client for the BitFan platform API.

The client has two distinct response patterns:

- **Identity flows** (``request_nonce``, ``post_identity_envelope``) use only
  the ``Authorization: Bearer`` header. The crypto proof lives inside the
  envelope body the caller already constructed (hotkey signatures, coldkey
  signatures, etc.) and the Platform verifies them server-side.
- **Snapshot flows** (``get_aggregate_snapshot``, ``get_detailed_manifest``,
  ``get_detailed_page``) additionally sign the request itself with
  :class:`prometheon.platform.schemas.ApiRequestPayload` under the
  ``PROMETHEON_API_REQUEST_V1`` domain. The signature is sent in the
  ``X-Prometheon-Request-Signature`` header so the Platform can bind the
  HTTP request to the validator hotkey.

The client returns already-parsed Pydantic models. It does **not** verify
snapshot signatures, ``records_hash``, or ``page_hash`` — those live in
:mod:`prometheon.platform.signing`. The runner composes the two: client to
fetch, signing to verify, mechanism engine to consume.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import TracebackType
from typing import Any, Final

import httpx
from bittensor_wallet import Keypair
from pydantic import BaseModel
from typing_extensions import Self

from prometheon.identity.roles import ChainNetwork, Role
from prometheon.platform.endpoints import (
    LATEST,
    NONCE_PATH,
    RECOVER_HOTKEY_PATH,
    ROTATE_HOTKEY_PATH,
    VERIFY_PATH,
    SnapshotMode,
    aggregate_path,
    detailed_manifest_path,
    detailed_page_path,
)
from prometheon.platform.errors import platform_error_from_response_body
from prometheon.platform.schemas import (
    AggregateSnapshot,
    ApiRequestPayload,
    DetailedManifest,
    DetailedPage,
    NonceRequestBody,
)
from prometheon.security.canonical import DOMAIN_API_REQUEST
from prometheon.security.hashes import EMPTY_SHA256_HEX, api_token_hash, body_hash
from prometheon.security.nonce import generate_api_request_nonce
from prometheon.security.signatures import sign_with_bittensor_keypair

# Per consolidated specification §17.1.
_DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
_CLIENT_NAME: Final[str] = "prometheon-cli"


class BitFanClient:
    """Typed HTTP client wrapping the BitFan platform API.

    Construct one client per (base_url, api_token, validator_keypair) tuple
    — typically once at CLI / validator startup — and reuse it across calls.
    The underlying :class:`httpx.Client` is created lazily and closed when
    the BitFanClient is closed or used as a context manager.

    Parameters
    ----------
    base_url:
        Platform API root, for example ``"https://api.bitfan.example"``.
    api_token:
        Raw API token; sent verbatim in ``Authorization: Bearer``. The hash
        of the token is bound to every signed request payload.
    platform_instance_id:
        Stable Platform environment identifier, as configured in
        ``[platform]`` config. Included in every signed request payload.
    chain_network:
        Bittensor chain environment. Included in every signed request payload.
    netuid:
        Subnet number. Included in every signed request payload.
    validator_keypair:
        SR25519 keypair used to sign snapshot API requests. Required for
        snapshot flows; may be ``None`` if the client is only used for
        identity flows.
    role:
        :class:`Role` used in the signed request payload. Required when
        ``validator_keypair`` is supplied; ignored otherwise.
    timeout_seconds:
        Per-request HTTP timeout. Defaults to 30 s.
    http_client:
        Optional pre-built :class:`httpx.Client` for tests; if ``None`` the
        client constructs and owns its own.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        platform_instance_id: str,
        chain_network: ChainNetwork,
        netuid: int,
        validator_keypair: Keypair | None = None,
        role: Role | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        if validator_keypair is not None and role is None:
            raise ValueError("role must be supplied when validator_keypair is provided")

        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._api_token_hash = api_token_hash(api_token)
        self._platform_instance_id = platform_instance_id
        self._chain_network = chain_network
        self._netuid = netuid
        self._validator_keypair = validator_keypair
        self._role = role
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout_seconds)

    # -----------------------------------------------------------------
    # Context-manager / lifecycle
    # -----------------------------------------------------------------

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client if the BitFanClient owns it."""
        if self._owns_client:
            self._http.close()

    # -----------------------------------------------------------------
    # Identity flows (no API request signature required)
    # -----------------------------------------------------------------

    def request_nonce(self, body: NonceRequestBody) -> dict[str, Any]:
        """``POST /v1/prometheon/identity/nonce``.

        Returns the raw response JSON. The caller is expected to validate
        it via :class:`prometheon.identity.payloads.NonceResponse`.
        """
        return self._post_json(NONCE_PATH, body=body.model_dump(mode="json"))

    def post_identity_envelope(self, envelope: BaseModel, *, endpoint: str) -> dict[str, Any]:
        """``POST`` a signed identity / rotation / recovery envelope.

        The ``endpoint`` argument must be one of the identity endpoint
        constants (``VERIFY_PATH``, ``ROTATE_HOTKEY_PATH``,
        ``RECOVER_HOTKEY_PATH``) or a custom path on the same authority.
        """
        return self._post_json(endpoint, body=envelope.model_dump(mode="json"))

    def post_verify_envelope(self, envelope: BaseModel) -> dict[str, Any]:
        """Convenience wrapper around ``post_identity_envelope`` for verify."""
        return self.post_identity_envelope(envelope, endpoint=VERIFY_PATH)

    def post_rotation_envelope(self, envelope: BaseModel) -> dict[str, Any]:
        """Convenience wrapper for hotkey-rotation envelopes."""
        return self.post_identity_envelope(envelope, endpoint=ROTATE_HOTKEY_PATH)

    def post_recovery_envelope(self, envelope: BaseModel) -> dict[str, Any]:
        """Convenience wrapper for hotkey-recovery envelopes."""
        return self.post_identity_envelope(envelope, endpoint=RECOVER_HOTKEY_PATH)

    # -----------------------------------------------------------------
    # Snapshot flows (require API request signature)
    # -----------------------------------------------------------------

    def get_aggregate_snapshot(self, activity_date: str = LATEST) -> AggregateSnapshot:
        """``GET /v1/prometheon/phase1/snapshots/{activity_date}/aggregate``."""
        path = aggregate_path(activity_date)
        raw = self._signed_get_json(path, mode=SnapshotMode.AGGREGATE)
        return AggregateSnapshot.model_validate(raw)

    def get_detailed_manifest(self, activity_date: str = LATEST) -> DetailedManifest:
        """``GET /v1/prometheon/phase1/snapshots/{activity_date}/detailed/manifest``."""
        path = detailed_manifest_path(activity_date)
        raw = self._signed_get_json(path, mode=SnapshotMode.DETAILED)
        return DetailedManifest.model_validate(raw)

    def get_detailed_page(self, activity_date: str, page_index: int) -> DetailedPage:
        """``GET /v1/prometheon/phase1/snapshots/{activity_date}/detailed/pages/{N}``."""
        path = detailed_page_path(activity_date, page_index)
        raw = self._signed_get_json(path, mode=SnapshotMode.DETAILED)
        return DetailedPage.model_validate(raw)

    # -----------------------------------------------------------------
    # Internal HTTP helpers
    # -----------------------------------------------------------------

    def _post_json(self, path: str, *, body: dict[str, Any]) -> dict[str, Any]:
        """POST a JSON body with the simple bearer-token-only auth header."""
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        response = self._http.post(url, headers=headers, json=body)
        return self._decode_or_raise(response)

    def _signed_get_json(self, path: str, *, mode: SnapshotMode) -> dict[str, Any]:
        """GET with the full set of signed snapshot-API headers."""
        if self._validator_keypair is None or self._role is None:
            raise RuntimeError(
                "signed snapshot GETs require validator_keypair and role; "
                "construct BitFanClient with both"
            )

        nonce = generate_api_request_nonce()
        # ISO 8601 with a literal Z, no fractional seconds — matches the
        # protocol timestamp profile in consolidated specification §10.
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        request_payload = ApiRequestPayload(
            method="GET",
            path=path,
            query_hash=EMPTY_SHA256_HEX,  # snapshot endpoints have no query params
            body_hash=body_hash(b""),
            timestamp=timestamp,
            nonce=nonce,
            chain_network=self._chain_network,
            platform_instance_id=self._platform_instance_id,
            netuid=self._netuid,
            role=self._role,
            mode=mode,
            validator_hotkey=self._validator_keypair.ss58_address,
            api_token_hash=self._api_token_hash,
        )
        signature_hex = sign_with_bittensor_keypair(
            self._validator_keypair,
            DOMAIN_API_REQUEST,
            request_payload.model_dump(mode="json"),
        )

        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
            "X-Prometheon-Hotkey": self._validator_keypair.ss58_address,
            "X-Prometheon-Nonce": nonce,
            "X-Prometheon-Timestamp": timestamp,
            "X-Prometheon-Request-Signature": signature_hex,
            "Client-Name": _CLIENT_NAME,
        }
        url = f"{self._base_url}{path}"
        response = self._http.get(url, headers=headers)
        return self._decode_or_raise(response)

    def _decode_or_raise(self, response: httpx.Response) -> dict[str, Any]:
        """Parse a 2xx JSON body, or raise the matching :class:`PlatformError`."""
        if response.is_success:
            try:
                data = response.json()
            except ValueError as exc:
                from prometheon.platform.errors import PlatformError

                raise PlatformError(
                    f"platform returned 2xx with non-JSON body: {exc}",
                    status_code=response.status_code,
                ) from exc
            if not isinstance(data, dict):
                from prometheon.platform.errors import PlatformError

                raise PlatformError(
                    f"platform returned 2xx with non-object JSON body: {type(data).__name__}",
                    status_code=response.status_code,
                )
            return data

        # On error, attempt to decode the structured error envelope.
        body: Any = None
        try:
            body = response.json()
        except ValueError:
            body = response.text
        raise platform_error_from_response_body(body, status_code=response.status_code)


__all__ = ["BitFanClient"]
