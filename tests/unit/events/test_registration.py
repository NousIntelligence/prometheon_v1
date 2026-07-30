"""Unit tests for ingest-endpoint registration.

These tests encode the wire truth learned in staging bring-up: the call
must carry the two environment-binding headers, and the platform wraps
every response in the standard success/error envelope — the mock
responses here use the real enveloped shapes, and the outgoing request's
headers are asserted, so a transport-layer regression fails loudly
instead of passing against an imaginary API.
"""

from __future__ import annotations

import json

import httpx
import pytest

from prometheon.events.registration import (
    RegistrationError,
    RegistrationResult,
    register_ingest_endpoint,
)

pytestmark = pytest.mark.unit


def _register(handler) -> RegistrationResult:  # type: ignore[no-untyped-def]
    return register_ingest_endpoint(
        base_url="https://platform.test",
        api_token="tok",
        ingest_endpoint_url="https://validator.example/ingest",
        chain_network="test",
        platform_instance_id="bitfan-staging",
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def _enveloped(data: dict[str, object]) -> dict[str, object]:
    return {"success": True, "data": data, "meta": {}}


class TestRegistration:
    def test_sends_binding_headers_and_unwraps_envelope(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer tok"
            # The environment-binding headers are REQUIRED — omitting them
            # is the exact bug staging bring-up hit (ENVIRONMENT_MISMATCH).
            assert request.headers["X-Prometheon-Chain-Network"] == "test"
            assert request.headers["X-Prometheon-Platform-Instance-Id"] == "bitfan-staging"
            assert request.url.path == "/api/v1/prometheon/identity/ingest-endpoint"
            return httpx.Response(
                200,
                json=_enveloped({"endpoint_id": "ep-1", "rotated": False, "unchanged": False}),
            )

        result = _register(handler)
        assert result.endpoint_id == "ep-1"
        assert not result.rotated and not result.unchanged

    def test_sends_the_binding_in_the_body_too(self) -> None:
        """r4 §2: the two environment fields are REQUIRED in the body.

        The headers are what staging accepted before r4 documented the
        body form; the guard reads either, so we send both.
        """
        seen: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(json.loads(request.content))
            return httpx.Response(
                200,
                json=_enveloped({"endpoint_id": "ep-1", "rotated": False, "unchanged": False}),
            )

        _register(handler)
        assert seen["ingest_endpoint_url"] == "https://validator.example/ingest"
        assert seen["chain_network"] == "test"
        assert seen["platform_instance_id"] == "bitfan-staging"

    def test_rotation_flag_surfaces_from_envelope(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_enveloped({"endpoint_id": "ep-1", "rotated": True, "unchanged": False}),
            )

        assert _register(handler).rotated

    def test_unchanged_noop_surfaces_from_envelope(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_enveloped({"endpoint_id": "ep-1", "rotated": False, "unchanged": True}),
            )

        assert _register(handler).unchanged

    def test_non_https_url_refused_locally(self) -> None:
        with pytest.raises(RegistrationError, match="HTTPS"):
            register_ingest_endpoint(
                base_url="https://platform.test",
                api_token="tok",
                ingest_endpoint_url="http://validator.example/ingest",
                chain_network="test",
                platform_instance_id="bitfan-staging",
                http=httpx.Client(
                    transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
                ),
            )

    def test_environment_mismatch_error_surfaces_status_and_code(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400,
                json={
                    "success": False,
                    "error": {
                        "code": "ENVIRONMENT_MISMATCH",
                        "message": "Missing chain_network / platform_instance_id binding.",
                    },
                },
            )

        with pytest.raises(RegistrationError) as excinfo:
            _register(handler)
        assert excinfo.value.status_code == 400
        assert "ENVIRONMENT_MISMATCH" in str(excinfo.value)

    def test_missing_endpoint_id_in_data_rejected(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_enveloped({"ok": True}))

        with pytest.raises(RegistrationError, match="endpoint_id"):
            _register(handler)

    def test_unenveloped_body_missing_endpoint_id_rejected(self) -> None:
        # Defensive: a bare body without the envelope and without the field.
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True})

        with pytest.raises(RegistrationError, match="endpoint_id"):
            _register(handler)
