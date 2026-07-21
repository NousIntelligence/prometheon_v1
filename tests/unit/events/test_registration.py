"""Unit tests for ingest-endpoint registration."""

from __future__ import annotations

import httpx
import pytest

from prometheon.events.registration import (
    RegistrationError,
    register_ingest_endpoint,
)

pytestmark = pytest.mark.unit


def _client(handler) -> httpx.Client:  # type: ignore[no-untyped-def]
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestRegistration:
    def test_happy_path(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer tok"
            assert request.url.path == "/api/v1/prometheon/identity/ingest-endpoint"
            return httpx.Response(
                200, json={"endpoint_id": "ep-1", "rotated": False, "unchanged": False}
            )

        result = register_ingest_endpoint(
            base_url="https://platform.test",
            api_token="tok",
            ingest_endpoint_url="https://validator.example/ingest",
            http=_client(handler),
        )
        assert result.endpoint_id == "ep-1"
        assert not result.rotated and not result.unchanged

    def test_rotation_flag_surfaces(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"endpoint_id": "ep-1", "rotated": True, "unchanged": False}
            )

        result = register_ingest_endpoint(
            base_url="https://platform.test",
            api_token="tok",
            ingest_endpoint_url="https://validator.example/ingest",
            http=_client(handler),
        )
        assert result.rotated

    def test_non_https_url_refused_locally(self) -> None:
        with pytest.raises(RegistrationError, match="HTTPS"):
            register_ingest_endpoint(
                base_url="https://platform.test",
                api_token="tok",
                ingest_endpoint_url="http://validator.example/ingest",
                http=_client(lambda _r: httpx.Response(200, json={})),
            )

    def test_platform_error_surfaces_status(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"code": "AUTH_TOKEN_SCOPE_MISSING"})

        with pytest.raises(RegistrationError) as excinfo:
            register_ingest_endpoint(
                base_url="https://platform.test",
                api_token="tok",
                ingest_endpoint_url="https://validator.example/ingest",
                http=_client(handler),
            )
        assert excinfo.value.status_code == 403

    def test_missing_endpoint_id_rejected(self) -> None:
        with pytest.raises(RegistrationError, match="endpoint_id"):
            register_ingest_endpoint(
                base_url="https://platform.test",
                api_token="tok",
                ingest_endpoint_url="https://validator.example/ingest",
                http=_client(lambda _r: httpx.Response(200, json={"ok": True})),
            )
