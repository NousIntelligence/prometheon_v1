"""Unit tests for ``prometheon.platform.client``.

Uses :class:`httpx.MockTransport` to intercept outgoing requests and
return controlled responses. The tests assert that the client emits the
right URL, the right headers (including the SR25519-signed
``X-Prometheon-Request-Signature``), and parses 2xx and 4xx/5xx responses
correctly.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from bittensor_wallet import Keypair

from prometheon.identity.roles import ChainNetwork, Role
from prometheon.platform.client import BitFanClient
from prometheon.platform.endpoints import NONCE_PATH, VERIFY_PATH, SnapshotMode
from prometheon.platform.errors import (
    AuthInvalidTokenError,
    NonceExpiredError,
    PlatformServerError,
    SnapshotNotReadyError,
)
from prometheon.platform.schemas import (
    AggregateSnapshot,
    ApiRequestPayload,
    DetailedManifest,
    DetailedPage,
    NonceRequestBody,
)
from prometheon.security.canonical import DOMAIN_API_REQUEST
from prometheon.security.hashes import api_token_hash
from prometheon.security.signatures import verify_bittensor_signature

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


API_TOKEN = "pmt_test_token_abcdef"
BASE_URL = "https://api.bitfan.test"
PLATFORM_INSTANCE_ID = "bitfan-test"
NETUID = 123
SS58_A = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
SS58_B = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
SS58_C = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
VALID_HEX32 = "0x" + "ab" * 32
VALID_HEX_SIG = "0x" + "cd" * 64


@pytest.fixture
def alice_keypair() -> Keypair:
    return Keypair.create_from_uri("//Alice")


def _make_client(
    *,
    transport: httpx.MockTransport,
    validator_keypair: Keypair | None = None,
    role: Role | None = None,
) -> BitFanClient:
    http_client = httpx.Client(transport=transport, timeout=5.0)
    return BitFanClient(
        base_url=BASE_URL,
        api_token=API_TOKEN,
        platform_instance_id=PLATFORM_INSTANCE_ID,
        chain_network=ChainNetwork.FINNEY,
        netuid=NETUID,
        validator_keypair=validator_keypair,
        role=role,
        http_client=http_client,
    )


def _ok_json(payload: dict[str, Any], status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _error_json(
    error_code: str, *, status_code: int, detail: str = "test detail"
) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=json.dumps({"code": error_code, "message": detail}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


class TestConstructorValidation:
    def test_role_required_when_keypair_provided(self, alice_keypair: Keypair) -> None:
        with pytest.raises(ValueError, match="role must be supplied"):
            BitFanClient(
                base_url=BASE_URL,
                api_token=API_TOKEN,
                platform_instance_id=PLATFORM_INSTANCE_ID,
                chain_network=ChainNetwork.FINNEY,
                netuid=NETUID,
                validator_keypair=alice_keypair,
                role=None,
            )

    def test_identity_only_client_does_not_require_keypair(self) -> None:
        client = BitFanClient(
            base_url=BASE_URL,
            api_token=API_TOKEN,
            platform_instance_id=PLATFORM_INSTANCE_ID,
            chain_network=ChainNetwork.FINNEY,
            netuid=NETUID,
        )
        client.close()


# ---------------------------------------------------------------------------
# Identity flow tests
# ---------------------------------------------------------------------------


class TestIdentityFlows:
    def test_request_nonce_returns_response_json(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.content)
            return _ok_json(
                {
                    "platform_account_id": "acct_test",
                    "username_hash": VALID_HEX32,
                    "email_hash": VALID_HEX32,
                    "nonce": "nonce_xyz",
                    "issued_at": "2026-05-20T00:00:00Z",
                    "expires_at": "2026-05-20T00:10:00Z",
                }
            )

        transport = httpx.MockTransport(handler)
        with _make_client(transport=transport) as client:
            response = client.request_nonce(
                NonceRequestBody(
                    role=Role.MINER,
                    netuid=NETUID,
                    username="alice",
                    email="alice@example.com",
                    hotkey_ss58=SS58_A,
                )
            )

        assert response["platform_account_id"] == "acct_test"
        assert captured["url"] == f"{BASE_URL}{NONCE_PATH}"
        assert captured["headers"]["authorization"] == f"Bearer {API_TOKEN}"
        assert captured["body"]["role"] == "miner"
        assert captured["body"]["netuid"] == NETUID

    def test_post_identity_envelope_uses_provided_endpoint(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            return _ok_json({"status": "verified"})

        envelope = NonceRequestBody(
            role=Role.MINER,
            netuid=NETUID,
            username="alice",
            email="alice@example.com",
            hotkey_ss58=SS58_A,
        )  # any BaseModel works for the wire test

        transport = httpx.MockTransport(handler)
        with _make_client(transport=transport) as client:
            response = client.post_identity_envelope(envelope, endpoint=VERIFY_PATH)

        assert response["status"] == "verified"
        assert captured["url"] == f"{BASE_URL}{VERIFY_PATH}"
        # Identity flow does NOT add X-Prometheon-* headers; only Authorization.
        assert "x-prometheon-hotkey" not in captured["headers"]
        assert "x-prometheon-request-signature" not in captured["headers"]

    def test_auth_invalid_token_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _error_json("AUTH_INVALID_TOKEN", status_code=401)

        transport = httpx.MockTransport(handler)
        with (
            _make_client(transport=transport) as client,
            pytest.raises(AuthInvalidTokenError) as exc_info,
        ):
            client.request_nonce(
                NonceRequestBody(
                    role=Role.MINER,
                    netuid=NETUID,
                    username="alice",
                    email="alice@example.com",
                    hotkey_ss58=SS58_A,
                )
            )
        assert exc_info.value.status_code == 401

    def test_nonce_expired_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _error_json("NONCE_EXPIRED", status_code=400)

        envelope = NonceRequestBody(
            role=Role.MINER,
            netuid=NETUID,
            username="alice",
            email="alice@example.com",
            hotkey_ss58=SS58_A,
        )
        transport = httpx.MockTransport(handler)
        with _make_client(transport=transport) as client, pytest.raises(NonceExpiredError):
            client.post_verify_envelope(envelope)


# ---------------------------------------------------------------------------
# Snapshot flow tests
# ---------------------------------------------------------------------------


def _aggregate_response_dict() -> dict[str, Any]:
    """Build a minimal valid aggregate snapshot response dict.

    The signature and records_hash here are placeholders; the client does
    not verify them — that happens in signing.py.
    """
    return {
        "domain": "PROMETHEON_SNAPSHOT_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "mode": "aggregate",
        "snapshot_id": "phase1:2026-05-18:aggregate",
        "chain_network": "finney",
        "platform_instance_id": "bitfan-test",
        "netuid": NETUID,
        "activity_date": "2026-05-18",
        "generated_at": "2026-05-19T00:20:31Z",
        "window_start_date": "2026-05-05",
        "window_end_date": "2026-05-18",
        "daily_score_cap": 20,
        "active_member_score_threshold": 50,
        "min_active_members_for_reward": 3,
        "top_k": 10,
        "burn_hotkey": SS58_C,
        "manual_burn_rate_ppm": 0,
        "platform_key_id": "platform-test",
        "records_hash": VALID_HEX32,
        "miners": [
            {
                "miner_hotkey": SS58_A,
                "miner_score_points": 100,
                "active_member_count": 5,
            },
            {
                "miner_hotkey": SS58_B,
                "miner_score_points": 200,
                "active_member_count": 8,
            },
        ],
        "platform_signature": VALID_HEX_SIG,
    }


class TestSnapshotFlows:
    def test_get_aggregate_snapshot_returns_parsed_model(self, alice_keypair: Keypair) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            return _ok_json(_aggregate_response_dict())

        transport = httpx.MockTransport(handler)
        with _make_client(
            transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
        ) as client:
            snapshot = client.get_aggregate_snapshot()

        assert isinstance(snapshot, AggregateSnapshot)
        assert snapshot.mode == "aggregate"
        # URL must include "latest" (the default).
        assert captured["url"] == (
            f"{BASE_URL}/api/v1/prometheon/phase1/snapshots/latest/aggregate"
        )

    def test_signed_get_includes_all_required_headers(self, alice_keypair: Keypair) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return _ok_json(_aggregate_response_dict())

        transport = httpx.MockTransport(handler)
        with _make_client(
            transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
        ) as client:
            client.get_aggregate_snapshot()

        headers = captured["headers"]
        assert headers["authorization"] == f"Bearer {API_TOKEN}"
        assert headers["x-prometheon-hotkey"] == alice_keypair.ss58_address
        assert headers["x-prometheon-nonce"].startswith("0x")
        assert headers["x-prometheon-timestamp"].endswith("Z")
        # The signature is 0x + 128 hex chars.
        assert len(headers["x-prometheon-request-signature"]) == 130

    def test_signed_get_signature_verifies_against_request_payload(
        self, alice_keypair: Keypair
    ) -> None:
        """The signature in the header must verify against a reconstructed
        ApiRequestPayload using the headers and path."""
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            captured["url"] = str(request.url)
            return _ok_json(_aggregate_response_dict())

        transport = httpx.MockTransport(handler)
        with _make_client(
            transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
        ) as client:
            client.get_aggregate_snapshot()

        headers = captured["headers"]
        # Reconstruct what the server would build from the request.
        reconstructed = ApiRequestPayload(
            method="GET",
            path="/api/v1/prometheon/phase1/snapshots/latest/aggregate",
            query_hash="0x" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            body_hash="0x" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            timestamp=headers["x-prometheon-timestamp"],
            nonce=headers["x-prometheon-nonce"],
            chain_network=ChainNetwork.FINNEY,
            platform_instance_id=PLATFORM_INSTANCE_ID,
            netuid=NETUID,
            role=Role.VALIDATOR,
            mode=SnapshotMode.AGGREGATE,
            validator_hotkey=alice_keypair.ss58_address,
            api_token_hash=api_token_hash(API_TOKEN),
        )
        # If the signature verifies, no exception is raised.
        verify_bittensor_signature(
            ss58_address=alice_keypair.ss58_address,
            signature_hex=headers["x-prometheon-request-signature"],
            domain=DOMAIN_API_REQUEST,
            payload=reconstructed.model_dump(mode="json"),
        )

    def test_get_aggregate_snapshot_with_specific_date(self, alice_keypair: Keypair) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return _ok_json(_aggregate_response_dict())

        transport = httpx.MockTransport(handler)
        with _make_client(
            transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
        ) as client:
            client.get_aggregate_snapshot("2026-05-18")

        assert captured["url"] == (
            f"{BASE_URL}/api/v1/prometheon/phase1/snapshots/2026-05-18/aggregate"
        )

    def test_snapshot_call_without_keypair_raises(self) -> None:
        transport = httpx.MockTransport(lambda request: _ok_json(_aggregate_response_dict()))
        with (
            _make_client(transport=transport) as client,
            pytest.raises(RuntimeError, match="validator_keypair"),
        ):
            client.get_aggregate_snapshot()

    def test_snapshot_not_ready_raises(self, alice_keypair: Keypair) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _error_json("SNAPSHOT_NOT_READY", status_code=425)

        transport = httpx.MockTransport(handler)
        with (
            _make_client(
                transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
            ) as client,
            pytest.raises(SnapshotNotReadyError),
        ):
            client.get_aggregate_snapshot()

    def test_5xx_raises_server_error(self, alice_keypair: Keypair) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, content=b"upstream timeout")

        transport = httpx.MockTransport(handler)
        with (
            _make_client(
                transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
            ) as client,
            pytest.raises(PlatformServerError) as exc_info,
        ):
            client.get_aggregate_snapshot()
        assert exc_info.value.status_code == 503


class TestDetailedSnapshotFlows:
    def test_get_detailed_manifest_returns_parsed_model(self, alice_keypair: Keypair) -> None:
        manifest_body = {
            "domain": "PROMETHEON_SNAPSHOT_V1",
            "schema_version": "1.0",
            "mechanism": "phase1_growth",
            "mechid": 0,
            "mode": "detailed",
            "snapshot_id": "phase1:2026-05-18:detailed",
            "chain_network": "finney",
            "platform_instance_id": "bitfan-test",
            "netuid": NETUID,
            "activity_date": "2026-05-18",
            "generated_at": "2026-05-19T00:20:31Z",
            "window_start_date": "2026-05-05",
            "window_end_date": "2026-05-18",
            "daily_score_cap": 20,
            "active_member_score_threshold": 50,
            "min_active_members_for_reward": 3,
            "top_k": 10,
            "burn_hotkey": SS58_C,
            "manual_burn_rate_ppm": 0,
            "platform_key_id": "platform-test",
            "record_count": 1,
            "page_size": 1,
            "page_count": 1,
            "pages": [
                {"page_index": 0, "record_count": 1, "page_hash": VALID_HEX32},
            ],
            "records_hash": VALID_HEX32,
            "platform_signature": VALID_HEX_SIG,
        }

        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return _ok_json(manifest_body)

        transport = httpx.MockTransport(handler)
        with _make_client(
            transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
        ) as client:
            manifest = client.get_detailed_manifest()

        assert isinstance(manifest, DetailedManifest)
        assert captured["url"].endswith("/latest/detailed/manifest")

    def test_get_detailed_page_returns_parsed_model(self, alice_keypair: Keypair) -> None:
        page_body = {
            "domain": "PROMETHEON_RECORD_PAGE_V1",
            "schema_version": "1.0",
            "mechanism": "phase1_growth",
            "mechid": 0,
            "chain_network": "finney",
            "platform_instance_id": "bitfan-test",
            "netuid": NETUID,
            "snapshot_id": "phase1:2026-05-18:detailed",
            "mode": "detailed",
            "activity_date": "2026-05-18",
            "page_index": 0,
            "record_count": 1,
            "records": [
                {"user_ref": "usr_a", "miner_hotkey": SS58_A, "user_score_14d_points": 73},
            ],
            "page_hash": VALID_HEX32,
        }

        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return _ok_json(page_body)

        transport = httpx.MockTransport(handler)
        with _make_client(
            transport=transport, validator_keypair=alice_keypair, role=Role.VALIDATOR
        ) as client:
            page = client.get_detailed_page("2026-05-18", 0)

        assert isinstance(page, DetailedPage)
        assert captured["url"] == (
            f"{BASE_URL}/api/v1/prometheon/phase1/snapshots/2026-05-18/detailed/pages/0"
        )
