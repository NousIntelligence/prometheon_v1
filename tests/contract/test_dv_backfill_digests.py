"""Backfill + digest contract gates through the production client.

Drives :class:`BackfillClient` against ``httpx.MockTransport`` responses
built from fixture bytes: catch-up must reproduce the exact stored bytes
(and therefore the fixture day digest), and digest verification must
accept a correctly-signed envelope (signed here with the derivable test
key, whose signature is deterministic) and reject tampering.

The mocked wire is held to the real contract, because the previous
version of this module was not and certified a client that could not
complete a single live call:

- every response body is wrapped in the platform's success envelope
  (``{"success": true, "data": {...}, "meta": {}}``) — payload fields are
  never top-level on the real API;
- :func:`_assert_wire` runs on *every* request and fails the test if the
  environment-binding headers are missing, so omitting them can never
  again be invisible.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.events.backfill import (
    BackfillClient,
    BackfillConfig,
    BackfillError,
    DigestVerificationError,
    compare_day,
    verify_signed_digest,
)
from prometheon.events.records import EventFamily, record_canonical_bytes
from prometheon.events.store import EventStore
from prometheon.platform.signing import TrustedKey
from prometheon.platform.wire import (
    CHAIN_NETWORK_HEADER,
    PLATFORM_INSTANCE_ID_HEADER,
)
from prometheon.security.canonical import DOMAIN_DAY_DIGEST, to_canonical_bytes

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"

BATCH: dict[str, Any] = json.loads(
    (FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json").read_text()
)
DIGEST_ENV: dict[str, Any] = json.loads(
    (FIXTURES / "event-record" / "03-day-digest" / "envelope.json").read_text()
)
EMPTY_DIGEST_ENV: dict[str, Any] = json.loads(
    (FIXTURES / "event-record" / "03-day-digest" / "empty_day.envelope.json").read_text()
)
KEY_INFO: dict[str, Any] = json.loads(
    (FIXTURES / "test-keys" / "ed25519-platform.json").read_text()
)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY_INFO["private_key_base64"]))

TRUSTED = {
    KEY_INFO["key_id"]: TrustedKey(
        public_key=KEY_INFO["public_key_hex"],
        not_before="2026-05-01T00:00:00Z",
        not_after="2026-12-31T00:00:00Z",
        status="active",
    )
}

CHAIN_NETWORK = "test"
INSTANCE_ID = "bitfan-staging"


def _assert_wire(request: httpx.Request) -> None:
    """Every read-API request must present the token and the env binding."""
    assert request.headers["Authorization"] == "Bearer unit-token"
    assert request.headers[CHAIN_NETWORK_HEADER] == CHAIN_NETWORK
    assert request.headers[PLATFORM_INSTANCE_ID_HEADER] == INSTANCE_ID


def _ok(payload: dict[str, Any]) -> httpx.Response:
    """A 200 shaped exactly like the platform's success envelope."""
    return httpx.Response(200, json={"success": True, "data": payload, "meta": {}})


def _error(status_code: int, code: str, message: str) -> httpx.Response:
    """A failure shaped exactly like the platform's error envelope."""
    return httpx.Response(
        status_code,
        json={"success": False, "error": {"code": code, "message": message}},
    )


def _signed_digest_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    message = DOMAIN_DAY_DIGEST.encode("ascii") + b"\n" + to_canonical_bytes(envelope)
    return {
        "family": envelope["family"],
        "epoch_id": envelope["epoch_id"],
        "records_hash": envelope["records_hash"],
        "record_count": envelope["record_count"],
        "signature": "0x" + PRIVATE_KEY.sign(message).hex(),
        "platform_key_id": KEY_INFO["key_id"],
        "signed_at": "2026-07-15T00:40:00Z",
    }


def _config() -> BackfillConfig:
    return BackfillConfig(
        base_url="http://read.test",
        api_token="unit-token",
        trusted_keys=TRUSTED,
        chain_network=CHAIN_NETWORK,
        platform_instance_id=INSTANCE_ID,
        allow_test_publisher_key=True,
    )


def _client(handler: Any) -> BackfillClient:
    return BackfillClient(_config(), httpx.Client(transport=httpx.MockTransport(handler)))


def _backfill_entries() -> list[dict[str, Any]]:
    return [
        {
            "seq": record["seq"],
            "event_id": record["event_id"],
            "canonical_bytes": "0x" + record_canonical_bytes(record).hex(),
        }
        for record in BATCH["envelope"]["records"]
    ]


def _page_payload(requested: int, entries: list[dict[str, Any]]) -> dict[str, Any]:
    page = [entry for entry in entries if entry["seq"] >= requested]
    return {
        "family": "activity",
        "from_seq": requested,
        "records": page,
        "next_seq": requested + len(page),
    }


def _seed_cursor(store: EventStore, family: EventFamily, last_seq: int) -> None:
    store._connection.execute(
        "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
        (family.value, last_seq),
    )
    store._connection.commit()


class TestReadApiWireContract:
    """The two conventions that broke this client in staging."""

    def test_requests_carry_the_environment_binding(self) -> None:
        seen: list[httpx.Headers] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers)
            return _ok(_page_payload(int(request.url.params["from_seq"]), []))

        _client(handler).fetch_page(EventFamily.ACTIVITY, 1)

        assert len(seen) == 1
        assert seen[0][CHAIN_NETWORK_HEADER] == CHAIN_NETWORK
        assert seen[0][PLATFORM_INSTANCE_ID_HEADER] == INSTANCE_ID
        assert seen[0]["Authorization"] == "Bearer unit-token"

    def test_success_envelope_is_unwrapped(self) -> None:
        entries = _backfill_entries()

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(_page_payload(int(request.url.params["from_seq"]), entries))

        page = _client(handler).fetch_page(EventFamily.ACTIVITY, entries[0]["seq"])
        # Payload fields, not envelope fields — the caller reads records/next_seq.
        assert isinstance(page["records"], list)
        assert isinstance(page["next_seq"], int)
        assert "success" not in page

    def test_missing_binding_surfaces_the_platform_error_code(self) -> None:
        """What staging actually returned before the fix."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _error(
                400,
                "ENVIRONMENT_MISMATCH",
                "Missing chain_network / platform_instance_id binding.",
            )

        with pytest.raises(BackfillError, match="ENVIRONMENT_MISMATCH"):
            _client(handler).fetch_page(EventFamily.ACTIVITY, 1)

    def test_error_envelope_on_a_200_is_not_mistaken_for_data(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"success": False, "error": {"code": "INTERNAL", "message": "nope"}},
            )

        with pytest.raises(BackfillError, match="INTERNAL"):
            _client(handler).fetch_page(EventFamily.ACTIVITY, 1)

    def test_non_enveloped_body_still_passes_through(self) -> None:
        """Defensive: an endpoint bypassing the interceptor must still work."""
        entries = _backfill_entries()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json=_page_payload(int(request.url.params["from_seq"]), entries)
            )

        page = _client(handler).fetch_page(EventFamily.ACTIVITY, entries[0]["seq"])
        assert len(page["records"]) == len(entries)

    def test_envelope_with_non_object_data_is_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"success": True, "data": [], "meta": {}})

        with pytest.raises(BackfillError, match="not an object"):
            _client(handler).fetch_page(EventFamily.ACTIVITY, 1)


class TestCatchUp:
    def test_catch_up_reproduces_fixture_digest(self, tmp_path: Path) -> None:
        entries = _backfill_entries()
        from_seq = BATCH["envelope"]["from_seq"]

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(_page_payload(int(request.url.params["from_seq"]), entries))

        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, EventFamily.ACTIVITY, from_seq - 1)

            added = _client(handler).catch_up(store, EventFamily.ACTIVITY)
            assert added == len(entries)
            assert store.last_stored_seq(EventFamily.ACTIVITY) == BATCH["envelope"]["to_seq"]

            stored = store.canonical_bytes_for_epoch(EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])
            recomputed = "0x" + hashlib.sha256(b"".join(stored)).hexdigest()
            assert recomputed == DIGEST_ENV["records_hash"]

    def test_empty_page_means_retry_later(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(_page_payload(int(request.url.params["from_seq"]), []))

        with EventStore(tmp_path / "e.sqlite") as store:
            assert _client(handler).catch_up(store, EventFamily.ACTIVITY) == 0


class TestDigestVerification:
    def test_fixture_digest_verifies_and_matches_stored_day(self, tmp_path: Path) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)
        digest = verify_signed_digest(payload, trusted_keys=TRUSTED, allow_test_publisher_key=True)
        assert digest.records_hash == DIGEST_ENV["records_hash"]

        entries = _backfill_entries()

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            if request.url.path.endswith("/backfill"):
                return _ok(_page_payload(int(request.url.params["from_seq"]), entries))
            return _ok(payload)

        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, EventFamily.ACTIVITY, BATCH["envelope"]["from_seq"] - 1)
            client = _client(handler)
            client.catch_up(store, EventFamily.ACTIVITY)
            report = client.check_day(store, EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])
            assert report.matches

    def test_digest_for_another_day_is_refused(self, tmp_path: Path) -> None:
        """A valid signature over the wrong day must not clear the gate."""
        payload = _signed_digest_payload(DIGEST_ENV)

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(payload)

        with (
            EventStore(tmp_path / "e.sqlite") as store,
            pytest.raises(BackfillError, match="was requested"),
        ):
            _client(handler).check_day(store, EventFamily.ACTIVITY, "2026-01-01")

    def test_empty_day_digest_matches_empty_store(self, tmp_path: Path) -> None:
        payload = _signed_digest_payload(EMPTY_DIGEST_ENV)
        digest = verify_signed_digest(payload, trusted_keys=TRUSTED, allow_test_publisher_key=True)
        with EventStore(tmp_path / "e.sqlite") as store:
            report = compare_day(store, digest)
            assert report.matches
            assert report.local_record_count == 0

    def test_tampered_records_hash_fails_signature(self) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)
        payload["records_hash"] = "0x" + "0" * 64
        with pytest.raises(DigestVerificationError, match="did not verify"):
            verify_signed_digest(payload, trusted_keys=TRUSTED, allow_test_publisher_key=True)

    def test_unwrapped_digest_reaches_the_verifier(self) -> None:
        """The envelope must be stripped before verification, not after.

        Handing ``verify_signed_digest`` the raw envelope is exactly the
        bug staging hit: it sees ``success``/``data``/``meta`` and reports
        missing required fields.
        """
        enveloped = {"success": True, "data": _signed_digest_payload(DIGEST_ENV), "meta": {}}
        with pytest.raises(DigestVerificationError, match="missing required fields"):
            verify_signed_digest(enveloped, trusted_keys=TRUSTED, allow_test_publisher_key=True)

    def test_incomplete_local_day_is_flagged(self, tmp_path: Path) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)
        digest = verify_signed_digest(payload, trusted_keys=TRUSTED, allow_test_publisher_key=True)
        with EventStore(tmp_path / "e.sqlite") as store:
            report = compare_day(store, digest)  # nothing stored locally
            assert not report.matches
            assert report.local_record_count == 0
            assert report.digest_record_count == DIGEST_ENV["record_count"]

    def test_test_key_refused_by_default(self) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)
        with pytest.raises(DigestVerificationError, match="test publisher key"):
            verify_signed_digest(payload, trusted_keys=TRUSTED)
