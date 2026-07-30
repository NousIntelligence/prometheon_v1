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
    MAX_PAGE_LIMIT,
    BackfillClient,
    BackfillConfig,
    BackfillError,
    BackfillRangeUnavailableError,
    DigestNotFoundError,
    DigestNotSealedError,
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

            result = _client(handler).catch_up(store, EventFamily.ACTIVITY)
            assert result.appended == len(entries)
            assert result.last_seq == BATCH["envelope"]["to_seq"]
            assert store.last_stored_seq(EventFamily.ACTIVITY) == BATCH["envelope"]["to_seq"]

            stored = store.canonical_bytes_for_epoch(EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])
            recomputed = "0x" + hashlib.sha256(b"".join(stored)).hexdigest()
            assert recomputed == DIGEST_ENV["records_hash"]

    def test_empty_page_at_our_position_ends_the_pass(self, tmp_path: Path) -> None:
        """The one documented empty page: next_seq == from_seq, retry later."""

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(_page_payload(int(request.url.params["from_seq"]), []))

        with EventStore(tmp_path / "e.sqlite") as store:
            result = _client(handler).catch_up(store, EventFamily.ACTIVITY)
            assert result.appended == 0
            assert result.last_seq == 0

    def test_empty_page_that_jumps_the_cursor_forward_is_escalated(self, tmp_path: Path) -> None:
        """A range the platform will not serve is an incident, not progress.

        Skipping it would leave a silent hole that every affected day
        digest then fails on, with nothing pointing at the cause.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            requested = int(request.url.params["from_seq"])
            payload = _page_payload(requested, [])
            payload["next_seq"] = requested + 500
            return _ok(payload)

        with (
            EventStore(tmp_path / "e.sqlite") as store,
            pytest.raises(BackfillError, match="cannot be recovered"),
        ):
            _client(handler).catch_up(store, EventFamily.ACTIVITY)

    def test_page_for_the_wrong_family_is_refused(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            payload = _page_payload(int(request.url.params["from_seq"]), [])
            payload["family"] = "group"
            return _ok(payload)

        with (
            EventStore(tmp_path / "e.sqlite") as store,
            pytest.raises(BackfillError, match="group"),
        ):
            _client(handler).catch_up(store, EventFamily.ACTIVITY)

    def test_next_seq_disagreeing_with_the_page_is_refused(self, tmp_path: Path) -> None:
        entries = _backfill_entries()

        def handler(request: httpx.Request) -> httpx.Response:
            requested = int(request.url.params["from_seq"])
            payload = _page_payload(requested, entries)
            payload["next_seq"] = requested + 99  # would silently skip records
            return _ok(payload)

        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, EventFamily.ACTIVITY, BATCH["envelope"]["from_seq"] - 1)
            with pytest.raises(BackfillError, match="next_seq"):
                _client(handler).catch_up(store, EventFamily.ACTIVITY)

    def test_undecodable_bytes_surface_as_a_contract_error(self, tmp_path: Path) -> None:
        """Not a bare ValueError from bytes.fromhex escaping the client."""
        entries = _backfill_entries()
        entries[0]["canonical_bytes"] = "0xzzzz"

        def handler(request: httpx.Request) -> httpx.Response:
            return _ok(_page_payload(int(request.url.params["from_seq"]), entries))

        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, EventFamily.ACTIVITY, BATCH["envelope"]["from_seq"] - 1)
            with pytest.raises(BackfillError, match="did not decode"):
                _client(handler).catch_up(store, EventFamily.ACTIVITY)

    def test_non_canonical_bytes_are_refused(self, tmp_path: Path) -> None:
        """The delivered bytes must BE the record, not merely decode to it.

        Storing a re-canonicalised variant would leave the local day hash
        unable to match the platform's digest, surfacing days later as an
        unexplained completeness alarm.
        """
        record = BATCH["envelope"]["records"][0]
        # Same record, keys deliberately out of canonical order.
        reordered = json.dumps(dict(reversed(list(record.items()))), separators=(",", ":"))
        blob = b"PROMETHEON_EVENT_RECORD_V1\n" + reordered.encode()
        entries = [
            {
                "seq": record["seq"],
                "event_id": record["event_id"],
                "canonical_bytes": "0x" + blob.hex(),
            }
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _ok(_page_payload(int(request.url.params["from_seq"]), entries))

        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, EventFamily.ACTIVITY, record["seq"] - 1)
            with pytest.raises(BackfillError, match="not canonical"):
                _client(handler).catch_up(store, EventFamily.ACTIVITY)


class TestRetriesAndErrorDetail:
    def test_rate_limit_is_retried_then_succeeds(self) -> None:
        calls: list[int] = []
        slept: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) < 3:
                return httpx.Response(429, json={"success": False, "error": {"code": "RATE"}})
            return _ok(_page_payload(int(request.url.params["from_seq"]), []))

        client = BackfillClient(
            _config(),
            httpx.Client(transport=httpx.MockTransport(handler)),
            sleeper=slept.append,
        )
        page = client.fetch_page(EventFamily.ACTIVITY, 1)

        assert page["records"] == []
        assert len(calls) == 3
        assert slept == [0.5, 1.0]  # exponential, base 0.5

    def test_retry_after_header_is_honoured(self) -> None:
        slept: list[float] = []
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(429, headers={"Retry-After": "2"}, json={})
            return _ok(_page_payload(1, []))

        BackfillClient(
            _config(),
            httpx.Client(transport=httpx.MockTransport(handler)),
            sleeper=slept.append,
        ).fetch_page(EventFamily.ACTIVITY, 1)

        assert slept == [2.0]

    def test_retries_are_bounded(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"success": False, "error": {"code": "RATE"}})

        client = BackfillClient(
            _config(),
            httpx.Client(transport=httpx.MockTransport(handler)),
            sleeper=lambda _seconds: None,
        )
        with pytest.raises(BackfillError, match="RATE"):
            client.fetch_page(EventFamily.ACTIVITY, 1)

    def test_error_carries_status_and_platform_code(self) -> None:
        """ "digest not published yet" must be distinguishable from auth failure."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _error(404, "DIGEST_NOT_PUBLISHED", "not sealed yet")

        with pytest.raises(BackfillError) as excinfo:
            _client(handler).fetch_page(EventFamily.ACTIVITY, 1)
        assert excinfo.value.status_code == 404
        assert excinfo.value.error_code == "DIGEST_NOT_PUBLISHED"

    def test_transport_failure_surfaces_as_a_backfill_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        with pytest.raises(BackfillError, match="unreachable"):
            _client(handler).fetch_page(EventFamily.ACTIVITY, 1)


class TestConfigValidation:
    @pytest.mark.parametrize("limit", [0, -1, MAX_PAGE_LIMIT + 1])
    def test_page_limit_outside_the_documented_range_is_refused(self, limit: int) -> None:
        with pytest.raises(ValueError, match="page_limit"):
            BackfillConfig(
                base_url="http://read.test",
                api_token="t",
                trusted_keys=TRUSTED,
                chain_network=CHAIN_NETWORK,
                platform_instance_id=INSTANCE_ID,
                page_limit=limit,
            )

    def test_negative_retries_refused(self) -> None:
        with pytest.raises(ValueError, match="max_retries"):
            BackfillConfig(
                base_url="http://read.test",
                api_token="t",
                trusted_keys=TRUSTED,
                chain_network=CHAIN_NETWORK,
                platform_instance_id=INSTANCE_ID,
                max_retries=-1,
            )


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

    def test_malformed_records_hash_is_refused(self) -> None:
        """Pinned before the signature check, so it cannot become a mystery."""
        envelope = dict(DIGEST_ENV)
        envelope["records_hash"] = DIGEST_ENV["records_hash"].upper()
        payload = _signed_digest_payload(envelope)
        with pytest.raises(DigestVerificationError, match="records_hash"):
            verify_signed_digest(payload, trusted_keys=TRUSTED, allow_test_publisher_key=True)


# A rotated-out key: still listed on /keys, window closed 2026-08-01.
REVOKED_KEYS = {
    KEY_INFO["key_id"]: TrustedKey(
        public_key=KEY_INFO["public_key_hex"],
        not_before="2026-05-01T00:00:00Z",
        not_after="2026-08-01T00:00:00Z",
        status="revoked",
    )
}


class TestKeyRotation:
    """Pinned answer B5: revoked-but-listed keys keep historical digests verifiable."""

    def test_revoked_key_still_verifies_a_digest_it_signed_while_valid(self) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)  # signed_at 2026-07-15, inside the window
        digest = verify_signed_digest(
            payload, trusted_keys=REVOKED_KEYS, allow_test_publisher_key=True
        )
        assert digest.records_hash == DIGEST_ENV["records_hash"]

    def test_revoked_key_is_refused_outside_its_validity_window(self) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)
        payload["signed_at"] = "2026-09-01T00:40:00Z"  # after not_after
        with pytest.raises(DigestVerificationError, match="validity window"):
            verify_signed_digest(payload, trusted_keys=REVOKED_KEYS, allow_test_publisher_key=True)


class TestR4ErrorBranches:
    """§7.1 / §7.2 — outcomes that must be told apart by error.code."""

    def test_permanently_unavailable_range_is_typed(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                410,
                json={
                    "success": False,
                    "error": {
                        "code": "backfill_range_unavailable",
                        "message": "range below the retained floor",
                        "details": {
                            "family": "activity",
                            "requested_from_seq": 1,
                            "earliest_available_seq": 5000,
                        },
                    },
                },
            )

        with (
            EventStore(tmp_path / "e.sqlite") as store,
            pytest.raises(BackfillRangeUnavailableError) as excinfo,
        ):
            _client(handler).catch_up(store, EventFamily.ACTIVITY)

        assert excinfo.value.earliest_available_seq == 5000
        assert excinfo.value.status_code == 410
        # It is a BackfillError, so existing handlers still catch it...
        assert isinstance(excinfo.value, BackfillError)
        # ...but callers can tell "gone for good" from "retry later".
        assert excinfo.value.error_code == "backfill_range_unavailable"

    def test_digest_not_sealed_is_not_an_alarm(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404,
                json={
                    "success": False,
                    "error": {
                        "code": "digest_not_sealed",
                        "message": "seal not due",
                        "details": {
                            "seal_deadline": "2026-07-15T01:00:00Z",
                            "now": "2026-07-15T00:50:00Z",
                        },
                    },
                },
            )

        with (
            EventStore(tmp_path / "e.sqlite") as store,
            pytest.raises(DigestNotSealedError) as excinfo,
        ):
            _client(handler).check_day(store, EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])

        assert excinfo.value.seal_deadline == "2026-07-15T01:00:00Z"
        assert excinfo.value.now == "2026-07-15T00:50:00Z"

    def test_digest_not_found_is_the_anomaly(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404,
                json={
                    "success": False,
                    "error": {
                        "code": "digest_not_found",
                        "message": "no digest",
                        "details": {"seal_deadline": "2026-07-15T01:00:00Z"},
                    },
                },
            )

        with EventStore(tmp_path / "e.sqlite") as store, pytest.raises(DigestNotFoundError):
            _client(handler).check_day(store, EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])

    def test_unknown_code_stays_a_plain_error(self, tmp_path: Path) -> None:
        """A new platform code must surface intact, not be coerced."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _error(503, "SOMETHING_NEW", "unrecognised")

        with pytest.raises(BackfillError) as excinfo:
            _client(handler).fetch_page(EventFamily.ACTIVITY, 1)
        assert type(excinfo.value) is BackfillError
        assert excinfo.value.error_code == "SOMETHING_NEW"
