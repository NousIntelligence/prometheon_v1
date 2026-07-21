"""Backfill + digest contract gates through the production client.

Drives :class:`BackfillClient` against ``httpx.MockTransport`` responses
built from fixture bytes: catch-up must reproduce the exact stored bytes
(and therefore the fixture day digest), and digest verification must
accept a correctly-signed envelope (signed here with the derivable test
key, whose signature is deterministic) and reject tampering.
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
    DigestVerificationError,
    compare_day,
    verify_signed_digest,
)
from prometheon.events.records import EventFamily, record_canonical_bytes
from prometheon.events.store import EventStore
from prometheon.platform.signing import TrustedKey
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


class TestCatchUp:
    def test_catch_up_reproduces_fixture_digest(self, tmp_path: Path) -> None:
        entries = _backfill_entries()
        from_seq = BATCH["envelope"]["from_seq"]

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer unit-token"
            requested = int(request.url.params["from_seq"])
            page = [entry for entry in entries if entry["seq"] >= requested]
            return httpx.Response(
                200,
                json={
                    "family": "activity",
                    "from_seq": requested,
                    "records": page,
                    "next_seq": requested + len(page),
                },
            )

        with EventStore(tmp_path / "e.sqlite") as store:
            store._connection.execute(
                "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
                (EventFamily.ACTIVITY.value, from_seq - 1),
            )
            store._connection.commit()

            added = _client(handler).catch_up(store, EventFamily.ACTIVITY)
            assert added == len(entries)
            assert store.last_stored_seq(EventFamily.ACTIVITY) == BATCH["envelope"]["to_seq"]

            stored = store.canonical_bytes_for_epoch(EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])
            recomputed = "0x" + hashlib.sha256(b"".join(stored)).hexdigest()
            assert recomputed == DIGEST_ENV["records_hash"]

    def test_empty_page_means_retry_later(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            requested = int(request.url.params["from_seq"])
            return httpx.Response(
                200,
                json={
                    "family": "activity",
                    "from_seq": requested,
                    "records": [],
                    "next_seq": requested,
                },
            )

        with EventStore(tmp_path / "e.sqlite") as store:
            assert _client(handler).catch_up(store, EventFamily.ACTIVITY) == 0


class TestDigestVerification:
    def test_fixture_digest_verifies_and_matches_stored_day(self, tmp_path: Path) -> None:
        payload = _signed_digest_payload(DIGEST_ENV)
        digest = verify_signed_digest(payload, trusted_keys=TRUSTED, allow_test_publisher_key=True)
        assert digest.records_hash == DIGEST_ENV["records_hash"]

        entries = _backfill_entries()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/backfill"):
                requested = int(request.url.params["from_seq"])
                page = [entry for entry in entries if entry["seq"] >= requested]
                return httpx.Response(
                    200,
                    json={
                        "family": "activity",
                        "from_seq": requested,
                        "records": page,
                        "next_seq": requested + len(page),
                    },
                )
            return httpx.Response(200, json=payload)

        with EventStore(tmp_path / "e.sqlite") as store:
            store._connection.execute(
                "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
                (EventFamily.ACTIVITY.value, BATCH["envelope"]["from_seq"] - 1),
            )
            store._connection.commit()
            client = _client(handler)
            client.catch_up(store, EventFamily.ACTIVITY)
            report = client.check_day(store, EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])
            assert report.matches

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
