"""Unit tests for the ingest pipeline's rejection paths.

Batches are built and signed locally with the derivable fixture key so
every guard can be exercised in isolation. The happy paths against real
fixture bytes live in the contract suite.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.events.ingest import (
    IngestConfig,
    IngestOutcome,
    process_push,
)
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore
from prometheon.platform.signing import TrustedKey
from prometheon.security.canonical import to_canonical_bytes

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "decentralized-validation"
KEY_INFO: dict[str, Any] = json.loads(
    (FIXTURES / "test-keys" / "ed25519-platform.json").read_text()
)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY_INFO["private_key_base64"]))

NOW = datetime(2026, 7, 14, 9, 20, 0, tzinfo=timezone.utc)
USER = "usr_evt_" + "cd" * 32


def _record(seq: int) -> dict[str, Any]:
    return {
        "domain": "PROMETHEON_EVENT_RECORD_V1",
        "family": "activity",
        "seq": seq,
        "epoch_id": "2026-07-14",
        "event_id": "0x" + hashlib.sha256(f"unit-{seq}".encode()).hexdigest(),
        "user_ref_evt": USER,
        "group_id": None,
        "received_ts": "2026-07-14T09:15:00Z",
        "category_id": None,
        "core": {
            "domain": "PROMETHEON_EVENT_V1",
            "kind": "login",
            "target": {},
            "scoring_fields": {},
            "client_ts": "2026-07-14T09:14:59Z",
            "client_nonce": "0x" + f"{seq:016x}",
        },
        "device_pubkey": None,
        "user_sig": None,
    }


def _signed_body(
    *,
    from_seq: int = 1,
    to_seq: int = 2,
    nonce: str = "unit-nonce-1",
    sent_at: str = "2026-07-14T09:20:00Z",
    mutate_envelope: dict[str, Any] | None = None,
    key_id: str | None = None,
    break_signature: bool = False,
) -> bytes:
    envelope: dict[str, Any] = {
        "domain": "PROMETHEON_INGEST_PUSH_V1",
        "platform_instance_id": "bitfan-local",
        "chain_network": "test",
        "family": "activity",
        "from_seq": from_seq,
        "to_seq": to_seq,
        "records": [_record(seq) for seq in range(from_seq, to_seq + 1)],
        "nonce": nonce,
        "sent_at": sent_at,
    }
    if mutate_envelope:
        envelope.update(mutate_envelope)
    message = b"PROMETHEON_INGEST_PUSH_V1\n" + to_canonical_bytes(envelope)
    signature = PRIVATE_KEY.sign(message)
    if break_signature:
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    body = {
        "envelope": envelope,
        "publisher_key_id": key_id or KEY_INFO["key_id"],
        "sig": "0x" + signature.hex(),
    }
    return to_canonical_bytes(body)


def _config(**overrides: Any) -> IngestConfig:
    base: dict[str, Any] = {
        "platform_instance_id": "bitfan-local",
        "chain_network": "test",
        "trusted_keys": {
            KEY_INFO["key_id"]: TrustedKey(
                public_key=KEY_INFO["public_key_hex"],
                not_before="2026-05-01T00:00:00Z",
                not_after="2026-12-31T00:00:00Z",
                status="active",
            )
        },
        "allow_test_publisher_key": True,
    }
    base.update(overrides)
    return IngestConfig(**base)


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    with EventStore(tmp_path / "e.sqlite") as opened:
        yield opened


def _push(store: EventStore, body: bytes, config: IngestConfig | None = None) -> IngestOutcome:
    return process_push(body, store=store, config=config or _config(), now=NOW)


class TestHappyAndStoreCases:
    def test_stores_and_acks(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body())
        assert outcome.http_status == 200
        assert outcome.body == {"received_through_seq": 2}

    def test_second_batch_continues(self, store: EventStore) -> None:
        _push(store, _signed_body())
        outcome = _push(store, _signed_body(from_seq=3, to_seq=3, nonce="unit-nonce-2"))
        assert outcome.http_status == 200
        assert outcome.body == {"received_through_seq": 3}


class TestSignatureGuards:
    def test_broken_signature(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(break_signature=True))
        assert (outcome.http_status, outcome.body["code"]) == (401, "signature_invalid")

    def test_unknown_key(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(key_id="platform-nope"))
        assert (outcome.http_status, outcome.body["code"]) == (401, "unknown_publisher_key")

    def test_revoked_key(self, store: EventStore) -> None:
        config = _config(
            trusted_keys={
                KEY_INFO["key_id"]: TrustedKey(
                    public_key=KEY_INFO["public_key_hex"],
                    not_before="2026-05-01T00:00:00Z",
                    not_after="2026-12-31T00:00:00Z",
                    status="revoked",
                )
            }
        )
        outcome = _push(store, _signed_body(), config)
        assert (outcome.http_status, outcome.body["code"]) == (401, "publisher_key_revoked")

    def test_sent_at_outside_key_validity(self, store: EventStore) -> None:
        config = _config(
            trusted_keys={
                KEY_INFO["key_id"]: TrustedKey(
                    public_key=KEY_INFO["public_key_hex"],
                    not_before="2026-08-01T00:00:00Z",
                    not_after="2026-12-31T00:00:00Z",
                )
            }
        )
        outcome = _push(store, _signed_body(), config)
        assert (outcome.http_status, outcome.body["code"]) == (
            401,
            "publisher_key_outside_validity",
        )

    def test_test_key_refused_by_default(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(), _config(allow_test_publisher_key=False))
        assert (outcome.http_status, outcome.body["code"]) == (
            401,
            "test_publisher_key_refused",
        )


class TestReplayGuards:
    def test_stale_sent_at(self, store: EventStore) -> None:
        stale = (NOW - timedelta(seconds=301)).strftime("%Y-%m-%dT%H:%M:%SZ")
        outcome = _push(store, _signed_body(sent_at=stale))
        assert (outcome.http_status, outcome.body["code"]) == (401, "replay_window")

    def test_future_sent_at(self, store: EventStore) -> None:
        future = (NOW + timedelta(seconds=301)).strftime("%Y-%m-%dT%H:%M:%SZ")
        outcome = _push(store, _signed_body(sent_at=future))
        assert (outcome.http_status, outcome.body["code"]) == (401, "replay_window")

    def test_nonce_replay(self, store: EventStore) -> None:
        _push(store, _signed_body())
        outcome = _push(store, _signed_body(from_seq=3, to_seq=3, nonce="unit-nonce-1"))
        assert (outcome.http_status, outcome.body["code"]) == (401, "replay_nonce")


class TestEnvelopeGuards:
    def test_wrong_environment(self, store: EventStore) -> None:
        outcome = _push(
            store, _signed_body(mutate_envelope={"platform_instance_id": "bitfan-prod"})
        )
        assert (outcome.http_status, outcome.body["code"]) == (403, "environment_mismatch")

    def test_count_mismatch(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(mutate_envelope={"to_seq": 5}))
        assert (outcome.http_status, outcome.body["code"]) == (400, "envelope_invalid")

    def test_unknown_family(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(mutate_envelope={"family": "telemetry"}))
        assert (outcome.http_status, outcome.body["code"]) == (400, "envelope_invalid")

    def test_batch_cap(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(), _config(max_batch_records=1))
        assert (outcome.http_status, outcome.body["code"]) == (400, "batch_too_large")

    def test_duplicate_key_body_rejected(self, store: EventStore) -> None:
        outcome = _push(store, b'{"envelope":1,"envelope":2}')
        assert (outcome.http_status, outcome.body["code"]) == (400, "duplicate_key")

    def test_body_too_large(self, store: EventStore) -> None:
        outcome = _push(store, _signed_body(), _config(max_body_bytes=64))
        assert (outcome.http_status, outcome.body["code"]) == (413, "body_too_large")

    def test_record_failing_validation_rejected(self, store: EventStore) -> None:
        bad = _record(1)
        bad["event_id"] = "0xNOTHEX"
        # Rebuild a signed envelope embedding the invalid record.
        envelope: dict[str, Any] = {
            "domain": "PROMETHEON_INGEST_PUSH_V1",
            "platform_instance_id": "bitfan-local",
            "chain_network": "test",
            "family": "activity",
            "from_seq": 1,
            "to_seq": 1,
            "records": [bad],
            "nonce": "unit-nonce-bad",
            "sent_at": "2026-07-14T09:20:00Z",
        }
        message = b"PROMETHEON_INGEST_PUSH_V1\n" + to_canonical_bytes(envelope)
        body = to_canonical_bytes(
            {
                "envelope": envelope,
                "publisher_key_id": KEY_INFO["key_id"],
                "sig": "0x" + PRIVATE_KEY.sign(message).hex(),
            }
        )
        outcome = _push(store, body)
        assert (outcome.http_status, outcome.body["code"]) == (400, "record_invalid")
        assert store.last_stored_seq(EventFamily.ACTIVITY) == 0
