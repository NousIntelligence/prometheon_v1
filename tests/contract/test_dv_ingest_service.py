"""Ingest-service contract gates: the fixture batch through the real app.

POSTs the EXACT ``ingest-push/01`` wire bytes at the production Starlette
app and asserts the contract's observable behavior for every cursor case —
including the fixture's second role as the cross-environment rejection
input. The day digest recomputed from what the service stored must equal
the fixture digest, closing the push → store → digest loop end-to-end.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from prometheon.events.ingest import IngestConfig, create_ingest_app
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore
from prometheon.platform.signing import TrustedKey

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"

WIRE_BYTES = bytes.fromhex(
    (FIXTURES / "ingest-push" / "01-signed-batch" / "wire.bytes.hex").read_text().strip()
)
BATCH: dict[str, Any] = json.loads(
    (FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json").read_text()
)
KEY_INFO: dict[str, Any] = json.loads(
    (FIXTURES / "test-keys" / "ed25519-platform.json").read_text()
)
DIGEST_ENV: dict[str, Any] = json.loads(
    (FIXTURES / "event-record" / "03-day-digest" / "envelope.json").read_text()
)

FIXTURE_CLOCK = datetime(2026, 7, 14, 9, 20, 0, tzinfo=timezone.utc)


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


def _post(store: EventStore, config: IngestConfig, content: bytes) -> httpx.Response:
    app = create_ingest_app(store, config, clock=lambda: FIXTURE_CLOCK)
    transport = httpx.ASGITransport(app=app)

    async def _run() -> httpx.Response:
        async with httpx.AsyncClient(transport=transport, base_url="http://ingest.test") as client:
            return await client.post("/", content=content)

    return asyncio.run(_run())


def _seed_cursor(store: EventStore, seq: int) -> None:
    store._connection.execute(
        "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
        (EventFamily.ACTIVITY.value, seq),
    )
    store._connection.commit()


class TestFixtureBatchDelivery:
    def test_exact_next_stores_and_acks(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, BATCH["envelope"]["from_seq"] - 1)
            response = _post(store, _config(), WIRE_BYTES)
            assert response.status_code == 200
            assert response.json() == {"received_through_seq": BATCH["envelope"]["to_seq"]}

            stored = store.canonical_bytes_for_epoch(EventFamily.ACTIVITY, DIGEST_ENV["epoch_id"])
            recomputed = "0x" + hashlib.sha256(b"".join(stored)).hexdigest()
            assert recomputed == DIGEST_ENV["records_hash"]

    def test_overlap_tail_consumed(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, BATCH["envelope"]["from_seq"])  # already hold 4207
            response = _post(store, _config(), WIRE_BYTES)
            assert response.status_code == 200
            assert response.json() == {"received_through_seq": BATCH["envelope"]["to_seq"]}
            stored_seqs = [record["seq"] for record in store.iter_family(EventFamily.ACTIVITY)]
            assert stored_seqs == [BATCH["envelope"]["to_seq"]]

    def test_full_duplicate_acks_without_storing(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, BATCH["envelope"]["to_seq"])
            response = _post(store, _config(), WIRE_BYTES)
            assert response.status_code == 200
            assert response.json() == {"received_through_seq": BATCH["envelope"]["to_seq"]}
            assert list(store.iter_family(EventFamily.ACTIVITY)) == []

    def test_forward_gap_rejected_with_position(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            response = _post(store, _config(), WIRE_BYTES)
            assert response.status_code == 409
            body = response.json()
            assert body["code"] == "gap"
            assert body["received_through_seq"] == 0
            assert list(store.iter_family(EventFamily.ACTIVITY)) == []

    def test_cross_environment_rejected(self, tmp_path: Path) -> None:
        # The fixture's platform_instance_id is bitfan-local; a staging
        # validator MUST refuse it — the fixture's documented second role.
        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, BATCH["envelope"]["from_seq"] - 1)
            config = _config(platform_instance_id="bitfan-staging")
            response = _post(store, config, WIRE_BYTES)
            assert response.status_code == 403
            assert response.json()["code"] == "environment_mismatch"
            assert list(store.iter_family(EventFamily.ACTIVITY)) == []

    def test_replayed_nonce_rejected(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            _seed_cursor(store, BATCH["envelope"]["from_seq"] - 1)
            config = _config()
            assert _post(store, config, WIRE_BYTES).status_code == 200
            replay = _post(store, config, WIRE_BYTES)
            assert replay.status_code == 401
            assert replay.json()["code"] == "replay_nonce"

    def test_test_key_refused_outside_local(self, tmp_path: Path) -> None:
        with EventStore(tmp_path / "e.sqlite") as store:
            config = _config(allow_test_publisher_key=False)
            response = _post(store, config, WIRE_BYTES)
            assert response.status_code == 401
            assert response.json()["code"] == "test_publisher_key_refused"
