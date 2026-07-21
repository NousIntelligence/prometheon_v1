"""Ingest push endpoint — the HTTP surface BitFan delivers batches to.

Implements the validator side of the ingest contract §4 as a **pure
pipeline** (:func:`process_push`) wrapped by a thin Starlette app
(:func:`create_ingest_app`). The pipeline enforces, in contract order:

1. body size cap and strict parse (duplicate/forbidden keys, floats);
2. publisher signature — Ed25519 over
   ``PROMETHEON_INGEST_PUSH_V1 + 0x0A + JCS(envelope)`` against the key
   resolved from ``publisher_key_id``, with the key's validity window
   checked at ``envelope.sent_at`` and the publicly-derivable **test key
   refused** unless explicitly allowed (fixture/local runs only);
3. environment binding (``platform_instance_id`` + ``chain_network``);
4. replay defence (fresh nonce, ``sent_at`` within the skew window);
5. envelope shape (family, contiguous seqs, record count = span, batch cap);
6. the four-case contiguity rule against the store cursor:
   exact-next → store all; overlap-with-new-tail → store the tail from
   ``last_stored + 1``; full duplicate → store nothing, ack the position;
   forward gap → reject and let the backfill client catch up.

ACK semantics: a ``2xx`` always carries ``received_through_seq`` (the only
field the platform reads); rejections are non-2xx with a machine-readable
``code`` and never a 200-with-reject-body. Nothing in this module reads a
wall clock — the app injects one, the pipeline takes ``now`` explicitly.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore, EventStoreError, prepare_wire_records
from prometheon.platform.signing import TrustedKeyMap
from prometheon.security.canonical import (
    DOMAIN_INGEST_PUSH,
    CanonicalEncodingError,
    parse_canonical_json,
    to_canonical_bytes,
)

# The committed, publicly-derivable fixture publisher key. Anyone can sign
# as it; a live validator must never trust it.
TEST_PUBLISHER_PUBKEY_HEX: Final[str] = (
    "0xaed1b5ea8a4ec357f061aac1020691c90c59dd71e5ab882c832781b3466d011e"
)

DEFAULT_MAX_BATCH_RECORDS: Final[int] = 1000
DEFAULT_MAX_BODY_BYTES: Final[int] = 10 * 1024 * 1024
DEFAULT_SENT_AT_SKEW_SECONDS: Final[int] = 300

_TS_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class IngestConfig:
    """Static configuration for the ingest pipeline."""

    platform_instance_id: str
    chain_network: str
    trusted_keys: TrustedKeyMap
    max_batch_records: int = DEFAULT_MAX_BATCH_RECORDS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    sent_at_skew_seconds: int = DEFAULT_SENT_AT_SKEW_SECONDS
    allow_test_publisher_key: bool = field(default=False)


@dataclass(frozen=True)
class IngestOutcome:
    """HTTP status + JSON body the handler returns."""

    http_status: int
    body: dict[str, Any]


def _reject(status: int, code: str, **extra: Any) -> IngestOutcome:
    return IngestOutcome(http_status=status, body={"code": code, **extra})


def _parse_sent_at(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def process_push(
    raw_body: bytes,
    *,
    store: EventStore,
    config: IngestConfig,
    now: datetime,
) -> IngestOutcome:
    """Run one push body through the full §4 pipeline."""
    # 1. Size + strict parse.
    if len(raw_body) > config.max_body_bytes:
        return _reject(413, "body_too_large")
    try:
        parsed = parse_canonical_json(raw_body)
    except CanonicalEncodingError as exc:
        return _reject(400, exc.code)
    if not isinstance(parsed, dict) or set(parsed.keys()) != {
        "envelope",
        "publisher_key_id",
        "sig",
    }:
        return _reject(400, "malformed_push")

    envelope = parsed["envelope"]
    publisher_key_id = parsed["publisher_key_id"]
    signature_hex = parsed["sig"]
    if not isinstance(envelope, dict) or not isinstance(publisher_key_id, str):
        return _reject(400, "malformed_push")
    if not isinstance(signature_hex, str) or not signature_hex.startswith("0x"):
        return _reject(400, "malformed_push")

    # Envelope fields needed before signature verification.
    sent_at_raw = envelope.get("sent_at")
    if not isinstance(sent_at_raw, str):
        return _reject(400, "envelope_invalid", detail="sent_at missing")
    sent_at = _parse_sent_at(sent_at_raw)
    if sent_at is None:
        return _reject(400, "envelope_invalid", detail="sent_at malformed")

    # 2. Publisher key + signature.
    key = config.trusted_keys.get(publisher_key_id)
    if key is None:
        return _reject(401, "unknown_publisher_key")
    if key.status != "active":
        return _reject(401, "publisher_key_revoked")
    if not (key.not_before <= sent_at_raw <= key.not_after):
        return _reject(401, "publisher_key_outside_validity")
    if key.public_key == TEST_PUBLISHER_PUBKEY_HEX and not config.allow_test_publisher_key:
        return _reject(401, "test_publisher_key_refused")

    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key[2:]))
        message = DOMAIN_INGEST_PUSH.encode("ascii") + b"\n" + to_canonical_bytes(envelope)
        public_key.verify(bytes.fromhex(signature_hex[2:]), message)
    except (InvalidSignature, ValueError):
        return _reject(401, "signature_invalid")

    # 3. Environment binding.
    if (
        envelope.get("platform_instance_id") != config.platform_instance_id
        or envelope.get("chain_network") != config.chain_network
    ):
        return _reject(403, "environment_mismatch")

    # 4. Replay defence.
    if abs((sent_at - now).total_seconds()) > config.sent_at_skew_seconds:
        return _reject(401, "replay_window")
    nonce = envelope.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return _reject(400, "envelope_invalid", detail="nonce missing")
    if store.nonce_seen(nonce):
        return _reject(401, "replay_nonce")

    # 5. Envelope shape.
    if envelope.get("domain") != DOMAIN_INGEST_PUSH:
        return _reject(400, "envelope_invalid", detail="wrong domain")
    family_raw = envelope.get("family")
    try:
        family = EventFamily(family_raw)
    except ValueError:
        return _reject(400, "envelope_invalid", detail=f"unknown family {family_raw!r}")
    from_seq = envelope.get("from_seq")
    to_seq = envelope.get("to_seq")
    records = envelope.get("records")
    if (
        not isinstance(from_seq, int)
        or isinstance(from_seq, bool)
        or not isinstance(to_seq, int)
        or isinstance(to_seq, bool)
        or from_seq < 1
        or to_seq < from_seq
        or not isinstance(records, list)
        or not records
    ):
        return _reject(400, "envelope_invalid", detail="seq range or records malformed")
    if len(records) != to_seq - from_seq + 1:
        return _reject(400, "envelope_invalid", detail="record count != seq span")
    if len(records) > config.max_batch_records:
        return _reject(400, "batch_too_large")
    for offset, wire_record in enumerate(records):
        if not isinstance(wire_record, dict) or wire_record.get("seq") != from_seq + offset:
            return _reject(400, "envelope_invalid", detail="records not contiguous")

    # 6. Four-case contiguity rule against the store cursor.
    last_stored = store.last_stored_seq(family)
    if from_seq > last_stored + 1:
        return _reject(409, "gap", received_through_seq=last_stored)

    if to_seq <= last_stored:
        store.record_nonce(nonce, seen_at=now.strftime(_TS_FORMAT))
        return IngestOutcome(200, {"received_through_seq": last_stored})

    tail = [record for record in records if record["seq"] > last_stored]
    try:
        prepared = prepare_wire_records(family, tail)
        new_cursor = store.append(family, prepared)
    except EventStoreError as exc:
        return _reject(500, "store_error", detail=str(exc))
    except ValueError as exc:  # EventRecordError and canonicalization failures
        return _reject(400, "record_invalid", detail=str(exc))

    store.record_nonce(nonce, seen_at=now.strftime(_TS_FORMAT))
    return IngestOutcome(200, {"received_through_seq": new_cursor})


def create_ingest_app(
    store: EventStore,
    config: IngestConfig,
    *,
    clock: Callable[[], datetime] | None = None,
) -> Starlette:
    """Build the Starlette app serving the push endpoint and a health probe.

    A single lock serializes pushes (the store is not thread-safe and the
    platform delivers at most one in-flight push per family — the lock also
    makes brief double-delivery during platform worker failover safe).
    """
    read_clock = clock if clock is not None else lambda: datetime.now(timezone.utc)
    lock = asyncio.Lock()

    async def ingest(request: Request) -> JSONResponse:
        raw_body = await request.body()
        async with lock:
            outcome = await run_in_threadpool(
                process_push, raw_body, store=store, config=config, now=read_clock()
            )
        return JSONResponse(outcome.body, status_code=outcome.http_status)

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/", ingest, methods=["POST"]),
            Route("/healthz", health, methods=["GET"]),
        ]
    )


__all__ = [
    "DEFAULT_MAX_BATCH_RECORDS",
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_SENT_AT_SKEW_SECONDS",
    "TEST_PUBLISHER_PUBKEY_HEX",
    "IngestConfig",
    "IngestOutcome",
    "create_ingest_app",
    "process_push",
]
