"""Backfill catch-up client and day-digest completeness verification.

Live push is forward-only from the platform's frontier; a validator that
is behind (fresh join, outage, rejected gap) pulls the missing range from
the read API and then proves whole-day completeness against the signed
day digest:

- :class:`BackfillClient.catch_up` pages
  ``GET /events/backfill?family=&from_seq=&limit=`` — each page is
  contiguous and gap-free, carrying the **exact canonical bytes** push
  would have delivered — validates every record through the strict
  parser + envelope model, and appends through the same store primitive
  the ingest service uses. An empty page with ``next_seq == from_seq``
  means "nothing materialized yet; retry later".
- :func:`verify_signed_digest` checks the platform's Ed25519 signature
  over ``PROMETHEON_DAY_DIGEST_V1 + 0x0A + JCS(envelope)`` with the key
  resolved from ``platform_key_id`` (validity window at ``signed_at``;
  the publicly-derivable test key refused unless explicitly allowed).
- :class:`BackfillClient.check_day` recomputes
  ``SHA-256(concat(stored canonical bytes in seq order))`` and the count
  for a (family, epoch) and compares both against the verified digest.
  A mismatch is the completeness alarm — identical for every validator,
  never resolved silently.

Every call obeys both platform wire conventions from
:mod:`prometheon.platform.wire` — environment-binding headers on the way
out, success-envelope unwrapping on the way back. Staging bring-up found
this module violating both, which had left the completeness gate and
catch-up dead on arrival while the mocked tests passed.

The HTTP client is injected (httpx), so tests drive the full code path
through ``httpx.MockTransport`` with fixture bytes. Those mocks must
reproduce the real envelope and assert the outgoing headers; a mock that
answers with a bare body certifies nothing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from prometheon.events.records import EventFamily, validate_event_record
from prometheon.events.store import (
    EventStore,
    EventStoreError,
    PreparedRecord,
    load_record_mapping,
)
from prometheon.platform.signing import TrustedKeyMap
from prometheon.platform.wire import (
    bearer_auth_headers,
    describe_error_body,
    is_error_envelope,
    unwrap_success_envelope,
)
from prometheon.security.canonical import (
    DOMAIN_DAY_DIGEST,
    CanonicalEncodingError,
    to_canonical_bytes,
)

TEST_PUBLISHER_PUBKEY_HEX: Final[str] = (
    "0xaed1b5ea8a4ec357f061aac1020691c90c59dd71e5ab882c832781b3466d011e"
)

BACKFILL_PATH: Final[str] = "/api/v1/prometheon/events/backfill"
DIGEST_PATH: Final[str] = "/api/v1/prometheon/events/digest"
DEFAULT_PAGE_LIMIT: Final[int] = 500

_EMPTY_SHA256: Final[str] = "0x" + hashlib.sha256(b"").hexdigest()


class BackfillError(RuntimeError):
    """The read API returned something the contract forbids."""


class DigestVerificationError(RuntimeError):
    """A day digest failed signature or shape verification."""


@dataclass(frozen=True)
class BackfillConfig:
    """Static configuration for the read-API client.

    ``chain_network`` and ``platform_instance_id`` are the environment
    binding every authenticated platform call must present (see
    :mod:`prometheon.platform.wire`); they are required, not optional, so
    a client cannot be constructed that the platform would reject.
    """

    base_url: str
    api_token: str
    trusted_keys: TrustedKeyMap
    chain_network: str
    platform_instance_id: str
    page_limit: int = DEFAULT_PAGE_LIMIT
    allow_test_publisher_key: bool = False


@dataclass(frozen=True)
class SignedDayDigest:
    """A verified per-(family, epoch) digest."""

    family: EventFamily
    epoch_id: str
    records_hash: str
    record_count: int
    platform_key_id: str
    signed_at: str


@dataclass(frozen=True)
class CompletenessReport:
    """Outcome of comparing local bytes against the signed digest."""

    family: EventFamily
    epoch_id: str
    matches: bool
    local_records_hash: str
    digest_records_hash: str
    local_record_count: int
    digest_record_count: int


def verify_signed_digest(
    payload: dict[str, Any],
    *,
    trusted_keys: TrustedKeyMap,
    allow_test_publisher_key: bool = False,
) -> SignedDayDigest:
    """Verify a digest API payload and return the typed digest.

    ``payload`` is the read-API response shape:
    ``{family, epoch_id, records_hash, record_count, signature,
    platform_key_id, signed_at}``. The signature covers the canonical
    envelope ``{domain, family, epoch_id, records_hash, record_count}``.
    """
    required = {
        "family",
        "epoch_id",
        "records_hash",
        "record_count",
        "signature",
        "platform_key_id",
        "signed_at",
    }
    if not isinstance(payload, dict) or not required.issubset(payload.keys()):
        raise DigestVerificationError("digest payload missing required fields")

    key_id = payload["platform_key_id"]
    key = trusted_keys.get(key_id)
    if key is None:
        raise DigestVerificationError(f"unknown platform_key_id {key_id!r}")
    if key.status != "active":
        raise DigestVerificationError(f"platform key {key_id!r} is revoked")
    signed_at = payload["signed_at"]
    if not isinstance(signed_at, str) or not (key.not_before <= signed_at <= key.not_after):
        raise DigestVerificationError("digest signed_at outside key validity window")
    if key.public_key == TEST_PUBLISHER_PUBKEY_HEX and not allow_test_publisher_key:
        raise DigestVerificationError("test publisher key refused for digests")

    envelope = {
        "domain": DOMAIN_DAY_DIGEST,
        "family": payload["family"],
        "epoch_id": payload["epoch_id"],
        "records_hash": payload["records_hash"],
        "record_count": payload["record_count"],
    }
    try:
        message = DOMAIN_DAY_DIGEST.encode("ascii") + b"\n" + to_canonical_bytes(envelope)
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key[2:]))
        signature = payload["signature"]
        if not isinstance(signature, str) or not signature.startswith("0x"):
            raise DigestVerificationError("digest signature malformed")
        public_key.verify(bytes.fromhex(signature[2:]), message)
    except InvalidSignature as exc:
        raise DigestVerificationError("digest signature did not verify") from exc
    except (ValueError, CanonicalEncodingError) as exc:
        raise DigestVerificationError(f"digest envelope malformed: {exc}") from exc

    try:
        family = EventFamily(payload["family"])
    except ValueError as exc:
        raise DigestVerificationError(f"unknown family {payload['family']!r}") from exc

    record_count = payload["record_count"]
    if not isinstance(record_count, int) or isinstance(record_count, bool) or record_count < 0:
        raise DigestVerificationError("record_count malformed")

    return SignedDayDigest(
        family=family,
        epoch_id=payload["epoch_id"],
        records_hash=payload["records_hash"],
        record_count=record_count,
        platform_key_id=key_id,
        signed_at=signed_at,
    )


class BackfillClient:
    """Pull-side catch-up against the platform read API."""

    def __init__(self, config: BackfillConfig, http: httpx.Client) -> None:
        self._config = config
        self._http = http

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """GET a read-API path and return the unwrapped payload.

        Carries the environment binding (omitting it earns
        ``400 ENVIRONMENT_MISMATCH``) and unwraps the success envelope, so
        callers see the payload fields directly. Failures keep the
        platform's error code in the message — that code is usually the
        entire diagnosis.
        """
        response = self._http.get(
            self._config.base_url.rstrip("/") + path,
            params=params,
            headers=bearer_auth_headers(
                api_token=self._config.api_token,
                chain_network=self._config.chain_network,
                platform_instance_id=self._config.platform_instance_id,
            ),
        )
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text
        if response.status_code != 200 or is_error_envelope(body):
            raise BackfillError(
                f"read API {path} failed: "
                f"{describe_error_body(body, status_code=response.status_code)}"
            )
        if not isinstance(body, dict):
            raise BackfillError("read API body is not an object")
        payload = unwrap_success_envelope(body)
        if not isinstance(payload, dict):
            raise BackfillError(
                f"read API {path} returned an envelope whose 'data' is "
                f"{type(payload).__name__}, not an object"
            )
        return payload

    def fetch_page(self, family: EventFamily, from_seq: int) -> dict[str, Any]:
        return self._get(
            BACKFILL_PATH,
            {
                "family": family.value,
                "from_seq": from_seq,
                "limit": self._config.page_limit,
            },
        )

    def catch_up(
        self,
        store: EventStore,
        family: EventFamily,
        *,
        max_pages: int = 1000,
    ) -> int:
        """Pull pages until the read API has nothing more; returns rows added.

        Every page's records are decoded from ``canonical_bytes``, strict-
        parsed, envelope-validated, checked byte-identical against their
        own decode (the bytes ARE the record), and appended contiguously.
        """
        appended = 0
        for _page_index in range(max_pages):
            cursor = store.last_stored_seq(family)
            page = self.fetch_page(family, cursor + 1)
            records = page.get("records")
            next_seq = page.get("next_seq")
            if not isinstance(records, list) or not isinstance(next_seq, int):
                raise BackfillError("backfill page malformed")
            if not records:
                # next_seq == from_seq means not-yet-materialized: caller
                # retries later. Anything else with no records is done.
                return appended

            prepared: list[PreparedRecord] = []
            expected_seq = cursor + 1
            for entry in records:
                if not isinstance(entry, dict):
                    raise BackfillError("backfill entry malformed")
                seq = entry.get("seq")
                blob_hex = entry.get("canonical_bytes")
                if seq != expected_seq:
                    raise BackfillError(
                        f"backfill page not contiguous: expected {expected_seq}, got {seq!r}"
                    )
                if not isinstance(blob_hex, str) or not blob_hex.startswith("0x"):
                    raise BackfillError("backfill canonical_bytes malformed")
                blob = bytes.fromhex(blob_hex[2:])
                raw = load_record_mapping(blob)
                _, view = validate_event_record(raw)
                if view.family is not family or view.seq != seq:
                    raise BackfillError(f"backfill record at seq {seq} does not match its envelope")
                if entry.get("event_id") != view.event_id:
                    raise BackfillError(f"backfill event_id mismatch at seq {seq}")
                prepared.append(PreparedRecord.from_mapping(raw, view))
                expected_seq += 1

            try:
                store.append(family, prepared)
            except EventStoreError as exc:
                raise BackfillError(f"backfill append failed: {exc}") from exc
            appended += len(prepared)
        raise BackfillError("backfill did not converge within max_pages")

    def fetch_digest(self, family: EventFamily, epoch_id: str) -> SignedDayDigest:
        """Fetch and verify the signed digest for exactly this (family, epoch).

        The signature proves the platform authored *some* digest, not that
        it answered the question asked: a correctly-signed digest for a
        different day would otherwise let :meth:`check_day` report a day
        complete that was never examined. Bind the answer to the request.
        """
        payload = self._get(DIGEST_PATH, {"family": family.value, "epoch": epoch_id})
        digest = verify_signed_digest(
            payload,
            trusted_keys=self._config.trusted_keys,
            allow_test_publisher_key=self._config.allow_test_publisher_key,
        )
        if digest.family is not family or digest.epoch_id != epoch_id:
            raise BackfillError(
                f"read API answered with a digest for {digest.family.value}/{digest.epoch_id} "
                f"when {family.value}/{epoch_id} was requested"
            )
        return digest

    def check_day(
        self, store: EventStore, family: EventFamily, epoch_id: str
    ) -> CompletenessReport:
        """Compare local bytes for (family, epoch) against the signed digest."""
        digest = self.fetch_digest(family, epoch_id)
        return compare_day(store, digest)


def compare_day(store: EventStore, digest: SignedDayDigest) -> CompletenessReport:
    """Recompute the local day hash/count and compare with a verified digest."""
    local_bytes = store.canonical_bytes_for_epoch(digest.family, digest.epoch_id)
    local_hash = (
        "0x" + hashlib.sha256(b"".join(local_bytes)).hexdigest() if local_bytes else _EMPTY_SHA256
    )
    local_count = len(local_bytes)
    return CompletenessReport(
        family=digest.family,
        epoch_id=digest.epoch_id,
        matches=(local_hash == digest.records_hash and local_count == digest.record_count),
        local_records_hash=local_hash,
        digest_records_hash=digest.records_hash,
        local_record_count=local_count,
        digest_record_count=digest.record_count,
    )


__all__ = [
    "BACKFILL_PATH",
    "DEFAULT_PAGE_LIMIT",
    "DIGEST_PATH",
    "BackfillClient",
    "BackfillConfig",
    "BackfillError",
    "CompletenessReport",
    "DigestVerificationError",
    "SignedDayDigest",
    "compare_day",
    "verify_signed_digest",
]
