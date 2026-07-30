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
import re
import time
from collections.abc import Callable
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
# ingest-contract.md: "`limit` default 500, capped at 1000."
MAX_PAGE_LIMIT: Final[int] = 1000
DEFAULT_MAX_RETRIES: Final[int] = 3
DEFAULT_RETRY_BASE_SECONDS: Final[float] = 0.5

_EMPTY_SHA256: Final[str] = "0x" + hashlib.sha256(b"").hexdigest()
_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-f]{64}$")
_RETRY_STATUS: Final[frozenset[int]] = frozenset({429, 502, 503, 504})

# Platform error codes we must branch on rather than merely report
# (ingest-contract §7.1 / §7.2 — "branch on error.code, never on the
# message; messages are English and may change, codes are stable").
_BACKFILL_RANGE_UNAVAILABLE: Final[str] = "backfill_range_unavailable"
_DIGEST_NOT_SEALED: Final[str] = "digest_not_sealed"
_DIGEST_NOT_FOUND: Final[str] = "digest_not_found"


class BackfillError(RuntimeError):
    """The read API returned something the contract forbids.

    Carries the HTTP status and the platform's error ``code`` when the
    failure came from a response, so a caller can tell "this day's digest
    is not published yet" from "this token cannot read events" without
    parsing the message.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class BackfillRangeUnavailableError(BackfillError):
    """``410 backfill_range_unavailable`` — the range is gone for good.

    ``from_seq`` is below the family's earliest retained seq, so those
    records will never be served (ingest-contract §7.1 case iii). This is
    not "wait": retrying is pointless. A caller either escalates or
    deliberately resumes from :attr:`earliest_available_seq`, recording a
    permanent gap — which every affected day digest will then fail on, so
    the decision belongs to a human, not to a retry loop.
    """

    def __init__(
        self,
        message: str,
        *,
        family: EventFamily,
        requested_from_seq: int,
        earliest_available_seq: int | None,
    ) -> None:
        super().__init__(message, status_code=410, error_code=_BACKFILL_RANGE_UNAVAILABLE)
        self.family = family
        self.requested_from_seq = requested_from_seq
        self.earliest_available_seq = earliest_available_seq


class DigestVerificationError(RuntimeError):
    """A day digest failed signature or shape verification."""


class DigestNotSealedError(BackfillError):
    """``404 digest_not_sealed`` — expected; the seal is not due yet.

    The platform's DB clock is before the epoch's seal deadline (the 00:40
    UTC cron plus 20 minutes' grace, so D+1 01:00). Wait; do not alarm.
    """

    def __init__(self, message: str, *, seal_deadline: str | None, now: str | None) -> None:
        super().__init__(message, status_code=404, error_code=_DIGEST_NOT_SEALED)
        self.seal_deadline = seal_deadline
        self.now = now


class DigestNotFoundError(BackfillError):
    """``404 digest_not_found`` — the anomaly; alarm.

    The epoch closed, its seal window elapsed, and the completeness proof
    is missing. Distinct from :class:`DigestNotSealedError` on purpose: one
    is a clock, the other is a missing proof, and only the second is an
    incident.
    """

    def __init__(self, message: str, *, seal_deadline: str | None, now: str | None) -> None:
        super().__init__(message, status_code=404, error_code=_DIGEST_NOT_FOUND)
        self.seal_deadline = seal_deadline
        self.now = now


@dataclass(frozen=True)
class BackfillConfig:
    """Static configuration for the read-API client.

    ``chain_network`` and ``platform_instance_id`` are the environment
    binding every authenticated platform call must present (see
    :mod:`prometheon.platform.wire`); they are required, not optional, so
    a client cannot be constructed that the platform would reject.

    ``max_retries`` covers the generic 429 backoff the platform asked for:
    there is no server-side rate limit on the read endpoints today, and
    this exists so a future one never breaks catch-up.
    """

    base_url: str
    api_token: str
    trusted_keys: TrustedKeyMap
    chain_network: str
    platform_instance_id: str
    page_limit: int = DEFAULT_PAGE_LIMIT
    allow_test_publisher_key: bool = False
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_base_seconds: float = DEFAULT_RETRY_BASE_SECONDS

    def __post_init__(self) -> None:
        # A page_limit of 0 would make catch-up a no-op that reports
        # success — indistinguishable from "caught up" — and anything
        # above the documented cap is silently clamped server-side, so the
        # local number would stop describing what actually happens.
        if not 1 <= self.page_limit <= MAX_PAGE_LIMIT:
            raise ValueError(
                f"page_limit must be within 1..{MAX_PAGE_LIMIT} (got {self.page_limit})"
            )
        if self.max_retries < 0:
            raise ValueError(f"max_retries must not be negative (got {self.max_retries})")


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
class CatchUpResult:
    """Outcome of a catch-up pass: rows added and where the cursor now sits.

    Deliberately *not* a completeness claim. Catch-up ends when the read
    API serves an empty page at our position, and that single response
    covers both "you have everything the platform has" and "the delivery
    worker has not materialized the next record yet" — the contract
    defines one meaning for it, ``retry later``, and the wire cannot tell
    the two apart. Only a signed day digest settles completeness, which is
    what :meth:`BackfillClient.check_day` is for.
    """

    appended: int
    last_seq: int


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

    **A revoked key still verifies a digest it signed while valid.** The
    key registry keeps revoked keys listed precisely so historical digests
    keep verifying across a rotation (pinned answer B5); the validity
    window at ``signed_at`` is the real gate, not ``status``. Requiring
    ``status == "active"`` here would make every day digest older than a
    rotation permanently unverifiable and turn the completeness gate into
    a standing false alarm. The push path is the opposite — a revoked key
    never signs *new* traffic, so the ingest service does require active.
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
    signed_at = payload["signed_at"]
    if not isinstance(signed_at, str) or not (key.not_before <= signed_at <= key.not_after):
        raise DigestVerificationError(
            f"digest signed_at {signed_at!r} outside the validity window of key {key_id!r} "
            f"({key.not_before} … {key.not_after})"
        )
    if key.public_key == TEST_PUBLISHER_PUBKEY_HEX and not allow_test_publisher_key:
        raise DigestVerificationError("test publisher key refused for digests")
    records_hash = payload["records_hash"]
    # Pinned before use: an unparseable hash would otherwise sail through
    # signature verification and surface later as an unexplained
    # completeness mismatch against a locally well-formed hash.
    if not isinstance(records_hash, str) or not _SHA256_HEX_RE.match(records_hash):
        raise DigestVerificationError(
            f"digest records_hash is not lowercase 0x-prefixed SHA-256 hex: {records_hash!r}"
        )

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

    def __init__(
        self,
        config: BackfillConfig,
        http: httpx.Client,
        *,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._http = http
        self._sleep = sleeper

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """GET a read-API path and return the unwrapped payload.

        Carries the environment binding (omitting it earns
        ``400 ENVIRONMENT_MISMATCH``) and unwraps the success envelope, so
        callers see the payload fields directly. Failures keep the
        platform's error code in the message and on the exception — that
        code is usually the entire diagnosis.

        Retries a rate-limit or transient-gateway status with exponential
        backoff, honouring ``Retry-After`` when the platform sends one.
        There is no server-side read limit today; this exists so a future
        one never breaks catch-up.
        """
        url = self._config.base_url.rstrip("/") + path
        headers = bearer_auth_headers(
            api_token=self._config.api_token,
            chain_network=self._config.chain_network,
            platform_instance_id=self._config.platform_instance_id,
        )
        attempts = self._config.max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                response = self._http.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                # Transport failures are contract failures from the
                # caller's point of view; they must not escape as a bare
                # httpx error past every ``except BackfillError``.
                raise BackfillError(f"read API {path} unreachable: {exc}") from exc

            if response.status_code in _RETRY_STATUS and attempt < attempts:
                self._sleep(self._retry_delay(response, attempt))
                continue

            try:
                body: Any = response.json()
            except ValueError:
                body = response.text
            if response.status_code != 200 or is_error_envelope(body):
                raise self._failure(path, response.status_code, body, params)
            if not isinstance(body, dict):
                raise BackfillError(
                    "read API body is not an object", status_code=response.status_code
                )
            payload = unwrap_success_envelope(body)
            if not isinstance(payload, dict):
                raise BackfillError(
                    f"read API {path} returned an envelope whose 'data' is "
                    f"{type(payload).__name__}, not an object",
                    status_code=response.status_code,
                )
            return payload

        raise BackfillError(f"read API {path} exhausted {attempts} attempts")

    @staticmethod
    def _failure(path: str, status_code: int, body: Any, params: dict[str, Any]) -> BackfillError:
        """Map a failed read-API response onto the exception it deserves.

        The contract's operational cases are distinguished by ``error.code``
        and nothing else — never by the message, which is English prose the
        platform may reword. Anything unrecognised stays a plain
        :class:`BackfillError` carrying the code, so a new platform code
        surfaces intact instead of being coerced into the wrong branch.
        """
        code = _error_code_of(body)
        detail = describe_error_body(body, status_code=status_code)
        details = body.get("error", {}).get("details") if isinstance(body, dict) else None
        details = details if isinstance(details, dict) else {}

        if code == _BACKFILL_RANGE_UNAVAILABLE:
            earliest = details.get("earliest_available_seq")
            requested = params.get("from_seq")
            return BackfillRangeUnavailableError(
                f"read API {path} refused the range: {detail}",
                family=EventFamily(str(params.get("family"))),
                requested_from_seq=int(requested) if isinstance(requested, int) else 0,
                earliest_available_seq=earliest if isinstance(earliest, int) else None,
            )
        if code == _DIGEST_NOT_SEALED:
            return DigestNotSealedError(
                f"digest not sealed yet: {detail}",
                seal_deadline=_str_or_none(details.get("seal_deadline")),
                now=_str_or_none(details.get("now")),
            )
        if code == _DIGEST_NOT_FOUND:
            return DigestNotFoundError(
                f"digest missing after its seal deadline: {detail}",
                seal_deadline=_str_or_none(details.get("seal_deadline")),
                now=_str_or_none(details.get("now")),
            )
        return BackfillError(
            f"read API {path} failed: {detail}",
            status_code=status_code,
            error_code=code,
        )

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        """Backoff before retry ``attempt``; ``Retry-After`` wins if sane."""
        header = response.headers.get("Retry-After")
        if header is not None:
            try:
                requested = float(header)
            except ValueError:
                requested = -1.0
            if 0 <= requested <= 60:
                return requested
        return self._config.retry_base_seconds * (2.0 ** (attempt - 1))

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
    ) -> CatchUpResult:
        """Pull pages until the read API has nothing more.

        Every page's records are decoded from ``canonical_bytes``, strict-
        parsed, envelope-validated, checked byte-identical against the
        delivered bytes (the bytes ARE the record), and appended
        contiguously.

        Ends when the read API serves an empty page at our position; that
        is not a completeness proof (see :class:`CatchUpResult`) — the day
        digest is. Records already appended stay appended if a later page
        fails, so a failed pass is always safe to re-run.
        """
        appended = 0
        for _page_index in range(max_pages):
            cursor = store.last_stored_seq(family)
            from_seq = cursor + 1
            page = self.fetch_page(family, from_seq)
            records = page.get("records")
            next_seq = page.get("next_seq")
            if not isinstance(records, list) or not isinstance(next_seq, int):
                raise BackfillError("backfill page malformed")
            self._check_page_echo(page, family, from_seq)
            if not records:
                if next_seq != from_seq:
                    # The documented empty page is next_seq == from_seq
                    # ("retry later"). A forward jump with no records says
                    # the platform's frontier is past a range it will not
                    # serve — records aged out of its retention, most
                    # likely, after a very long outage. Skipping ahead
                    # would leave a silent hole that every affected day
                    # digest then fails on, with nothing pointing at the
                    # cause. Stop and say so instead.
                    raise BackfillError(
                        f"read API served no records for {family.value} at seq {from_seq} but "
                        f"moved the cursor to {next_seq}: seq {from_seq}..{next_seq - 1} is "
                        "unavailable and cannot be recovered by backfill — escalate rather "
                        "than skipping the range"
                    )
                return CatchUpResult(appended=appended, last_seq=cursor)

            prepared: list[PreparedRecord] = []
            expected_seq = from_seq
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
                # Everything from here to the append is decode + strict
                # validation of platform-supplied bytes. Any failure is a
                # contract violation and is reported as one, rather than
                # escaping as a ValueError from bytes.fromhex or a
                # validation error from the record parser.
                try:
                    blob = bytes.fromhex(blob_hex[2:])
                    raw = load_record_mapping(blob)
                    _, view = validate_event_record(raw)
                except (ValueError, EventStoreError) as exc:
                    raise BackfillError(
                        f"backfill record at seq {seq} did not decode: {exc}"
                    ) from exc
                if view.family is not family or view.seq != seq:
                    raise BackfillError(f"backfill record at seq {seq} does not match its envelope")
                if entry.get("event_id") != view.event_id:
                    raise BackfillError(f"backfill event_id mismatch at seq {seq}")
                record = PreparedRecord.from_mapping(raw, view)
                # The contract promises these are the SAME bytes push
                # delivers, stored once and byte-identical. Verify it here
                # instead of storing a re-canonicalised variant: any
                # difference would otherwise surface days later as an
                # unexplained day-digest mismatch.
                if record.canonical_bytes != blob:
                    raise BackfillError(
                        f"backfill record at seq {seq} is not canonical: the delivered bytes "
                        "differ from their canonical re-encoding, so the platform's day digest "
                        "cannot match any store that keeps them"
                    )
                prepared.append(record)
                expected_seq += 1

            if next_seq != expected_seq:
                raise BackfillError(
                    f"backfill page ends at seq {expected_seq - 1} but next_seq is {next_seq}; "
                    "the page is documented contiguous, so the cursor to resume from is ambiguous"
                )

            try:
                store.append(family, prepared)
            except EventStoreError as exc:
                raise BackfillError(f"backfill append failed: {exc}") from exc
            appended += len(prepared)
        raise BackfillError(
            f"backfill did not converge within {max_pages} pages ({appended} records stored, "
            f"cursor at {store.last_stored_seq(family)}); re-run to continue"
        )

    @staticmethod
    def _check_page_echo(page: dict[str, Any], family: EventFamily, from_seq: int) -> None:
        """Confirm the page answers the request it echoes back.

        Both fields are documented on every page (§7.1), so a missing one
        is itself a contract breach — and skipping the check when they are
        absent would leave the empty-page case unguarded, which is exactly
        the case that decides whether catch-up stops.
        """
        echoed_family = page.get("family")
        if echoed_family != family.value:
            raise BackfillError(
                f"backfill page is for family {echoed_family!r}, not {family.value!r}"
            )
        echoed_from = page.get("from_seq")
        if echoed_from != from_seq:
            raise BackfillError(
                f"backfill page starts at from_seq {echoed_from!r}, not the requested {from_seq}"
            )

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


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _error_code_of(body: Any) -> str | None:
    """The platform's error ``code``, when the body carries one."""
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            code: str = error["code"]
            return code
        if isinstance(body.get("code"), str):
            flat: str = body["code"]
            return flat
    return None


__all__ = [
    "BACKFILL_PATH",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_PAGE_LIMIT",
    "DIGEST_PATH",
    "MAX_PAGE_LIMIT",
    "BackfillClient",
    "BackfillConfig",
    "BackfillError",
    "BackfillRangeUnavailableError",
    "CatchUpResult",
    "CompletenessReport",
    "DigestNotFoundError",
    "DigestNotSealedError",
    "DigestVerificationError",
    "SignedDayDigest",
    "compare_day",
    "verify_signed_digest",
]
