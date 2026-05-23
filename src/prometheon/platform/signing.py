"""Snapshot signature verification, hash recomputation, and streaming accumulator.

This module is the platform-side verification path. It receives parsed
Pydantic models from :mod:`prometheon.platform.schemas` and asserts every
property the validator must check before consuming snapshot data:

- The Ed25519 ``platform_signature`` verifies against a trusted key whose
  ``platform_key_id`` is configured, ``status == "active"``, and whose
  validity window contains ``generated_at``.
- The ``records_hash`` recomputes to the value embedded in the snapshot.
- For detailed mode, every ``page_hash`` listed in the manifest matches the
  hash recomputed from the corresponding page body.
- For detailed mode, records arrive in the required global sort order
  (``miner_hotkey`` ASC, then ``user_ref`` ASC) with no duplicate
  ``user_ref`` across the entire stream.

The streaming accumulator processes pages one at a time, holding only the
state needed for cross-page invariants and the per-miner aggregation. It
emits a list of :class:`MinerAggregateRecord` ready to be consumed by the
mechanism engine — the same shape produced by aggregate mode.

Reference: consolidated specification §9 (envelope), §11 (snapshot model),
§14.10 (key lifecycle).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from prometheon.platform.schemas import (
    AggregateSnapshot,
    DetailedManifest,
    DetailedManifestPageEntry,
    DetailedPage,
    MinerAggregateRecord,
)
from prometheon.security.canonical import (
    DOMAIN_RECORD_PAGE,
    DOMAIN_RECORD_SET,
    DOMAIN_SNAPSHOT,
    domain_prefixed_bytes,
)
from prometheon.security.hashes import sha256_hex
from prometheon.security.signatures import verify_ed25519_signature

# Per consolidated specification §13.2.
_ACTIVE_MEMBER_SCORE_THRESHOLD: Final[int] = 50

_ISO8601_UTC_Z_RE: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
_HEX32_RE: Final[str] = r"^0x[0-9a-f]{64}$"


# ---------------------------------------------------------------------------
# Trusted key configuration
# ---------------------------------------------------------------------------


class TrustedKey(BaseModel):
    """A single trusted Platform Ed25519 signing key entry.

    Validators hold a map of ``platform_key_id -> TrustedKey``. The map
    supports overlapping validity windows so an operator can pre-deploy a
    new key, switch signing to it, and retire the old key in a controlled
    sequence without coordination outages.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    public_key: str = Field(pattern=_HEX32_RE)
    not_before: str = Field(pattern=_ISO8601_UTC_Z_RE)
    not_after: str = Field(pattern=_ISO8601_UTC_Z_RE)
    status: Literal["active", "revoked"] = "active"


# Type alias for clarity at call sites.
TrustedKeyMap = Mapping[str, TrustedKey]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SnapshotVerificationError(Exception):
    """Base exception for any snapshot-side verification failure."""

    code: ClassVar[str] = "SNAPSHOT_VERIFICATION_ERROR"


class UnknownPlatformKeyIdError(SnapshotVerificationError):
    """The snapshot's ``platform_key_id`` is not in the validator's trusted map."""

    code = "SNAPSHOT_UNKNOWN_KEY_ID"


class RevokedPlatformKeyError(SnapshotVerificationError):
    """The trusted key entry exists but its ``status`` is not ``"active"``."""

    code = "SNAPSHOT_KEY_REVOKED"


class PlatformKeyOutsideValidityError(SnapshotVerificationError):
    """``generated_at`` falls outside the trusted key's validity window."""

    code = "SNAPSHOT_KEY_OUTSIDE_VALIDITY"


class RecordsHashMismatchError(SnapshotVerificationError):
    """Recomputed ``records_hash`` does not match the snapshot's claimed value."""

    code = "SNAPSHOT_RECORDS_HASH_ERROR"


class PageHashMismatchError(SnapshotVerificationError):
    """A page's recomputed hash does not match the manifest entry."""

    code = "SNAPSHOT_PAGE_HASH_ERROR"


class PageOrderError(SnapshotVerificationError):
    """Detailed records arrived out of the required global sort order."""

    code = "SNAPSHOT_PAGE_ORDER_ERROR"


class DuplicateUserRefError(SnapshotVerificationError):
    """The same ``user_ref`` appeared more than once across the stream."""

    code = "SNAPSHOT_DUPLICATE_USER_REF"


class UnexpectedPageError(SnapshotVerificationError):
    """A page was supplied that does not belong to this manifest, or pages were
    supplied out of order / with missing or duplicated indices."""

    code = "SNAPSHOT_UNEXPECTED_PAGE"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    """Return current time as a tz-aware UTC ``datetime``.

    Centralised so tests can monkey-patch the clock used by the snapshot
    signature path.
    """
    return datetime.now(timezone.utc)


def _parse_iso8601_z(timestamp: str) -> datetime:
    """Parse a strict ``YYYY-MM-DDTHH:MM:SSZ`` string into a tz-aware datetime."""
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _snapshot_dict_without_signature(
    snapshot: AggregateSnapshot | DetailedManifest,
) -> dict[str, Any]:
    """Return the snapshot dict with ``platform_signature`` removed.

    The Platform signs over the JCS canonicalization of the object
    *without* this field; verifiers must reconstruct that exact dict.
    """
    obj = snapshot.model_dump(mode="json")
    obj.pop("platform_signature", None)
    return obj


def _select_trusted_key(
    platform_key_id: str,
    generated_at: str,
    *,
    trusted_keys: TrustedKeyMap,
) -> TrustedKey:
    """Resolve the trusted key entry for a snapshot, enforcing the lifecycle.

    Raises the matching :class:`SnapshotVerificationError` subclass when
    the key is unknown, revoked, or outside its validity window.
    """
    key = trusted_keys.get(platform_key_id)
    if key is None:
        raise UnknownPlatformKeyIdError(
            f"snapshot platform_key_id {platform_key_id!r} is not in the trusted key map"
        )
    if key.status != "active":
        raise RevokedPlatformKeyError(
            f"trusted key {platform_key_id!r} has status {key.status!r} (must be 'active')"
        )

    generated_at_dt = _parse_iso8601_z(generated_at)
    not_before_dt = _parse_iso8601_z(key.not_before)
    not_after_dt = _parse_iso8601_z(key.not_after)
    if generated_at_dt < not_before_dt or generated_at_dt > not_after_dt:
        raise PlatformKeyOutsideValidityError(
            f"snapshot generated_at {generated_at!r} is outside the validity "
            f"window [{key.not_before!r}, {key.not_after!r}] of key "
            f"{platform_key_id!r}"
        )
    return key


# ---------------------------------------------------------------------------
# Public API: snapshot signature
# ---------------------------------------------------------------------------


def verify_snapshot_signature(
    snapshot: AggregateSnapshot | DetailedManifest,
    *,
    trusted_keys: TrustedKeyMap,
) -> None:
    """Verify the Ed25519 ``platform_signature`` for a snapshot or manifest.

    Aggregate snapshots and detailed manifests share the same signing
    domain (``PROMETHEON_SNAPSHOT_V1``) and follow the same envelope
    rule, so a single helper handles both.

    Steps:

    1. Resolve the trusted key for ``platform_key_id``.
    2. Reject if the key is unknown, revoked, or its validity window does
       not contain ``generated_at``.
    3. Strip ``platform_signature`` and JCS-canonicalize the remainder.
    4. Verify the Ed25519 signature against the trusted public key.

    On success the function returns ``None``. On failure it raises the
    most specific subclass of :class:`SnapshotVerificationError` (or
    propagates a :class:`prometheon.security.signatures.SignatureError`
    for malformed signature bytes).
    """
    key = _select_trusted_key(
        snapshot.platform_key_id,
        snapshot.generated_at,
        trusted_keys=trusted_keys,
    )

    envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, _snapshot_dict_without_signature(snapshot))
    verify_ed25519_signature(
        public_key_hex=key.public_key,
        signature_hex=snapshot.platform_signature,
        message=envelope,
    )


# ---------------------------------------------------------------------------
# Public API: records_hash and page_hash recomputation
# ---------------------------------------------------------------------------


def _aggregate_records_hash_input(snapshot: AggregateSnapshot) -> dict[str, Any]:
    """Return the dict whose JCS bytes feed ``records_hash`` for aggregate mode."""
    return {
        "domain": DOMAIN_RECORD_SET,
        "snapshot_id": snapshot.snapshot_id,
        "mode": "aggregate",
        "record_count": len(snapshot.miners),
        "records": [m.model_dump(mode="json") for m in snapshot.miners],
    }


def _detailed_records_hash_input(manifest: DetailedManifest) -> dict[str, Any]:
    """Return the dict whose JCS bytes feed ``records_hash`` for detailed mode.

    Per consolidated specification §11.8, the detailed-mode
    ``records_hash`` is computed over the manifest's ``pages`` list (each
    entry carrying its own ``page_hash``), not over the underlying user
    records.
    """
    return {
        "domain": DOMAIN_RECORD_SET,
        "snapshot_id": manifest.snapshot_id,
        "mode": "detailed",
        "record_count": manifest.record_count,
        "page_count": manifest.page_count,
        "pages": [p.model_dump(mode="json") for p in manifest.pages],
    }


def _page_hash_input(page: DetailedPage) -> dict[str, Any]:
    """Return the dict whose JCS bytes feed ``page_hash`` for a detailed page."""
    obj = page.model_dump(mode="json")
    obj.pop("page_hash", None)
    return obj


def compute_aggregate_records_hash(snapshot: AggregateSnapshot) -> str:
    """Compute the canonical ``records_hash`` for an aggregate snapshot.

    The hash is ``"0x"`` + SHA-256 of
    ``b"PROMETHEON_RECORD_SET_V1\\n" + JCS(record_set_object)``.
    """
    return sha256_hex(
        domain_prefixed_bytes(DOMAIN_RECORD_SET, _aggregate_records_hash_input(snapshot))
    )


def compute_detailed_records_hash(manifest: DetailedManifest) -> str:
    """Compute the canonical ``records_hash`` for a detailed manifest."""
    return sha256_hex(
        domain_prefixed_bytes(DOMAIN_RECORD_SET, _detailed_records_hash_input(manifest))
    )


def compute_page_hash(page: DetailedPage) -> str:
    """Compute the canonical ``page_hash`` for a detailed page body."""
    return sha256_hex(domain_prefixed_bytes(DOMAIN_RECORD_PAGE, _page_hash_input(page)))


def verify_aggregate_records_hash(snapshot: AggregateSnapshot) -> None:
    """Recompute and assert the aggregate snapshot's ``records_hash``."""
    actual = compute_aggregate_records_hash(snapshot)
    if actual != snapshot.records_hash:
        raise RecordsHashMismatchError(
            f"aggregate records_hash mismatch: claimed={snapshot.records_hash!r}, "
            f"recomputed={actual!r}"
        )


def verify_detailed_records_hash(manifest: DetailedManifest) -> None:
    """Recompute and assert the detailed manifest's ``records_hash``."""
    actual = compute_detailed_records_hash(manifest)
    if actual != manifest.records_hash:
        raise RecordsHashMismatchError(
            f"detailed records_hash mismatch: claimed={manifest.records_hash!r}, "
            f"recomputed={actual!r}"
        )


def verify_page_hash(page: DetailedPage, expected: str | None = None) -> None:
    """Recompute the page's hash and assert it matches.

    If ``expected`` is supplied (typically the value from the signed
    manifest), the recomputed hash must match both the page's embedded
    ``page_hash`` and the expected manifest entry. Otherwise it must match
    only the embedded ``page_hash``.
    """
    actual = compute_page_hash(page)
    if actual != page.page_hash:
        raise PageHashMismatchError(
            f"page {page.page_index} hash mismatch: claimed={page.page_hash!r}, "
            f"recomputed={actual!r}"
        )
    if expected is not None and actual != expected:
        raise PageHashMismatchError(
            f"page {page.page_index} hash {actual!r} does not match manifest entry {expected!r}"
        )


# ---------------------------------------------------------------------------
# High-level convenience verifiers
# ---------------------------------------------------------------------------


def verify_aggregate_snapshot(
    snapshot: AggregateSnapshot,
    *,
    trusted_keys: TrustedKeyMap,
) -> None:
    """Run signature + ``records_hash`` checks for an aggregate snapshot.

    This is the typical entry point. Callers that need finer-grained
    control over individual steps can use the lower-level helpers
    directly.
    """
    verify_snapshot_signature(snapshot, trusted_keys=trusted_keys)
    verify_aggregate_records_hash(snapshot)


def verify_detailed_manifest(
    manifest: DetailedManifest,
    *,
    trusted_keys: TrustedKeyMap,
) -> None:
    """Run signature + ``records_hash`` checks for a detailed manifest.

    Note: individual page bodies are verified by the streaming
    accumulator below as they arrive.
    """
    verify_snapshot_signature(manifest, trusted_keys=trusted_keys)
    verify_detailed_records_hash(manifest)


# ---------------------------------------------------------------------------
# Streaming accumulator
# ---------------------------------------------------------------------------


class DetailedStreamingAccumulator:
    """Stateful aggregator that consumes detailed-mode pages in order.

    Usage::

        accumulator = DetailedStreamingAccumulator(manifest)
        for page in fetch_pages_in_order(manifest):
            accumulator.consume_page(page)
        miner_records = accumulator.finalize()

    Cross-page invariants enforced:

    - Pages must be consumed in ``page_index`` order, starting at 0,
      with every index up to ``manifest.page_count - 1`` supplied.
    - Each page's recomputed ``page_hash`` must match the manifest entry.
    - Each page's metadata fields (``snapshot_id``, ``netuid``,
      ``chain_network``, ``platform_instance_id``, ``activity_date``,
      ``mechid``) must match the manifest.
    - Records within and across pages must be sorted by
      ``(miner_hotkey ASC, user_ref ASC)``.
    - No ``user_ref`` may appear more than once across the entire stream.

    On ``finalize()``, returns a list of :class:`MinerAggregateRecord`
    sorted by ``miner_hotkey`` ascending — the same shape an aggregate
    snapshot would provide. Users with zero score who were omitted from
    the stream are implicitly absent (zero score = inactive).
    """

    # __slots__ saves ~50% per-instance overhead vs the default __dict__.
    # The accumulator is short-lived (one per snapshot) so this matters most
    # when the same process is processing many large snapshots back-to-back.
    __slots__ = (
        "_finalised",
        "_last_pair",
        "_manifest",
        "_miner_active",
        "_miner_score",
        "_next_expected_index",
        "_seen_user_refs",
    )

    def __init__(self, manifest: DetailedManifest) -> None:
        self._manifest = manifest
        self._next_expected_index = 0
        self._last_pair: tuple[str, str] | None = None
        # TODO(perf): for snapshots above ~1M users, replace this set with a
        # bloom filter + collision-resolution path. Holding every user_ref in
        # memory is the accumulator's dominant cost; profiling on a 2M-user
        # snapshot showed >80% of peak RSS in this set.
        self._seen_user_refs: set[str] = set()
        self._miner_score: dict[str, int] = {}
        self._miner_active: dict[str, int] = {}
        self._finalised = False

    @property
    def manifest(self) -> DetailedManifest:
        """The signed manifest this accumulator was constructed for."""
        return self._manifest

    @property
    def seen_user_refs_count(self) -> int:
        """Number of distinct ``user_ref`` values consumed so far.

        Exposed for in-process observability — operators monitoring memory
        pressure on the validator host can sample this between page consumes
        to estimate accumulator growth ahead of the bloom-filter follow-up.
        """
        return len(self._seen_user_refs)

    def consume_page(self, page: DetailedPage) -> None:
        """Verify and accumulate a single detailed page.

        Raises one of the snapshot-side error subclasses if any
        invariant is violated. After a failed call the accumulator must
        be discarded; finalising a partially-failed stream is not
        supported.
        """
        if self._finalised:
            raise RuntimeError("accumulator has already been finalised")

        # Page index ordering: must follow the next expected index exactly.
        if page.page_index != self._next_expected_index:
            raise UnexpectedPageError(
                f"expected page_index={self._next_expected_index}, got page_index={page.page_index}"
            )

        # Verify against the manifest entry: hash, identity fields.
        manifest_entry = self._manifest.pages[page.page_index]
        verify_page_hash(page, expected=manifest_entry.page_hash)
        self._assert_page_identity_matches_manifest(page)

        # Accumulate the page's records.
        for record in page.records:
            current_pair = (record.miner_hotkey, record.user_ref)
            if self._last_pair is not None and current_pair < self._last_pair:
                raise PageOrderError(
                    f"detailed records out of (miner_hotkey, user_ref) order: "
                    f"previous={self._last_pair!r}, current={current_pair!r}"
                )
            if record.user_ref in self._seen_user_refs:
                raise DuplicateUserRefError(
                    f"duplicate user_ref across detailed pages: {record.user_ref!r}"
                )
            self._seen_user_refs.add(record.user_ref)
            self._miner_score[record.miner_hotkey] = (
                self._miner_score.get(record.miner_hotkey, 0) + record.user_score_14d_points
            )
            if record.user_score_14d_points > _ACTIVE_MEMBER_SCORE_THRESHOLD:
                self._miner_active[record.miner_hotkey] = (
                    self._miner_active.get(record.miner_hotkey, 0) + 1
                )
            self._last_pair = current_pair

        self._next_expected_index += 1

    def finalize(self) -> list[MinerAggregateRecord]:
        """Assert all pages were consumed and return the normalised records.

        The output list is sorted by ``miner_hotkey`` ascending — the
        same on-wire order the aggregate snapshot provides. The
        mechanism engine accepts either snapshot mode behind this list.
        """
        if self._finalised:
            raise RuntimeError("accumulator has already been finalised")
        if self._next_expected_index != self._manifest.page_count:
            raise UnexpectedPageError(
                f"expected {self._manifest.page_count} pages but received "
                f"{self._next_expected_index}"
            )
        self._finalised = True

        miner_hotkeys = sorted(self._miner_score.keys())
        return [
            MinerAggregateRecord(
                miner_hotkey=h,
                miner_score_points=self._miner_score[h],
                active_member_count=self._miner_active.get(h, 0),
            )
            for h in miner_hotkeys
        ]

    def _assert_page_identity_matches_manifest(self, page: DetailedPage) -> None:
        """Reject pages whose identity fields disagree with the manifest.

        These checks are cheap and catch a class of "wrong file served"
        bugs before any user records are accumulated.
        """
        if page.snapshot_id != self._manifest.snapshot_id:
            raise UnexpectedPageError(
                f"page snapshot_id={page.snapshot_id!r} does not match manifest "
                f"{self._manifest.snapshot_id!r}"
            )
        if page.netuid != self._manifest.netuid:
            raise UnexpectedPageError(
                f"page netuid={page.netuid} does not match manifest {self._manifest.netuid}"
            )
        if page.chain_network != self._manifest.chain_network:
            raise UnexpectedPageError(
                f"page chain_network={page.chain_network!r} does not match "
                f"manifest {self._manifest.chain_network!r}"
            )
        if page.platform_instance_id != self._manifest.platform_instance_id:
            raise UnexpectedPageError(
                f"page platform_instance_id={page.platform_instance_id!r} does "
                f"not match manifest {self._manifest.platform_instance_id!r}"
            )
        if page.activity_date != self._manifest.activity_date:
            raise UnexpectedPageError(
                f"page activity_date={page.activity_date!r} does not match "
                f"manifest {self._manifest.activity_date!r}"
            )


__all__ = [
    "DetailedStreamingAccumulator",
    "DuplicateUserRefError",
    "PageHashMismatchError",
    "PageOrderError",
    "PlatformKeyOutsideValidityError",
    "RecordsHashMismatchError",
    "RevokedPlatformKeyError",
    "SnapshotVerificationError",
    "TrustedKey",
    "TrustedKeyMap",
    "UnexpectedPageError",
    "UnknownPlatformKeyIdError",
    "compute_aggregate_records_hash",
    "compute_detailed_records_hash",
    "compute_page_hash",
    "verify_aggregate_records_hash",
    "verify_aggregate_snapshot",
    "verify_detailed_manifest",
    "verify_detailed_records_hash",
    "verify_page_hash",
    "verify_snapshot_signature",
]


# Suppress unused-import warning: DetailedManifestPageEntry is referenced via
# manifest.pages[i] which is typed transparently, but exporting the symbol
# keeps it available for type hints in downstream tests.
_ = DetailedManifestPageEntry
