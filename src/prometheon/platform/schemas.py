"""Pydantic models for every wire shape on the BitFan platform contract.

This module is the source of truth for what the platform sends and what it
receives. Every model is immutable (``frozen=True``), forbids extra fields,
and validates with strict field-level regexes and ranges. Any deviation in
the wire payload (uppercase hex, malformed timestamp, missing field,
unexpected policy constant) becomes a Pydantic validation error well
before any signature or hash check runs.

Models exposed:

- :class:`NonceRequestBody`              — ``POST /identity/nonce`` request body.
- :class:`MinerAggregateRecord`          — single row in the aggregate snapshot.
- :class:`AggregateSnapshot`             — full ``aggregate`` snapshot response.
- :class:`DetailedManifestPageEntry`     — single ``pages[]`` entry inside the manifest.
- :class:`DetailedManifest`              — full ``detailed`` manifest response.
- :class:`UserScoreRecord`               — single row inside a detailed page.
- :class:`DetailedPage`                  — full detailed-mode page response.
- :class:`ApiRequestPayload`             — the ``PROMETHEON_API_REQUEST_V1`` canonical
                                           payload signed by the validator on every
                                           snapshot API request.

The locked Phase 1 policy constants (``daily_score_cap = 20``,
``active_member_score_threshold = 50``, ``min_active_members_for_reward = 3``,
``top_k = 10``) are declared as Literals so a snapshot that arrives with
any other value fails parse before reaching the engine.
"""

from __future__ import annotations

from typing import ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from prometheon.identity.roles import ChainNetwork, Role
from prometheon.platform.endpoints import SnapshotMode

# Reused regex patterns. ``HEX32`` is a 32-byte SHA-256 digest in canonical
# form; ``HEX_SIG`` is a 64-byte signature. ISO8601-UTC-Z is the strict
# timestamp profile; ``DATE_YMD`` is the strict date form.
_HEX32_RE: Final[str] = r"^0x[0-9a-f]{64}$"
_HEX_SIG_RE: Final[str] = r"^0x[0-9a-f]{128}$"
_ISO8601_UTC_Z_RE: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
_DATE_YMD_RE: Final[str] = r"^\d{4}-\d{2}-\d{2}$"
_SS58_LOOSE_RE: Final[str] = r"^[1-9A-HJ-NP-Za-km-z]{46,48}$"

# Per consolidated specification §3 / §10.
_MAX_BURN_RATE_PPM: Final[int] = 1_000_000
_MAX_USER_SCORE_14D: Final[int] = 280


# ---------------------------------------------------------------------------
# Nonce request body
# ---------------------------------------------------------------------------


class NonceRequestBody(BaseModel):
    """Body of ``POST /api/v1/prometheon/identity/nonce``.

    The CLI sends ``username`` and ``email`` so the platform can return
    canonical hashes. The hotkey is bound to the issued nonce.

    ``chain_network`` and ``platform_instance_id`` are included so the
    platform's environment-binding guard (which runs on every identity
    endpoint) can refuse cross-environment replays. The other identity
    endpoints (verify, rotate, recover) supply these fields via the
    signed payload; the nonce request supplies them directly because
    there is no signed payload at this stage.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    role: Role
    netuid: int = Field(ge=0)
    username: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=3, max_length=320)
    hotkey_ss58: str = Field(pattern=_SS58_LOOSE_RE)
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Aggregate snapshot
# ---------------------------------------------------------------------------


class MinerAggregateRecord(BaseModel):
    """One row inside an aggregate snapshot's ``miners`` array."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    miner_hotkey: str = Field(pattern=_SS58_LOOSE_RE)
    miner_score_points: int = Field(ge=0)
    active_member_count: int = Field(ge=0)


class AggregateSnapshot(BaseModel):
    """Full response for ``GET /snapshots/{date}/aggregate``.

    Phase 1 policy constants are locked via ``Literal`` defaults; any
    deviation from the expected values causes a validation error during
    parse. The Ed25519 ``platform_signature`` is included as a sibling
    field; signature verification strips it before recomputing the
    domain-prefixed envelope.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    domain: Literal["PROMETHEON_SNAPSHOT_V1"]
    schema_version: Literal["1.0"]
    mechanism: Literal["phase1_growth"]
    mechid: Literal[0]
    mode: Literal["aggregate"]
    snapshot_id: str = Field(min_length=1)
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    activity_date: str = Field(pattern=_DATE_YMD_RE)
    generated_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    window_start_date: str = Field(pattern=_DATE_YMD_RE)
    window_end_date: str = Field(pattern=_DATE_YMD_RE)
    daily_score_cap: Literal[20]
    active_member_score_threshold: Literal[50]
    min_active_members_for_reward: Literal[3]
    top_k: Literal[10]
    burn_hotkey: str = Field(pattern=_SS58_LOOSE_RE)
    manual_burn_rate_ppm: int = Field(ge=0, le=_MAX_BURN_RATE_PPM)
    platform_key_id: str = Field(min_length=1)
    records_hash: str = Field(pattern=_HEX32_RE)
    miners: list[MinerAggregateRecord]
    # Opaque platform-side build identifier. We accept it so strict
    # ``extra="forbid"`` doesn't reject the snapshot, but the engine
    # ignores its value. The records_hash is computed over the miners
    # array only, so this field never affects integrity checks.
    snapshot_build_id: str | None = None
    platform_signature: str = Field(pattern=_HEX_SIG_RE)

    @model_validator(mode="after")
    def _validate_miner_ordering_and_uniqueness(self) -> AggregateSnapshot:
        """Reject snapshots whose ``miners`` are out of order or contain duplicates.

        The on-wire contract requires the array to be sorted by
        ``miner_hotkey`` ascending and to contain no duplicates. Both
        constraints are enforceable in a single pass, so the check is
        cheap and runs at parse time before any downstream code.
        """
        seen: set[str] = set()
        last: str | None = None
        for record in self.miners:
            if record.miner_hotkey in seen:
                raise ValueError(
                    f"duplicate miner_hotkey in aggregate snapshot: {record.miner_hotkey!r}"
                )
            if last is not None and record.miner_hotkey < last:
                raise ValueError(
                    "aggregate snapshot miners must be sorted by miner_hotkey ascending"
                )
            seen.add(record.miner_hotkey)
            last = record.miner_hotkey
        return self


# ---------------------------------------------------------------------------
# Detailed manifest
# ---------------------------------------------------------------------------


class DetailedManifestPageEntry(BaseModel):
    """One ``pages[]`` entry inside a detailed-mode manifest."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    page_index: int = Field(ge=0)
    record_count: int = Field(ge=0)
    page_hash: str = Field(pattern=_HEX32_RE)


class DetailedManifest(BaseModel):
    """Full response for ``GET /snapshots/{date}/detailed/manifest``.

    The manifest is the Ed25519-signed trust root for detailed-mode
    snapshots. Page bodies do not carry their own platform signature; the
    page's ``page_hash`` being listed in this signed manifest is what
    binds them.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    domain: Literal["PROMETHEON_SNAPSHOT_V1"]
    schema_version: Literal["1.0"]
    mechanism: Literal["phase1_growth"]
    mechid: Literal[0]
    mode: Literal["detailed"]
    snapshot_id: str = Field(min_length=1)
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    activity_date: str = Field(pattern=_DATE_YMD_RE)
    generated_at: str = Field(pattern=_ISO8601_UTC_Z_RE)
    window_start_date: str = Field(pattern=_DATE_YMD_RE)
    window_end_date: str = Field(pattern=_DATE_YMD_RE)
    daily_score_cap: Literal[20]
    active_member_score_threshold: Literal[50]
    min_active_members_for_reward: Literal[3]
    top_k: Literal[10]
    burn_hotkey: str = Field(pattern=_SS58_LOOSE_RE)
    manual_burn_rate_ppm: int = Field(ge=0, le=_MAX_BURN_RATE_PPM)
    platform_key_id: str = Field(min_length=1)
    record_count: int = Field(ge=0)
    page_size: int = Field(gt=0)
    page_count: int = Field(ge=0)
    pages: list[DetailedManifestPageEntry]
    records_hash: str = Field(pattern=_HEX32_RE)
    # Opaque platform-side build identifier; see AggregateSnapshot.
    snapshot_build_id: str | None = None
    platform_signature: str = Field(pattern=_HEX_SIG_RE)

    @model_validator(mode="after")
    def _validate_pages_consistency(self) -> DetailedManifest:
        """Reject manifests whose ``pages[]`` is inconsistent with its metadata.

        Checks:

        - ``len(pages) == page_count``.
        - ``page_index`` starts at 0 and increments by 1 with no gaps.
        - No page (except the last) has ``record_count != page_size``.
        - The sum of per-page ``record_count`` equals top-level
          ``record_count``.

        These rules implement the validator-side rejections required by
        consolidated specification §18.4.
        """
        if len(self.pages) != self.page_count:
            raise ValueError(
                f"manifest page_count={self.page_count} but len(pages)={len(self.pages)}"
            )

        total = 0
        for i, page in enumerate(self.pages):
            if page.page_index != i:
                raise ValueError(f"manifest pages[{i}].page_index={page.page_index}, expected {i}")
            is_last = i == len(self.pages) - 1
            if not is_last and page.record_count != self.page_size:
                raise ValueError(
                    f"manifest page {i} record_count={page.record_count} differs "
                    f"from page_size={self.page_size}; only the last page may be short"
                )
            if page.record_count > self.page_size:
                raise ValueError(
                    f"manifest page {i} record_count={page.record_count} exceeds "
                    f"page_size={self.page_size}"
                )
            total += page.record_count

        if total != self.record_count:
            raise ValueError(f"manifest record_count={self.record_count} but pages sum to {total}")
        return self


# ---------------------------------------------------------------------------
# Detailed page
# ---------------------------------------------------------------------------


class UserScoreRecord(BaseModel):
    """One row inside a detailed-mode page's ``records`` array.

    ``user_score_14d_points`` is bounded above by ``DAILY_SCORE_CAP * 14``
    = 280. Anything above that is rejected at parse time.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    user_ref: str = Field(min_length=1)
    miner_hotkey: str = Field(pattern=_SS58_LOOSE_RE)
    user_score_14d_points: int = Field(ge=0, le=_MAX_USER_SCORE_14D)


class DetailedPage(BaseModel):
    """Full response for ``GET /snapshots/{date}/detailed/pages/{page_index}``.

    Pages do not carry an Ed25519 signature; their integrity comes from
    the ``page_hash`` recorded in the signed manifest.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    domain: Literal["PROMETHEON_RECORD_PAGE_V1"]
    schema_version: Literal["1.0"]
    mechanism: Literal["phase1_growth"]
    mechid: Literal[0]
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    snapshot_id: str = Field(min_length=1)
    mode: Literal["detailed"]
    activity_date: str = Field(pattern=_DATE_YMD_RE)
    page_index: int = Field(ge=0)
    record_count: int = Field(ge=0)
    records: list[UserScoreRecord]
    page_hash: str = Field(pattern=_HEX32_RE)

    @model_validator(mode="after")
    def _validate_record_count_and_ordering(self) -> DetailedPage:
        """Reject pages where ``record_count`` lies or records are out of order.

        The global ordering rule (``miner_hotkey`` ASC, then ``user_ref``
        ASC) is enforced both inside each page and across page boundaries.
        The cross-page check happens in the streaming accumulator; this
        method enforces the intra-page invariant.
        """
        if self.record_count != len(self.records):
            raise ValueError(
                f"page record_count={self.record_count} but len(records)={len(self.records)}"
            )

        last_pair: tuple[str, str] | None = None
        for record in self.records:
            current_pair = (record.miner_hotkey, record.user_ref)
            if last_pair is not None and current_pair < last_pair:
                raise ValueError(
                    "detailed page records must be sorted by (miner_hotkey ASC, user_ref ASC)"
                )
            last_pair = current_pair
        return self


# ---------------------------------------------------------------------------
# API request payload (PROMETHEON_API_REQUEST_V1)
# ---------------------------------------------------------------------------


class ApiRequestPayload(BaseModel):
    """The canonical payload signed by every validator snapshot API call.

    The validator builds this object, JCS-canonicalises it under the
    ``PROMETHEON_API_REQUEST_V1`` domain, signs it with its hotkey, and
    sends the resulting signature in the ``X-Prometheon-Request-Signature``
    header. The server reconstructs the same object from the inbound
    request and verifies the signature.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    domain: Literal["PROMETHEON_API_REQUEST_V1"] = "PROMETHEON_API_REQUEST_V1"
    method: Literal["GET", "POST", "PUT", "DELETE"]
    path: str = Field(min_length=1)
    query_hash: str = Field(pattern=_HEX32_RE)
    body_hash: str = Field(pattern=_HEX32_RE)
    timestamp: str = Field(pattern=_ISO8601_UTC_Z_RE)
    nonce: str = Field(pattern=r"^0x[0-9a-f]{32,128}$")
    chain_network: ChainNetwork
    platform_instance_id: str = Field(min_length=1)
    netuid: int = Field(ge=0)
    role: Role
    mode: SnapshotMode | None = None
    validator_hotkey: str = Field(pattern=_SS58_LOOSE_RE)
    api_token_hash: str = Field(pattern=_HEX32_RE)

    @model_validator(mode="after")
    def _validate_path_shape(self) -> ApiRequestPayload:
        """Apply the path canonicalization rules from §9.5.

        - Must start with ``/``.
        - Must not contain duplicate slashes.
        - Must not end with ``/`` (Phase 1 endpoints are defined without
          trailing slashes).
        """
        if not self.path.startswith("/"):
            raise ValueError(f"path must start with '/', got {self.path!r}")
        if "//" in self.path:
            raise ValueError(f"path must not contain '//', got {self.path!r}")
        if self.path.endswith("/") and self.path != "/":
            raise ValueError(f"path must not end with '/', got {self.path!r}")
        return self


__all__ = [
    "AggregateSnapshot",
    "ApiRequestPayload",
    "DetailedManifest",
    "DetailedManifestPageEntry",
    "DetailedPage",
    "MinerAggregateRecord",
    "NonceRequestBody",
    "UserScoreRecord",
]
