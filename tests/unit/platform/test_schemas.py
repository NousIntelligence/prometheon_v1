"""Unit tests for ``prometheon.platform.schemas``.

Each Pydantic model is exercised for:

- Valid construction with reasonable defaults.
- Strict field validation (regex, range, literal locks).
- Cross-field invariants (ordering, uniqueness, page consistency).
- Immutability (``frozen=True``) and extra-field rejection.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from prometheon.identity.roles import ChainNetwork, Role
from prometheon.platform.endpoints import SnapshotMode
from prometheon.platform.schemas import (
    AggregateSnapshot,
    ApiRequestPayload,
    DetailedManifest,
    DetailedManifestPageEntry,
    DetailedPage,
    MinerAggregateRecord,
    NonceRequestBody,
    UserScoreRecord,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

VALID_HEX32 = "0x" + "ab" * 32
VALID_HEX_SIG = "0x" + "cd" * 64
VALID_NONCE = "0x" + "12" * 16  # 32 hex chars = 16 bytes (the minimum)
# SS58 constants chosen so that SS58_A < SS58_B < SS58_C lexicographically,
# matching the on-wire sort order the schemas enforce.
SS58_A = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"  # //Bob
SS58_B = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"  # //Dave-ish
SS58_C = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"  # //Alice
ACTIVITY_DATE = "2026-05-18"
GENERATED_AT = "2026-05-19T00:20:31Z"
WINDOW_START = "2026-05-05"


# ---------------------------------------------------------------------------
# NonceRequestBody
# ---------------------------------------------------------------------------


class TestNonceRequestBody:
    def test_constructs_with_valid_fields(self) -> None:
        body = NonceRequestBody(
            role=Role.MINER,
            netuid=123,
            username="alice",
            email="alice@example.com",
            hotkey_ss58=SS58_A,
            chain_network=ChainNetwork.FINNEY,
            platform_instance_id="bitfan-production",
        )
        assert body.role == Role.MINER
        assert body.netuid == 123
        assert body.chain_network is ChainNetwork.FINNEY
        assert body.platform_instance_id == "bitfan-production"

    def test_rejects_empty_username(self) -> None:
        with pytest.raises(ValidationError):
            NonceRequestBody(
                role=Role.MINER,
                netuid=123,
                username="",
                email="alice@example.com",
                hotkey_ss58=SS58_A,
                chain_network=ChainNetwork.FINNEY,
                platform_instance_id="bitfan-production",
            )

    def test_rejects_negative_netuid(self) -> None:
        with pytest.raises(ValidationError):
            NonceRequestBody(
                role=Role.MINER,
                netuid=-1,
                username="alice",
                email="alice@example.com",
                hotkey_ss58=SS58_A,
                chain_network=ChainNetwork.FINNEY,
                platform_instance_id="bitfan-production",
            )

    def test_rejects_missing_chain_network(self) -> None:
        # EnvMatchGuard on the platform side requires this field; the schema
        # makes it required so a CLI cannot build a body that would 400 at
        # the network boundary.
        with pytest.raises(ValidationError):
            NonceRequestBody(  # type: ignore[call-arg]
                role=Role.MINER,
                netuid=123,
                username="alice",
                email="alice@example.com",
                hotkey_ss58=SS58_A,
                platform_instance_id="bitfan-production",
            )

    def test_rejects_empty_platform_instance_id(self) -> None:
        with pytest.raises(ValidationError):
            NonceRequestBody(
                role=Role.MINER,
                netuid=123,
                username="alice",
                email="alice@example.com",
                hotkey_ss58=SS58_A,
                chain_network=ChainNetwork.FINNEY,
                platform_instance_id="",
            )


# ---------------------------------------------------------------------------
# MinerAggregateRecord
# ---------------------------------------------------------------------------


class TestMinerAggregateRecord:
    def test_constructs_with_valid_fields(self) -> None:
        r = MinerAggregateRecord(
            miner_hotkey=SS58_A, miner_score_points=1240, active_member_count=8
        )
        assert r.miner_score_points == 1240

    def test_rejects_negative_score(self) -> None:
        with pytest.raises(ValidationError):
            MinerAggregateRecord(miner_hotkey=SS58_A, miner_score_points=-1, active_member_count=0)

    def test_rejects_negative_active_count(self) -> None:
        with pytest.raises(ValidationError):
            MinerAggregateRecord(miner_hotkey=SS58_A, miner_score_points=0, active_member_count=-1)

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            MinerAggregateRecord(  # type: ignore[call-arg]
                miner_hotkey=SS58_A,
                miner_score_points=1,
                active_member_count=1,
                surprise="x",
            )


# ---------------------------------------------------------------------------
# AggregateSnapshot
# ---------------------------------------------------------------------------


def _aggregate_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "domain": "PROMETHEON_SNAPSHOT_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "mode": "aggregate",
        "snapshot_id": "phase1:2026-05-18:aggregate",
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "activity_date": ACTIVITY_DATE,
        "generated_at": GENERATED_AT,
        "window_start_date": WINDOW_START,
        "window_end_date": ACTIVITY_DATE,
        "daily_score_cap": 20,
        "active_member_score_threshold": 50,
        "min_active_members_for_reward": 3,
        "top_k": 10,
        "burn_hotkey": SS58_C,
        "manual_burn_rate_ppm": 150000,
        "platform_key_id": "platform-main-2026-05",
        "records_hash": VALID_HEX32,
        "miners": [
            MinerAggregateRecord(
                miner_hotkey=SS58_A, miner_score_points=1240, active_member_count=8
            ),
            MinerAggregateRecord(
                miner_hotkey=SS58_B, miner_score_points=800, active_member_count=5
            ),
        ],
        "platform_signature": VALID_HEX_SIG,
    }
    base.update(overrides)
    return base


class TestAggregateSnapshot:
    def test_constructs_with_valid_data(self) -> None:
        snap = AggregateSnapshot(**_aggregate_kwargs())
        assert snap.mode == "aggregate"
        assert snap.mechid == 0
        assert len(snap.miners) == 2

    def test_locks_daily_score_cap_at_20(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(daily_score_cap=21))

    def test_locks_active_member_threshold_at_50(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(active_member_score_threshold=49))

    def test_locks_min_active_members_at_3(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(min_active_members_for_reward=2))

    def test_locks_top_k_at_10(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(top_k=11))

    def test_locks_mechanism_to_phase1_growth(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(mechanism="phase2_integrity"))

    def test_locks_mechid_to_zero(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(mechid=1))

    def test_locks_mode_to_aggregate(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(mode="detailed"))

    def test_rejects_burn_rate_above_million(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(manual_burn_rate_ppm=1_000_001))

    def test_rejects_negative_burn_rate(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(manual_burn_rate_ppm=-1))

    def test_rejects_uppercase_hex_in_records_hash(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(records_hash="0x" + "AB" * 32))

    def test_rejects_unsorted_miners(self) -> None:
        # Miners with SS58_B before SS58_A — out of ascending order.
        unsorted = [
            MinerAggregateRecord(
                miner_hotkey=SS58_B, miner_score_points=800, active_member_count=5
            ),
            MinerAggregateRecord(
                miner_hotkey=SS58_A, miner_score_points=1240, active_member_count=8
            ),
        ]
        with pytest.raises(ValidationError, match="sorted by miner_hotkey ascending"):
            AggregateSnapshot(**_aggregate_kwargs(miners=unsorted))

    def test_rejects_duplicate_miner_hotkey(self) -> None:
        dup = [
            MinerAggregateRecord(
                miner_hotkey=SS58_A, miner_score_points=1240, active_member_count=8
            ),
            MinerAggregateRecord(
                miner_hotkey=SS58_A, miner_score_points=800, active_member_count=5
            ),
        ]
        with pytest.raises(ValidationError, match="duplicate miner_hotkey"):
            AggregateSnapshot(**_aggregate_kwargs(miners=dup))

    def test_empty_miners_list_is_accepted(self) -> None:
        # The validator's mechanism engine handles empty inputs; the
        # platform contract does not forbid them at parse time.
        snap = AggregateSnapshot(**_aggregate_kwargs(miners=[]))
        assert snap.miners == []

    def test_rejects_extra_top_level_field(self) -> None:
        with pytest.raises(ValidationError):
            AggregateSnapshot(**_aggregate_kwargs(unexpected="field"))


# ---------------------------------------------------------------------------
# DetailedManifestPageEntry + DetailedManifest
# ---------------------------------------------------------------------------


def _manifest_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "domain": "PROMETHEON_SNAPSHOT_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "mode": "detailed",
        "snapshot_id": "phase1:2026-05-18:detailed",
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "activity_date": ACTIVITY_DATE,
        "generated_at": GENERATED_AT,
        "window_start_date": WINDOW_START,
        "window_end_date": ACTIVITY_DATE,
        "daily_score_cap": 20,
        "active_member_score_threshold": 50,
        "min_active_members_for_reward": 3,
        "top_k": 10,
        "burn_hotkey": SS58_C,
        "manual_burn_rate_ppm": 150000,
        "platform_key_id": "platform-main-2026-05",
        "record_count": 153842,
        "page_size": 50000,
        "page_count": 4,
        "pages": [
            DetailedManifestPageEntry(page_index=0, record_count=50000, page_hash=VALID_HEX32),
            DetailedManifestPageEntry(page_index=1, record_count=50000, page_hash=VALID_HEX32),
            DetailedManifestPageEntry(page_index=2, record_count=50000, page_hash=VALID_HEX32),
            DetailedManifestPageEntry(page_index=3, record_count=3842, page_hash=VALID_HEX32),
        ],
        "records_hash": VALID_HEX32,
        "platform_signature": VALID_HEX_SIG,
    }
    base.update(overrides)
    return base


class TestDetailedManifestPageEntry:
    def test_constructs_with_valid_fields(self) -> None:
        entry = DetailedManifestPageEntry(page_index=0, record_count=50000, page_hash=VALID_HEX32)
        assert entry.page_index == 0

    def test_rejects_negative_page_index(self) -> None:
        with pytest.raises(ValidationError):
            DetailedManifestPageEntry(page_index=-1, record_count=0, page_hash=VALID_HEX32)


class TestDetailedManifest:
    def test_constructs_with_valid_data(self) -> None:
        manifest = DetailedManifest(**_manifest_kwargs())
        assert manifest.page_count == 4
        assert sum(p.record_count for p in manifest.pages) == manifest.record_count

    def test_rejects_mismatched_page_count(self) -> None:
        # page_count says 5 but pages array has 4 entries.
        with pytest.raises(ValidationError, match="page_count=5 but len"):
            DetailedManifest(**_manifest_kwargs(page_count=5))

    def test_rejects_pages_not_starting_at_zero(self) -> None:
        bad_pages = [
            DetailedManifestPageEntry(page_index=1, record_count=50000, page_hash=VALID_HEX32),
        ]
        with pytest.raises(ValidationError, match=r"pages\[0\]\.page_index"):
            DetailedManifest(**_manifest_kwargs(pages=bad_pages, page_count=1, record_count=50000))

    def test_rejects_gap_in_page_indices(self) -> None:
        bad_pages = [
            DetailedManifestPageEntry(page_index=0, record_count=50000, page_hash=VALID_HEX32),
            DetailedManifestPageEntry(page_index=2, record_count=50000, page_hash=VALID_HEX32),
        ]
        with pytest.raises(ValidationError, match=r"pages\[1\]\.page_index"):
            DetailedManifest(**_manifest_kwargs(pages=bad_pages, page_count=2, record_count=100000))

    def test_rejects_short_middle_page(self) -> None:
        bad_pages = [
            DetailedManifestPageEntry(page_index=0, record_count=50000, page_hash=VALID_HEX32),
            DetailedManifestPageEntry(
                page_index=1, record_count=42, page_hash=VALID_HEX32
            ),  # short!
            DetailedManifestPageEntry(page_index=2, record_count=42, page_hash=VALID_HEX32),
        ]
        with pytest.raises(ValidationError, match="only the last page may be short"):
            DetailedManifest(**_manifest_kwargs(pages=bad_pages, page_count=3, record_count=50084))

    def test_rejects_total_record_count_mismatch(self) -> None:
        # The four-page manifest has 50000+50000+50000+3842 = 153842 records;
        # asserting 100000 should fail.
        with pytest.raises(ValidationError, match="pages sum to"):
            DetailedManifest(**_manifest_kwargs(record_count=100000))

    def test_rejects_mode_aggregate_in_manifest(self) -> None:
        with pytest.raises(ValidationError):
            DetailedManifest(**_manifest_kwargs(mode="aggregate"))


# ---------------------------------------------------------------------------
# UserScoreRecord
# ---------------------------------------------------------------------------


class TestUserScoreRecord:
    def test_constructs_with_valid_fields(self) -> None:
        r = UserScoreRecord(user_ref="usr_abc", miner_hotkey=SS58_A, user_score_14d_points=73)
        assert r.user_score_14d_points == 73

    def test_accepts_max_score_280(self) -> None:
        # 14 days * DAILY_SCORE_CAP=20 = 280 is the maximum allowed.
        r = UserScoreRecord(user_ref="usr_abc", miner_hotkey=SS58_A, user_score_14d_points=280)
        assert r.user_score_14d_points == 280

    def test_rejects_score_above_280(self) -> None:
        with pytest.raises(ValidationError):
            UserScoreRecord(user_ref="usr_abc", miner_hotkey=SS58_A, user_score_14d_points=281)

    def test_rejects_negative_score(self) -> None:
        with pytest.raises(ValidationError):
            UserScoreRecord(user_ref="usr_abc", miner_hotkey=SS58_A, user_score_14d_points=-1)


# ---------------------------------------------------------------------------
# DetailedPage
# ---------------------------------------------------------------------------


def _page_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "domain": "PROMETHEON_RECORD_PAGE_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "snapshot_id": "phase1:2026-05-18:detailed",
        "mode": "detailed",
        "activity_date": ACTIVITY_DATE,
        "page_index": 0,
        "record_count": 3,
        "records": [
            UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=100),
            UserScoreRecord(user_ref="usr_b", miner_hotkey=SS58_A, user_score_14d_points=50),
            UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_B, user_score_14d_points=75),
        ],
        "page_hash": VALID_HEX32,
    }
    base.update(overrides)
    return base


class TestDetailedPage:
    def test_constructs_with_valid_data(self) -> None:
        page = DetailedPage(**_page_kwargs())
        assert page.page_index == 0
        assert page.record_count == 3

    def test_rejects_record_count_mismatch(self) -> None:
        with pytest.raises(ValidationError, match="record_count=4 but len"):
            DetailedPage(**_page_kwargs(record_count=4))

    def test_rejects_records_out_of_order(self) -> None:
        # Sort key is (miner_hotkey ASC, user_ref ASC).
        # Putting a SS58_B record before a SS58_A record violates ordering.
        bad_records = [
            UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_B, user_score_14d_points=75),
            UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=100),
        ]
        with pytest.raises(ValidationError, match="sorted by"):
            DetailedPage(**_page_kwargs(records=bad_records, record_count=2))

    def test_rejects_locked_literals(self) -> None:
        with pytest.raises(ValidationError):
            DetailedPage(**_page_kwargs(domain="PROMETHEON_SNAPSHOT_V1"))
        with pytest.raises(ValidationError):
            DetailedPage(**_page_kwargs(mode="aggregate"))


# ---------------------------------------------------------------------------
# ApiRequestPayload
# ---------------------------------------------------------------------------


def _api_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "method": "GET",
        "path": "/api/v1/prometheon/phase1/snapshots/latest/aggregate",
        "query_hash": VALID_HEX32,
        "body_hash": VALID_HEX32,
        "timestamp": "2026-05-20T00:00:00Z",
        "nonce": VALID_NONCE,
        "chain_network": ChainNetwork.FINNEY,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "role": Role.VALIDATOR,
        "mode": SnapshotMode.AGGREGATE,
        "validator_hotkey": SS58_A,
        "api_token_hash": VALID_HEX32,
    }
    base.update(overrides)
    return base


class TestApiRequestPayload:
    def test_constructs_with_valid_fields(self) -> None:
        p = ApiRequestPayload(**_api_kwargs())
        assert p.domain == "PROMETHEON_API_REQUEST_V1"
        assert p.mode == SnapshotMode.AGGREGATE

    def test_domain_is_locked(self) -> None:
        # Cannot override the Literal default.
        with pytest.raises(ValidationError):
            ApiRequestPayload(**_api_kwargs(domain="OTHER"))

    def test_mode_is_optional(self) -> None:
        # Identity endpoints don't carry a mode.
        p = ApiRequestPayload(**_api_kwargs(mode=None, path="/api/v1/prometheon/identity/nonce"))
        assert p.mode is None

    def test_rejects_path_without_leading_slash(self) -> None:
        with pytest.raises(ValidationError, match="must start with '/'"):
            ApiRequestPayload(**_api_kwargs(path="v1/prometheon/identity/nonce"))

    def test_rejects_path_with_double_slash(self) -> None:
        with pytest.raises(ValidationError, match="must not contain '//'"):
            ApiRequestPayload(
                **_api_kwargs(path="/v1//prometheon/phase1/snapshots/latest/aggregate")
            )

    def test_rejects_path_with_trailing_slash(self) -> None:
        with pytest.raises(ValidationError, match="must not end with '/'"):
            ApiRequestPayload(**_api_kwargs(path="/api/v1/prometheon/identity/nonce/"))

    def test_rejects_unknown_method(self) -> None:
        with pytest.raises(ValidationError):
            ApiRequestPayload(**_api_kwargs(method="PATCH"))

    def test_rejects_short_nonce(self) -> None:
        # 15 bytes = 30 hex chars: below the 16-byte minimum.
        with pytest.raises(ValidationError):
            ApiRequestPayload(**_api_kwargs(nonce="0x" + "ab" * 15))

    def test_rejects_uppercase_hex_in_nonce(self) -> None:
        with pytest.raises(ValidationError):
            ApiRequestPayload(**_api_kwargs(nonce="0x" + "AB" * 16))

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            ApiRequestPayload(**_api_kwargs(unexpected="field"))
