"""Unit tests for ``prometheon.platform.signing``.

Builds real Ed25519-signed snapshots and pages from test keys, then runs
the full verification pipeline against them. Covers the happy path, every
key-lifecycle rejection, every hash-mismatch path, and the cross-page
invariants enforced by ``DetailedStreamingAccumulator``.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.identity.roles import ChainNetwork
from prometheon.platform.schemas import (
    AggregateSnapshot,
    DetailedManifest,
    DetailedPage,
    MinerAggregateRecord,
    UserScoreRecord,
)
from prometheon.platform.signing import (
    DetailedStreamingAccumulator,
    DuplicateUserRefError,
    PageHashMismatchError,
    PageOrderError,
    PlatformKeyOutsideValidityError,
    RecordsHashMismatchError,
    RevokedPlatformKeyError,
    TrustedKey,
    UnexpectedPageError,
    UnknownPlatformKeyIdError,
    compute_aggregate_records_hash,
    compute_detailed_records_hash,
    compute_page_hash,
    verify_aggregate_records_hash,
    verify_aggregate_snapshot,
    verify_detailed_manifest,
    verify_detailed_records_hash,
    verify_page_hash,
    verify_snapshot_signature,
)
from prometheon.security.canonical import DOMAIN_SNAPSHOT, domain_prefixed_bytes
from prometheon.security.signatures import SignatureVerificationError

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

SS58_A = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
SS58_B = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
SS58_C = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
GENERATED_AT = "2026-05-19T00:20:31Z"
KEY_ID = "platform-test-2026"


@pytest.fixture
def ed25519_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)


@pytest.fixture
def ed25519_public_key_hex(ed25519_private_key: Ed25519PrivateKey) -> str:
    return "0x" + ed25519_private_key.public_key().public_bytes_raw().hex()


@pytest.fixture
def trusted_keys(ed25519_public_key_hex: str) -> dict[str, TrustedKey]:
    return {
        KEY_ID: TrustedKey(
            public_key=ed25519_public_key_hex,
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            status="active",
        )
    }


def _aggregate_dict_unsigned(
    miners: list[MinerAggregateRecord],
    *,
    generated_at: str = GENERATED_AT,
    platform_key_id: str = KEY_ID,
) -> dict[str, Any]:
    """Aggregate snapshot dict without records_hash or platform_signature."""
    return {
        "domain": "PROMETHEON_SNAPSHOT_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "mode": "aggregate",
        "snapshot_id": "phase1:2026-05-18:aggregate",
        "chain_network": ChainNetwork.FINNEY.value,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "activity_date": "2026-05-18",
        "generated_at": generated_at,
        "window_start_date": "2026-05-05",
        "window_end_date": "2026-05-18",
        "daily_score_cap": 20,
        "active_member_score_threshold": 50,
        "min_active_members_for_reward": 3,
        "top_k": 10,
        "burn_hotkey": SS58_C,
        "manual_burn_rate_ppm": 150000,
        "platform_key_id": platform_key_id,
        "miners": [m.model_dump(mode="json") for m in miners],
    }


def _build_signed_aggregate(
    private_key: Ed25519PrivateKey,
    miners: list[MinerAggregateRecord],
    *,
    generated_at: str = GENERATED_AT,
    platform_key_id: str = KEY_ID,
) -> AggregateSnapshot:
    """Build a fully-signed aggregate snapshot from a test private key."""
    raw = _aggregate_dict_unsigned(
        miners, generated_at=generated_at, platform_key_id=platform_key_id
    )

    # Construct a temporary AggregateSnapshot via model_validate using a
    # dummy hash + signature, then overwrite both with real values.
    placeholder = {
        **raw,
        "records_hash": "0x" + "00" * 32,
        "platform_signature": "0x" + "00" * 64,
    }
    tmp = AggregateSnapshot.model_validate(placeholder)
    records_hash = compute_aggregate_records_hash(tmp)

    raw_with_hash = {**raw, "records_hash": records_hash}
    envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, raw_with_hash)
    sig_hex = "0x" + private_key.sign(envelope).hex()

    final = {**raw_with_hash, "platform_signature": sig_hex}
    return AggregateSnapshot.model_validate(final)


def _detailed_manifest_dict_unsigned(
    page_bodies: list[dict[str, Any]],
    *,
    generated_at: str = GENERATED_AT,
    platform_key_id: str = KEY_ID,
) -> dict[str, Any]:
    """Build the manifest dict without records_hash / platform_signature.

    ``page_bodies`` must already include their final ``page_hash`` values
    so the manifest's per-page hash entries line up.
    """
    pages = [
        {
            "page_index": body["page_index"],
            "record_count": body["record_count"],
            "page_hash": body["page_hash"],
        }
        for body in page_bodies
    ]
    record_count = sum(p["record_count"] for p in pages)
    page_size = (
        max((p["record_count"] for p in pages[:-1]), default=page_bodies[0]["record_count"])
        if pages
        else 1
    )

    return {
        "domain": "PROMETHEON_SNAPSHOT_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "mode": "detailed",
        "snapshot_id": "phase1:2026-05-18:detailed",
        "chain_network": ChainNetwork.FINNEY.value,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "activity_date": "2026-05-18",
        "generated_at": generated_at,
        "window_start_date": "2026-05-05",
        "window_end_date": "2026-05-18",
        "daily_score_cap": 20,
        "active_member_score_threshold": 50,
        "min_active_members_for_reward": 3,
        "top_k": 10,
        "burn_hotkey": SS58_C,
        "manual_burn_rate_ppm": 150000,
        "platform_key_id": platform_key_id,
        "record_count": record_count,
        "page_size": page_size,
        "page_count": len(pages),
        "pages": pages,
    }


def _build_signed_page(
    records: list[UserScoreRecord],
    *,
    page_index: int,
) -> DetailedPage:
    """Build a DetailedPage with the correct ``page_hash`` field."""
    raw: dict[str, Any] = {
        "domain": "PROMETHEON_RECORD_PAGE_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "chain_network": ChainNetwork.FINNEY.value,
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "snapshot_id": "phase1:2026-05-18:detailed",
        "mode": "detailed",
        "activity_date": "2026-05-18",
        "page_index": page_index,
        "record_count": len(records),
        "records": [r.model_dump(mode="json") for r in records],
        "page_hash": "0x" + "00" * 32,
    }
    # Two-pass: parse with placeholder, compute hash, re-parse with real hash.
    placeholder_page = DetailedPage.model_validate(raw)
    actual_hash = compute_page_hash(placeholder_page)
    raw["page_hash"] = actual_hash
    return DetailedPage.model_validate(raw)


def _build_signed_manifest(
    private_key: Ed25519PrivateKey,
    pages: list[DetailedPage],
    *,
    generated_at: str = GENERATED_AT,
    platform_key_id: str = KEY_ID,
) -> DetailedManifest:
    """Build a fully-signed detailed manifest from a list of signed pages."""
    page_bodies = [p.model_dump(mode="json") for p in pages]
    raw = _detailed_manifest_dict_unsigned(
        page_bodies, generated_at=generated_at, platform_key_id=platform_key_id
    )
    placeholder = {
        **raw,
        "records_hash": "0x" + "00" * 32,
        "platform_signature": "0x" + "00" * 64,
    }
    tmp = DetailedManifest.model_validate(placeholder)
    records_hash = compute_detailed_records_hash(tmp)

    raw_with_hash = {**raw, "records_hash": records_hash}
    envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, raw_with_hash)
    sig_hex = "0x" + private_key.sign(envelope).hex()
    final = {**raw_with_hash, "platform_signature": sig_hex}
    return DetailedManifest.model_validate(final)


# ---------------------------------------------------------------------------
# TrustedKey
# ---------------------------------------------------------------------------


class TestTrustedKey:
    def test_constructs_with_valid_fields(self, ed25519_public_key_hex: str) -> None:
        k = TrustedKey(
            public_key=ed25519_public_key_hex,
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            status="active",
        )
        assert k.status == "active"

    def test_status_defaults_to_active(self, ed25519_public_key_hex: str) -> None:
        k = TrustedKey(
            public_key=ed25519_public_key_hex,
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        )
        assert k.status == "active"

    def test_rejects_unknown_status(self, ed25519_public_key_hex: str) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TrustedKey(
                public_key=ed25519_public_key_hex,
                not_before="2026-01-01T00:00:00Z",
                not_after="2027-01-01T00:00:00Z",
                status="pending",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Aggregate signature + records_hash
# ---------------------------------------------------------------------------


class TestAggregateSignatureVerification:
    def test_valid_signature_verifies(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        miners = [
            MinerAggregateRecord(
                miner_hotkey=SS58_A, miner_score_points=1000, active_member_count=8
            ),
            MinerAggregateRecord(
                miner_hotkey=SS58_B, miner_score_points=500, active_member_count=4
            ),
        ]
        snap = _build_signed_aggregate(ed25519_private_key, miners)
        verify_snapshot_signature(snap, trusted_keys=trusted_keys)

    def test_unknown_key_id_rejected(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        snap = _build_signed_aggregate(
            ed25519_private_key,
            [
                MinerAggregateRecord(
                    miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1
                )
            ],
            platform_key_id="some-other-key",
        )
        with pytest.raises(UnknownPlatformKeyIdError):
            verify_snapshot_signature(snap, trusted_keys=trusted_keys)

    def test_revoked_key_rejected(
        self, ed25519_private_key: Ed25519PrivateKey, ed25519_public_key_hex: str
    ) -> None:
        revoked = {
            KEY_ID: TrustedKey(
                public_key=ed25519_public_key_hex,
                not_before="2026-01-01T00:00:00Z",
                not_after="2027-01-01T00:00:00Z",
                status="revoked",
            )
        }
        snap = _build_signed_aggregate(
            ed25519_private_key,
            [
                MinerAggregateRecord(
                    miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1
                )
            ],
        )
        with pytest.raises(RevokedPlatformKeyError):
            verify_snapshot_signature(snap, trusted_keys=revoked)

    def test_outside_validity_window_rejected(
        self, ed25519_private_key: Ed25519PrivateKey, ed25519_public_key_hex: str
    ) -> None:
        narrow = {
            KEY_ID: TrustedKey(
                public_key=ed25519_public_key_hex,
                not_before="2027-01-01T00:00:00Z",  # window starts AFTER generated_at
                not_after="2027-06-01T00:00:00Z",
                status="active",
            )
        }
        snap = _build_signed_aggregate(
            ed25519_private_key,
            [
                MinerAggregateRecord(
                    miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1
                )
            ],
        )
        with pytest.raises(PlatformKeyOutsideValidityError):
            verify_snapshot_signature(snap, trusted_keys=narrow)

    def test_tampered_field_breaks_signature(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        miners = [
            MinerAggregateRecord(
                miner_hotkey=SS58_A, miner_score_points=1000, active_member_count=8
            ),
        ]
        snap = _build_signed_aggregate(ed25519_private_key, miners)
        # Rebuild the snapshot with a single field changed; signature
        # still points at the original payload.
        tampered_dict = snap.model_dump(mode="json")
        tampered_dict["netuid"] = 999
        tampered = AggregateSnapshot.model_validate(tampered_dict)
        with pytest.raises(SignatureVerificationError):
            verify_snapshot_signature(tampered, trusted_keys=trusted_keys)


class TestAggregateRecordsHash:
    def test_computed_and_verified(self, ed25519_private_key: Ed25519PrivateKey) -> None:
        miners = [
            MinerAggregateRecord(miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1)
        ]
        snap = _build_signed_aggregate(ed25519_private_key, miners)
        verify_aggregate_records_hash(snap)
        # Recompute and assert determinism.
        assert compute_aggregate_records_hash(snap) == snap.records_hash

    def test_mismatch_rejected(self, ed25519_private_key: Ed25519PrivateKey) -> None:
        miners = [
            MinerAggregateRecord(miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1)
        ]
        snap = _build_signed_aggregate(ed25519_private_key, miners)
        tampered = snap.model_copy(update={"records_hash": "0x" + "ab" * 32})
        with pytest.raises(RecordsHashMismatchError):
            verify_aggregate_records_hash(tampered)


# ---------------------------------------------------------------------------
# Page hash + detailed manifest
# ---------------------------------------------------------------------------


class TestPageHash:
    def test_computed_and_verified(self) -> None:
        page = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=100),
                UserScoreRecord(user_ref="usr_b", miner_hotkey=SS58_A, user_score_14d_points=200),
            ],
            page_index=0,
        )
        verify_page_hash(page)
        assert compute_page_hash(page) == page.page_hash

    def test_mismatch_rejected(self) -> None:
        page = _build_signed_page(
            [UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=10)],
            page_index=0,
        )
        tampered = page.model_copy(update={"page_hash": "0x" + "ab" * 32})
        with pytest.raises(PageHashMismatchError):
            verify_page_hash(tampered)

    def test_expected_argument_rejects_manifest_mismatch(self) -> None:
        page = _build_signed_page(
            [UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=10)],
            page_index=0,
        )
        with pytest.raises(PageHashMismatchError):
            verify_page_hash(page, expected="0x" + "ff" * 32)


class TestDetailedManifest:
    def test_valid_manifest_verifies(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        # page 0 (non-last) has full page_size of 2; page 1 (last) is shorter.
        pages = [
            _build_signed_page(
                [
                    UserScoreRecord(
                        user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=100
                    ),
                    UserScoreRecord(
                        user_ref="usr_b", miner_hotkey=SS58_A, user_score_14d_points=60
                    ),
                ],
                page_index=0,
            ),
            _build_signed_page(
                [
                    UserScoreRecord(
                        user_ref="usr_c", miner_hotkey=SS58_B, user_score_14d_points=120
                    ),
                ],
                page_index=1,
            ),
        ]
        manifest = _build_signed_manifest(ed25519_private_key, pages)
        verify_detailed_manifest(manifest, trusted_keys=trusted_keys)

    def test_records_hash_mismatch_rejected(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        pages = [
            _build_signed_page(
                [UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=100)],
                page_index=0,
            )
        ]
        manifest = _build_signed_manifest(ed25519_private_key, pages)
        tampered = manifest.model_copy(update={"records_hash": "0x" + "ab" * 32})
        with pytest.raises(RecordsHashMismatchError):
            verify_detailed_records_hash(tampered)


# ---------------------------------------------------------------------------
# verify_aggregate_snapshot (the convenience entry point)
# ---------------------------------------------------------------------------


class TestVerifyAggregateSnapshot:
    def test_happy_path(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        miners = [
            MinerAggregateRecord(miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1),
            MinerAggregateRecord(miner_hotkey=SS58_B, miner_score_points=2, active_member_count=2),
        ]
        snap = _build_signed_aggregate(ed25519_private_key, miners)
        verify_aggregate_snapshot(snap, trusted_keys=trusted_keys)

    def test_records_hash_mismatch_caught(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        trusted_keys: dict[str, TrustedKey],
    ) -> None:
        # Build a fully signed snapshot, then forge a new platform_signature
        # over the tampered records_hash so the signature passes but the
        # records_hash recomputation fails.
        miners = [
            MinerAggregateRecord(miner_hotkey=SS58_A, miner_score_points=1, active_member_count=1)
        ]
        snap = _build_signed_aggregate(ed25519_private_key, miners)
        tampered_dict = snap.model_dump(mode="json")
        tampered_dict["records_hash"] = "0x" + "ab" * 32
        # Re-sign the tampered envelope so the signature now matches the
        # bad records_hash. The records_hash check itself must still fire.
        without_sig = {k: v for k, v in tampered_dict.items() if k != "platform_signature"}
        envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, without_sig)
        new_sig = "0x" + ed25519_private_key.sign(envelope).hex()
        tampered_dict["platform_signature"] = new_sig
        tampered = AggregateSnapshot.model_validate(tampered_dict)
        with pytest.raises(RecordsHashMismatchError):
            verify_aggregate_snapshot(tampered, trusted_keys=trusted_keys)


# ---------------------------------------------------------------------------
# DetailedStreamingAccumulator
# ---------------------------------------------------------------------------


class TestStreamingAccumulator:
    @pytest.fixture
    def two_page_setup(
        self, ed25519_private_key: Ed25519PrivateKey
    ) -> tuple[DetailedManifest, list[DetailedPage]]:
        page0 = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=100),
                UserScoreRecord(user_ref="usr_b", miner_hotkey=SS58_A, user_score_14d_points=40),
            ],
            page_index=0,
        )
        page1 = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_c", miner_hotkey=SS58_B, user_score_14d_points=80),
                UserScoreRecord(user_ref="usr_d", miner_hotkey=SS58_B, user_score_14d_points=200),
            ],
            page_index=1,
        )
        manifest = _build_signed_manifest(ed25519_private_key, [page0, page1])
        return manifest, [page0, page1]

    def test_happy_path_finalises_to_two_miner_records(
        self,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, pages = two_page_setup
        acc = DetailedStreamingAccumulator(manifest)
        for page in pages:
            acc.consume_page(page)
        result = acc.finalize()
        assert len(result) == 2
        # SS58_A has 100 + 40 = 140 score, 1 active member (only 100 > 50).
        # SS58_B has 80 + 200 = 280 score, 2 active members (both > 50).
        by_hotkey = {r.miner_hotkey: r for r in result}
        assert by_hotkey[SS58_A].miner_score_points == 140
        assert by_hotkey[SS58_A].active_member_count == 1
        assert by_hotkey[SS58_B].miner_score_points == 280
        assert by_hotkey[SS58_B].active_member_count == 2

    def test_pages_out_of_order_rejected(
        self,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, pages = two_page_setup
        acc = DetailedStreamingAccumulator(manifest)
        with pytest.raises(UnexpectedPageError):
            acc.consume_page(pages[1])  # expected index 0, got 1

    def test_finalize_before_all_pages_rejected(
        self,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, pages = two_page_setup
        acc = DetailedStreamingAccumulator(manifest)
        acc.consume_page(pages[0])
        with pytest.raises(UnexpectedPageError):
            acc.finalize()

    def test_duplicate_user_ref_across_pages_rejected(
        self, ed25519_private_key: Ed25519PrivateKey
    ) -> None:
        # Build two pages that each reference the same user_ref.
        page0 = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_x", miner_hotkey=SS58_A, user_score_14d_points=100),
            ],
            page_index=0,
        )
        page1 = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_x", miner_hotkey=SS58_B, user_score_14d_points=50),
            ],
            page_index=1,
        )
        manifest = _build_signed_manifest(ed25519_private_key, [page0, page1])

        acc = DetailedStreamingAccumulator(manifest)
        acc.consume_page(page0)
        with pytest.raises(DuplicateUserRefError):
            acc.consume_page(page1)

    def test_cross_page_ordering_violation_rejected(
        self, ed25519_private_key: Ed25519PrivateKey
    ) -> None:
        # Page 0 ends with SS58_B; page 1 starts with SS58_A. That's a
        # backwards step across the page boundary.
        page0 = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_B, user_score_14d_points=10),
            ],
            page_index=0,
        )
        page1 = _build_signed_page(
            [
                UserScoreRecord(user_ref="usr_b", miner_hotkey=SS58_A, user_score_14d_points=10),
            ],
            page_index=1,
        )
        manifest = _build_signed_manifest(ed25519_private_key, [page0, page1])

        acc = DetailedStreamingAccumulator(manifest)
        acc.consume_page(page0)
        with pytest.raises(PageOrderError):
            acc.consume_page(page1)

    def test_page_hash_mismatch_against_manifest(
        self,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, pages = two_page_setup
        # Forge a page with a valid-looking but wrong hash.
        tampered = pages[0].model_copy(update={"page_hash": "0x" + "ee" * 32})
        acc = DetailedStreamingAccumulator(manifest)
        with pytest.raises(PageHashMismatchError):
            acc.consume_page(tampered)

    def test_page_identity_mismatch_rejected(
        self,
        ed25519_private_key: Ed25519PrivateKey,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, _pages = two_page_setup
        # Build a fresh page with a different snapshot_id (still
        # internally consistent — page_hash recomputes correctly).
        rogue_records = [
            UserScoreRecord(user_ref="usr_a", miner_hotkey=SS58_A, user_score_14d_points=1)
        ]
        rogue_dict: dict[str, Any] = {
            "domain": "PROMETHEON_RECORD_PAGE_V1",
            "schema_version": "1.0",
            "mechanism": "phase1_growth",
            "mechid": 0,
            "chain_network": ChainNetwork.FINNEY.value,
            "platform_instance_id": "bitfan-production",
            "netuid": 123,
            "snapshot_id": "phase1:2026-05-18:other",  # different
            "mode": "detailed",
            "activity_date": "2026-05-18",
            "page_index": 0,
            "record_count": len(rogue_records),
            "records": [r.model_dump(mode="json") for r in rogue_records],
            "page_hash": "0x" + "00" * 32,
        }
        tmp = DetailedPage.model_validate(rogue_dict)
        rogue_dict["page_hash"] = compute_page_hash(tmp)
        rogue = DetailedPage.model_validate(rogue_dict)

        acc = DetailedStreamingAccumulator(manifest)
        # Page hash matches its own body, but identity does not match the
        # manifest's snapshot_id. The hash check would still fail because
        # the manifest entry's page_hash refers to a different page body,
        # so we expect PageHashMismatchError (the identity check would
        # also catch it if the hashes happened to collide).
        with pytest.raises((PageHashMismatchError, UnexpectedPageError)):
            acc.consume_page(rogue)

    def test_consume_after_finalize_rejected(
        self,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, pages = two_page_setup
        acc = DetailedStreamingAccumulator(manifest)
        for page in pages:
            acc.consume_page(page)
        acc.finalize()
        with pytest.raises(RuntimeError):
            acc.consume_page(pages[0])

    def test_finalize_twice_rejected(
        self,
        two_page_setup: tuple[DetailedManifest, list[DetailedPage]],
    ) -> None:
        manifest, pages = two_page_setup
        acc = DetailedStreamingAccumulator(manifest)
        for page in pages:
            acc.consume_page(page)
        acc.finalize()
        with pytest.raises(RuntimeError):
            acc.finalize()
