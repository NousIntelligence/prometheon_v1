"""Decentralized Validation wire-contract tests.

Byte-level conformance against the vendored fixture suite
(``tests/fixtures/decentralized-validation/``, release r3 / BitFan commit
``bce1b9b``). Everything deterministic is asserted byte-for-byte with this
repo's own pinned primitives (``rfc8785`` for JCS, ``cryptography`` for
Ed25519 / P-256); randomized signatures are verify-asserted per the suite's
documented regeneration policy.

Covers, in the shared build-order's terms:

- step 1 gate: the RFC 8785 canonical-JSON corpus;
- step 2 gate: event-record canonical bytes (activity + verdict) and the
  record envelope invariants;
- step 3 gate: the P-256 device signature over the EVENT_V1 core;
- step 5 gate: the INGEST_PUSH_V1 wire body, publisher signature, and the
  four-case contiguity / overlap / duplicate / gap scenario;
- step 7 gate: the per-(family, epoch) day digest, populated and empty.

The scoring-side suites (kernel table, qualification, streaks, attribution)
live in ``test_dv_score_contract.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"

DOMAIN_EVENT = b"PROMETHEON_EVENT_V1\n"
DOMAIN_RECORD = b"PROMETHEON_EVENT_RECORD_V1\n"
DOMAIN_DIGEST = b"PROMETHEON_DAY_DIGEST_V1\n"
DOMAIN_PUSH = b"PROMETHEON_INGEST_PUSH_V1\n"

# The committed, publicly-derivable TEST publisher key. It must never be
# accepted outside fixture tests — the production trusted-key config pins a
# different, private staging/production key.
TEST_PUBLISHER_PUBKEY_HEX = "0xaed1b5ea8a4ec357f061aac1020691c90c59dd71e5ab882c832781b3466d011e"
LIVE_STAGING_PUBKEY_HEX = "0xff6ebda35c55062e4caa4551e844dbfe7af11ab72cfc713bd6d8edaa20cb4028"


def _jcs(obj: Any) -> bytes:
    return rfc8785.dumps(obj)


def _read_hex(path: Path) -> bytes:
    text = path.read_text().strip()
    return bytes.fromhex(text[2:] if text.startswith("0x") else text)


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _verify_p256(pub_sec1: bytes, sig_rs: bytes, message: bytes) -> None:
    pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_sec1)
    der = encode_dss_signature(
        int.from_bytes(sig_rs[:32], "big"), int.from_bytes(sig_rs[32:], "big")
    )
    pubkey.verify(der, message, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# canonical-json corpus
# ---------------------------------------------------------------------------


def _canonical_cases() -> list[Path]:
    return sorted(p for p in (FIXTURES / "canonical-json").iterdir() if p.is_dir())


@pytest.mark.parametrize("case", _canonical_cases(), ids=lambda p: p.name)
def test_canonical_json_case_reproduces(case: Path) -> None:
    ours = _jcs(_load(case / "input.json"))
    assert ours == _read_hex(case / "canonical.bytes.hex")
    assert hashlib.sha256(ours).digest() == _read_hex(case / "canonical.sha256.hex")


# ---------------------------------------------------------------------------
# event-record/01 — signed activity record
# ---------------------------------------------------------------------------


class TestSignedActivityRecord:
    @pytest.fixture(scope="class")
    def case(self) -> Path:
        return FIXTURES / "event-record" / "01-signed-activity-record"

    def test_core_canonical_bytes(self, case: Path) -> None:
        record = _load(case / "record.json")
        assert DOMAIN_EVENT + _jcs(record["core"]) == _read_hex(case / "core.canonical.bytes.hex")

    def test_record_canonical_bytes(self, case: Path) -> None:
        record = _load(case / "record.json")
        assert DOMAIN_RECORD + _jcs(record) == _read_hex(case / "record.canonical.bytes.hex")

    def test_event_id_file_matches_record_field(self, case: Path) -> None:
        # event_id derives from the raw platform user id, which validators
        # never receive — it is an opaque dedup key; only file/field
        # consistency is assertable subnet-side.
        record = _load(case / "record.json")
        assert (case / "event_id.hex").read_text().strip() == record["event_id"]

    def test_device_signature_shapes(self, case: Path) -> None:
        pub = _read_hex(case / "device_public_key.hex")
        sig = _read_hex(case / "device_signature.hex")
        assert len(pub) == 65 and pub[0] == 0x04
        assert len(sig) == 64
        record = _load(case / "record.json")
        assert record["device_pubkey"] == "0x" + pub.hex()
        assert record["user_sig"] == "0x" + sig.hex()

    def test_device_signature_verifies_over_core(self, case: Path) -> None:
        record = _load(case / "record.json")
        _verify_p256(
            _read_hex(case / "device_public_key.hex"),
            _read_hex(case / "device_signature.hex"),
            DOMAIN_EVENT + _jcs(record["core"]),
        )

    def test_device_signature_rejects_mutated_core(self, case: Path) -> None:
        record = _load(case / "record.json")
        with pytest.raises(InvalidSignature):
            _verify_p256(
                _read_hex(case / "device_public_key.hex"),
                _read_hex(case / "device_signature.hex"),
                DOMAIN_EVENT + _jcs(record["core"]) + b"x",
            )


# ---------------------------------------------------------------------------
# event-record/02 — platform-authored verdict record
# ---------------------------------------------------------------------------


class TestVerdictRecord:
    @pytest.fixture(scope="class")
    def record(self) -> dict[str, Any]:
        return _load(
            FIXTURES / "event-record" / "02-platform-authored-verdict-record" / "record.json"
        )

    def test_canonical_bytes(self, record: dict[str, Any]) -> None:
        expected = _read_hex(
            FIXTURES
            / "event-record"
            / "02-platform-authored-verdict-record"
            / "record.canonical.bytes.hex"
        )
        assert DOMAIN_RECORD + _jcs(record) == expected

    def test_platform_authored_records_are_unsigned(self, record: dict[str, Any]) -> None:
        assert record["device_pubkey"] is None
        assert record["user_sig"] is None

    def test_weight_bp_in_locked_sub_full_set(self, record: dict[str, Any]) -> None:
        # A verdict RECORD never carries full weight — absence IS 10000.
        assert record["core"]["weight_bp"] in (0, 1250, 2500, 5000)

    def test_epoch_id_is_sequencing_day_not_applies_to_epoch(self, record: dict[str, Any]) -> None:
        # R1 rule: epoch_id = DB-clock sequencing day, uniformly, every
        # family. A verdict for epoch D is sealed on D+1 and carries D+1;
        # scoring joins on core.applies_to_epoch only.
        assert record["epoch_id"] == record["received_ts"][:10]
        assert record["epoch_id"] != record["core"]["applies_to_epoch"]


# ---------------------------------------------------------------------------
# ingest-push/01 — signed batch, and the test publisher key
# ---------------------------------------------------------------------------


class TestIngestPushSignedBatch:
    @pytest.fixture(scope="class")
    def case(self) -> Path:
        return FIXTURES / "ingest-push" / "01-signed-batch"

    @pytest.fixture(scope="class")
    def batch(self, case: Path) -> dict[str, Any]:
        return _load(case / "signed_batch.json")

    @pytest.fixture(scope="class")
    def key_info(self) -> dict[str, Any]:
        return _load(FIXTURES / "test-keys" / "ed25519-platform.json")

    def test_wire_bytes_are_jcs_of_signed_batch(self, case: Path, batch: dict[str, Any]) -> None:
        assert _jcs(batch) == _read_hex(case / "wire.bytes.hex")

    def test_envelope_binds_fixture_environment(self, batch: dict[str, Any]) -> None:
        # bitfan-local is the fixture environment; a validator configured
        # for staging/production MUST reject this envelope, so the fixture
        # doubles as the cross-env rejection input.
        assert batch["envelope"]["platform_instance_id"] == "bitfan-local"

    def test_batch_is_contiguous(self, batch: dict[str, Any]) -> None:
        env = batch["envelope"]
        seqs = [r["seq"] for r in env["records"]]
        assert seqs == list(range(env["from_seq"], env["to_seq"] + 1))

    def test_record_one_is_byte_identical_to_event_record_01(self, batch: dict[str, Any]) -> None:
        standalone = _load(FIXTURES / "event-record" / "01-signed-activity-record" / "record.json")
        assert _jcs(batch["envelope"]["records"][0]) == _jcs(standalone)

    def test_publisher_signature_verifies(
        self, batch: dict[str, Any], key_info: dict[str, Any]
    ) -> None:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_info["public_key_hex"][2:]))
        pub.verify(
            bytes.fromhex(batch["sig"][2:]),
            DOMAIN_PUSH + _jcs(batch["envelope"]),
        )
        assert batch["publisher_key_id"] == key_info["key_id"]

    def test_publisher_signature_rejects_mutated_envelope(
        self, batch: dict[str, Any], key_info: dict[str, Any]
    ) -> None:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_info["public_key_hex"][2:]))
        with pytest.raises(InvalidSignature):
            pub.verify(
                bytes.fromhex(batch["sig"][2:]),
                DOMAIN_PUSH + _jcs(batch["envelope"]) + b"x",
            )

    def test_test_key_is_publicly_derivable_and_must_stay_fixtures_only(
        self, key_info: dict[str, Any]
    ) -> None:
        # The seed is sha256 of a published label: ANYONE can sign as this
        # key. It must never appear in a live trusted-key config; the live
        # staging key is a different, private key.
        seed = hashlib.sha256(key_info["seed_label"].encode("ascii")).digest()
        assert base64.b64decode(key_info["private_key_base64"]) == seed
        derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
        assert "0x" + derived.hex() == key_info["public_key_hex"] == TEST_PUBLISHER_PUBKEY_HEX
        assert key_info["public_key_hex"] != LIVE_STAGING_PUBKEY_HEX


# ---------------------------------------------------------------------------
# ingest-push/02 — contiguity / overlap / duplicate / gap scenario
# ---------------------------------------------------------------------------


def _ack_rule(last_stored: int, from_seq: int, to_seq: int) -> tuple[list[int], int]:
    """The normative four-case ingest rule (ingest-contract §4.4).

    exact-next -> store all; overlap-with-new-tail -> store the tail from
    ``last_stored + 1``; full duplicate -> store nothing, ack position;
    forward gap -> store nothing (backfill), ack position.
    """
    if from_seq > last_stored + 1:
        return [], last_stored
    store = [s for s in range(from_seq, to_seq + 1) if s > last_stored]
    return store, (to_seq if store else last_stored)


class TestIngestPushOverlapScenario:
    @pytest.fixture(scope="class")
    def scenario(self) -> dict[str, Any]:
        return _load(FIXTURES / "ingest-push" / "02-overlap-batch" / "scenario.json")

    def test_scenario_targets_the_signed_batch_range(self, scenario: dict[str, Any]) -> None:
        batch = _load(FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json")
        assert scenario["from_seq"] == batch["envelope"]["from_seq"]
        assert scenario["to_seq"] == batch["envelope"]["to_seq"]

    def test_scenario_covers_all_four_canonical_cases(self, scenario: dict[str, Any]) -> None:
        assert {c["name"] for c in scenario["cases"]} == {
            "exact_next",
            "overlap_with_new_tail",
            "full_duplicate",
            "forward_gap",
        }

    def test_every_case_matches_the_recomputed_rule(self, scenario: dict[str, Any]) -> None:
        for c in scenario["cases"]:
            store, ack = _ack_rule(
                c["given_last_stored_seq"], scenario["from_seq"], scenario["to_seq"]
            )
            assert store == c["expect_store_seqs"], c["name"]
            assert ack == c["expect_ack_received_through_seq"], c["name"]


# ---------------------------------------------------------------------------
# event-record/03 — day digest (populated + empty day)
# ---------------------------------------------------------------------------


class TestDayDigest:
    @pytest.fixture(scope="class")
    def case(self) -> Path:
        return FIXTURES / "event-record" / "03-day-digest"

    @pytest.fixture(scope="class")
    def batch_records(self) -> list[dict[str, Any]]:
        batch = _load(FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json")
        return batch["envelope"]["records"]

    def test_records_hash_is_concat_hash_in_seq_order(
        self, case: Path, batch_records: list[dict[str, Any]]
    ) -> None:
        concat = b"".join(DOMAIN_RECORD + _jcs(r) for r in batch_records)
        assert hashlib.sha256(concat).digest() == _read_hex(case / "records_hash.hex")

    def test_envelope_fields_are_consistent(
        self, case: Path, batch_records: list[dict[str, Any]]
    ) -> None:
        env = _load(case / "envelope.json")
        assert env["records_hash"] == "0x" + _read_hex(case / "records_hash.hex").hex()
        assert env["record_count"] == len(batch_records)
        assert all(r["epoch_id"] == env["epoch_id"] for r in batch_records)

    def test_envelope_canonical_bytes(self, case: Path) -> None:
        env = _load(case / "envelope.json")
        assert DOMAIN_DIGEST + _jcs(env) == _read_hex(case / "envelope.canonical.bytes.hex")

    def test_empty_day_is_signed_statement_of_emptiness(self, case: Path) -> None:
        env = _load(case / "empty_day.envelope.json")
        expected = _read_hex(case / "empty_day.records_hash.hex")
        assert expected == hashlib.sha256(b"").digest()
        assert env["records_hash"] == "0x" + expected.hex()
        assert env["record_count"] == 0
