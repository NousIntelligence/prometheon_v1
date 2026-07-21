"""Decentralized Validation parser + record-model contract gates.

Routes the vendored fixtures through the PRODUCTION code paths (unlike
``test_dv_wire_contract.py``, which pins the wire bytes with raw pinned
primitives):

- ``json-parser-rejection/`` → :func:`prometheon.security.canonical.parse_canonical_json`
  must reject every case with the fixture's ``expected_code``.
- ``canonical-json/`` → :func:`prometheon.security.canonical.to_canonical_bytes`
  must reproduce every corpus case byte-for-byte.
- ``event-record/01`` + ``02`` and the ingest-push batch records →
  :func:`prometheon.events.records.parse_event_record` must strict-parse,
  validate, and reproduce the canonical bytes through the production
  helpers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from prometheon.events.records import (
    EventFamily,
    EventRecordError,
    core_canonical_bytes,
    parse_event_record,
    record_canonical_bytes,
    validate_event_record,
)
from prometheon.security.canonical import (
    CanonicalEncodingError,
    parse_canonical_json,
    to_canonical_bytes,
)

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"


def _read_hex(path: Path) -> bytes:
    text = path.read_text().strip()
    return bytes.fromhex(text[2:] if text.startswith("0x") else text)


# ---------------------------------------------------------------------------
# json-parser-rejection — the strict parser's negative gate
# ---------------------------------------------------------------------------


def _rejection_cases() -> list[Path]:
    return sorted(p for p in (FIXTURES / "json-parser-rejection").iterdir() if p.is_dir())


@pytest.mark.parametrize("case", _rejection_cases(), ids=lambda p: p.name)
def test_strict_parser_rejects_with_expected_code(case: Path) -> None:
    raw = (case / "input.raw").read_bytes()
    expected_code = (case / "expected_code.txt").read_text().strip()
    with pytest.raises(CanonicalEncodingError) as excinfo:
        parse_canonical_json(raw)
    assert excinfo.value.code == expected_code


# ---------------------------------------------------------------------------
# canonical-json — the positive corpus through the production encoder
# ---------------------------------------------------------------------------


def _canonical_cases() -> list[Path]:
    return sorted(p for p in (FIXTURES / "canonical-json").iterdir() if p.is_dir())


@pytest.mark.parametrize("case", _canonical_cases(), ids=lambda p: p.name)
def test_production_encoder_reproduces_corpus_case(case: Path) -> None:
    parsed = parse_canonical_json((case / "input.json").read_bytes())
    ours = to_canonical_bytes(parsed)
    assert ours == _read_hex(case / "canonical.bytes.hex")
    assert hashlib.sha256(ours).digest() == _read_hex(case / "canonical.sha256.hex")


# ---------------------------------------------------------------------------
# event-record — production parse/validate/canonicalize round-trip
# ---------------------------------------------------------------------------


class TestActivityRecordThroughProductionModel:
    @pytest.fixture(scope="class")
    def case(self) -> Path:
        return FIXTURES / "event-record" / "01-signed-activity-record"

    def test_parses_validates_and_reproduces_bytes(self, case: Path) -> None:
        raw_mapping, view = parse_event_record((case / "record.json").read_bytes())
        assert view.family is EventFamily.ACTIVITY
        assert view.seq == 4207
        assert view.device_pubkey is not None and view.user_sig is not None
        assert record_canonical_bytes(raw_mapping) == _read_hex(case / "record.canonical.bytes.hex")
        assert core_canonical_bytes(raw_mapping["core"]) == _read_hex(
            case / "core.canonical.bytes.hex"
        )


class TestVerdictRecordThroughProductionModel:
    @pytest.fixture(scope="class")
    def case(self) -> Path:
        return FIXTURES / "event-record" / "02-platform-authored-verdict-record"

    def test_parses_validates_and_reproduces_bytes(self, case: Path) -> None:
        raw_mapping, view = parse_event_record((case / "record.json").read_bytes())
        assert view.family is EventFamily.EXCLUSION
        assert view.device_pubkey is None and view.user_sig is None
        assert view.core["kind"] == "verdict"
        assert record_canonical_bytes(raw_mapping) == _read_hex(case / "record.canonical.bytes.hex")


def test_every_ingest_push_batch_record_validates() -> None:
    batch = json.loads(
        (FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json").read_text()
    )
    for wire_record in batch["envelope"]["records"]:
        raw_mapping, view = validate_event_record(wire_record)
        assert view.family is EventFamily.ACTIVITY
        assert raw_mapping is wire_record


# ---------------------------------------------------------------------------
# Negative controls through the production model
# ---------------------------------------------------------------------------


def _valid_record_mapping() -> dict[str, Any]:
    case = FIXTURES / "event-record" / "01-signed-activity-record"
    result: Any = json.loads((case / "record.json").read_text())
    assert isinstance(result, dict)
    return result


class TestProductionModelNegativeControls:
    def test_record_with_forbidden_key_rejected_at_parse(self) -> None:
        mapping = _valid_record_mapping()
        text = json.dumps(mapping)[:-1] + ',"__proto__":{"x":1}}'
        with pytest.raises(EventRecordError) as excinfo:
            parse_event_record(text)
        assert excinfo.value.code == "forbidden_key"

    def test_record_with_float_rejected_at_parse(self) -> None:
        mapping = _valid_record_mapping()
        mapping["core"]["scoring_fields"]["dwell_seconds"] = 41.5
        with pytest.raises(EventRecordError) as excinfo:
            parse_event_record(json.dumps(mapping))
        assert excinfo.value.code == "float_literal"

    def test_signature_fields_must_pair(self) -> None:
        mapping = _valid_record_mapping()
        mapping["user_sig"] = None
        with pytest.raises(EventRecordError):
            validate_event_record(mapping)

    def test_kind_must_match_family(self) -> None:
        mapping = _valid_record_mapping()
        mapping["core"]["kind"] = "verdict"
        with pytest.raises(EventRecordError):
            validate_event_record(mapping)

    def test_uppercase_hex_event_id_rejected(self) -> None:
        mapping = _valid_record_mapping()
        mapping["event_id"] = mapping["event_id"].upper().replace("0X", "0x")
        with pytest.raises(EventRecordError):
            validate_event_record(mapping)
