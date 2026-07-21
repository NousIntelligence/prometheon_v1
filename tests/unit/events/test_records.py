"""Unit tests for the event-record envelope model.

The contract suite covers fixture round-trips; these tests pin the
envelope-validation rules on hand-built records so failures name the exact
rule rather than a fixture diff.
"""

from __future__ import annotations

from typing import Any

import pytest

from prometheon.events.records import (
    EventFamily,
    EventRecordError,
    validate_event_record,
)

pytestmark = pytest.mark.unit


def _record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "domain": "PROMETHEON_EVENT_RECORD_V1",
        "family": "identity",
        "seq": 7,
        "epoch_id": "2026-07-20",
        "event_id": "0x" + "ab" * 32,
        "user_ref_evt": "usr_evt_" + "cd" * 32,
        "group_id": None,
        "received_ts": "2026-07-20T09:15:04Z",
        "category_id": None,
        "core": {"kind": "device_key_register", "public_key": "0x04" + "ee" * 64},
        "device_pubkey": None,
        "user_sig": None,
    }
    base.update(overrides)
    return base


class TestEnvelopeValidation:
    def test_valid_identity_record_passes(self) -> None:
        raw, view = validate_event_record(_record())
        assert view.family is EventFamily.IDENTITY
        assert raw["seq"] == 7

    def test_wrong_domain_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(domain="PROMETHEON_EVENT_V1"))

    def test_unknown_family_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(family="telemetry"))

    def test_zero_seq_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(seq=0))

    def test_bool_seq_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(seq=True))

    def test_bad_epoch_shape_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(epoch_id="2026/07/20"))

    def test_received_ts_with_milliseconds_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(received_ts="2026-07-20T09:15:04.123Z"))

    def test_received_ts_with_offset_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(received_ts="2026-07-20T09:15:04+00:00"))

    def test_extra_envelope_field_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(_record(surprise=1))

    def test_non_object_rejected(self) -> None:
        with pytest.raises(EventRecordError):
            validate_event_record(["not", "a", "record"])


class TestFamilyKindRules:
    def test_identity_kind_in_activity_family_rejected(self) -> None:
        record = _record(family="activity")
        record["core"] = {"kind": "device_key_register"}
        with pytest.raises(EventRecordError):
            validate_event_record(record)

    def test_activity_core_requires_event_domain(self) -> None:
        record = _record(family="activity")
        record["core"] = {"kind": "login", "target": {}, "scoring_fields": {}}
        with pytest.raises(EventRecordError):
            validate_event_record(record)

    def test_platform_authored_families_never_device_signed(self) -> None:
        record = _record(
            device_pubkey="0x04" + "aa" * 64,
            user_sig="0x" + "bb" * 64,
        )
        with pytest.raises(EventRecordError):
            validate_event_record(record)

    def test_genesis_import_accepted_for_identity_and_group(self) -> None:
        identity = _record()
        identity["core"] = {"kind": "genesis_import", "genesis_kind": "device_key_register"}
        validate_event_record(identity)

        group = _record(family="group")
        group["core"] = {"kind": "genesis_import", "genesis_kind": "member_joined"}
        validate_event_record(group)

    def test_null_user_only_on_verdicts_complete(self) -> None:
        marker = _record(family="exclusion", user_ref_evt=None)
        marker["core"] = {
            "kind": "verdicts_complete",
            "applies_to_epoch": "2026-07-19",
            "verdict_count": 3,
        }
        validate_event_record(marker)

        userless_bind = _record(user_ref_evt=None)
        with pytest.raises(EventRecordError):
            validate_event_record(userless_bind)
