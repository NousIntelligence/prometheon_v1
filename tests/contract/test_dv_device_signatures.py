"""Device-signature contract gates through the production module.

- ``event-record/01`` — the fixture's real P-256 signature must classify
  ``verified`` given its registration, and mutations must classify
  ``invalid`` / ``unregistered`` correctly.
- ``score-kernel/02`` — every record's ``signature_status`` in the
  40-event qualification scenario must reproduce through
  :func:`prometheon.events.device_signatures.classify_signature` fed by a
  :class:`DeviceKeyRegistry` built from the scenario's key events —
  covering all four statuses including the post-revoke case.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prometheon.events.device_signatures import (
    DeviceKeyRegistry,
    SignatureStatus,
    classify_signature,
    verify_core_signature,
)

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _registry_from_key_events(key_events: list[dict[str, Any]]) -> DeviceKeyRegistry:
    registry = DeviceKeyRegistry()
    for event in key_events:
        # Scenario key events are flat mappings (kind at top level).
        registry.apply_identity_record(
            {
                "user_ref_evt": event["user_ref_evt"],
                "epoch_id": event["epoch_id"],
                "core": {"kind": event["kind"], "public_key": event["public_key"]},
            }
        )
    return registry


class TestFixtureRecordClassification:
    @pytest.fixture(scope="class")
    def record(self) -> dict[str, Any]:
        return _load(FIXTURES / "event-record" / "01-signed-activity-record" / "record.json")

    @pytest.fixture(scope="class")
    def registry(self, record: dict[str, Any]) -> DeviceKeyRegistry:
        registry = DeviceKeyRegistry()
        registry.apply_identity_record(
            {
                "user_ref_evt": record["user_ref_evt"],
                "epoch_id": record["epoch_id"],
                "core": {"kind": "device_key_register", "public_key": record["device_pubkey"]},
            }
        )
        return registry

    def test_fixture_signature_verifies_cryptographically(self, record: dict[str, Any]) -> None:
        assert verify_core_signature(record["device_pubkey"], record["user_sig"], record["core"])

    def test_classifies_verified_with_registration(
        self, record: dict[str, Any], registry: DeviceKeyRegistry
    ) -> None:
        assert classify_signature(record, registry) is SignatureStatus.VERIFIED

    def test_classifies_unregistered_without_registration(self, record: dict[str, Any]) -> None:
        assert classify_signature(record, DeviceKeyRegistry()) is SignatureStatus.UNREGISTERED

    def test_mutated_core_classifies_invalid(
        self, record: dict[str, Any], registry: DeviceKeyRegistry
    ) -> None:
        mutated = json.loads(json.dumps(record))
        mutated["core"]["scoring_fields"]["dwell_seconds"] += 1
        assert classify_signature(mutated, registry) is SignatureStatus.INVALID


def test_qualification_scenario_signature_statuses_reproduce() -> None:
    scenario = _load(FIXTURES / "score-kernel" / "02-qualification" / "scenario.json")
    registry = _registry_from_key_events(scenario["device_key_events"])
    expected_by_seq = {v["seq"]: v["signature_status"] for v in scenario["expected"]["verdicts"]}
    seen_statuses: set[str] = set()
    for record in scenario["records"]:
        ours = classify_signature(record, registry)
        assert ours.value == expected_by_seq[record["seq"]], record["seq"]
        seen_statuses.add(ours.value)
    assert seen_statuses == {"unsigned", "verified", "invalid", "unregistered"}
