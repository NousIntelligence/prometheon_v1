"""Production scoring-engine contract gates.

Replays the vendored r3 scoring vectors through the PRODUCTION engine
(:mod:`prometheon.mechanisms.phase1_growth.event_scoring`) — the same
fixtures the test-local reference in ``_dv_reference`` gates, so the two
implementations cross-check each other permanently:

- ``score-kernel/01`` — every kernel-table case through
  :func:`kernel_daily_score`.
- ``score-kernel/02`` — the 40-event scenario end-to-end: per-event
  verdicts (incl. all four signature statuses) and per-user day rows must
  equal ``expected`` exactly.
- ``score-kernel/03`` — the streak vectors through :func:`streak_bonus_for`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prometheon.events.device_signatures import DeviceKeyRegistry
from prometheon.mechanisms.phase1_growth.event_scoring import (
    FULL_WEIGHT_BP,
    EventScoringEngine,
    kernel_daily_score,
    streak_bonus_for,
)

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def test_kernel_table_reproduces_through_production_kernel() -> None:
    table = _load(FIXTURES / "score-kernel" / "01-exhaustive-composition-table" / "cases.json")
    for case in table["cases"]:
        ours = kernel_daily_score(case["daily_raw"], case["streak_bonus"], case["weight_bp"])
        assert ours == case["expected_daily_score"], case


def test_streak_vectors_reproduce_through_production_derivation() -> None:
    vectors = _load(FIXTURES / "score-kernel" / "03-streak-vectors" / "vectors.json")["vectors"]
    for vector in vectors:
        assert streak_bonus_for(vector["prior_raw_desc"]) == vector["bonus"], vector


class TestQualificationScenarioThroughProductionEngine:
    @pytest.fixture(scope="class")
    def scenario(self) -> dict[str, Any]:
        return _load(FIXTURES / "score-kernel" / "02-qualification" / "scenario.json")

    @pytest.fixture(scope="class")
    def engine(self, scenario: dict[str, Any]) -> EventScoringEngine:
        registry = DeviceKeyRegistry()
        for event in scenario["device_key_events"]:
            registry.apply_identity_record(
                {
                    "user_ref_evt": event["user_ref_evt"],
                    "epoch_id": event["epoch_id"],
                    "core": {"kind": event["kind"], "public_key": event["public_key"]},
                }
            )
        return EventScoringEngine(registry)

    @pytest.fixture(scope="class")
    def verdicts(
        self, scenario: dict[str, Any], engine: EventScoringEngine
    ) -> list[dict[str, Any]]:
        return [
            engine.process(record).as_mapping()
            for record in sorted(scenario["records"], key=lambda r: r["seq"])
        ]

    def test_per_event_verdicts_match(
        self, scenario: dict[str, Any], verdicts: list[dict[str, Any]]
    ) -> None:
        assert verdicts == scenario["expected"]["verdicts"]

    def test_per_user_day_rows_match(
        self, scenario: dict[str, Any], engine: EventScoringEngine, verdicts: list[dict[str, Any]]
    ) -> None:
        del verdicts  # ordering fixture: ensures records were processed first
        weights = {
            (w["user_ref_evt"], w["applies_to_epoch"]): w["weight_bp"]
            for w in scenario["exclusion_weights"]
        }
        for block in scenario["expected"]["days"]:
            user = block["user_ref_evt"]
            for expected_day in block["days"]:
                weight = weights.get((user, expected_day["epoch_id"]), FULL_WEIGHT_BP)
                ours = engine.compose_day(user, expected_day["epoch_id"], weight)
                assert ours.as_mapping() == expected_day, (user, expected_day)

    def test_no_positive_raw_days_beyond_expected(
        self, scenario: dict[str, Any], engine: EventScoringEngine, verdicts: list[dict[str, Any]]
    ) -> None:
        del verdicts
        expected_pairs = {
            (block["user_ref_evt"], day["epoch_id"])
            for block in scenario["expected"]["days"]
            for day in block["days"]
        }
        positive = {pair for pair, raw in engine.raw_scores().items() if raw > 0}
        assert positive <= expected_pairs
