"""Decentralized Validation scoring-contract tests.

Replays the vendored r3 scoring vectors through the test-local reference
scorer (``_dv_reference``): the exhaustive kernel table, the end-to-end
qualification scenario (per-kind thresholds/caps/dedups with exact window
boundaries and the four signature statuses), the streak-derivation vectors,
and the attribution vectors (C2 start-of-day binding, C3 day-close
membership, per-day clamp, strict active-member threshold, eligibility).

The production scoring engine (later PR) gates against these same files;
this module remains as the independent cross-check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from contract import _dv_reference as ref

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# score-kernel/01 — exhaustive composition table
# ---------------------------------------------------------------------------


class TestKernelTable:
    @pytest.fixture(scope="class")
    def table(self) -> dict[str, Any]:
        return _load(FIXTURES / "score-kernel" / "01-exhaustive-composition-table" / "cases.json")

    def test_domain_is_exhaustive(self, table: dict[str, Any]) -> None:
        assert len(table["cases"]) == table["case_count"] == 420
        expected = {
            (raw, bonus, bp)
            for raw in range(21)
            for bonus in range(4)
            for bp in (0, 1250, 2500, 5000, 10000)
        }
        actual = {(c["daily_raw"], c["streak_bonus"], c["weight_bp"]) for c in table["cases"]}
        assert actual == expected

    def test_every_case_reproduces(self, table: dict[str, Any]) -> None:
        for case in table["cases"]:
            ours = ref.daily_score(case["daily_raw"], case["streak_bonus"], case["weight_bp"])
            assert ours == case["expected_daily_score"], case


# ---------------------------------------------------------------------------
# score-kernel/02 — end-to-end qualification
# ---------------------------------------------------------------------------


class TestQualificationScenario:
    @pytest.fixture(scope="class")
    def scenario(self) -> dict[str, Any]:
        return _load(FIXTURES / "score-kernel" / "02-qualification" / "scenario.json")

    @pytest.fixture(scope="class")
    def replay(
        self, scenario: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], dict[tuple[str, str], int]]:
        return ref.replay_qualification(scenario)

    def test_per_event_verdicts_match(
        self,
        scenario: dict[str, Any],
        replay: tuple[list[dict[str, Any]], dict[tuple[str, str], int]],
    ) -> None:
        verdicts, _ = replay
        assert verdicts == scenario["expected"]["verdicts"]

    def test_signature_statuses_cover_all_four_cases(self, scenario: dict[str, Any]) -> None:
        statuses = {v["signature_status"] for v in scenario["expected"]["verdicts"]}
        assert statuses == {"unsigned", "verified", "invalid", "unregistered"}

    def test_per_user_day_rows_match(
        self,
        scenario: dict[str, Any],
        replay: tuple[list[dict[str, Any]], dict[tuple[str, str], int]],
    ) -> None:
        _, raw_by_user_day = replay
        weights = {
            (w["user_ref_evt"], w["applies_to_epoch"]): w["weight_bp"]
            for w in scenario["exclusion_weights"]
        }
        for block in scenario["expected"]["days"]:
            for expected_day in block["days"]:
                ours = ref.compose_day(
                    block["user_ref_evt"],
                    expected_day["epoch_id"],
                    raw_by_user_day,
                    weights,
                )
                assert ours == expected_day, (block["user_ref_evt"], expected_day)

    def test_no_scoring_days_beyond_expected(
        self,
        scenario: dict[str, Any],
        replay: tuple[list[dict[str, Any]], dict[tuple[str, str], int]],
    ) -> None:
        _, raw_by_user_day = replay
        expected_pairs = {
            (block["user_ref_evt"], d["epoch_id"])
            for block in scenario["expected"]["days"]
            for d in block["days"]
        }
        ours_pairs = {pair for pair, raw in raw_by_user_day.items() if raw > 0}
        assert ours_pairs <= expected_pairs


# ---------------------------------------------------------------------------
# score-kernel/03 — streak vectors
# ---------------------------------------------------------------------------


def _streak_vectors() -> list[dict[str, Any]]:
    data = _load(FIXTURES / "score-kernel" / "03-streak-vectors" / "vectors.json")
    return data["vectors"]


@pytest.mark.parametrize(
    "vector",
    _streak_vectors(),
    ids=lambda v: "prior=" + "-".join(str(r) for r in v["prior_raw_desc"]),
)
def test_streak_vector_reproduces(vector: dict[str, Any]) -> None:
    assert ref.streak_bonus(vector["prior_raw_desc"]) == vector["bonus"]


# ---------------------------------------------------------------------------
# attribution/01 — C2/C3 attribution vectors
# ---------------------------------------------------------------------------


class TestAttributionVectors:
    @pytest.fixture(scope="class")
    def scenario(self) -> dict[str, Any]:
        return _load(FIXTURES / "attribution" / "01-vectors" / "scenario.json")

    @pytest.fixture(scope="class")
    def attributed(self, scenario: dict[str, Any]) -> dict[tuple[str, str], str | None]:
        leaders = {
            g["group_id"]: g["user_ref_evt"]
            for g in scenario["group_events"]
            if g["kind"] == "group_created"
        }
        joins = [g for g in scenario["group_events"] if g["kind"] == "member_joined"]
        result: dict[tuple[str, str], str | None] = {}
        for row in scenario["expected"]["per_user_day"]:
            user, epoch = row["key"].split("|")
            group = ref.membership_at_day_close(user, epoch, joins)
            hotkey = (
                ref.binding_at_day_start(leaders[group], epoch, scenario["binding_events"])
                if group is not None
                else None
            )
            result[(user, epoch)] = hotkey
        return result

    def test_per_user_day_hotkeys_match(
        self, scenario: dict[str, Any], attributed: dict[tuple[str, str], str | None]
    ) -> None:
        ours = [
            {"key": f"{user}|{epoch}", "hotkey": hotkey}
            for (user, epoch), hotkey in attributed.items()
        ]
        assert ours == scenario["expected"]["per_user_day"]

    def test_miner_scores_apply_the_per_day_clamp(
        self, scenario: dict[str, Any], attributed: dict[tuple[str, str], str | None]
    ) -> None:
        scores = {
            (s["user_ref_evt"], s["epoch_id"]): s["daily_score"] for s in scenario["daily_scores"]
        }
        sums: dict[str, int] = {}
        for (user, epoch), hotkey in attributed.items():
            if hotkey is None:
                continue
            clamped = min(ref.ATTRIBUTION_DAY_CLAMP, max(0, scores.get((user, epoch), 0)))
            sums[hotkey] = sums.get(hotkey, 0) + clamped
        expected = {m["hotkey"]: m["score"] for m in scenario["expected"]["miner_score"]}
        assert sums == expected

    def test_active_members_and_eligibility(
        self, scenario: dict[str, Any], attributed: dict[tuple[str, str], str | None]
    ) -> None:
        scores = {
            (s["user_ref_evt"], s["epoch_id"]): s["daily_score"] for s in scenario["daily_scores"]
        }
        per_member: dict[tuple[str, str], int] = {}
        for (user, epoch), hotkey in attributed.items():
            if hotkey is None:
                continue
            clamped = min(ref.ATTRIBUTION_DAY_CLAMP, max(0, scores.get((user, epoch), 0)))
            per_member[(hotkey, user)] = per_member.get((hotkey, user), 0) + clamped

        expected_active = {m["hotkey"]: m["n"] for m in scenario["expected"]["active_members"]}
        ours_active = {
            hotkey: sum(1 for (h, _u), total in per_member.items() if h == hotkey and total > 50)
            for hotkey in expected_active
        }
        assert ours_active == expected_active

        expected_eligible = {m["hotkey"]: m["ok"] for m in scenario["expected"]["eligible"]}
        assert {h: n >= 3 for h, n in ours_active.items()} == expected_eligible
