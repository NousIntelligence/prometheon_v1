"""Attribution contract gate through the production module.

Replays ``attribution/01-vectors`` through
:mod:`prometheon.mechanisms.phase1_growth.event_attribution`: per-user-day
hotkeys (day-close membership with start-of-day binding), miner sums with the
per-day clamp, strict active-member counts, and eligibility.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prometheon.mechanisms.phase1_growth.event_attribution import (
    BindingLedger,
    GroupLedger,
    aggregate_miner_scores,
)

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"


@pytest.fixture(scope="module")
def scenario() -> dict[str, Any]:
    data: Any = json.loads((FIXTURES / "attribution" / "01-vectors" / "scenario.json").read_text())
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def ledgers(scenario: dict[str, Any]) -> tuple[GroupLedger, BindingLedger]:
    groups = GroupLedger()
    for record in sorted(scenario["group_events"], key=lambda r: r["seq"]):
        groups.apply_group_record(record)

    bindings = BindingLedger()
    for event in scenario["binding_events"]:
        # Vector shorthand: {role: miner|validator, kind: bind|unbind,
        # user_ref_evt, hotkey_ss58, at}. The role MUST be carried through
        # to the record kind — an adapter that stamps every event as a
        # miner binding hands the ledger a lie and hides the very defect
        # this vector exists to catch (a dual-role leader's validator bind
        # taking over the group).
        bound = event["kind"] == "bind"
        kind = f"{event['role']}_hotkey_{'bind' if bound else 'unbind'}"
        timestamp_field = "bound_at" if bound else "unbound_at"
        bindings.apply_identity_record(
            {
                "user_ref_evt": event["user_ref_evt"],
                "core": {
                    "kind": kind,
                    "hotkey_ss58": event.get("hotkey_ss58"),
                    timestamp_field: event["at"],
                },
            }
        )
    return groups, bindings


@pytest.fixture(scope="module")
def result(scenario: dict[str, Any], ledgers: tuple[GroupLedger, BindingLedger]) -> Any:
    groups, bindings = ledgers
    daily_scores = {
        (row["user_ref_evt"], row["epoch_id"]): row["daily_score"]
        for row in scenario["daily_scores"]
    }
    return aggregate_miner_scores(daily_scores, groups, bindings)


def test_per_user_day_hotkeys_match(scenario: dict[str, Any], result: Any) -> None:
    for row in scenario["expected"]["per_user_day"]:
        user, epoch = row["key"].split("|")
        assert result.per_user_day_hotkey[(user, epoch)] == row["hotkey"], row["key"]
    assert len(result.per_user_day_hotkey) == len(scenario["expected"]["per_user_day"])


def test_miner_scores_match(scenario: dict[str, Any], result: Any) -> None:
    expected = {m["hotkey"]: m["score"] for m in scenario["expected"]["miner_score"]}
    assert result.miner_scores == expected


def test_active_members_match(scenario: dict[str, Any], result: Any) -> None:
    expected = {m["hotkey"]: m["n"] for m in scenario["expected"]["active_members"]}
    assert result.active_members == expected


def test_eligibility_matches(scenario: dict[str, Any], result: Any) -> None:
    expected = {m["hotkey"]: m["ok"] for m in scenario["expected"]["eligible"]}
    assert result.eligible == expected
