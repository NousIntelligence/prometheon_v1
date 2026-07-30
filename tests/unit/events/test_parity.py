"""Unit tests for the advisory parity-report submission (ingest-contract §10).

Every §10.3 rule is enforced locally before a request goes out, so these
tests are the gate on that: a violation must fail with the rule named, not
as a wire code from the platform. The transport tests use the real
envelope and assert the outgoing environment binding, as every mocked
platform call in this repo now must.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from prometheon.events.parity import (
    MAX_PARITY_ROWS,
    PARITY_REPORT_PATH,
    ParityReportError,
    scores_hash,
    submit_parity_report,
    validate_parity_report,
)
from prometheon.platform.wire import CHAIN_NETWORK_HEADER, PLATFORM_INSTANCE_ID_HEADER

pytestmark = pytest.mark.unit

FIXTURES = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "decentralized-validation"
    / "parity-report"
    / "01-scores-hash"
)

EPOCH = "2026-07-29"
CHAIN_NETWORK = "test"
INSTANCE_ID = "bitfan-staging"
TODAY = "2026-07-30"


def _user(prefix: str) -> str:
    return "usr_evt_" + (prefix * 64)[:64]


def _report(rows: list[dict[str, Any]] | None = None, epoch: str = EPOCH) -> dict[str, Any]:
    scores = rows if rows is not None else [{"user_ref_evt": _user("a"), "daily_score": 1}]
    return {"epoch": epoch, "scores": scores, "scores_hash": scores_hash(epoch, scores)}


def _ok(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": payload, "meta": {}})


def _accepted(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "advisory_only": True,
        "report_id": "11111111-2222-3333-4444-555555555555",
        "epoch": EPOCH,
        "scores_received": 1,
        "scores_hash": scores_hash(EPOCH, [{"user_ref_evt": _user("a"), "daily_score": 1}]),
        "status": "pending",
        "received_at": "2026-07-30T02:14:07Z",
        "diffed_at": None,
        "verdict": None,
        "epoch_agreement": {"reports": 3, "diffed": 2, "matched": 2},
    }
    payload.update(overrides)
    return payload


def _submit(handler: Any, report: dict[str, Any] | None = None, **kwargs: Any) -> Any:
    return submit_parity_report(
        base_url="http://platform.test",
        api_token="unit-token",
        report=report if report is not None else _report(),
        chain_network=CHAIN_NETWORK,
        platform_instance_id=INSTANCE_ID,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


class TestScoresHashVector:
    def test_matches_the_pinned_fixture(self) -> None:
        """The platform recomputes this and rejects a mismatch."""
        fixture: Any = json.loads((FIXTURES / "report.json").read_text())
        assert scores_hash(fixture["epoch"], fixture["scores"]) == fixture["scores_hash"]


class TestLocalValidation:
    def test_accepts_a_well_formed_report(self) -> None:
        validate_parity_report(_report(), today=TODAY)

    def test_rejects_an_epoch_that_is_not_closed(self) -> None:
        with pytest.raises(ParityReportError, match="not closed"):
            validate_parity_report(_report(epoch=TODAY), today=TODAY)

    def test_rejects_a_malformed_epoch(self) -> None:
        with pytest.raises(ParityReportError, match="YYYY-MM-DD"):
            validate_parity_report(_report(epoch="29-07-2026"))

    def test_rejects_unsorted_rows(self) -> None:
        rows = [
            {"user_ref_evt": _user("b"), "daily_score": 1},
            {"user_ref_evt": _user("a"), "daily_score": 2},
        ]
        report = {"epoch": EPOCH, "scores": rows, "scores_hash": scores_hash(EPOCH, rows)}
        with pytest.raises(ParityReportError, match="sorted ascending"):
            validate_parity_report(report)

    def test_rejects_duplicate_users(self) -> None:
        rows = [
            {"user_ref_evt": _user("a"), "daily_score": 1},
            {"user_ref_evt": _user("a"), "daily_score": 2},
        ]
        report = {"epoch": EPOCH, "scores": rows, "scores_hash": scores_hash(EPOCH, rows)}
        with pytest.raises(ParityReportError, match="more than once"):
            validate_parity_report(report)

    def test_rejects_a_non_integer_score(self) -> None:
        rows = [{"user_ref_evt": _user("a"), "daily_score": True}]
        report = {"epoch": EPOCH, "scores": rows, "scores_hash": scores_hash(EPOCH, rows)}
        with pytest.raises(ParityReportError, match="non-integer"):
            validate_parity_report(report)

    def test_rejects_a_malformed_user_ref(self) -> None:
        rows = [{"user_ref_evt": "not-a-pseudonym", "daily_score": 1}]
        report = {"epoch": EPOCH, "scores": rows, "scores_hash": scores_hash(EPOCH, rows)}
        with pytest.raises(ParityReportError, match="user_ref_evt"):
            validate_parity_report(report)

    def test_rejects_too_many_rows(self) -> None:
        rows = [
            {"user_ref_evt": "usr_evt_" + f"{index:064x}", "daily_score": 1}
            for index in range(MAX_PARITY_ROWS + 1)
        ]
        report = {"epoch": EPOCH, "scores": rows, "scores_hash": scores_hash(EPOCH, rows)}
        with pytest.raises(ParityReportError, match="row cap"):
            validate_parity_report(report)

    def test_rejects_a_hash_that_does_not_cover_the_rows(self) -> None:
        report = _report()
        report["scores"] = [{"user_ref_evt": _user("a"), "daily_score": 99}]
        with pytest.raises(ParityReportError, match="scores_hash"):
            validate_parity_report(report)

    def test_zero_rows_are_legal(self) -> None:
        """Absence means zero, and an explicit zero row is equivalent."""
        validate_parity_report(_report(rows=[{"user_ref_evt": _user("a"), "daily_score": 0}]))
        validate_parity_report(_report(rows=[]))


class TestSubmission:
    def test_sends_the_binding_in_body_and_headers(self) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = request.headers
            seen["body"] = json.loads(request.content)
            seen["path"] = request.url.path
            return _ok(_accepted())

        _submit(handler)

        assert seen["path"] == PARITY_REPORT_PATH
        assert seen["headers"][CHAIN_NETWORK_HEADER] == CHAIN_NETWORK
        assert seen["headers"][PLATFORM_INSTANCE_ID_HEADER] == INSTANCE_ID
        assert seen["body"]["chain_network"] == CHAIN_NETWORK
        assert seen["body"]["platform_instance_id"] == INSTANCE_ID
        assert seen["body"]["scores_hash"] == _report()["scores_hash"]

    def test_fresh_submission_is_pending(self) -> None:
        verdict = _submit(lambda request: _ok(_accepted()))
        assert verdict.is_pending
        assert verdict.advisory_only
        assert verdict.epoch_agreement == {"reports": 3, "diffed": 2, "matched": 2}

    def test_clean_verdict(self) -> None:
        verdict = _submit(
            lambda request: _ok(
                _accepted(
                    status="match",
                    verdict={
                        "agreed_count": 412,
                        "score_mismatches": 0,
                        "platform_only": 0,
                        "report_only": 0,
                    },
                )
            )
        )
        assert verdict.is_clean
        assert not verdict.is_pending

    def test_mismatch_verdict_is_surfaced(self) -> None:
        verdict = _submit(
            lambda request: _ok(
                _accepted(
                    status="mismatch",
                    verdict={
                        "agreed_count": 400,
                        "score_mismatches": 2,
                        "platform_only": 1,
                        "report_only": 0,
                    },
                )
            )
        )
        assert not verdict.is_clean
        assert verdict.verdict is not None
        assert verdict.verdict["score_mismatches"] == 2

    def test_platform_rejection_code_is_carried(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400,
                json={
                    "success": False,
                    "error": {
                        "code": "parity_scores_hash_mismatch",
                        "message": "hash does not match rows",
                    },
                },
            )

        with pytest.raises(ParityReportError) as excinfo:
            _submit(handler)
        assert excinfo.value.error_code == "parity_scores_hash_mismatch"
        assert excinfo.value.status_code == 400

    def test_local_validation_runs_before_any_request(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("must not reach the network")

        with pytest.raises(ParityReportError, match="not closed"):
            _submit(handler, report=_report(epoch=TODAY), today=TODAY)
