"""Submission of the advisory parity report (ingest-contract §10).

The validator posts the per-user ``daily_score`` set it computed for one
closed epoch; the platform diffs it against its own numbers and records the
verdict. That is what turns "N consecutive clean shadow days" from a
judgement call into a measured, per-epoch fact with an audit trail on both
sides.

**Advisory only, by construction.** Nothing submitted here, and nothing
returned, is an input to scoring, weighting, ranking, or validator
standing. The response carries no platform score values and no judgement
about any other validator — only this report's own verdict counts and the
epoch's aggregate agreement. Treat any future response field that looks
like guidance as a contract violation to raise, not as something to act on:
a validator that adjusts what it submits based on what the platform says
has stopped recomputing independently, which is the entire point of the
program.

The verdict is asynchronous: the platform's web process cannot resolve
``user_ref_evt`` pseudonyms (the key lives only in its worker), so a fresh
submission comes back ``pending`` and re-posting the identical bytes is how
you poll. Re-posting *different* bytes for the same epoch replaces the row
and re-queues the diff — the supported way to correct a report.

Every rule in §10.3 is enforced locally before the request goes out. The
platform would reject a violation anyway; failing here means an operator
sees which rule and why, instead of a wire code.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Final

import httpx

from prometheon.platform.wire import (
    bearer_auth_headers,
    describe_error_body,
    is_error_envelope,
    unwrap_success_envelope,
)
from prometheon.security.canonical import to_canonical_bytes

PARITY_REPORT_PATH: Final[str] = "/api/v1/prometheon/events/parity-report"
MAX_PARITY_ROWS: Final[int] = 10_000

_EPOCH_RE: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_USER_REF_RE: Final[re.Pattern[str]] = re.compile(r"^usr_evt_[0-9a-f]{64}$")


class ParityReportError(RuntimeError):
    """The report was refused — locally before sending, or by the platform."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


@dataclass(frozen=True)
class ParityVerdict:
    """The platform's stored verdict for one submitted report."""

    report_id: str
    epoch: str
    status: str
    scores_received: int
    advisory_only: bool
    verdict: dict[str, Any] | None
    epoch_agreement: dict[str, Any] | None

    @property
    def is_clean(self) -> bool:
        """True only for a diffed report with zero divergences."""
        return self.status == "match"

    @property
    def is_pending(self) -> bool:
        """The worker has not diffed it yet; re-submit to poll."""
        return self.status == "pending"


def scores_hash(epoch: str, scores: list[dict[str, Any]]) -> str:
    """``"0x" + sha256(JCS({epoch, scores}))`` — a plain hash, no domain.

    JCS sorts object keys but preserves array order, so the contractual
    sort by ``user_ref_evt`` is part of the hashed bytes.
    """
    return "0x" + hashlib.sha256(to_canonical_bytes({"epoch": epoch, "scores": scores})).hexdigest()


def validate_parity_report(report: dict[str, Any], *, today: str | None = None) -> None:
    """Enforce §10.3 locally; raise :class:`ParityReportError` on any breach.

    ``today`` (a ``YYYY-MM-DD`` UTC date) enables the closed-epoch check.
    The platform decides this on its own DB clock and is authoritative, so
    this only catches the obvious case — submitting today or the future —
    rather than trying to second-guess a clock we cannot read.
    """
    epoch = report.get("epoch")
    if not isinstance(epoch, str) or not _EPOCH_RE.match(epoch):
        raise ParityReportError(f"epoch must be YYYY-MM-DD, got {epoch!r}")
    if today is not None and epoch >= today:
        raise ParityReportError(
            f"epoch {epoch} is not closed yet (today is {today} UTC); "
            "an epoch can only be reported once the day has ended"
        )

    scores = report.get("scores")
    if not isinstance(scores, list):
        raise ParityReportError("scores must be a list")
    if len(scores) > MAX_PARITY_ROWS:
        raise ParityReportError(f"{len(scores)} rows exceeds the {MAX_PARITY_ROWS}-row cap")

    previous: str | None = None
    for index, row in enumerate(scores):
        if not isinstance(row, dict):
            raise ParityReportError(f"row {index} is not an object")
        user = row.get("user_ref_evt")
        score = row.get("daily_score")
        if not isinstance(user, str) or not _USER_REF_RE.match(user):
            raise ParityReportError(f"row {index} has a malformed user_ref_evt: {user!r}")
        if not isinstance(score, int) or isinstance(score, bool):
            raise ParityReportError(f"row {index} has a non-integer daily_score: {score!r}")
        if previous is not None:
            if user == previous:
                raise ParityReportError(f"user_ref_evt {user} appears more than once")
            if user < previous:
                raise ParityReportError(
                    f"rows must be sorted ascending by user_ref_evt (row {index} breaks the order)"
                )
        previous = user

    declared = report.get("scores_hash")
    recomputed = scores_hash(epoch, scores)
    if declared != recomputed:
        raise ParityReportError(
            f"scores_hash does not match the rows: declared {declared!r}, recomputed {recomputed}"
        )


def submit_parity_report(
    *,
    base_url: str,
    api_token: str,
    report: dict[str, Any],
    chain_network: str,
    platform_instance_id: str,
    http: httpx.Client,
    today: str | None = None,
) -> ParityVerdict:
    """Submit (or re-submit, to poll) one epoch's parity report."""
    validate_parity_report(report, today=today)

    response = http.post(
        base_url.rstrip("/") + PARITY_REPORT_PATH,
        json={
            "epoch": report["epoch"],
            "scores": report["scores"],
            "scores_hash": report["scores_hash"],
            "chain_network": chain_network,
            "platform_instance_id": platform_instance_id,
        },
        headers=bearer_auth_headers(
            api_token=api_token,
            chain_network=chain_network,
            platform_instance_id=platform_instance_id,
        ),
    )

    try:
        body: Any = response.json()
    except ValueError:
        body = response.text
    if response.status_code not in (200, 201) or is_error_envelope(body):
        raise ParityReportError(
            f"parity report refused: {describe_error_body(body, status_code=response.status_code)}",
            status_code=response.status_code,
            error_code=_error_code_of(body),
        )
    if not isinstance(body, dict):
        raise ParityReportError("parity response is not an object")
    data = unwrap_success_envelope(body)
    if not isinstance(data, dict) or "report_id" not in data:
        raise ParityReportError("parity response missing report_id")

    return ParityVerdict(
        report_id=str(data["report_id"]),
        epoch=str(data.get("epoch", report["epoch"])),
        status=str(data.get("status", "pending")),
        scores_received=int(data.get("scores_received", len(report["scores"]))),
        advisory_only=bool(data.get("advisory_only", True)),
        verdict=data["verdict"] if isinstance(data.get("verdict"), dict) else None,
        epoch_agreement=(
            data["epoch_agreement"] if isinstance(data.get("epoch_agreement"), dict) else None
        ),
    )


def _error_code_of(body: Any) -> str | None:
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            code: str = error["code"]
            return code
    return None


__all__ = [
    "MAX_PARITY_ROWS",
    "PARITY_REPORT_PATH",
    "ParityReportError",
    "ParityVerdict",
    "scores_hash",
    "submit_parity_report",
    "validate_parity_report",
]
