"""Automatic day-digest attestation on the validator side.

Once a day is sealed the platform publishes a signed digest per family.
This module walks the sealed days a validator has not yet countersigned,
verifies each against the records it actually holds, signs the ones that
match, and keeps the result as local evidence — an append-only
``attestations.ndjson`` beside the state file.

It is driven from the validator runner, which is the only long-running
process holding an unlocked hotkey. Two consequences shape the design:

- **Nothing here may fail a cycle.** Weight submission is the runner's
  job; attestation is bookkeeping alongside it. Every failure mode is
  reported as an outcome, never raised into the cycle.
- **Retry is free.** A day that is not sealed yet, or a platform that is
  briefly unreachable, simply stays pending and is picked up on the next
  cycle. Nothing needs a scheduler or an operator.

Attesting is idempotent: the local log is the dedupe index, so a restart
re-reads what was already signed and does not sign it again.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final, Literal

from bittensor_wallet import Keypair

from prometheon.events.attestation import (
    AttestationError,
    DigestAttestation,
    DigestMismatchError,
    attest_day,
    submit_attestation,
    verify_attestation,
)
from prometheon.events.backfill import (
    BackfillClient,
    BackfillError,
    DigestNotFoundError,
    DigestNotSealedError,
)
from prometheon.events.pipeline import SCORING_WINDOW_DAYS, parse_epoch
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore
from prometheon.validator.state import DEFAULT_STATE_DIR

logger = logging.getLogger(__name__)

ATTESTATIONS_FILE_NAME: Final[str] = "attestations.ndjson"

#: How far back to look for unattested sealed days. The scoring window is
#: the meaningful horizon — those are the days that actually produced
#: weights — and it bounds first-run work to one pass over 14 days.
DEFAULT_LOOKBACK_DAYS: Final[int] = SCORING_WINDOW_DAYS

#: Wall-clock ceiling for one sweep. The runner calls this inside its cycle,
#: so an unbounded sweep delays weight submission: 14 days x 4 families is 56
#: round trips, and against a hanging read API each one costs the full HTTP
#: timeout. The sweep is resumable — an unsigned day simply stays out of the
#: log and is retried next cycle, oldest first — so stopping early costs
#: nothing but time.
DEFAULT_SWEEP_BUDGET_SECONDS: Final[float] = 30.0

OutcomeStatus = Literal[
    "signed", "submitted", "pending_seal", "mismatch", "error", "deferred", "rejected"
]

#: Statuses an operator needs to see. ``rejected`` belongs here because the
#: platform refusing an attestation means our signature or our registration
#: is wrong — neither fixes itself, and neither is retryable.
PROBLEM_STATUSES: Final[tuple[str, ...]] = ("mismatch", "error", "rejected")


@dataclass(frozen=True)
class AttestationOutcome:
    """What happened for one (family, epoch)."""

    key: str
    status: OutcomeStatus
    detail: str | None = None


def attestations_path(directory: Path | str = DEFAULT_STATE_DIR) -> Path:
    """Absolute path to the append-only attestation log."""
    return Path(directory) / ATTESTATIONS_FILE_NAME


def read_attested_keys(directory: Path | str = DEFAULT_STATE_DIR) -> set[str]:
    """The ``family/epoch`` keys already signed, read from the log.

    A malformed line is skipped rather than fatal: the log is evidence,
    and one unreadable line must not stop a validator from attesting the
    rest — or, worse, make it re-sign days it has already covered.
    """
    path = attestations_path(directory)
    if not path.exists():
        return set()
    keys: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            family = row.get("family")
            epoch = row.get("epoch_id")
            if isinstance(family, str) and isinstance(epoch, str):
                keys.add(f"{family}/{epoch}")
    return keys


def is_permanent_rejection(exc: BackfillError) -> bool:
    """True when the platform refused this attestation for good.

    A 4xx other than 429 means the body will never be accepted: the
    signature does not verify, or the hotkey is not a registered validator.
    Re-sending it every cycle would hammer an endpoint that has already
    given its answer. 5xx, 429, and transport failures stay retryable.
    """
    code = exc.status_code
    return code is not None and 400 <= code < 500 and code != 429


def append_attestation(
    attestation: DigestAttestation,
    *,
    directory: Path | str = DEFAULT_STATE_DIR,
    delivered: bool = False,
    rejected: bool = False,
) -> None:
    """Append one attestation to the log, creating the directory if needed.

    ``delivered`` records whether the platform has accepted it. It sits
    outside the signed envelope — like ``version`` — so it changes nothing
    a verifier reconstructs, and a later line for the same day supersedes
    an earlier one.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    row = {**attestation.to_wire(), "delivered": delivered, "rejected": rejected}
    with attestations_path(directory).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def read_undelivered(directory: Path | str = DEFAULT_STATE_DIR) -> list[dict[str, Any]]:
    """Stored attestations the platform has not yet accepted, oldest first.

    The last line written for a ``family/epoch`` wins, so a redelivery
    supersedes the failed attempt. A row without ``delivered`` predates
    delivery tracking and counts as delivered — re-POSTing every historical
    attestation on upgrade would be a surprise, not a fix.
    """
    latest: dict[str, dict[str, Any]] = {}
    path = attestations_path(directory)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            family = row.get("family")
            epoch = row.get("epoch_id")
            if isinstance(family, str) and isinstance(epoch, str):
                latest[f"{family}/{epoch}"] = row
    return [
        row
        for _, row in sorted(latest.items())
        if row.get("delivered") is False and row.get("rejected") is not True
    ]


def sealed_epochs_before(today: str, *, lookback_days: int = DEFAULT_LOOKBACK_DAYS) -> list[str]:
    """Sealed epoch ids, oldest first: the ``lookback_days`` days before ``today``.

    Today is excluded — a day in progress has no digest, by construction.
    """
    end = datetime.strptime(parse_epoch(today), "%Y-%m-%d")
    return [
        (end - timedelta(days=offset)).strftime("%Y-%m-%d")
        for offset in range(lookback_days, 0, -1)
    ]


class DigestAttestor:
    """Signs every sealed day digest that matches the local record set."""

    def __init__(
        self,
        *,
        client: BackfillClient,
        keypair: Keypair,
        state_directory: Path | str = DEFAULT_STATE_DIR,
        submit: bool = False,
        families: tuple[EventFamily, ...] = tuple(EventFamily),
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        budget_seconds: float | None = DEFAULT_SWEEP_BUDGET_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._keypair = keypair
        self._state_directory = Path(state_directory)
        self._submit = submit
        self._families = families
        self._lookback_days = lookback_days
        # ``None`` means no ceiling — for the CLI, where an operator is
        # present and waiting is the point.
        self._budget_seconds = budget_seconds
        self._clock = clock

    def attest_pending(self, *, store: EventStore, today: str) -> list[AttestationOutcome]:
        """Attest every unsigned sealed day, oldest first.

        Returns one outcome per attempted (family, epoch). Days already in
        the log are skipped silently — they are the steady state, and
        reporting them would drown the ones that matter.
        """
        attested = read_attested_keys(self._state_directory)
        outcomes: list[AttestationOutcome] = []
        started = self._clock()

        outcomes.extend(self._redeliver_pending())

        for epoch_id in sealed_epochs_before(today, lookback_days=self._lookback_days):
            for family in self._families:
                key = f"{family.value}/{epoch_id}"
                if key in attested:
                    continue
                if self._out_of_budget(started):
                    # Stop cleanly rather than hold the cycle open. What is
                    # left stays unsigned, so the next sweep resumes here.
                    outcomes.append(
                        AttestationOutcome(
                            key=key,
                            status="deferred",
                            detail=f"sweep budget of {self._budget_seconds}s reached",
                        )
                    )
                    return outcomes
                outcome = self._attest_one(store=store, family=family, epoch_id=epoch_id, key=key)
                outcomes.append(outcome)
                if outcome.status in ("signed", "submitted"):
                    attested.add(key)
        return outcomes

    def _out_of_budget(self, started: float) -> bool:
        return self._budget_seconds is not None and (
            self._clock() - started >= self._budget_seconds
        )

    def _redeliver_pending(self) -> list[AttestationOutcome]:
        """Re-POST attestations signed earlier but never accepted.

        A signature is complete when it is written; delivery is separate and
        can fail on its own. Without this, a submission that failed once was
        never attempted again, because the day was already in the log.
        """
        if not self._submit:
            return []
        outcomes: list[AttestationOutcome] = []
        for row in read_undelivered(self._state_directory):
            key = f"{row.get('family')}/{row.get('epoch_id')}"
            try:
                attestation = verify_attestation(row)
            except AttestationError as exc:
                outcomes.append(AttestationOutcome(key=key, status="error", detail=str(exc)))
                continue
            try:
                submit_attestation(self._client, attestation)
            except Exception as exc:
                outcomes.append(
                    AttestationOutcome(key=key, status="signed", detail=f"not delivered: {exc}")
                )
                continue
            append_attestation(attestation, directory=self._state_directory, delivered=True)
            outcomes.append(AttestationOutcome(key=key, status="submitted"))
        return outcomes

    def _attest_one(
        self, *, store: EventStore, family: EventFamily, epoch_id: str, key: str
    ) -> AttestationOutcome:
        try:
            attestation = attest_day(
                client=self._client,
                store=store,
                family=family,
                epoch_id=epoch_id,
                keypair=self._keypair,
            )
        except DigestNotSealedError:
            # Expected around the rollover: the day has closed but the
            # platform has not sealed it. Next cycle picks it up.
            return AttestationOutcome(key=key, status="pending_seal")
        except DigestMismatchError as exc:
            # Deliberately not signed and deliberately not retried into
            # silence: the records this validator holds are not the ones
            # the platform published a hash for.
            logger.warning("digest attestation refused: %s", exc)
            return AttestationOutcome(key=key, status="mismatch", detail=str(exc))
        except DigestNotFoundError as exc:
            return AttestationOutcome(key=key, status="error", detail=str(exc))
        except Exception as exc:
            # Narrower tuples have already failed here once: DigestVerificationError
            # subclasses RuntimeError, not BackfillError, so an unrecognised
            # platform_key_id used to abort every later day in the window
            # permanently. The specific handlers above still separate
            # pending_seal and mismatch from generic failure.
            return AttestationOutcome(key=key, status="error", detail=str(exc))

        append_attestation(attestation, directory=self._state_directory, delivered=False)

        if not self._submit:
            return AttestationOutcome(key=key, status="signed")
        try:
            submit_attestation(self._client, attestation)
        except BackfillError as exc:
            if is_permanent_rejection(exc):
                # Refused for good. Record it so no later sweep re-sends it,
                # and report it: a rejection means our signature or our
                # registration is wrong, and neither fixes itself.
                append_attestation(
                    attestation, directory=self._state_directory, delivered=False, rejected=True
                )
                return AttestationOutcome(key=key, status="rejected", detail=str(exc))
            return AttestationOutcome(key=key, status="signed", detail=f"not delivered: {exc}")
        except Exception as exc:
            # The signature is already written locally, which is what makes
            # it evidence. Delivery can be retried; the statement stands
            # either way, so this is not an error for the day.
            return AttestationOutcome(key=key, status="signed", detail=f"not delivered: {exc}")
        append_attestation(attestation, directory=self._state_directory, delivered=True)
        return AttestationOutcome(key=key, status="submitted")


def summarize(outcomes: list[AttestationOutcome]) -> dict[str, Any]:
    """Compact per-status counts for the runtime log."""
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    summary: dict[str, Any] = {"counts": counts}
    problems = [o for o in outcomes if o.status in PROBLEM_STATUSES]
    if problems:
        summary["problems"] = [
            {"key": o.key, "status": o.status, "detail": o.detail} for o in problems
        ]
    return summary


def utc_today() -> str:
    """Today's UTC date as an epoch id."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


__all__ = [
    "ATTESTATIONS_FILE_NAME",
    "DEFAULT_LOOKBACK_DAYS",
    "DEFAULT_SWEEP_BUDGET_SECONDS",
    "PROBLEM_STATUSES",
    "AttestationOutcome",
    "DigestAttestor",
    "append_attestation",
    "attestations_path",
    "is_permanent_rejection",
    "read_attested_keys",
    "read_undelivered",
    "sealed_epochs_before",
    "summarize",
    "utc_today",
]
