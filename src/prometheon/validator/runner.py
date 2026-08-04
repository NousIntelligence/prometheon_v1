"""Validator runtime orchestrator.

Composes the event-stream scorer, mechanism engine, chain adapter and
local state into a single end-to-end cycle.

A full cycle is:

1. Sync the metagraph fresh from the chain.
2. Source this cycle's miner records (:meth:`ValidatorRunner.build_plan`):

   - ``weight_source = "events"`` (**the live path, default**) —
     recompute from the validator's own event store over the rolling
     window ``[now - 14 days, now]``, whose last bucket is the
     in-progress day. Rankings therefore move with activity rather than
     stepping once a day, and every cycle rescores.
   - ``weight_source = "snapshot"`` — the pull-based predecessor,
     retained as an incident fallback: fetch, verify the Ed25519
     signature and every records / page hash, and use the result.

3. Resolve the burn policy. On the event path the target is the subnet
   owner hotkey read from chain and the rate is the locked Phase 1
   constant; on the fallback both come from the signed snapshot header.
4. Run :func:`compute_phase1_weight_plan`.
5. For ready plans: run the pre-submission policy gate, re-resolve UIDs,
   convert to u16, submit via the chain adapter.
6. Persist updated :class:`ValidatorState` and append an NDJSON event.

Two properties of the live path worth stating explicitly, because both
are deliberate:

- **No completeness gate.** The validator scores whatever its own store
  holds and submits. Two validators whose stores differ will submit
  different vectors, and chain consensus resolves that. Refusing to
  submit in order to protect a determinism property would cost dividends
  and eventually the registration — a worse failure than a temporarily
  divergent vector. Day digests and ``ingest check-day`` are operator
  diagnostics, never a precondition here.
- **The store is opened read-only.** The ingest service is its only
  writer; the weight path must never become a second one.

The runner is structured as a class so tests can inject:

- A fake :class:`prometheon.platform.client.BitFanClient` (fallback only)
- A fake subtensor object satisfying :class:`SubtensorProtocol`
- A fake :class:`prometheon.chain.weights.WeightSubmissionStrategy`

All external dependencies pass through the constructor or the
:meth:`run_once` arguments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from bittensor_wallet import Keypair

from prometheon.chain.metagraph import MetagraphView
from prometheon.chain.uids import resolve_plan_targets
from prometheon.chain.weights import (
    ChainAdapterCapabilities,
    ChainHyperparameters,
    ChainWeightVector,
    assert_phase1_compatible,
    to_u16_chain_vector,
)
from prometheon.events.pipeline import (
    ENGINE_VERSION,
    EventStreamScores,
    build_parity_report,
    current_epoch,
    score_event_stream,
)
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore
from prometheon.identity.roles import ChainNetwork
from prometheon.mechanisms.phase1_growth.engine import (
    WeightPlan,
    compute_phase1_weight_plan,
)
from prometheon.mechanisms.phase1_growth.policy import (
    MANUAL_BURN_RATE_PPM,
    Phase1Policy,
)
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord
from prometheon.platform.client import BitFanClient
from prometheon.platform.endpoints import LATEST, SnapshotMode
from prometheon.platform.errors import PlatformError
from prometheon.platform.schemas import AggregateSnapshot, DetailedManifest
from prometheon.platform.signing import (
    DetailedStreamingAccumulator,
    TrustedKeyMap,
    verify_aggregate_snapshot,
    verify_detailed_manifest,
)
from prometheon.validator.config import ValidatorConfig, WeightSource
from prometheon.validator.report import hotkey_fingerprint, report_event
from prometheon.validator.state import (
    DEFAULT_STATE_DIR,
    ValidatorState,
    read_state,
    write_state,
)

# Cap on the message field that lands in state.json / events.ndjson. The
# detail string is server-provided when the error is a PlatformError, so
# we strip C0 control characters (which would otherwise corrupt the log
# stream or the operator-facing trailer) and length-bound it.
_PERSIST_MESSAGE_CAP: int = 300


def _safe_failure_summary(exc: BaseException) -> tuple[str, str]:
    """Return a ``(code, message)`` pair safe to persist to disk.

    For :class:`PlatformError` we never serialise the raw ``details`` dict
    or ``str(exc)`` — only the wire code plus a control-char-stripped,
    length-bound ``detail`` string. The ``details`` dict has already been
    privacy-sanitised at parse time but is intentionally kept off-disk so
    the long-running validator's state file does not accumulate
    server-controlled typed payloads.

    For non-platform exceptions we fall back to the class name and
    ``str(exc)`` — these are subnet-internal errors whose messages we
    author.
    """
    if isinstance(exc, PlatformError):
        code = exc.code or exc.__class__.__name__
        raw_detail = exc.detail or ""
        clean = "".join(ch for ch in raw_detail if ord(ch) >= 0x20 or ch == "\t")
        if len(clean) > _PERSIST_MESSAGE_CAP:
            clean = clean[: _PERSIST_MESSAGE_CAP - 3] + "..."
        message = clean or f"platform returned {code}"
        return code, message
    code = getattr(exc, "code", exc.__class__.__name__)
    return code, str(exc)


class RunnerError(Exception):
    """Base exception for runner orchestration failures.

    The runner catches more specific errors from each layer and rewraps
    them as :class:`RunnerError` only when the layer's exception type
    would be unhelpful at the top level. Most concrete errors propagate
    unchanged so operators see precise diagnostics.
    """

    code: str = "validator.runner_error"


class EventWeightSourceError(RunnerError):
    """The local event store cannot produce weights this cycle.

    Raised before any chain interaction, so a cycle that cannot score
    submits nothing rather than submitting from partial inputs.
    """

    code: str = "validator.event_weight_source"


class SubtensorProtocol(Protocol):
    """Minimal interface the runner needs from the subtensor adapter.

    Implemented by the real :class:`prometheon.chain.subtensor` helpers
    wrapped behind a small façade; tests substitute a fake.
    """

    def sync_metagraph(self, netuid: int) -> MetagraphView: ...
    def read_hyperparameters(self, netuid: int) -> ChainHyperparameters: ...
    def read_subnet_owner_hotkey(self, netuid: int) -> str: ...
    def submit_set_weights(
        self,
        *,
        netuid: int,
        vector: ChainWeightVector,
        version_key: int,
        mechid: int | None,
    ) -> str | None: ...


@dataclass(frozen=True)
class CycleResult:
    """The structured outcome of one :meth:`ValidatorRunner.run_once` call."""

    plan: WeightPlan
    submitted: bool
    extrinsic_hash: str | None
    failure_code: str | None = None


class ValidatorRunner:
    """End-to-end validator orchestrator for one cycle at a time.

    The runner does not loop on its own — that's the caller's job
    (either the CLI driver or the test harness). One call to
    :meth:`run_once` performs one full snapshot-verify-engine-submit
    cycle.
    """

    def __init__(
        self,
        *,
        config: ValidatorConfig,
        platform_client: BitFanClient,
        subtensor: SubtensorProtocol,
        wallet_hotkey: Keypair,
        capabilities: ChainAdapterCapabilities,
        state_directory: Path | str = DEFAULT_STATE_DIR,
    ) -> None:
        self._config = config
        self._client = platform_client
        self._subtensor = subtensor
        self._wallet_hotkey = wallet_hotkey
        self._capabilities = capabilities
        self._state_directory = Path(state_directory)
        self._last_event_scores: EventStreamScores | None = None
        self._last_event_cursors: dict[str, int] = {}
        self._last_scores_hash: str | None = None

    # -----------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------

    def run_once(self) -> CycleResult:
        """Execute one full cycle and return the result.

        Catches every layer-specific exception, records it in the
        persisted state + NDJSON log, and re-raises after writing.
        Operators can either tail the events file or wrap calls in their
        own retry loop.
        """
        try:
            return self._run_cycle()
        except Exception as exc:
            code, message = _safe_failure_summary(exc)
            self._persist_failure(code=code, message=message)
            report_event(
                event_type="cycle_failed",
                state_directory=self._state_directory,
                code=code,
                message=message,
            )
            raise

    # -----------------------------------------------------------------
    # Cycle steps
    # -----------------------------------------------------------------

    def build_plan(self, *, metagraph: MetagraphView) -> WeightPlan:
        """Produce this cycle's weight plan without touching the chain.

        The plan-building half of a cycle — source the miner records,
        resolve the burn policy, run the engine — split out so the A/B
        harness can compare the two weight sources through the *same*
        code the runner submits from. A harness that re-implemented this
        would prove only that the copy agrees with itself.

        Takes the metagraph as an argument rather than syncing its own, so
        a caller comparing two sources holds one chain read across both
        and cannot attribute UID churn to the weight source.
        """
        if self._config.validator.weight_source is WeightSource.EVENTS:
            records, snapshot_id, activity_date = self._score_event_stream()
        else:
            records, snapshot_id, activity_date = self._fetch_and_verify_snapshot()
        return compute_phase1_weight_plan(
            records,
            metagraph=metagraph,
            policy=self._burn_policy(),
            chain_network=ChainNetwork(self._config.chain.network),
            platform_instance_id=self._config.platform.platform_instance_id,
            netuid=self._config.chain.netuid,
            snapshot_id=snapshot_id,
            activity_date=activity_date,
        )

    def _run_cycle(self) -> CycleResult:
        metagraph = self._subtensor.sync_metagraph(self._config.chain.netuid)
        hyperparams = self._subtensor.read_hyperparameters(self._config.chain.netuid)

        # Pre-submission policy gate: commit-reveal, mechid, version key.
        assert_phase1_compatible(
            hyperparams=hyperparams,
            capabilities=self._capabilities,
            configured_version_key=self._config.chain.version_key,
            fail_on_weights_version_mismatch=self._config.chain.fail_on_weights_version_mismatch,
            allow_legacy_sdk_without_mechid=self._config.chain.allow_legacy_sdk_without_mechid,
        )

        plan = self.build_plan(metagraph=metagraph)
        snapshot_id = plan.snapshot_id

        if plan.status != "ready":
            report_event(
                event_type="cycle_no_valid_weight_target",
                state_directory=self._state_directory,
                snapshot_id=snapshot_id,
                burn_case=plan.burn_case,
                failure_reason=plan.failure_reason,
            )
            self._persist_success(plan=plan, extrinsic_hash=None, submitted=False)
            return CycleResult(
                plan=plan,
                submitted=False,
                extrinsic_hash=None,
                failure_code=plan.failure_reason,
            )

        if self._config.validator.dry_run or not self._config.validator.submit_weights:
            report_event(
                event_type="cycle_dry_run",
                state_directory=self._state_directory,
                snapshot_id=snapshot_id,
                burn_case=plan.burn_case,
                target_count=len(plan.items),
            )
            self._persist_success(plan=plan, extrinsic_hash=None, submitted=False)
            return CycleResult(plan=plan, submitted=False, extrinsic_hash=None)

        targets = resolve_plan_targets(plan, metagraph=metagraph)
        vector = to_u16_chain_vector(targets)
        mechid = 0 if self._capabilities.supports_mechid else None
        extrinsic_hash = self._subtensor.submit_set_weights(
            netuid=self._config.chain.netuid,
            vector=vector,
            version_key=self._config.chain.version_key,
            mechid=mechid,
        )
        report_event(
            event_type="cycle_submitted",
            state_directory=self._state_directory,
            snapshot_id=snapshot_id,
            burn_case=plan.burn_case,
            target_count=len(plan.items),
            extrinsic_hash=extrinsic_hash,
        )
        self._persist_success(plan=plan, extrinsic_hash=extrinsic_hash, submitted=True)
        return CycleResult(plan=plan, submitted=True, extrinsic_hash=extrinsic_hash)

    # -----------------------------------------------------------------
    # Snapshot fetch + verify
    # -----------------------------------------------------------------

    def _fetch_and_verify_snapshot(self) -> tuple[list[MinerRecord], str, str]:
        """Return ``(miner_records, snapshot_id, activity_date)``.

        Implements aggregate vs detailed mode switching, signature
        verification, and (for detailed) the streaming accumulator.
        """
        trusted_keys: TrustedKeyMap = self._config.platform.snapshot_keys
        activity_date = self._config.validator.activity_date or LATEST

        if self._config.validator.mode is SnapshotMode.AGGREGATE:
            snapshot: AggregateSnapshot = self._client.get_aggregate_snapshot(activity_date)
            verify_aggregate_snapshot(snapshot, trusted_keys=trusted_keys)
            self._burn_hotkey_signed = snapshot.burn_hotkey
            self._burn_rate_ppm_signed = snapshot.manual_burn_rate_ppm
            records: list[MinerRecord] = list(snapshot.miners)
            return records, snapshot.snapshot_id, snapshot.activity_date

        # Detailed mode.
        manifest: DetailedManifest = self._client.get_detailed_manifest(activity_date)
        verify_detailed_manifest(manifest, trusted_keys=trusted_keys)
        accumulator = DetailedStreamingAccumulator(manifest)
        for page_index in range(manifest.page_count):
            page = self._client.get_detailed_page(manifest.activity_date, page_index)
            accumulator.consume_page(page)
        self._burn_hotkey_signed = manifest.burn_hotkey
        self._burn_rate_ppm_signed = manifest.manual_burn_rate_ppm
        return accumulator.finalize(), manifest.snapshot_id, manifest.activity_date

    # -----------------------------------------------------------------
    # Event-stream scoring (the live weight path)
    # -----------------------------------------------------------------

    def _score_event_stream(self) -> tuple[list[MinerRecord], str, str]:
        """Recompute miner records from the local event store.

        Substitutes exactly one call — the snapshot fetch — and hands the
        identical ``MinerRecord`` list to the identical downstream path:
        eligibility, ranking, largest-remainder allocation, UID resolution
        and the ``set_weights`` adapter are untouched.

        Scores the **live rolling window** ending on the in-progress day,
        so rankings move with activity rather than stepping once a day.
        The store is opened **read-only**: the ingest service is its
        writer, and the weight path must never become a second one.

        There is deliberately no completeness gate. The validator scores
        what its own store holds and submits; two validators whose stores
        differ will submit different vectors, and chain consensus resolves
        that. Digest verification stays an operator diagnostic
        (``ingest check-day``), never a precondition for setting weights —
        a validator that stops submitting to protect a determinism
        property loses dividends and eventually its registration, which is
        a worse failure than a temporarily divergent vector.
        """
        epoch = current_epoch()
        db_path = self._config.validator.events_db
        if not db_path.exists():
            raise EventWeightSourceError(
                f"event store {db_path} does not exist; run 'prometheon ingest serve' "
                "to receive the stream before scoring from it"
            )

        with EventStore(db_path, read_only=True) as store:
            scores = score_event_stream(store, scoring_date=epoch, live=True)
            cursors = {family.value: store.last_stored_seq(family) for family in EventFamily}

        report = build_parity_report(scores)
        self._last_event_scores = scores
        self._last_event_cursors = cursors
        self._last_scores_hash = str(report["scores_hash"])

        report_event(
            event_type="cycle_scored_from_events",
            state_directory=self._state_directory,
            epoch=epoch,
            scores_hash=self._last_scores_hash,
            engine_version=ENGINE_VERSION,
            miner_count=len(scores.miner_records),
            scored_users=len(report["scores"]),
            cursors=cursors,
        )
        # The plan's identity fields carry the inputs, not a fake snapshot
        # id — anything that reads state must be able to tell the two
        # sources apart at a glance.
        return scores.miner_records, f"events:{epoch}:{self._last_scores_hash[2:18]}", epoch

    def _burn_policy(self) -> Phase1Policy:
        """Burn target + rate for this cycle.

        On the event path the stream carries no policy fields, so the
        target is the subnet owner hotkey read from chain and the rate is
        the locked Phase 1 constant. Both are identical for every
        validator by construction. On the snapshot fallback they keep
        coming from the signed snapshot header.
        """
        if self._config.validator.weight_source is WeightSource.EVENTS:
            return Phase1Policy(
                burn_hotkey=self._subtensor.read_subnet_owner_hotkey(self._config.chain.netuid),
                manual_burn_rate_ppm=MANUAL_BURN_RATE_PPM,
            )
        return Phase1Policy(
            burn_hotkey=self._burn_hotkey_signed,
            manual_burn_rate_ppm=self._burn_rate_ppm_signed,
        )

    # -----------------------------------------------------------------
    # State persistence
    # -----------------------------------------------------------------

    def _persist_success(
        self,
        *,
        plan: WeightPlan,
        extrinsic_hash: str | None,
        submitted: bool,
    ) -> None:
        previous = read_state(directory=self._state_directory) or self._initial_state()
        # Event mode records the inputs that produced the vector, so
        # `prometheon status` can answer "which data made these weights?"
        # without re-deriving anything.
        event_fields: dict[str, object] = {
            "weight_source": self._config.validator.weight_source.value
        }
        if self._config.validator.weight_source is WeightSource.EVENTS:
            event_fields.update(
                last_scored_epoch=self._last_event_scores.scoring_date
                if self._last_event_scores
                else None,
                last_scores_hash=self._last_scores_hash,
                last_engine_version=ENGINE_VERSION,
                last_stream_cursors=dict(self._last_event_cursors) or None,
            )
        updated = previous.with_update(
            **event_fields,
            last_accepted_snapshot_id=plan.snapshot_id,
            last_weight_plan_hash=None,
            last_metagraph_block=plan.metagraph_block,
            last_extrinsic_hash=extrinsic_hash,
            last_submit_status="success" if submitted else "skipped",
            last_error=None,
        )
        write_state(updated, directory=self._state_directory)

    def _persist_failure(self, *, code: str, message: str) -> None:
        previous = read_state(directory=self._state_directory) or self._initial_state()
        updated = previous.with_update(
            last_submit_status="failed",
            last_error=f"{code}: {message}",
        )
        write_state(updated, directory=self._state_directory)

    def _initial_state(self) -> ValidatorState:
        return ValidatorState(
            chain_network=self._config.chain.network.value,
            platform_instance_id=self._config.platform.platform_instance_id,
            netuid=self._config.chain.netuid,
            validator_hotkey=self._wallet_hotkey.ss58_address,
            mode=self._config.validator.mode.value,
        )

    # Late-bound attributes populated by the snapshot step; declared
    # here for type clarity.
    _burn_hotkey_signed: str = ""
    _burn_rate_ppm_signed: int = 0


def read_api_token(config: ValidatorConfig) -> str:
    """Read the validator API token from the configured environment variable."""
    env_name = config.platform.api_token_env
    value = os.environ.get(env_name)
    if not value:
        raise RunnerError(
            f"validator API token environment variable {env_name!r} is unset or empty"
        )
    return value


__all__ = [
    "CycleResult",
    "RunnerError",
    "SubtensorProtocol",
    "ValidatorRunner",
    "_safe_failure_summary",
    "hotkey_fingerprint",
    "read_api_token",
]
