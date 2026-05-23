"""Validator runtime orchestrator.

Composes the security primitives, identity verifier, platform client,
snapshot signature verifier, mechanism engine, chain adapter, and local
state into a single end-to-end cycle.

A full cycle is:

1. Refresh the platform snapshot (aggregate single response or detailed
   manifest + streamed pages).
2. Verify the Ed25519 platform signature and every records / page hash.
3. Sync the metagraph fresh from the chain.
4. Build the engine inputs: normalised miner records,
   :class:`MetagraphView`, :class:`Phase1Policy` (with burn values from
   the signed snapshot).
5. Run :func:`compute_phase1_weight_plan`.
6. For ready plans: run the pre-submission policy gate, re-resolve UIDs,
   convert to u16, submit via the chain adapter.
7. Persist updated :class:`ValidatorState` and append an NDJSON event.

The runner is structured as a class so tests can inject:

- A fake :class:`prometheon.platform.client.BitFanClient`
- A fake subtensor object (with ``metagraph``, ``set_weights`` etc.)
- A fake :class:`prometheon.chain.weights.WeightSubmissionStrategy`
- A custom clock

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
from prometheon.identity.roles import ChainNetwork
from prometheon.mechanisms.phase1_growth.engine import (
    WeightPlan,
    compute_phase1_weight_plan,
)
from prometheon.mechanisms.phase1_growth.policy import Phase1Policy
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord
from prometheon.platform.client import BitFanClient
from prometheon.platform.endpoints import LATEST, SnapshotMode
from prometheon.platform.schemas import AggregateSnapshot, DetailedManifest
from prometheon.platform.signing import (
    DetailedStreamingAccumulator,
    TrustedKeyMap,
    verify_aggregate_snapshot,
    verify_detailed_manifest,
)
from prometheon.validator.config import ValidatorConfig
from prometheon.validator.report import hotkey_fingerprint, report_event
from prometheon.validator.state import (
    DEFAULT_STATE_DIR,
    ValidatorState,
    read_state,
    write_state,
)


class RunnerError(Exception):
    """Base exception for runner orchestration failures.

    The runner catches more specific errors from each layer and rewraps
    them as :class:`RunnerError` only when the layer's exception type
    would be unhelpful at the top level. Most concrete errors propagate
    unchanged so operators see precise diagnostics.
    """

    code: str = "validator.runner_error"


class SubtensorProtocol(Protocol):
    """Minimal interface the runner needs from the subtensor adapter.

    Implemented by the real :class:`prometheon.chain.subtensor` helpers
    wrapped behind a small façade; tests substitute a fake.
    """

    def sync_metagraph(self, netuid: int) -> MetagraphView: ...
    def read_hyperparameters(self, netuid: int) -> ChainHyperparameters: ...
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
            code = getattr(exc, "code", exc.__class__.__name__)
            self._persist_failure(code=code, message=str(exc))
            report_event(
                event_type="cycle_failed",
                state_directory=self._state_directory,
                code=code,
                message=str(exc),
            )
            raise

    # -----------------------------------------------------------------
    # Cycle steps
    # -----------------------------------------------------------------

    def _run_cycle(self) -> CycleResult:
        records, snapshot_id, activity_date = self._fetch_and_verify_snapshot()
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

        policy = Phase1Policy(
            burn_hotkey=self._signed_burn_hotkey(records, snapshot_id),
            manual_burn_rate_ppm=self._signed_burn_rate_ppm(),
        )
        plan = compute_phase1_weight_plan(
            records,
            metagraph=metagraph,
            policy=policy,
            chain_network=ChainNetwork(self._config.chain.network),
            platform_instance_id=self._config.platform.platform_instance_id,
            netuid=self._config.chain.netuid,
            snapshot_id=snapshot_id,
            activity_date=activity_date,
        )

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

    def _signed_burn_hotkey(self, records: list[MinerRecord], snapshot_id: str) -> str:
        """Return the burn hotkey lifted from the most recent signed snapshot."""
        return self._burn_hotkey_signed

    def _signed_burn_rate_ppm(self) -> int:
        """Return the burn rate lifted from the most recent signed snapshot."""
        return self._burn_rate_ppm_signed

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
        updated = previous.with_update(
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
    "hotkey_fingerprint",
    "read_api_token",
]
