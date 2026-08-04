"""``prometheon validator run`` — start the validator runtime.

Loads the TOML config, builds the platform client, connects to the
subtensor, detects SDK capabilities, instantiates :class:`ValidatorRunner`,
and either runs a single cycle (``--once``) or loops forever sleeping
between iterations.

Loop control:

- ``--once``     exits after a single cycle (useful for cron-style
                 schedulers and integration tests).
- ``--cycles``   exits after N cycles.
- otherwise the command loops until interrupted, sleeping the
  configured ``weight_submission_check_interval_minutes`` between
  attempts.
"""

from __future__ import annotations

import contextlib
import tempfile
import time
from pathlib import Path
from typing import Any

import click
import httpx

from prometheon.chain.subtensor import (
    connect as connect_subtensor,
)
from prometheon.chain.subtensor import (
    detect_capabilities,
    read_hyperparameters,
    read_subnet_owner_hotkey,
    submit_set_weights,
    sync_metagraph_view,
)
from prometheon.chain.uids import resolve_plan_targets
from prometheon.chain.wallet import get_hotkey_keypair, load_wallet
from prometheon.chain.weights import to_u16_chain_vector
from prometheon.cli._common import echo_info, echo_success, read_api_token_or_exit
from prometheon.cli.ingest_cmd import build_backfill_config
from prometheon.cli.renderer import render_error
from prometheon.events.backfill import BackfillClient
from prometheon.identity.errors import IdentityError
from prometheon.identity.roles import Role
from prometheon.platform.client import BitFanClient
from prometheon.platform.errors import PlatformError
from prometheon.security.signatures import SignatureError
from prometheon.validator.attestor import DigestAttestor
from prometheon.validator.config import (
    ValidatorConfig,
    WeightSource,
    load_validator_config,
)
from prometheon.validator.runner import ValidatorRunner


class _SubtensorAdapter:
    """Thin adapter exposing the runner's expected method set.

    Wraps the module-level helpers in :mod:`prometheon.chain.subtensor`
    so the runner can call ``sync_metagraph``, ``read_hyperparameters``,
    and ``submit_set_weights`` without knowing about the SDK shape.
    """

    def __init__(self, subtensor: object, wallet: object) -> None:
        self._subtensor = subtensor
        self._wallet = wallet

    def sync_metagraph(self, netuid: int) -> object:
        return sync_metagraph_view(self._subtensor, netuid=netuid)

    def read_hyperparameters(self, netuid: int) -> object:
        return read_hyperparameters(self._subtensor, netuid=netuid)

    def read_subnet_owner_hotkey(self, netuid: int) -> str:
        return read_subnet_owner_hotkey(self._subtensor, netuid=netuid)

    def submit_set_weights(
        self,
        *,
        netuid: int,
        vector: object,
        version_key: int,
        mechid: int | None,
    ) -> str | None:
        return submit_set_weights(
            self._subtensor,
            wallet=self._wallet,
            netuid=netuid,
            vector=vector,  # type: ignore[arg-type]
            version_key=version_key,
            mechid=mechid,
        )


@click.group(name="validator")
def validator() -> None:
    """Validator runtime sub-commands."""


@validator.command(name="run")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to the TOML validator configuration file.",
)
@click.option(
    "--state-directory",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path(".validator-state"),
    show_default=True,
    help="Directory for the persisted state file and event log.",
)
@click.option("--once", is_flag=True, help="Run a single cycle and exit.")
@click.option(
    "--cycles",
    type=int,
    default=0,
    help="Run N cycles and exit; 0 means loop until interrupted.",
)
@click.pass_context
def run(
    ctx: click.Context,
    config_path: Path,
    state_directory: Path,
    once: bool,
    cycles: int,
) -> None:
    """Start the validator runtime against the given configuration."""
    verbose: bool = bool(ctx.obj.get("verbose", False)) if ctx.obj else False
    config = load_validator_config(config_path)
    echo_info(
        f"loaded config: network={config.chain.network.value}, "
        f"netuid={config.chain.netuid}, mode={config.validator.mode.value}"
    )

    api_token = read_api_token_or_exit(env_var=config.platform.api_token_env, explicit=None)
    wallet = load_wallet(name=config.wallet.name, hotkey_name=config.wallet.hotkey)
    keypair = get_hotkey_keypair(wallet)
    echo_info(f"validator hotkey: {keypair.ss58_address}")

    subtensor = connect_subtensor(config.chain.network)
    capabilities = detect_capabilities()
    echo_info(
        f"SDK detected: bittensor={capabilities.sdk_version}, "
        f"supports_mechid={capabilities.supports_mechid}"
    )

    with contextlib.ExitStack() as stack:
        attestor: DigestAttestor | None = None
        if config.validator.attest_digests:
            # The runner is the only long-running process holding an
            # unlocked hotkey, so this is where a countersignature can be
            # produced without an operator present. The HTTP client lives
            # as long as the loop does.
            http = stack.enter_context(
                httpx.Client(timeout=config.platform.request_timeout_seconds)
            )
            attestor = DigestAttestor(
                client=BackfillClient(build_backfill_config(config, api_token=api_token), http),
                keypair=keypair,
                state_directory=state_directory,
                submit=config.validator.submit_attestations,
            )
        _run_with_clients(
            config=config,
            api_token=api_token,
            keypair=keypair,
            wallet=wallet,
            subtensor=subtensor,
            capabilities=capabilities,
            state_directory=state_directory,
            attestor=attestor,
            once=once,
            cycles=cycles,
            verbose=verbose,
        )


def _run_with_clients(
    *,
    config: ValidatorConfig,
    api_token: str,
    keypair: Any,
    wallet: Any,
    subtensor: Any,
    capabilities: Any,
    state_directory: Path,
    attestor: DigestAttestor | None,
    once: bool,
    cycles: int,
    verbose: bool,
) -> None:
    """Open the platform client and drive the cycle loop."""
    with BitFanClient(
        base_url=config.platform.base_url,
        api_token=api_token,
        platform_instance_id=config.platform.platform_instance_id,
        chain_network=config.chain.network,
        netuid=config.chain.netuid,
        validator_keypair=keypair,
        role=Role.VALIDATOR,
        timeout_seconds=config.platform.request_timeout_seconds,
    ) as platform_client:
        runner = ValidatorRunner(
            config=config,
            platform_client=platform_client,
            subtensor=_SubtensorAdapter(subtensor, wallet),  # type: ignore[arg-type]
            wallet_hotkey=keypair,
            capabilities=capabilities,
            state_directory=state_directory,
            attestor=attestor,
        )
        _run_loop(runner, config=config, once=once, cycles=cycles, verbose=verbose)
    echo_success("validator runner exited cleanly")


@validator.command(name="compare-weights")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validator TOML config.",
)
def compare_weights(config_path: Path) -> None:
    """Run both weight paths on one cycle and diff the u16 vectors.

    Record-level parity (``ingest score --snapshot-json``) compares miner
    records. This is the runner-level equivalent, and it is the one that
    proves a flip is safe: it compares what would actually be submitted,
    after eligibility, ranking, largest-remainder allocation and UID
    resolution — steps where two identical record sets can still diverge
    (a UID that moved, a tie broken differently, a burn slice that
    differs because the two paths source burn differently).

    Submits nothing. Exit 3 means the vectors differ.
    """
    config = load_validator_config(config_path)
    api_token = read_api_token_or_exit(env_var=config.platform.api_token_env, explicit=None)
    wallet = load_wallet(name=config.wallet.name, hotkey_name=config.wallet.hotkey)
    keypair = get_hotkey_keypair(wallet)
    subtensor = connect_subtensor(config.chain.network)
    adapter = _SubtensorAdapter(subtensor, wallet)

    # One metagraph for both paths: comparing against two different chain
    # reads would attribute UID churn to the weight source.
    metagraph = adapter.sync_metagraph(config.chain.netuid)

    with BitFanClient(
        base_url=config.platform.base_url,
        api_token=api_token,
        platform_instance_id=config.platform.platform_instance_id,
        chain_network=config.chain.network,
        netuid=config.chain.netuid,
        validator_keypair=keypair,
        role=Role.VALIDATOR,
        timeout_seconds=config.platform.request_timeout_seconds,
    ) as platform_client:
        vectors: dict[str, dict[int, int]] = {}
        for source in (WeightSource.EVENTS, WeightSource.SNAPSHOT):
            probe = ValidatorRunner(
                config=config.model_copy(
                    update={
                        "validator": config.validator.model_copy(
                            update={"weight_source": source, "dry_run": True}
                        )
                    }
                ),
                platform_client=platform_client,
                subtensor=adapter,  # type: ignore[arg-type]
                wallet_hotkey=keypair,
                capabilities=detect_capabilities(),
                state_directory=Path(tempfile.mkdtemp(prefix="prometheon-compare-")),
            )
            plan = probe.build_plan(metagraph=metagraph)  # type: ignore[arg-type]
            targets = resolve_plan_targets(plan, metagraph=metagraph)  # type: ignore[arg-type]
            vector = to_u16_chain_vector(targets)
            vectors[source.value] = dict(zip(vector.uids, vector.weights, strict=True))
            echo_info(
                f"{source.value}: {len(vector.uids)} targets "
                f"(plan {plan.status}, id {plan.snapshot_id})"
            )

    events = vectors["events"]
    snapshot = vectors["snapshot"]
    if events == snapshot:
        echo_success(f"weight vectors identical across both paths ({len(events)} UIDs)")
        return

    click.echo("VECTOR MISMATCH between weight sources", err=True)
    for uid in sorted(set(events) | set(snapshot)):
        ours = events.get(uid)
        theirs = snapshot.get(uid)
        if ours != theirs:
            click.echo(f"  uid {uid}: events={ours} snapshot={theirs}", err=True)
    raise click.exceptions.Exit(3)


def _run_loop(
    runner: ValidatorRunner,
    *,
    config: ValidatorConfig,
    once: bool,
    cycles: int,
    verbose: bool,
) -> None:
    """Drive the runner with a sleep cadence between cycles.

    ``--once`` and ``--cycles`` short-circuit the loop; otherwise we
    sleep ``config.scheduler.weight_submission_check_interval_minutes``
    between cycles. Errors raised by the runner are routed through the
    CLI renderer when they belong to the catalogued families so the
    operator sees the same structured remediation block they would for
    a one-shot command, prefixed with the cycle index for log
    correlation.
    """
    iteration = 0
    last_cycle_failed = False
    interval_seconds = config.scheduler.weight_submission_check_interval_minutes * 60
    while True:
        iteration += 1
        echo_info(f"cycle {iteration} starting")
        try:
            result = runner.run_once()
            last_cycle_failed = False
            echo_info(
                f"cycle {iteration} result: status={result.plan.status}, "
                f"submitted={result.submitted}, extrinsic={result.extrinsic_hash}"
            )
        except (PlatformError, IdentityError, SignatureError) as exc:
            # The runner has already persisted the failure via
            # _safe_failure_summary; here we surface the rendered block
            # so the operator sees the remediation inline.
            click.echo(f"cycle {iteration} failed:", err=True)
            click.echo(render_error(exc, verbose=verbose), err=True, nl=False)
            last_cycle_failed = True
        except Exception as exc:
            click.echo(f"cycle {iteration} failed: {exc}", err=True)
            last_cycle_failed = True

        if once or (cycles > 0 and iteration >= cycles):
            # A bounded run is what supervisors and cron drive, so its exit
            # status has to carry the outcome. Exiting 0 after a failed
            # cycle makes the fail-closed path invisible to exactly the
            # things watching for it.
            if last_cycle_failed:
                raise click.exceptions.Exit(1)
            return
        time.sleep(interval_seconds)


__all__ = ["validator"]
