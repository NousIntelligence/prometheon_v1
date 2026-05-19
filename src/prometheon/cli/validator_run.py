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

import time
from pathlib import Path

import click

from prometheon.chain.subtensor import (
    connect as connect_subtensor,
)
from prometheon.chain.subtensor import (
    detect_capabilities,
    read_hyperparameters,
    submit_set_weights,
    sync_metagraph_view,
)
from prometheon.chain.wallet import get_hotkey_keypair, load_wallet
from prometheon.cli._common import echo_info, echo_success, read_api_token_or_exit
from prometheon.identity.roles import Role
from prometheon.platform.client import BitFanClient
from prometheon.validator.config import load_validator_config
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
def run(config_path: Path, state_directory: Path, once: bool, cycles: int) -> None:
    """Start the validator runtime against the given configuration."""
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
        )
        _run_loop(runner, config=config, once=once, cycles=cycles)
    echo_success("validator runner exited cleanly")


def _run_loop(runner: ValidatorRunner, *, config, once: bool, cycles: int) -> None:  # type: ignore[no-untyped-def]
    """Drive the runner with a sleep cadence between cycles.

    ``--once`` and ``--cycles`` short-circuit the loop; otherwise we
    sleep ``config.scheduler.weight_submission_check_interval_minutes``
    between cycles.
    """
    iteration = 0
    interval_seconds = config.scheduler.weight_submission_check_interval_minutes * 60
    while True:
        iteration += 1
        echo_info(f"cycle {iteration} starting")
        try:
            result = runner.run_once()
            echo_info(
                f"cycle {iteration} result: status={result.plan.status}, "
                f"submitted={result.submitted}, extrinsic={result.extrinsic_hash}"
            )
        except Exception as exc:
            # The runner has already persisted the failure; here we log
            # at the CLI level so operators see the error inline.
            click.echo(f"cycle {iteration} failed: {exc}", err=True)

        if once or (cycles > 0 and iteration >= cycles):
            return
        time.sleep(interval_seconds)


__all__ = ["validator"]
