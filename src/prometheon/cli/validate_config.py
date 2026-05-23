"""``prometheon validate-config`` — load and validate a validator config.

Read-only: parses the TOML file, runs every check that
:func:`load_validator_config` performs (strict policy guards, locked
constants, snapshot-key map non-empty, etc.), and prints a one-line
summary. Exits non-zero on any validation failure.

Operators use this to verify a config in CI / before deployment
without needing to start the validator runtime, which otherwise also
requires a wallet, an API token, and a reachable subtensor.
"""

from __future__ import annotations

from pathlib import Path

import click

from prometheon.cli._common import echo_info, echo_success
from prometheon.validator.config import ConfigError, load_validator_config


@click.command(name="validate-config")
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def validate_config(config_path: Path) -> None:
    """Load and validate a validator TOML configuration file."""
    try:
        config = load_validator_config(config_path)
    except ConfigError as exc:
        click.echo(f"invalid: {exc}", err=True)
        raise SystemExit(1) from exc

    echo_info(
        f"network={config.chain.network.value} "
        f"netuid={config.chain.netuid} "
        f"mode={config.validator.mode.value} "
        f"snapshot_keys={len(config.platform.snapshot_keys)}"
    )
    echo_success(f"{config_path} is valid")


__all__ = ["validate_config"]
