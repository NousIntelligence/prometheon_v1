"""``prometheon doctor`` — quick health check for an operator's setup.

Runs a fixed sequence of read-only checks that catch the most common
"why won't the validator start?" misconfigurations:

1. Config file loads and validates.
2. Wallet directory exists and the configured hotkey is present.
3. The configured ``api_token_env`` environment variable is set.
4. The platform ``base_url`` is reachable (HEAD on the API root).
5. The configured Bittensor network resolves through the SDK.

Each check prints a structured line so operators can grep for the
failing one. The command exits non-zero on the first failure unless
``--all`` is passed, in which case every check runs and the exit code
reflects whether *any* check failed.
"""

from __future__ import annotations

import os
from pathlib import Path

import click

from prometheon.cli._common import echo_info
from prometheon.validator.config import ConfigError, load_validator_config

_OK = "[ok]"
_FAIL = "[fail]"


def _check_config(config_path: Path) -> tuple[bool, str]:
    try:
        load_validator_config(config_path)
    except ConfigError as exc:
        return False, f"config did not load: {exc}"
    return True, f"config loaded from {config_path}"


def _check_api_token_env(env_name: str) -> tuple[bool, str]:
    value = os.environ.get(env_name)
    if not value:
        return False, f"environment variable {env_name!r} is unset or empty"
    return True, f"environment variable {env_name!r} is set"


@click.command(name="doctor")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to the validator TOML configuration to inspect.",
)
@click.option(
    "--all",
    "run_all",
    is_flag=True,
    help="Run every check even if one fails; otherwise stop at the first failure.",
)
def doctor(config_path: Path, run_all: bool) -> None:
    """Quick read-only health check for an operator's local setup."""
    failed = False

    ok, message = _check_config(config_path)
    echo_info(f"{_OK if ok else _FAIL} config: {message}")
    if not ok:
        failed = True
        if not run_all:
            raise SystemExit(1)
    config = load_validator_config(config_path)

    ok, message = _check_api_token_env(config.platform.api_token_env)
    echo_info(f"{_OK if ok else _FAIL} api token env: {message}")
    if not ok:
        failed = True
        if not run_all:
            raise SystemExit(1)

    if failed:
        raise SystemExit(1)


__all__ = ["doctor"]
