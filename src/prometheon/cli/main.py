"""Root Click command group for the ``prometheon`` CLI.

This module wires the individual command implementations into a single
entry point. ``pyproject.toml`` registers ``prometheon.cli.main:main`` as
the ``prometheon`` console script.

The group itself is intentionally thin — argument parsing, wallet
loading, platform-client construction, and the operational work all
live in the sub-command modules.
"""

from __future__ import annotations

import logging
import sys

import click

from prometheon.cli.recover_hotkey import recover_hotkey
from prometheon.cli.rotate_hotkey import rotate_hotkey
from prometheon.cli.status import status
from prometheon.cli.validator_run import validator
from prometheon.cli.verify_miner import verify_miner
from prometheon.cli.verify_validator import verify_validator
from prometheon.version import __version__


@click.group(name="prometheon", context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    default="INFO",
    show_default=True,
    help="Python logging level for the CLI.",
)
def cli(log_level: str) -> None:
    """Prometheon command-line interface.

    The ``prometheon`` binary groups every operator-facing command:
    identity verification, hotkey rotation and recovery, the validator
    runtime, and local status inspection.

    Run ``prometheon <command> --help`` for command-specific usage.
    """
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


# Sub-command registration. Each is implemented as a top-level Click
# command in its own module; the group below composes them into one CLI.
cli.add_command(verify_miner)
cli.add_command(verify_validator)
cli.add_command(rotate_hotkey)
cli.add_command(recover_hotkey)
cli.add_command(validator)
cli.add_command(status)


def main() -> None:
    """Entry point declared in ``pyproject.toml`` under ``project.scripts``."""
    cli()


__all__ = ["cli", "main"]
