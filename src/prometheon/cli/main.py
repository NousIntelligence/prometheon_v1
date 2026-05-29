"""Root Click command group for the ``prometheon`` CLI.

This module wires the individual command implementations into a single
entry point. ``pyproject.toml`` registers ``prometheon.cli.main:main`` as
the ``prometheon`` console script.

The group itself is intentionally thin — argument parsing, wallet
loading, platform-client construction, and the operational work all
live in the sub-command modules. What lives *here*, beyond command
registration, is the single exception-handling boundary that turns any
:class:`prometheon.platform.errors.PlatformError`,
:class:`prometheon.identity.errors.IdentityError`, or
:class:`prometheon.security.signatures.SignatureError` raised by a
sub-command into a structured operator-facing block via
:func:`prometheon.cli.renderer.render_error`. Click's
``standalone_mode=False`` is required so that ``cli()`` re-raises those
errors instead of converting them to ``UsageError`` tracebacks.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import click

from prometheon.cli.recover_hotkey import recover_hotkey
from prometheon.cli.renderer import render_error
from prometheon.cli.rotate_hotkey import rotate_hotkey
from prometheon.cli.status import status
from prometheon.cli.validator_run import validator
from prometheon.cli.verify_miner import verify_miner
from prometheon.cli.verify_validator import verify_validator
from prometheon.identity.errors import IdentityError
from prometheon.platform.errors import PlatformError
from prometheon.security.signatures import SignatureError
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
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help=(
        "Include a sanitised diagnostic trailer in any error output. Independent of --log-level."
    ),
)
@click.pass_context
def cli(ctx: click.Context, log_level: str, verbose: bool) -> None:
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
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


# Sub-command registration. Each is implemented as a top-level Click
# command in its own module; the group below composes them into one CLI.
cli.add_command(verify_miner)
cli.add_command(verify_validator)
cli.add_command(rotate_hotkey)
cli.add_command(recover_hotkey)
cli.add_command(validator)
cli.add_command(status)


def _is_verbose_argv(argv: list[str]) -> bool:
    """Detect ``--verbose`` / ``-v`` on the command line.

    Used by :func:`main` to know how to render an exception caught from
    ``cli()`` — by the time the exception reaches the handler the Click
    context (and the ``ctx.obj`` carrying the parsed flag) is gone, so
    we re-parse argv at the top level. The two short / long forms are
    distinctive enough that no sub-command currently shares them; if
    that changes, route them through the same Click option on each
    sub-command.
    """
    for token in argv:
        if token in ("--verbose", "-v"):
            return True
        if token == "--":  # noqa: S105 — literal argv terminator, not a credential
            break
    return False


def _dispatch_to_renderer(exc: BaseException, *, verbose: bool) -> int:
    """Print the renderer's output to stderr and return the exit code."""
    sys.stderr.write(render_error(exc, verbose=verbose))
    return 1


def main(argv: list[str] | None = None) -> Any:
    """Entry point declared in ``pyproject.toml`` under ``project.scripts``.

    Runs ``cli()`` with ``standalone_mode=False`` so that exceptions
    raised by sub-commands surface here instead of being converted to
    generic Click tracebacks. Catches the three subnet-internal error
    families (platform, identity, signature) and routes them through
    :func:`prometheon.cli.renderer.render_error`. Click's own
    :class:`click.exceptions.ClickException` family (usage errors, bad
    parameters) keeps its native rendering so the help-text affordances
    work unchanged.
    """
    raw_argv = argv if argv is not None else sys.argv[1:]
    verbose = _is_verbose_argv(raw_argv)
    try:
        cli.main(args=raw_argv, standalone_mode=False)
    except (PlatformError, IdentityError, SignatureError) as exc:
        sys.exit(_dispatch_to_renderer(exc, verbose=verbose))
    except click.exceptions.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except click.exceptions.Abort:
        sys.stderr.write("Aborted!\n")
        sys.exit(130)
    except KeyboardInterrupt:
        sys.stderr.write("Aborted!\n")
        sys.exit(130)
    return 0


__all__ = ["cli", "main"]
