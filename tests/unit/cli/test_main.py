"""Unit tests for the CLI entry point's exit-code and error boundary.

``main()`` runs Click with ``standalone_mode=False``, which changes how a
deliberate ``click.exceptions.Exit`` behaves: Click *returns* its code
instead of raising it. The entry point therefore has to translate that
return into the process exit status, and these tests pin it — the
shadow-parity mismatch signal (``ingest score --snapshot-json`` → 3) and
the completeness alarm (``ingest check-day`` → 3) are read by automation,
so a silently swallowed code reports success on a failed comparison.
"""

from __future__ import annotations

from collections.abc import Iterator

import click
import pytest

from prometheon.cli.main import cli, main

pytestmark = pytest.mark.unit

PROBE = "_exit-probe"


@pytest.fixture
def exit_probe() -> Iterator[None]:
    """Attach a command that exits with a caller-chosen code."""

    @click.command(name=PROBE)
    @click.option("--code", type=int, required=True)
    def probe(code: int) -> None:
        click.echo("probe ran")
        if code:
            raise click.exceptions.Exit(code)

    cli.add_command(probe)
    try:
        yield
    finally:
        cli.commands.pop(PROBE, None)


class TestExitCodes:
    @pytest.mark.usefixtures("exit_probe")
    @pytest.mark.parametrize("code", [1, 2, 3, 130])
    def test_explicit_exit_becomes_the_process_status(self, code: int) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main([PROBE, "--code", str(code)])
        assert excinfo.value.code == code

    @pytest.mark.usefixtures("exit_probe")
    def test_zero_exit_is_success(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([PROBE, "--code", "0"]) == 0
        assert "probe ran" in capsys.readouterr().out

    def test_usage_error_keeps_click_status(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["definitely-not-a-command"])
        assert excinfo.value.code == 2

    def test_help_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--help"]) == 0
        assert "Prometheon command-line interface" in capsys.readouterr().out
