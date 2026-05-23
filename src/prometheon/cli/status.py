"""``prometheon status`` — print local validator state.

Operator-facing diagnostic that reads the persisted state file under
``.validator-state/state.json`` (or a custom directory) and prints a
human-readable summary. Used in monitoring scripts and to confirm the
runner is making forward progress between cycles.
"""

from __future__ import annotations

from pathlib import Path

import click

from prometheon.validator.state import read_state


@click.command(name="status")
@click.option(
    "--state-directory",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path(".validator-state"),
    show_default=True,
    help="Directory holding the persisted state file.",
)
def status(state_directory: Path) -> None:
    """Print the most recent validator state, if any.

    Exit code 0 indicates a state file was found and printed. Exit code
    2 indicates the directory is empty (no cycle has run yet).
    """
    persisted = read_state(directory=state_directory)
    if persisted is None:
        click.echo(
            f"no validator state at {state_directory}; the runner has not completed a cycle yet."
        )
        raise click.exceptions.Exit(2)

    click.echo(f"  network              : {persisted.chain_network}")
    click.echo(f"  platform_instance_id : {persisted.platform_instance_id}")
    click.echo(f"  netuid               : {persisted.netuid}")
    click.echo(f"  validator_hotkey     : {persisted.validator_hotkey}")
    click.echo(f"  mode                 : {persisted.mode}")
    click.echo(f"  last_snapshot_id     : {persisted.last_accepted_snapshot_id}")
    click.echo(f"  last_metagraph_block : {persisted.last_metagraph_block}")
    click.echo(f"  last_submit_status   : {persisted.last_submit_status}")
    click.echo(f"  last_extrinsic_hash  : {persisted.last_extrinsic_hash}")
    click.echo(f"  last_error           : {persisted.last_error}")
    click.echo(f"  updated_at           : {persisted.updated_at}")


__all__ = ["status"]
