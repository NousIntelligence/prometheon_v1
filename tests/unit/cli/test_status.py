"""``prometheon status`` must explain which inputs produced the weights.

The runner records the event path's provenance — scored epoch,
``scores_hash``, engine version, per-family stream cursors — precisely so
an operator can answer "which data made these weights?" without
re-deriving anything. Printing only the snapshot id would leave that
question unanswerable on the live path, and the validator guide promises
these fields, so this module holds the promise to the code.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from prometheon.cli.status import status
from prometheon.validator.state import ValidatorState, write_state

pytestmark = pytest.mark.unit


def _state(**overrides: object) -> ValidatorState:
    base: dict[str, object] = {
        "chain_network": "test",
        "platform_instance_id": "bitfan-staging",
        "netuid": 481,
        "validator_hotkey": "5DfhGyQdFobKM8NsWvEeAKobikbEwFP6y8kMPuJqU6EfMV8L",
        "mode": "aggregate",
    }
    base.update(overrides)
    return ValidatorState.model_validate(base)


def _run(tmp_path: Path, state: ValidatorState) -> str:
    write_state(state, directory=tmp_path)
    result = CliRunner().invoke(status, ["--state-directory", str(tmp_path)])
    assert result.exit_code == 0, result.output
    return result.output


class TestStatusOutput:
    def test_event_path_shows_its_provenance(self, tmp_path: Path) -> None:
        output = _run(
            tmp_path,
            _state(
                weight_source="events",
                last_scored_epoch="2026-08-03",
                last_scores_hash="0x" + "ab" * 32,
                last_engine_version="scoring-port-r4/2a36285f",
                last_stream_cursors={
                    "activity": 4208,
                    "identity": 10,
                    "group": 325,
                    "exclusion": 7,
                },
            ),
        )
        assert "weight_source        : events" in output
        assert "scored_epoch         : 2026-08-03" in output
        assert "0xabab" in output
        assert "scoring-port-r4/2a36285f" in output
        # Cursors sorted, so two operators comparing output see the same order.
        assert "activity=4208, exclusion=7, group=325, identity=10" in output

    def test_snapshot_fallback_shows_the_snapshot_id_instead(self, tmp_path: Path) -> None:
        output = _run(
            tmp_path,
            _state(weight_source="snapshot", last_accepted_snapshot_id="snap-2026-08-03"),
        )
        assert "weight_source        : snapshot" in output
        assert "last_snapshot_id     : snap-2026-08-03" in output
        assert "scores_hash" not in output

    def test_missing_cursors_do_not_break_the_output(self, tmp_path: Path) -> None:
        """A cycle can fail before cursors are recorded."""
        output = _run(tmp_path, _state(weight_source="events"))
        assert "stream_cursors       : none" in output

    def test_absent_state_exits_two(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(status, ["--state-directory", str(tmp_path / "empty")])
        assert result.exit_code == 2
        assert "has not completed a cycle" in result.output
