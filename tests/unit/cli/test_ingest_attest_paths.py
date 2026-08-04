"""``ingest attest`` must open the store its own config names.

The command requires ``--config``, which already carries ``[validator]
events_db``. An independent default for ``--db`` meant the documented
invocation — config only, no ``--db`` — opened a relative path that does not
exist on a validator whose store lives anywhere else, and died on a raw
sqlite error rather than doing the work.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from bittensor_wallet import Keypair
from click.testing import CliRunner

from prometheon.cli import ingest_cmd
from prometheon.events.backfill import DigestNotSealedError
from prometheon.events.store import EventStore

pytestmark = pytest.mark.unit

#: The shipped example, so this test tracks the real config shape rather
#: than a hand-rolled subset that can drift away from it.
EXAMPLE_CONFIG = Path("configs/localnet.example.toml").resolve()


def _config_naming(store_path: Path, target: Path) -> Path:
    """Write the example config with ``events_db`` pointed at ``store_path``."""
    text = EXAMPLE_CONFIG.read_text()
    text = re.sub(r"^events_db = .*$", f'events_db = "{store_path}"', text, flags=re.M)
    target.write_text(text)
    return target


class _StubClient:
    """Stands in for the read-API client; every day is simply unsealed."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def fetch_digest(self, family: Any, epoch_id: str) -> Any:
        raise DigestNotSealedError("not sealed", seal_deadline=None, now=None)


@pytest.fixture
def wired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A real store at a non-default path, plus a config naming it."""
    store_path = tmp_path / "custom" / "events.sqlite"
    store_path.parent.mkdir(parents=True)
    EventStore(store_path).close()

    config_path = _config_naming(store_path, tmp_path / "validator.toml")

    # Neither a wallet on disk nor a network is part of what this pins.
    monkeypatch.setattr(
        ingest_cmd, "load_hotkey_or_exit", lambda **_: Keypair.create_from_uri("//AttestPathTest")
    )
    monkeypatch.setattr(ingest_cmd, "BackfillClient", _StubClient)
    monkeypatch.setenv("PROMETHEON_VALIDATOR_API_TOKEN", "unit-token")
    return config_path


def _invoke(config_path: Path, tmp_path: Path, *extra: str) -> Any:
    return CliRunner().invoke(
        ingest_cmd.attest,
        [
            "--config",
            str(config_path),
            "--state-directory",
            str(tmp_path / "state"),
            "--wallet-name",
            "validator",
            "--wallet-hotkey",
            "default",
            *extra,
        ],
    )


def test_db_defaults_to_the_configs_events_db(wired: Path, tmp_path: Path) -> None:
    result = _invoke(wired, tmp_path)
    assert result.exit_code == 0, result.output
    # Reached the sweep, so the store opened: every day reports unsealed.
    assert "not sealed yet" in result.output


def test_explicit_db_flag_still_overrides_the_config(wired: Path, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere" / "events.sqlite"
    other.parent.mkdir(parents=True)
    EventStore(other).close()

    result = _invoke(wired, tmp_path, "--db", str(other))
    assert result.exit_code == 0, result.output


def test_a_store_path_that_does_not_exist_is_reported(wired: Path, tmp_path: Path) -> None:
    """The failure an operator should see when they point at nothing."""
    result = _invoke(wired, tmp_path, "--db", str(tmp_path / "nope" / "events.sqlite"))
    assert result.exit_code != 0
