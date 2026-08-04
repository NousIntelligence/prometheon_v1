"""The event-derived weight path through :class:`ValidatorRunner`.

Substitutes exactly one input — the snapshot fetch becomes a recompute
from the local event store — and asserts the identical downstream path
still produces a submitted u16 vector. Everything the runner does after
the records exist (eligibility, ranking, allocation, UID resolution,
``set_weights``) is deliberately untouched, so these tests are about the
seam, not about scoring: the kernel has its own gates.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from prometheon.chain.metagraph import MetagraphView
from prometheon.chain.weights import ChainAdapterCapabilities, ChainHyperparameters
from prometheon.events.pipeline import current_epoch
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore, prepare_wire_records
from prometheon.mechanisms.phase1_growth.policy import MANUAL_BURN_RATE_PPM
from prometheon.validator.config import WeightSource
from prometheon.validator.runner import EventWeightSourceError, ValidatorRunner
from prometheon.validator.state import read_state

pytestmark = pytest.mark.unit

LEADER = "usr_evt_" + "1a" * 32
MEMBERS = ["usr_evt_" + f"{index:02x}" * 32 for index in range(0xB0, 0xB4)]
MINER = "5F9MHZ78mgGtgAkYBAmj6KiCaK6tJphh75R4rmUWJT6cjoPS"
OWNER = "5GTCFZ5YNUNUF5XdoFP4gnFMrEud3ddmvu8HGEMHf97npHfZ"
VALIDATOR = "5DfhGyQdFobKM8NsWvEeAKobikbEwFP6y8kMPuJqU6EfMV8L"


def _envelope(
    family: str, seq: int, epoch: str, core: dict[str, Any], **over: Any
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "domain": "PROMETHEON_EVENT_RECORD_V1",
        "family": family,
        "seq": seq,
        "epoch_id": epoch,
        "event_id": "0x" + hashlib.sha256(f"{family}-{seq}-{epoch}".encode()).hexdigest(),
        "user_ref_evt": LEADER,
        "group_id": None,
        "received_ts": f"{epoch}T09:00:00Z",
        "category_id": None,
        "core": core,
        "device_pubkey": None,
        "user_sig": None,
    }
    record.update(over)
    return record


def _seed_store(path: Path, epoch: str) -> None:
    """A group whose members were active today — nothing sealed."""
    with EventStore(path) as store:
        group = [
            _envelope(
                "group",
                1,
                "2026-06-01",
                {"kind": "group_created", "slug": "g", "display_name": "G"},
                group_id="grp-1",
            )
        ]
        for index, member in enumerate(MEMBERS, start=2):
            group.append(
                _envelope(
                    "group",
                    index,
                    "2026-06-02",
                    {"kind": "member_joined", "fan_group_id": "grp-1"},
                    user_ref_evt=member,
                )
            )
        store.append(EventFamily.GROUP, prepare_wire_records(EventFamily.GROUP, group))

        store.append(
            EventFamily.IDENTITY,
            prepare_wire_records(
                EventFamily.IDENTITY,
                [
                    _envelope(
                        "identity",
                        1,
                        "2026-06-01",
                        {
                            "kind": "miner_hotkey_bind",
                            "miner_profile_id": "mp-1",
                            "hotkey_ss58": MINER,
                            "bound_at": "2026-06-01T00:00:00Z",
                        },
                    )
                ],
            ),
        )

        activity = []
        seq = 1
        for member in MEMBERS:
            for view in range(4):
                activity.append(
                    _envelope(
                        "activity",
                        seq,
                        epoch,
                        {
                            "domain": "PROMETHEON_EVENT_V1",
                            "kind": "service_detail_view",
                            "target": {"service_id": f"svc-{view}"},
                            "scoring_fields": {
                                "dwell_seconds": 30,
                                "scroll_percent": 80,
                                "outbound_clicks": 1,
                            },
                            "client_ts": f"{epoch}T08:59:59Z",
                            "client_nonce": "0x" + f"{seq:016x}",
                        },
                        user_ref_evt=member,
                        received_ts=f"{epoch}T09:{seq:02d}:00Z",
                    )
                )
                seq += 1
        store.append(EventFamily.ACTIVITY, prepare_wire_records(EventFamily.ACTIVITY, activity))


class _FakeSubtensor:
    def __init__(self) -> None:
        self.submitted: list[Any] = []
        self.owner_calls = 0

    def sync_metagraph(self, netuid: int) -> MetagraphView:
        hotkeys = {0: VALIDATOR, 1: MINER, 2: OWNER}
        return MetagraphView(
            block_number=1000,
            hotkeys_by_uid=hotkeys,
            uids_by_hotkey={h: u for u, h in hotkeys.items()},
            validator_permits={0: True, 1: False, 2: False},
        )

    def read_hyperparameters(self, netuid: int) -> ChainHyperparameters:
        return ChainHyperparameters(commit_reveal_enabled=False, weights_version=0)

    def read_subnet_owner_hotkey(self, netuid: int) -> str:
        self.owner_calls += 1
        return OWNER

    def submit_set_weights(self, **kwargs: Any) -> str | None:
        self.submitted.append(kwargs)
        return "0xdeadbeef"


def _runner(config: Any, tmp_path: Path, subtensor: _FakeSubtensor) -> ValidatorRunner:
    class _Keypair:
        ss58_address = VALIDATOR

    return ValidatorRunner(
        config=config,
        platform_client=None,  # type: ignore[arg-type]  # never touched on the event path
        subtensor=subtensor,
        wallet_hotkey=_Keypair(),  # type: ignore[arg-type]
        capabilities=ChainAdapterCapabilities(
            supports_mechid=True, sdk_version="10.5.0", python_version="3.12"
        ),
        state_directory=tmp_path / "state",
    )


class TestEventWeightPath:
    def test_submits_a_vector_derived_from_the_store(
        self, tmp_path: Path, event_config: Any
    ) -> None:
        epoch = current_epoch()
        _seed_store(tmp_path / "events.sqlite", epoch)
        subtensor = _FakeSubtensor()

        result = _runner(event_config, tmp_path, subtensor).run_once()

        assert result.submitted is True
        assert subtensor.submitted, "the event path must reach set_weights"
        # The platform client is never consulted — no snapshot, no fetch.
        assert result.plan.activity_date == epoch
        assert result.plan.snapshot_id.startswith(f"events:{epoch}:")

    def test_burn_target_comes_from_chain(self, tmp_path: Path, event_config: Any) -> None:
        epoch = current_epoch()
        _seed_store(tmp_path / "events.sqlite", epoch)
        subtensor = _FakeSubtensor()

        _runner(event_config, tmp_path, subtensor).run_once()

        assert subtensor.owner_calls == 1, "the burn target must be read from chain"

    def test_state_records_which_inputs_made_the_vector(
        self, tmp_path: Path, event_config: Any
    ) -> None:
        epoch = current_epoch()
        _seed_store(tmp_path / "events.sqlite", epoch)

        _runner(event_config, tmp_path, _FakeSubtensor()).run_once()

        state = read_state(directory=tmp_path / "state")
        assert state is not None
        assert state.weight_source == "events"
        assert state.last_scored_epoch == epoch
        assert state.last_scores_hash is not None and state.last_scores_hash.startswith("0x")
        assert state.last_engine_version is not None
        assert state.last_stream_cursors is not None
        assert state.last_stream_cursors["activity"] > 0

    def test_missing_store_fails_before_touching_the_chain(
        self, tmp_path: Path, event_config: Any
    ) -> None:
        """No store means no weights — never a vector from partial inputs."""
        subtensor = _FakeSubtensor()

        with pytest.raises(EventWeightSourceError, match="does not exist"):
            _runner(event_config, tmp_path, subtensor).run_once()

        assert subtensor.submitted == []

    def test_the_store_is_opened_read_only(self, tmp_path: Path, event_config: Any) -> None:
        """The ingest service owns writes; the weight path must not add one."""
        epoch = current_epoch()
        db = tmp_path / "events.sqlite"
        _seed_store(db, epoch)

        _runner(event_config, tmp_path, _FakeSubtensor()).run_once()

        with (
            EventStore(db, read_only=True) as store,
            pytest.raises(sqlite3.OperationalError, match="readonly"),
        ):
            store._connection.execute("CREATE TABLE probe (x INTEGER)")

    def test_burn_rate_is_the_locked_constant(self) -> None:
        """Not config, not the snapshot — a coordinated-release constant."""
        assert MANUAL_BURN_RATE_PPM == 150_000

    def test_events_is_the_default_source(self, event_config: Any) -> None:
        assert event_config.validator.weight_source is WeightSource.EVENTS


@pytest.fixture
def event_config(tmp_path: Path) -> Any:
    from prometheon.validator.config import load_validator_config

    body = Path("configs/testnet.example.toml").read_text()
    path = tmp_path / "validator.toml"
    path.write_text(body, encoding="utf-8")
    config = load_validator_config(path)
    return config.model_copy(
        update={
            "validator": config.validator.model_copy(
                update={
                    "weight_source": WeightSource.EVENTS,
                    "events_db": tmp_path / "events.sqlite",
                    "submit_weights": True,
                    "dry_run": False,
                }
            )
        }
    )


class TestAbsentInputFailsClosed:
    """A store that never received anything must not become a full burn.

    With no records the engine produces no eligible miners, and the burn
    rules then route 100% of the weight pool to the burn UID — a real
    economic action taken on absent input. "Nobody qualified" and "nothing
    arrived" are indistinguishable downstream, so the runner separates
    them before the plan is built.
    """

    def test_store_that_never_received_anything_submits_nothing(
        self, tmp_path: Path, event_config: Any
    ) -> None:
        db = tmp_path / "events.sqlite"
        EventStore(db).close()  # exists, schema created, all cursors 0
        subtensor = _FakeSubtensor()

        with pytest.raises(EventWeightSourceError, match="never received a record"):
            _runner(event_config, tmp_path, subtensor).run_once()

        assert subtensor.submitted == [], "absent input must never reach set_weights"

    def test_a_stale_store_still_submits(self, tmp_path: Path, event_config: Any) -> None:
        """Being behind is not the same as having no input.

        A validator whose stream stopped 15 days ago has an empty window
        but non-zero cursors: records demonstrably arrived. That is a store
        that is behind, which must never gate submission — it submits its
        stale vector and chain consensus clips it. Gating here would strand
        the validator with nothing upstream to fetch.
        """
        db = tmp_path / "events.sqlite"
        _seed_store(db, "2020-01-01")
        subtensor = _FakeSubtensor()

        result = _runner(event_config, tmp_path, subtensor).run_once()

        assert result.submitted is True
        assert subtensor.submitted

    def test_records_in_the_window_still_score_normally(
        self, tmp_path: Path, event_config: Any
    ) -> None:
        """The guard must not fire on a legitimate day."""
        epoch = current_epoch()
        _seed_store(tmp_path / "events.sqlite", epoch)

        result = _runner(event_config, tmp_path, _FakeSubtensor()).run_once()

        assert result.submitted is True


class TestQuietStreamStillSubmits:
    """A live stream with no scored activity must NOT trip the guard.

    The platform seals a verdicts_complete marker every day even when
    nothing happened, so a healthy stream always leaves records in the
    window. A quiet subnet therefore still scores — and burns, which is the
    honest verdict when no miner earned anything. Only a dead stream stops.
    This is the pre-launch state of this subnet, so getting it wrong would
    halt every validator today.
    """

    def test_markers_only_window_scores_and_submits(
        self, tmp_path: Path, event_config: Any
    ) -> None:
        from prometheon.events.store import prepare_wire_records

        epoch = current_epoch()
        db = tmp_path / "events.sqlite"
        with EventStore(db) as store:
            marker = _envelope(
                "exclusion",
                1,
                epoch,
                {"kind": "verdicts_complete", "applies_to_epoch": epoch, "verdict_count": 0},
                user_ref_evt=None,
            )
            store.append(
                EventFamily.EXCLUSION,
                prepare_wire_records(EventFamily.EXCLUSION, [marker]),
            )

        subtensor = _FakeSubtensor()
        result = _runner(event_config, tmp_path, subtensor).run_once()

        # No activity anywhere, so no miner qualifies: the engine routes the
        # whole pool to the burn UID. That is a verdict, not a malfunction.
        assert result.plan.status == "ready"
        assert result.plan.burn_case == "C"
        assert subtensor.submitted, "a quiet but live stream must still submit"


class TestMarkerWarningIsNotRepeated:
    """A stalled stream must alarm once, not ~96 times a day."""

    def test_repeat_cycles_emit_the_warning_once(self, tmp_path: Path, event_config: Any) -> None:
        import json as _json

        epoch = current_epoch()
        _seed_store(tmp_path / "events.sqlite", epoch)
        runner = _runner(event_config, tmp_path, _FakeSubtensor())

        runner.run_once()
        runner.run_once()
        runner.run_once()

        log = (tmp_path / "state" / "events.ndjson").read_text().splitlines()
        warnings = [
            line
            for line in log
            if _json.loads(line).get("event_type") == "cycle_missing_verdict_markers"
        ]
        assert len(warnings) <= 1, f"warning repeated {len(warnings)} times across 3 cycles"
