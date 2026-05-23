"""Unit tests for ``prometheon.validator.state``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prometheon.validator.state import (
    EVENTS_FILE_NAME,
    STATE_FILE_NAME,
    ValidatorState,
    append_event,
    events_path,
    read_state,
    state_path,
    write_state,
)

pytestmark = pytest.mark.unit


def _state(**overrides: object) -> ValidatorState:
    defaults: dict[str, object] = {
        "chain_network": "finney",
        "platform_instance_id": "bitfan-production",
        "netuid": 123,
        "validator_hotkey": "5G_test_hotkey_value",
        "mode": "aggregate",
    }
    defaults.update(overrides)
    return ValidatorState.model_validate(defaults)


class TestValidatorState:
    def test_constructs_with_defaults(self) -> None:
        state = _state()
        assert state.schema_version == "1.0"
        assert state.last_extrinsic_hash is None

    def test_with_update_returns_new_instance(self) -> None:
        original = _state(last_submit_status="success")
        updated = original.with_update(last_submit_status="failed")
        assert original.last_submit_status == "success"
        assert updated.last_submit_status == "failed"
        # Timestamp gets refreshed.
        assert updated.updated_at >= original.updated_at


class TestWriteAndRead:
    def test_round_trip(self, tmp_path: Path) -> None:
        state = _state(
            last_accepted_snapshot_id="phase1:2026-05-18:aggregate",
            last_metagraph_block=1234567,
        )
        write_state(state, directory=tmp_path)
        loaded = read_state(directory=tmp_path)
        assert loaded is not None
        assert loaded.last_accepted_snapshot_id == "phase1:2026-05-18:aggregate"
        assert loaded.last_metagraph_block == 1234567

    def test_read_returns_none_when_missing(self, tmp_path: Path) -> None:
        assert read_state(directory=tmp_path) is None

    def test_write_is_atomic_no_tmp_files_left(self, tmp_path: Path) -> None:
        write_state(_state(), directory=tmp_path)
        # Only the final state.json should exist; no .state-* temp files.
        remaining = sorted(p.name for p in tmp_path.iterdir())
        assert STATE_FILE_NAME in remaining
        assert all(not name.startswith(".state-") for name in remaining)

    def test_overwrites_existing_state(self, tmp_path: Path) -> None:
        write_state(_state(last_submit_status="success"), directory=tmp_path)
        write_state(_state(last_submit_status="failed"), directory=tmp_path)
        loaded = read_state(directory=tmp_path)
        assert loaded is not None
        assert loaded.last_submit_status == "failed"

    def test_state_path_uses_correct_filename(self, tmp_path: Path) -> None:
        assert state_path(tmp_path) == tmp_path / STATE_FILE_NAME

    def test_persisted_json_is_human_readable(self, tmp_path: Path) -> None:
        write_state(_state(), directory=tmp_path)
        raw = (tmp_path / STATE_FILE_NAME).read_text(encoding="utf-8")
        # Sorted keys + indent=2 means we can re-parse and check shape.
        decoded = json.loads(raw)
        assert decoded["chain_network"] == "finney"


class TestAppendEvent:
    def test_event_is_appended_with_timestamp(self, tmp_path: Path) -> None:
        append_event({"event_type": "snapshot_accepted"}, directory=tmp_path)
        contents = (tmp_path / EVENTS_FILE_NAME).read_text(encoding="utf-8")
        line = contents.strip()
        decoded = json.loads(line)
        assert decoded["event_type"] == "snapshot_accepted"
        assert decoded["timestamp"].endswith("Z")

    def test_multiple_appends_one_per_line(self, tmp_path: Path) -> None:
        append_event({"event_type": "a"}, directory=tmp_path)
        append_event({"event_type": "b"}, directory=tmp_path)
        lines = (tmp_path / EVENTS_FILE_NAME).read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["event_type"] == "a"
        assert json.loads(lines[1])["event_type"] == "b"

    def test_supplied_timestamp_is_preserved(self, tmp_path: Path) -> None:
        append_event({"event_type": "x", "timestamp": "2026-05-20T00:00:00Z"}, directory=tmp_path)
        contents = (tmp_path / EVENTS_FILE_NAME).read_text(encoding="utf-8").strip()
        decoded = json.loads(contents)
        assert decoded["timestamp"] == "2026-05-20T00:00:00Z"

    def test_events_path_uses_correct_filename(self, tmp_path: Path) -> None:
        assert events_path(tmp_path) == tmp_path / EVENTS_FILE_NAME
