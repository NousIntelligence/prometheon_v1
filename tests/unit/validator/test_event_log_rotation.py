"""The runtime event log must not grow without bound.

A validator appends here every cycle, forever. Unbounded, the file is a
slow disk-full incident on a host whose only job is to keep submitting
weights — and it would surface as a write error mid-cycle rather than as
anything an operator could diagnose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from prometheon.validator.state import append_event, events_path

pytestmark = pytest.mark.unit


class TestEventLogRotation:
    def test_small_log_is_never_rotated(self, tmp_path: Path) -> None:
        for index in range(20):
            append_event({"event_type": "cycle", "n": index}, directory=tmp_path)

        assert events_path(tmp_path).exists()
        assert not events_path(tmp_path).with_suffix(".ndjson.1").exists()
        assert len(events_path(tmp_path).read_text().splitlines()) == 20

    def test_oversized_log_rolls_over_and_keeps_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("prometheon.validator.state.EVENTS_MAX_BYTES", 200)

        for index in range(40):
            append_event({"event_type": "cycle", "n": index, "pad": "x" * 40}, directory=tmp_path)

        live = events_path(tmp_path)
        assert live.exists(), "the live log must exist after rotation"
        assert live.with_suffix(".ndjson.1").exists(), "a rotated generation must be kept"
        # The most recent event is always in the live file.
        assert '"n": 39' in live.read_text()

    def test_generations_are_bounded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rotation must discard the oldest, not accumulate forever."""
        monkeypatch.setattr("prometheon.validator.state.EVENTS_MAX_BYTES", 120)
        monkeypatch.setattr("prometheon.validator.state.EVENTS_KEEP_ROTATIONS", 2)

        for index in range(60):
            append_event({"event_type": "cycle", "n": index, "pad": "y" * 40}, directory=tmp_path)

        rotations = sorted(p.name for p in tmp_path.glob("events.ndjson.*"))
        assert rotations == ["events.ndjson.1", "events.ndjson.2"], rotations

    def test_rotation_preserves_valid_ndjson(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every retained line must still parse — rotation splits, never truncates."""
        import json

        monkeypatch.setattr("prometheon.validator.state.EVENTS_MAX_BYTES", 200)
        for index in range(40):
            append_event({"event_type": "cycle", "n": index, "pad": "z" * 40}, directory=tmp_path)

        for path in [events_path(tmp_path), *tmp_path.glob("events.ndjson.*")]:
            for line in path.read_text().splitlines():
                assert json.loads(line)["event_type"] == "cycle"
