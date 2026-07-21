"""Store-to-digest contract gate.

Appends the ingest-push fixture batch through the production store and
recomputes the day digest from what the store returns — proving the
storage layer preserves the exact bytes the digest contract hashes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore, prepare_wire_records

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def test_stored_batch_reproduces_the_day_digest(tmp_path: Path) -> None:
    batch = _load(FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json")
    envelope = batch["envelope"]
    digest_env = _load(FIXTURES / "event-record" / "03-day-digest" / "envelope.json")
    expected_hash = digest_env["records_hash"]

    with EventStore(tmp_path / "events.sqlite") as store:
        # The fixture batch starts at seq 4207; seed the cursor as if the
        # stream up to 4206 was already consumed and pruned.
        store._connection.execute(
            "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
            (EventFamily.ACTIVITY.value, envelope["from_seq"] - 1),
        )
        store._connection.commit()

        prepared = prepare_wire_records(EventFamily.ACTIVITY, envelope["records"])
        store.append(EventFamily.ACTIVITY, prepared)

        stored_bytes = store.canonical_bytes_for_epoch(EventFamily.ACTIVITY, digest_env["epoch_id"])
        assert (
            store.record_count_for_epoch(EventFamily.ACTIVITY, digest_env["epoch_id"])
            == digest_env["record_count"]
        )

    recomputed = hashlib.sha256(b"".join(stored_bytes)).hexdigest()
    assert "0x" + recomputed == expected_hash
