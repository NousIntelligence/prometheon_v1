"""Unit tests for ``prometheon.chain.metagraph``."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from prometheon.chain.metagraph import MetagraphView

pytestmark = pytest.mark.unit


SS58_A = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
SS58_B = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"


class TestMetagraphView:
    def test_constructs_with_consistent_indices(self) -> None:
        view = MetagraphView(
            block_number=100,
            hotkeys_by_uid={1: SS58_A, 2: SS58_B},
            uids_by_hotkey={SS58_A: 1, SS58_B: 2},
        )
        assert view.block_number == 100
        assert view.is_registered(SS58_A)
        assert view.uid_for(SS58_A) == 1

    def test_empty_view_constructs(self) -> None:
        view = MetagraphView(block_number=0)
        assert view.block_number == 0
        assert view.hotkeys_by_uid == {}

    def test_is_registered_returns_false_for_unknown(self) -> None:
        view = MetagraphView(
            block_number=0,
            hotkeys_by_uid={1: SS58_A},
            uids_by_hotkey={SS58_A: 1},
        )
        assert not view.is_registered(SS58_B)
        assert view.uid_for(SS58_B) is None

    def test_index_size_mismatch_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must be inverses"):
            MetagraphView(
                block_number=0,
                hotkeys_by_uid={1: SS58_A, 2: SS58_B},
                uids_by_hotkey={SS58_A: 1},
            )

    def test_inconsistent_mapping_rejected(self) -> None:
        with pytest.raises(ValidationError, match="index inconsistency"):
            MetagraphView(
                block_number=0,
                hotkeys_by_uid={1: SS58_A},
                uids_by_hotkey={SS58_A: 2},  # mismatched UID
            )

    def test_negative_block_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MetagraphView(block_number=-1)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MetagraphView(  # type: ignore[call-arg]
                block_number=0,
                surprise="x",
            )
