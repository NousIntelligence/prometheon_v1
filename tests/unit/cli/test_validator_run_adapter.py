"""The concrete subtensor adapter must satisfy the runner's port.

`_SubtensorAdapter` is what `validator run` actually hands the runner,
while every runner unit test injects a fake. That gap let the event
weight path ship needing `read_subnet_owner_hotkey` on the port while the
real adapter lacked it — a fake that implements the protocol proves
nothing about the object used in production. This module closes it
structurally, so a future port method cannot be added without the adapter
following.
"""

from __future__ import annotations

import inspect

import pytest

from prometheon.cli.validator_run import _SubtensorAdapter
from prometheon.validator.runner import SubtensorProtocol

pytestmark = pytest.mark.unit


def _protocol_methods() -> set[str]:
    return {
        name
        for name in dir(SubtensorProtocol)
        if not name.startswith("_") and callable(getattr(SubtensorProtocol, name, None))
    }


class TestAdapterSatisfiesThePort:
    def test_implements_every_protocol_method(self) -> None:
        missing = sorted(
            name for name in _protocol_methods() if not hasattr(_SubtensorAdapter, name)
        )
        assert not missing, f"_SubtensorAdapter is missing port methods: {missing}"

    def test_read_subnet_owner_hotkey_is_wired(self) -> None:
        """The event path's burn target comes through this call."""
        assert hasattr(_SubtensorAdapter, "read_subnet_owner_hotkey")

    def test_signatures_accept_netuid(self) -> None:
        for name in ("sync_metagraph", "read_hyperparameters", "read_subnet_owner_hotkey"):
            signature = inspect.signature(getattr(_SubtensorAdapter, name))
            assert "netuid" in signature.parameters, f"{name} must take netuid"

    def test_delegates_to_the_chain_helper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def fake(subtensor: object, *, netuid: int) -> str:
            seen["netuid"] = netuid
            return "5GTCFZ5YNUNUF5XdoFP4gnFMrEud3ddmvu8HGEMHf97npHfZ"

        monkeypatch.setattr("prometheon.cli.validator_run.read_subnet_owner_hotkey", fake)
        adapter = _SubtensorAdapter(object(), object())

        assert adapter.read_subnet_owner_hotkey(481).startswith("5GTCFZ5Y")
        assert seen["netuid"] == 481
