"""Metagraph view — the typed, in-memory snapshot the engine consumes.

The full metagraph synchronisation logic against the live subtensor lives
in a follow-up module. This file defines only the data shape: a Pydantic
model that captures the fields the Phase 1 weight engine and the chain
adapter need.

Keeping the model here in :mod:`prometheon.chain` (rather than inside
:mod:`prometheon.mechanisms`) means the engine treats the metagraph as an
input parameter and stays a pure function — it does not import any chain
SDK code itself.

Fields:

- ``block_number``         current chain block at sync time.
- ``hotkeys_by_uid``       canonical UID → SS58 hotkey map (the chain's view).
- ``uids_by_hotkey``       inverse map; the engine uses this to resolve
                           ``burn_hotkey`` and every miner hotkey to a
                           current UID.
- ``validator_permits``    UID → bool, whether each UID holds a validator
                           permit on the subnet.
- ``stakes``               UID → integer stake in TAO atomic units (rao).
                           Optional for Phase 1 (currently unused by the
                           engine).
- ``min_allowed_weights``  chain hyperparameter; the chain adapter checks
                           the final weight vector against it.
- ``max_weights_limit``    chain hyperparameter; the chain adapter
                           respects this on submission.
- ``weights_version``      the chain's expected ``version_key`` value.
- ``weights_rate_limit``   block-count rate limit for ``set_weights``.
- ``activity_cutoff``      block-count safety cutoff for validator activity.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MetagraphView(BaseModel):
    """Read-only typed snapshot of the relevant on-chain metagraph state.

    Constructed by :mod:`prometheon.chain` after a fresh sync; consumed by
    the Phase 1 weight engine and by the chain adapter. The engine never
    mutates it.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    block_number: int = Field(ge=0)
    hotkeys_by_uid: dict[int, str] = Field(default_factory=dict)
    uids_by_hotkey: dict[str, int] = Field(default_factory=dict)

    validator_permits: dict[int, bool] = Field(default_factory=dict)
    stakes: dict[int, int] = Field(default_factory=dict)

    # Chain hyperparameters. Defaults are conservative: zero rate limit
    # means "no enforcement" until the adapter overrides them with the
    # values queried from the chain.
    min_allowed_weights: int = Field(default=1, ge=0)
    max_weights_limit: int = Field(default=65535, ge=0)
    weights_version: int = Field(default=0, ge=0)
    weights_rate_limit: int = Field(default=0, ge=0)
    activity_cutoff: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _validate_index_consistency(self) -> MetagraphView:
        """Reject metagraphs whose two index maps disagree.

        ``hotkeys_by_uid`` and ``uids_by_hotkey`` must be exact inverses.
        Constructing the view with mismatched maps is a programmer error
        and should fail loudly so divergent UID resolution can't happen
        downstream.
        """
        if len(self.hotkeys_by_uid) != len(self.uids_by_hotkey):
            raise ValueError(
                f"hotkeys_by_uid has {len(self.hotkeys_by_uid)} entries but "
                f"uids_by_hotkey has {len(self.uids_by_hotkey)}; maps must be inverses"
            )
        for uid, hotkey in self.hotkeys_by_uid.items():
            mirror = self.uids_by_hotkey.get(hotkey)
            if mirror != uid:
                raise ValueError(
                    f"index inconsistency: hotkeys_by_uid[{uid}]={hotkey!r} but "
                    f"uids_by_hotkey[{hotkey!r}]={mirror}"
                )
        return self

    def is_registered(self, hotkey: str) -> bool:
        """Return ``True`` if ``hotkey`` currently has a UID on the subnet."""
        return hotkey in self.uids_by_hotkey

    def uid_for(self, hotkey: str) -> int | None:
        """Return the current UID for ``hotkey``, or ``None`` if unregistered."""
        return self.uids_by_hotkey.get(hotkey)


__all__ = ["MetagraphView"]
