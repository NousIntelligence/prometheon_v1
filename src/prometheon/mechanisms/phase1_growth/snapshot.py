"""Normalised miner-record model consumed by the Phase 1 engine.

The engine operates on a single record shape regardless of whether the
snapshot was downloaded in aggregate mode or assembled from a streamed
detailed manifest. That shape is identical to the wire-level
``MinerAggregateRecord`` defined in :mod:`prometheon.platform.schemas`,
so this module re-exports it under the engine-friendly name
``MinerRecord``.

Keeping a name in :mod:`prometheon.mechanisms.phase1_growth` rather than
forcing every engine caller to import from ``platform.schemas`` preserves
the architectural separation: the engine layer depends on the wire
schema, not the other way around.
"""

from __future__ import annotations

from prometheon.platform.schemas import MinerAggregateRecord as MinerRecord

__all__ = ["MinerRecord"]
