"""Validator runtime: configuration, scheduler, runner, local state, reporting.

This module orchestrates the validator lifecycle:

1. Load and validate configuration.
2. Sync metagraph at startup and on a throttled cadence.
3. Refresh the signed snapshot.
4. Re-resolve hotkey-to-UID per submission attempt.
5. Run the pure mechanism engine.
6. Submit weights through the chain adapter.
7. Persist atomic local state and append events to the runtime log.

The runner deliberately keeps mechanism logic outside its own module — the
pure engine in ``prometheon.mechanisms.phase1_growth`` receives validated
inputs and returns a ``WeightPlan``; the runtime only handles the surrounding
operational concerns.
"""
