"""Phase 1 weight engine — pure deterministic transformation from a set of
miner records to a ``WeightPlan``.

The records come from the validator's own recomputation over the signed
event stream (the live path) or from a verified signed snapshot (the
retained fallback); the engine is identical either way and does not know
which produced them.

This sub-package is the core of the subnet's economic logic. Its contract is
strict:

- No I/O. No clock. No randomness. No floats.
- All scores, counts, and weights are integers.
- ``compute_phase1_weight_plan(snapshot, metagraph, runtime, policy)`` is the
  single public entry point.

Helpers are split by concern:

- ``snapshot``       normalized miner-record models
- ``aggregate``      aggregate-mode score extraction
- ``detailed``       detailed-mode streaming accumulator
- ``eligibility``    threshold and registration filtering
- ``ranking``        deterministic ordering with explicit tie-breakers
- ``burn``           burn-case A/B/C/D resolution
- ``allocation``     largest-remainder integer allocation
- ``engine``         orchestrates the pipeline and emits the ``WeightPlan``

Tests under ``tests/unit/phase1_growth`` cover the fixture matrix described in
the consolidated specification.
"""
