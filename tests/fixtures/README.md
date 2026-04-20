# Shared Fixture Suite

This directory holds the **deterministic fixture suite** referenced by contract tests and used by integration tests. The suite must remain byte-identical with the platform-side implementation; any change is a coordinated contract change.

## Layout

| Directory | Contents |
|---|---|
| [`snapshots/`](./snapshots/) | Aggregate snapshots, detailed manifests, and detailed pages — each accompanied by the canonical JSON, the SHA-256 of canonical bytes, expected `records_hash`, expected `page_hash`, and a test-key Ed25519 signature. |
| [`metagraphs/`](./metagraphs/) | Synthetic metagraph snapshots with `hotkeys_by_uid` / `uids_by_hotkey` maps used to exercise registration filtering and UID resolution. |
| [`weights/`](./weights/) | Expected `WeightPlan` outputs for each fixture scenario (each of burn cases A/B/C/D, ties, missing-burn, top-K boundaries, score-zero exclusions, etc.). |

## Test keys

Fixtures sign with **test keys only**. Real Platform Ed25519 keys never appear here. A separate fixture lists the test keypairs and their fingerprints; verifiers in contract tests load only those test keys.

## Versioning

Each fixture file carries a version suffix when its canonical bytes change. Replacing the bytes of an existing fixture without bumping the suffix is forbidden — downstream golden-vector tests would silently drift.
