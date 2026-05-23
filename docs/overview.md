# Overview

Prometheon Phase 1 is a Bittensor subnet that converts BitFan platform-qualified user activity into deterministic on-chain weights.

The subnet's rewarded work is **real growth of a BitFan Fan Group**, not subnet-side inference or scoring. Miners operate Fan Groups on the BitFan platform; validators consume a daily platform-signed snapshot, run a pure integer weight engine against the current Bittensor metagraph, and submit weights to the chain.

This document describes the architecture at a high level. For role-specific operational guides see [`miner.md`](./miner.md) and [`validator.md`](./validator.md).

---

## Multi-Phase Repository Strategy

Prometheon ships one phase per repository. This repository is Phase 1 only:

| Phase | Repository | Status |
|---|---|---|
| Phase 1 — growth incentive | `NousIntelligence/prometheon_v1` | **Active** |
| Phase 2 | future repository | Reserved |
| Phase 3 | future repository | Reserved |
| Phase 4 | future repository | Reserved |

No scaffolding for future phases lives in this tree. When a future phase ships it will be in its own dedicated repository, the same way Uniswap separates `v1-contracts`, `v2-core`, `v3-core`, `v4-core`.

---

## Components

```text
[Miners on BitFan]                 [BitFan Platform]                  [Validators]                [Bittensor chain]
       │                                  │                                │                              │
       │  operate Fan Groups              │                                │                              │
       ├─────────────────────────────────▶│                                │                              │
       │                                  │                                │                              │
       │                                  │  scores user activity (14d)    │                              │
       │                                  ├──────────┐                     │                              │
       │                                  │          ▼                     │                              │
       │                                  │  generates signed snapshot     │                              │
       │                                  │          │                     │                              │
       │                                  │ daily snapshot (Ed25519)       │                              │
       │                                  ├───────────────────────────────▶│                              │
       │                                  │                                │  verifies signature, hash    │
       │                                  │                                │  runs pure Phase 1 engine    │
       │                                  │                                │  resolves UIDs, u16 convert  │
       │                                  │                                │  set_weights(version_key=N)  │
       │                                  │                                ├─────────────────────────────▶│
       │                                  │                                │                              │
```

Every component has a clear responsibility:

- **Miners** grow Fan Groups; they do not run a daemon that submits work to validators.
- **The BitFan platform** is the sole authority on user activity scoring, anti-farming detection, and snapshot signing.
- **Validators** transform a signed snapshot into an on-chain weight vector — deterministically, with no subjective scoring.
- **The Bittensor chain** processes the submitted weights through Yuma consensus and emits.

---

## What This Repository Contains

| Layer | Modules | Owns |
|---|---|---|
| Security primitives | `src/prometheon/security/` | RFC 8785 JCS, hashing, SR25519 + Ed25519 signature wrappers, request nonces. |
| Identity protocol | `src/prometheon/identity/` | Canonical payload models, envelope verifiers for verify / rotate / recover flows. |
| BitFan client | `src/prometheon/platform/` | Wire schemas, signed snapshot verification, streaming detailed-mode accumulator, typed HTTP client. |
| Phase 1 engine | `src/prometheon/mechanisms/phase1_growth/` | Pure deterministic engine: eligibility, ranking, burn cases, integer allocation, `WeightPlan`. |
| Chain adapter | `src/prometheon/chain/` | Wallet loading, subtensor connection, metagraph view, UID resolution, u16 conversion, weight submission. |
| Validator runtime | `src/prometheon/validator/` | Config loader, scheduler, cycle runner, atomic state, NDJSON event log. |
| CLI | `src/prometheon/cli/` | `prometheon` operator commands. |
| Miner-side helpers | `src/prometheon/miner/` | Informational status output only — no work submission. |
| Telemetry | `src/prometheon/telemetry/` | Stdlib + structlog logging configuration. |

The pure engine is the heart of the subnet. Everything else exists to feed it verified inputs and route its output to the chain.

---

## End-to-End Data Flow

For one cycle:

1. **Platform signed snapshot** — validator fetches the latest aggregate snapshot (or detailed manifest + pages) via the BitFan API. The request itself is signed with the validator hotkey under `PROMETHEON_API_REQUEST_V1`.
2. **Signature + hash verification** — validator checks the Ed25519 platform signature against its trusted-key map, recomputes `records_hash` (and per-page hashes in detailed mode), enforces every cross-environment and policy-constant invariant.
3. **Metagraph sync** — fresh `MetagraphView` pulled from the chain.
4. **Engine** — `compute_phase1_weight_plan` produces a `WeightPlan` with either `status="ready"` or `status="no_valid_weight_target"`.
5. **Pre-submission gate** — commit-reveal detection (fail closed if enabled), SDK `mechid` support check, `weights_version` policy check.
6. **UID re-resolution** — every plan item re-resolved against the fresh metagraph (no stale UIDs).
7. **u16 conversion** — second largest-remainder allocation from `WEIGHT_UNITS=1_000_000_000` down to `CHAIN_WEIGHT_UNITS=65_535`.
8. **Submit** — `set_weights(version_key, mechid=0)` via the chain adapter.
9. **Persist** — atomic state file + NDJSON event line.

Given the same signed snapshot, the same metagraph state, and the same configuration, every compliant validator produces the same weight vector. This is by design.

---

## Where To Go Next

- [`miner.md`](./miner.md) — how to set up as a miner and grow a Fan Group.
- [`validator.md`](./validator.md) — how to set up and run the validator.
- [`scoring.md`](./scoring.md) — the 14-day scoring window, active-member threshold, top-K selection, proportional weights.
- [`burn-policy.md`](./burn-policy.md) — burn cases A/B/C/D and the fail-closed posture.
- [`hotkey-rotation.md`](./hotkey-rotation.md) — normal rotation and the two recovery paths.
- [`security.md`](./security.md) — signing primitives, replay defenses, key rotation.
- [`platform-api.md`](./platform-api.md) — the public subset of the BitFan API surface.
- [`deployment/`](./deployment/) — localnet, testnet, mainnet deployment guides.
