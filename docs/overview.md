# Overview

Prometheon Phase 1 is a Bittensor subnet that converts BitFan platform-qualified user activity into deterministic on-chain weights.

The subnet's rewarded work is **real growth of a BitFan Fan Group**, not subnet-side inference or scoring. A Fan Group is a community surface on the BitFan platform that any signed-in user can create and lead — owning one is independent of, and a prerequisite for, becoming a miner. A miner is simply a Fan Group leader who has additionally registered a Bittensor hotkey and verified it against their platform account. Validators consume the platform's signed event streams, recompute user scores independently from the frozen formula, run a pure integer weight engine against the current Bittensor metagraph, and submit weights to the chain.

This document describes the architecture at a high level. For role-specific operational guides see [`miner.md`](./miner.md) and [`validator.md`](./validator.md).

---

## Multi-Phase Repository Strategy

Prometheon ships one phase per repository. This repository is Phase 1 only:

| Phase | Repository | Status |
|---|---|---|
| Phase 1 — growth incentive | `BitSpaceorganization/prometheon_v1` | **Active** |
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
       │                                  │  signs every event record      │                              │
       │                                  │          │                     │                              │
       │                                  │ pushes signed event streams    │                              │
       │                                  ├───────────────────────────────▶│                              │
       │                                  │                                │  verifies + stores locally   │
       │                                  │                                │  recomputes scores itself    │
       │                                  │                                │  runs pure Phase 1 engine    │
       │                                  │                                │  resolves UIDs, u16 convert  │
       │                                  │                                │  set_weights(version_key=N)  │
       │                                  │                                ├─────────────────────────────▶│
       │                                  │                                │                              │
```

Every component has a clear responsibility:

- **Miners** are Fan Group leaders who have verified a registered hotkey; they grow their Fan Group and do not run a daemon that submits work to validators. Fan Group ownership comes first; `verify-miner` layers mining status on top.
- **The BitFan platform** is the sole authority on what *happened* — it records activity and issues anti-fraud verdicts — and it signs every record it emits. It is no longer the authority on the resulting scores: validators recompute those.
- **Validators** recompute scores from their own copy of the signed streams and transform the result into an on-chain weight vector — deterministically, with no subjective scoring.
- **The Bittensor chain** processes the submitted weights through Yuma consensus and emits.

### Subnet-side preconditions

Phase 1 operates against a subnet using **plain `set_weights`** submission only. The commit-reveal weight-submission scheme is deliberately out of scope for this phase.

Concretely, this means the target netuid must have the chain hyperparameter `commit_reveal_weights_enabled = False`. The validator's pre-submission policy gate reads this from `subtensor.get_subnet_hyperparameters(netuid)` and fails closed with `chain.commit_reveal_enabled` when the subnet is in commit-reveal mode — see [`docs/validator.md` § Troubleshooting](./validator.md#troubleshooting) for the subnet-owner's one-shot resolution.

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

1. **Recompute from the local event store** — the validator scores the rolling window `[now − 14 days, now]` from records the platform pushed to it, which it verified and stored itself. No fetch happens in the weight path. *(The snapshot fallback replaces this step with an authenticated fetch plus signature and hash verification — see [`validator.md`](./validator.md#weight-source).)*
2. **Burn policy** — the burn target is the subnet owner hotkey read from chain; the rate is a locked constant. Neither comes from the platform.
3. **Metagraph sync** — fresh `MetagraphView` pulled from the chain.
4. **Engine** — `compute_phase1_weight_plan` produces a `WeightPlan` with either `status="ready"` or `status="no_valid_weight_target"`.
5. **Pre-submission gate** — commit-reveal detection (fail closed if enabled), SDK `mechid` support check, `weights_version` policy check.
6. **UID re-resolution** — every plan item re-resolved against the fresh metagraph (no stale UIDs).
7. **u16 conversion** — second largest-remainder allocation from `WEIGHT_UNITS=1_000_000_000` down to `CHAIN_WEIGHT_UNITS=65_535`.
8. **Submit** — `set_weights(version_key, mechid=0)` via the chain adapter.
9. **Persist** — atomic state file + NDJSON event line.

Given the same stored records, the same metagraph state, and the same configuration, every compliant validator produces the same weight vector. Validators whose stores differ will differ — expected during catch-up, and resolved by chain consensus rather than by refusing to submit.

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
