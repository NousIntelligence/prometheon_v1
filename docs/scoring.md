# Scoring System

Prometheon Phase 1 is a deterministic, integer-only scoring system. Given the same stored event records, the same metagraph, and the same configuration, every compliant validator produces the same weight vector.

This document describes the rules that turn user activity into miner weights. The full algorithm specification lives alongside the code in the engine module.

---

## 14-Day Rolling Window

Every user has a single integer score representing their qualified activity over the last 14 days:

```text
user_score_14d_points : int    0 <= score <= 280
```

The upper bound is `DAILY_SCORE_CAP × 14 = 280`, where the daily cap is **20** for Phase 1. A user cannot exceed 20 score points in a single day regardless of how much they do.

**Validators compute this themselves** from the signed event stream, over the window `[now − 14 days, now]` — the in-progress day included, so scores move continuously rather than stepping once a day.

Anti-fraud detection remains platform-side, but it now arrives as signed `verdict` records carrying a weight in basis points, which the validator applies. A verdict for the current day does not exist until the platform seals it the following morning, so today's activity is scored at full weight until then; the rolling window corrects it afterwards.

---

## Active Member Threshold

A user is an **active member** for threshold purposes if and only if their 14-day score is **strictly greater than 50**:

```text
is_active_member(user) := user_score_14d_points > 50
```

A user with exactly 50 points does **not** count as active. This boundary is deliberate.

For a miner:

```text
active_member_count(miner) := count(users in miner's Fan Group with score > 50)
```

The contract that each user can join only one Fan Group is enforced platform-side. The validator does not redo this check.

---

## Reward Eligibility

A miner is eligible for any allocation only if they meet **all** of the following:

1. The miner's hotkey is currently registered in the chain metagraph.
2. The miner's hotkey is not the configured `burn_hotkey`.
3. The miner has **≥ 3 active members** (`MIN_ACTIVE_MEMBERS_FOR_REWARD = 3`).
4. The miner has **positive** total score (`miner_score_points > 0`).

Miners that fail any of these checks are dropped from candidate selection. The audit trail (`WeightPlan.excluded`) records why each dropped miner was dropped.

---

## Ranking and Top-K Selection

Eligible candidates are sorted by a strict total order:

1. `miner_score_points` descending.
2. `active_member_count` descending (used to break score ties).
3. `miner_hotkey` ascending lexicographic (used to break score + active-count ties).

The top `min(10, len(candidates))` miners win:

```text
winners = sorted_candidates[: min(PHASE1_TOP_K, len(sorted_candidates))]
```

With fewer than 10 eligible miners, every eligible miner wins. With more than 10, only the top 10 receive any allocation. There is no participation share for ranks 11+.

---

## Proportional Allocation Inside the Top K

The top 10 share the miner reward pool **proportionally by score**, using **largest-remainder integer allocation**. The total pool is `WEIGHT_UNITS = 1_000_000_000`; with a non-zero burn rate, the miner pool is reduced by the burn slice (see [`burn-policy.md`](./burn-policy.md)).

The allocation algorithm is:

1. For each winner, compute the ideal share `floor(miner_pool_units × score_i / total_score)`.
2. The sum of those floors falls short of `miner_pool_units` by some non-negative remainder ≤ number of winners.
3. The remainder is distributed one unit at a time, using a deterministic priority order:
   - largest fractional remainder first,
   - then largest score,
   - then largest active-member count,
   - then smallest hotkey lexicographically.

After step 3, the per-winner shares sum to **exactly** `miner_pool_units`. No floating-point arithmetic enters this calculation.

---

## Chain Submission

The engine emits integer weight units summing to `WEIGHT_UNITS = 1_000_000_000`. The Bittensor chain expects u16 weight values summing to `CHAIN_WEIGHT_UNITS = 65_535`. The chain adapter applies the same largest-remainder approach a second time at the u16 boundary, so the on-chain submission also sums to exactly the chain's expected total.

The final `set_weights` call carries `version_key` and `mechid=0`. Phase 1 uses plain `set_weights` only — commit-reveal is reserved for a future phase.

---

## What Happens When No Miners Are Eligible

If every candidate fails eligibility, the burn target rules in [`burn-policy.md`](./burn-policy.md) take over:

- If the configured burn hotkey is currently registered in the metagraph, 100% of the weight goes to the burn UID (Case C).
- If the burn hotkey is not registered either, the engine emits `status = "no_valid_weight_target"` and the runner **does not submit**. This is the fail-closed posture from consolidated specification §2.11 / §12.11 Case D.

This is the only failure mode of the engine itself. Every other failure (a missing or unreadable event store, environment mismatch, chain hyperparameter mismatch) happens upstream and triggers a cycle-level error before the engine runs.

---

## Properties

- **Determinism**: same inputs → same `WeightPlan` (byte-identical when dumped through JCS canonicalization).
- **Integer-only inside the engine**: no floats; chain-boundary conversion to u16 is a separate, isolated step.
- **Reproducible across implementations**: any conforming implementation in any language reaches the same result against the shared fixture suite.
- **Auditable**: every excluded miner is recorded with a stable `reason` code.
