# Burn Policy

The burn target is a hotkey whose UID receives a configured fraction of the weight pool. The fraction (`manual_burn_rate_ppm`, in parts-per-million) and the burn target hotkey itself are both carried inside the signed snapshot; they are **not** validator config. Validators consume the signed values verbatim.

The Phase 1 engine resolves which of four mutually exclusive cases applies on every cycle.

---

## The Four Cases

The case is determined by two questions:

- Do any eligible miners exist after filtering and top-K selection?
- Is the configured `burn_hotkey` currently registered in the chain metagraph?

| Case | Winners exist | Burn hotkey in metagraph | Behavior |
|---|---|---|---|
| **A** | Yes | Yes | `burn_units` to burn UID; remainder to winners proportionally. |
| **B** | Yes | No | Effective burn rate 0; 100% of the weight pool goes to winners. |
| **C** | No | Yes | 100% of the weight pool goes to the burn UID. |
| **D** | No | No | **Fail closed.** `status = "no_valid_weight_target"`, runner does NOT submit. |

Case D is the only condition under which a compliant validator deliberately skips submission.

---

## Why Burn Exists

Burn is a control surface for the subnet operator. The signed snapshot's `manual_burn_rate_ppm` lets the operator allocate a fraction of emissions to a known burn target (e.g. a treasury or a wallet with no withdrawal rights). The validator does not interpret this — it just allocates the configured fraction to the registered UID.

Because the value is carried inside the signed snapshot, the operator cannot be impersonated. A change to `manual_burn_rate_ppm` requires the platform to re-sign with its Ed25519 key.

---

## Burn-Unit Calculation

The burn fraction is expressed in parts per million:

```text
burn_units = floor(WEIGHT_UNITS × manual_burn_rate_ppm / 1_000_000)
```

With `WEIGHT_UNITS = 1_000_000_000`, the division is always exact for any non-negative integer `manual_burn_rate_ppm ≤ 1_000_000`. There is no rounding.

In Case A:

```text
effective_burn_units = burn_units
miner_pool_units     = WEIGHT_UNITS - effective_burn_units
```

The miner pool then flows through the largest-remainder allocation described in [`scoring.md`](./scoring.md).

In Case C the burn UID receives the entire `WEIGHT_UNITS` budget.

In Case B the burn slice is effectively 0; the entire `WEIGHT_UNITS` goes to winners.

In Case D no submission happens at all.

---

## Burn Hotkey Resolution

The validator resolves `burn_hotkey` to a UID using the **current** metagraph on every cycle (consolidated specification §13.5). UIDs are not stable identity — a hotkey can move slots between cycles. Resolving fresh prevents stale-UID hijacks.

If the burn hotkey is missing from the metagraph at the moment of submission, Case B (winners present) or Case D (no winners) applies. There is no fallback to a different burn target.

---

## What the Validator Logs

For every cycle the runner emits a structured event with the resolved case:

```text
cycle_submitted   { burn_case: "A" | "B" | "C", ... }
cycle_no_valid_weight_target { burn_case: "D", failure_reason: "no_eligible_miners_and_burn_hotkey_missing" }
```

Operators can grep the NDJSON event log under `.validator-state/events.ndjson` to confirm which case the engine reached on any given day.
