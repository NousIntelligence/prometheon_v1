# Burn Policy

The burn target is a hotkey whose UID receives a configured fraction of the weight pool. Neither the fraction (`manual_burn_rate_ppm`, in parts-per-million) nor the target hotkey is validator config — an operator cannot set either one.

Where they come from depends on the weight path:

| Path | `burn_hotkey` | `manual_burn_rate_ppm` |
|---|---|---|
| **Event stream** (live) | the **subnet owner hotkey**, read from chain (`get_subnet_owner_hotkey`) | the locked constant `MANUAL_BURN_RATE_PPM` in `policy.py` |
| **Snapshot** (fallback) | carried inside the signed snapshot | carried inside the signed snapshot |

On the event path the stream carries no policy fields, and the chain has no burn-rate equivalent — `min_burn` / `max_burn` / `get_subnet_burn_cost()` are all **registration** costs, a different concept. So the rate is a frozen constant next to `DAILY_SCORE_CAP` and `PHASE1_TOP_K`, and changing it is a coordinated release. It is deliberately not config: two operators configuring different rates would submit different weight vectors for reasons unrelated to the data, and nothing would reveal the divergence.

Both paths currently produce the same slice — 150 000 ppm (15%) is the value the platform already signs.

The Phase 1 engine resolves which of four mutually exclusive cases applies on every cycle.

---

## The Four Cases

The case is determined by two questions:

- Do any eligible miners exist after filtering and top-K selection?
- Is the `burn_hotkey` (see the table above for where it comes from) currently registered in the chain metagraph?

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

On the snapshot path the value rides inside the signed snapshot, so the operator cannot be impersonated: a change requires the platform to re-sign with its Ed25519 key. On the event path the equivalent guarantee comes from the values being unforgeable in a different way — the target is chain state every validator reads identically, and the rate is compiled in.

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
