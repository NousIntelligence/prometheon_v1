# Validator Guide

Validators verify a daily platform-signed snapshot, transform it deterministically into a weight vector, and submit the result on-chain. There is no subjective scoring: every compliant validator running the same inputs produces the same output.

This guide walks through the full validator setup, configuration, and operational loop.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Bittensor wallet | Coldkey + hotkey pair. Validator permits are chain-governed; you need a permit to set weights. |
| BitFan platform account | Sign up at the BitFan platform with a stable username and verified email. |
| Bootstrap token (first verify only) | Obtained from the [BitFan portal](https://bitfanweb-production-658c.up.railway.app/me/prometheon) — click *Get bootstrap token* with role *validator*. The token is one-time, scoped to `identity:verify:validator`, expires after one hour, and is auto-revoked the moment `verify-validator` succeeds. Export it as `PROMETHEON_VALIDATOR_API_TOKEN`. |
| Operational validator token | Issued by the BitFan portal once verification succeeds; carries the `snapshot:read:aggregate` (or `:detailed`) scope used by `validator run`. Same env var name as the bootstrap token, but you re-export the new token after first verify. |
| Linux host | The runner is a single Python process; CPU and disk footprint are minimal. |

Install:

```bash
pip install prometheon            # or `uv sync` from the repository
```

---

## Step 1 — Verify Your Validator Account

The first call uses the one-time bootstrap token from the BitFan portal:

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<bootstrap token from BitFan portal>"

prometheon verify-validator \
    --username             <bitfan_username> \
    --email                <bitfan_email> \
    --wallet-name          <coldkey_directory_name> \
    --wallet-hotkey        <hotkey_file_name> \
    --platform-base-url    https://api.bitfan.example \
    --platform-instance-id bitfan-production \
    --chain-network        finney \
    --netuid               <netuid>
```

On success the platform sets `validator_verified = true` for your account, binds your hotkey, and revokes the bootstrap token — all in the same transaction. After verify completes, return to the BitFan portal to issue your operational validator token (with `snapshot:read:aggregate` or `:detailed` scope) and re-export it under the same env var for the `validator run` step.

---

## Step 2 — Configure the Runtime

Copy one of the example configs and fill in your values:

```bash
cp configs/finney.example.toml ~/prometheon-validator.toml
```

Edit the key sections:

```toml
[chain]
network = "finney"
netuid = <real_netuid>
version_key = <operator_provided_version_key>
fail_on_weights_version_mismatch = true   # do not relax on finney

[wallet]
name = "validator"
hotkey = "default"

[platform]
base_url = "https://api.bitfan.example"
platform_instance_id = "bitfan-production"
api_token_env = "PROMETHEON_VALIDATOR_API_TOKEN"

[platform.snapshot_keys."platform-main-2026-05"]
public_key = "0x<32_bytes_lowercase_hex>"
not_before = "2026-05-01T00:00:00Z"
not_after  = "2026-09-01T00:00:00Z"
status     = "active"

[validator]
mode = "aggregate"             # or "detailed"
activity_date = "latest"
submit_weights = true
dry_run = false

[burn]
enabled = true
burn_hotkey = "<configured_burn_hotkey>"
manual_burn_rate_ppm = 150000  # placeholder — the signed snapshot's value wins live
```

The runtime will refuse to start if:

- Any locked Phase 1 constant in the config (`daily_score_cap`, `active_member_score_threshold`, `min_active_members_for_reward`, `top_k`, `weight_units`) deviates from the spec.
- The config sets `allow_legacy_sdk_without_mechid = true` on any network other than `local`.
- The `platform.snapshot_keys` map is empty.

See [`deployment/mainnet.md`](./deployment/mainnet.md) for the operational checklist around `version_key`, snapshot key rotation, and chain hyperparameter compatibility.

### Snapshot Modes

The `[validator] mode` setting selects how the validator consumes the daily platform-signed snapshot:

- `aggregate` — a single signed response carrying the full per-miner roll-up. Cheapest call (one HTTP request) and the default for typical operators.
- `detailed` — a signed manifest plus N page bodies streamed through the validator's accumulator. The detailed mode lets you cross-check per-user activity for forensic / auditing workflows; it is more expensive in bandwidth but produces identical engine output. Most operators run aggregate.

The platform may refuse to serve the requested mode for a given activity date (`SNAPSHOT_MODE_INVALID`) — switch the configured mode to one it does support.

### Snapshot Reads

Snapshot reads are authenticated and signed. Every request carries the `PROMETHEON_*_API_TOKEN` and an `X-Prometheon-*` header set signed under `PROMETHEON_API_REQUEST_V1` (skew window 300 s; nonce TTL 600 s). See [`security.md` § API Request Signing](./security.md#api-request-signing) for the canonical body.

The token must carry the matching `snapshot:read:<aggregate|detailed>` scope; the platform refuses scope-mismatched reads with `AUTH_TOKEN_SCOPE_MISSING` and surfaces the required scope through the renderer's typed-details line. Account-level refusal (e.g., your validator account has not completed verify) surfaces as `SNAPSHOT_ACCESS_DENIED`.

---

## Step 3 — Run

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<token>"
prometheon validator run --config ~/prometheon-validator.toml
```

The runner loops forever, performing one cycle every
`scheduler.weight_submission_check_interval_minutes`. Each cycle:

1. Fetches and verifies the latest signed snapshot (Ed25519 signature, `records_hash`, for detailed mode every page hash + global ordering + duplicate `user_ref` rejection).
2. Re-syncs the metagraph fresh from the chain.
3. Runs the pre-submission policy gate: commit-reveal detection, SDK `mechid` support, `weights_version` policy check.
4. Runs the pure mechanism engine. Result is either `status="ready"` or `status="no_valid_weight_target"` (no eligible miners and no burn hotkey in the metagraph — Case D).
5. For ready plans: re-resolves every UID, converts to u16, calls `set_weights(version_key, mechid=0)`.
6. Persists `.validator-state/state.json` atomically and appends an event line to `.validator-state/events.ndjson`.

For one-shot or scheduled execution:

```bash
prometheon validator run --config <path> --once
prometheon validator run --config <path> --cycles 5
```

For dry-run (no chain submission):

```bash
# Edit the config:
# [validator]
# submit_weights = false
# or
# dry_run = true
```

---

## Step 4 — Monitor

The fastest local check:

```bash
prometheon status
```

prints the persisted state file (last snapshot accepted, last block submitted, last extrinsic hash, last error). Exit code 0 = state present; exit code 2 = no cycle has completed yet.

For an event-by-event view, tail the NDJSON log:

```bash
tail -F .validator-state/events.ndjson | jq .
```

Event types emitted:

- `cycle_submitted` — successful chain submission.
- `cycle_no_valid_weight_target` — Case D (fail closed; no submission).
- `cycle_dry_run` — `dry_run=true` or `submit_weights=false`.
- `cycle_failed` — exception during a cycle (the runner re-raises after persisting).

---

## Operational Notes

- **Snapshot key rotation**: the platform team will publish new `platform_key_id` entries before retiring an old one. Add the new entry to your `[platform.snapshot_keys]` config block before the platform starts signing with it. Multiple active keys may coexist.
- **`weights_version`**: changes when the subnet owner bumps the on-chain weight version. The runtime detects a mismatch at startup and fails closed by default on `finney`.
- **Commit-reveal**: not supported in Phase 1. If the subnet enables commit-reveal at the chain level the runner will fail closed (`chain.commit_reveal_enabled`).
- **Activity cutoff**: respected by the scheduler. A cycle that arrives too close to the cutoff window will be skipped to avoid an out-of-bounds submission.

For deployment on each environment see the dedicated guides under [`deployment/`](./deployment/).
