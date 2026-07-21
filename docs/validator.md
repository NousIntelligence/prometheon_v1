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
    --platform-base-url    https://subnet-api.bitfan.ai \
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
base_url = "https://subnet-api.bitfan.ai"
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

## Troubleshooting

The CLI prints a structured block on every failure: the wire code on the top line, a one-line headline, and a Remediation paragraph. Add `--verbose` for a sanitised diagnostic trailer that captures the typed `details` payload, HTTP status, and exception class:

```bash
prometheon --verbose validator run --config ~/prometheon-validator.toml --once
```

For long-running validators, the same renderer block is emitted to stderr per failed cycle, prefixed with the cycle index — `tail -F` on stderr captures it in real time. The renderer redacts credential-shape values from the trailer (see [`security.md` § API Tokens](./security.md#api-tokens)).

The persisted `.validator-state/state.json` carries the last failure as a `(code, message)` pair; the `events.ndjson` log carries one line per cycle-level outcome. Neither file ever contains the typed `details` dict — those stay on the in-memory exception so a long-running validator's state file does not accumulate server-controlled fields.

### Codes you are most likely to hit

#### Snapshot-side codes

| Wire code | Likely cause | Resolution |
|---|---|---|
| `SNAPSHOT_NOT_READY` | No snapshot has been published for the requested activity date yet. | Wait for the platform's publish cadence to complete for the day, or set `activity_date` in `[validator]` to a date already published. |
| `SNAPSHOT_MODE_INVALID` | The configured `mode` (`aggregate` / `detailed`) is not served for this date. | Switch the configured mode to one the platform supports — typically `aggregate`. See [Snapshot Modes](#snapshot-modes). |
| `SNAPSHOT_DATE_INVALID` | The `activity_date` is outside the platform's publishing window or wrong-shaped. | Use `YYYY-MM-DD` for a date inside the window, or `latest`. |
| `SNAPSHOT_ACCESS_DENIED` | Your account does not currently have access to the snapshot read endpoint for this snapshot. | Confirm `verify-validator` completed and that your operational token carries the `snapshot:read:<aggregate\|detailed>` scope. See [Snapshot Reads](#snapshot-reads). |
| `SNAPSHOT_PAGE_NOT_FOUND` / `SNAPSHOT_STORAGE_ERROR` | Transient platform-side storage condition. | Retry. If the failure persists across several minutes, raise it with the platform team. |
| `SNAPSHOT_STORAGE_ACCESS_DENIED` | Infrastructure-level access policy on the platform storage backend refused the read. | Out of operator scope — contact platform operators. |
| `SNAPSHOT_PAGE_HASH_ERROR` | The platform's server-side integrity check rejected one of its own pages. | Retry. If the failure repeats, the platform team needs to re-publish the snapshot. |
| `signature.verification_failed` (local) | The CLI could not verify the platform's Ed25519 signature on the snapshot. **This is the local-side error**; the renderer's block carries the `(local verification)` origin label. | Re-fetch the snapshot. If the failure persists, confirm `[platform.snapshot_keys]` in your config matches the platform's currently published key set. See [`security.md` § Snapshot Integrity](./security.md#snapshot-integrity). |

#### Identity / authentication codes

| Wire code | Likely cause | Resolution |
|---|---|---|
| `AUTH_INVALID_TOKEN` | Operational token revoked, expired, or never valid for this platform instance. | Re-issue from the BitFan portal with the matching scope and re-export `PROMETHEON_VALIDATOR_API_TOKEN`. |
| `AUTH_TOKEN_SCOPE_MISSING` | Token does not carry the scope the endpoint requires; the renderer's typed-details line shows which. | Re-issue with the correct scope. |
| `ACCOUNT_NOT_VERIFIED` | Endpoint requires a verified validator account. | Run `prometheon verify-validator` first using a bootstrap token. |
| `ENVIRONMENT_MISMATCH` | `chain_network` / `platform_instance_id` does not match what the platform expects. The typed-details line shows the expected values. | Update the `[chain]` and `[platform]` blocks in your config. See [`security.md` § Cross-Environment Replay Defense](./security.md#cross-environment-replay-defense). |

#### Subnet runtime fail-closed conditions

These are not platform errors; they are conditions the validator refuses to start (or submit) under because the result would be unsafe.

| Code | Cause | Resolution |
|---|---|---|
| `chain.commit_reveal_enabled` | The subnet has commit-reveal turned on at the chain level. Phase 1 does not support commit-reveal. | If you do not own the subnet, wait until the subnet owner disables commit-reveal, or contact them. The validator refuses to submit until then. If you **do** own the subnet, see [Subnet-owner resolution](#subnet-owner-resolution-disable-commit-reveal) below. |
| `chain.weights_version_mismatch` | The configured `[chain] version_key` differs from the chain's `weights_version` hyperparameter. | Update `version_key` in the config to the value the subnet owner has currently set. |
| `chain.mechid_missing` | The installed `bittensor` SDK lacks `mechid` support and the config does not enable the legacy override. | Upgrade the `bittensor` package. The legacy override (`allow_legacy_sdk_without_mechid = true`) is only acceptable on `local`. |
| `chain.set_weights_failed` | The chain rejected the `set_weights` extrinsic — see the `--verbose` trailer for the underlying SDK error. | Inspect the trailer's `ExtrinsicResponse` diagnostic fields and act on the specific cause (insufficient stake, version key drift, permit revocation, etc.). |
| `NO_VALID_WEIGHT_TARGET` | Engine returned `status=no_valid_weight_target` (Case D — no qualifying miner). | Expected and self-resolves when at least one eligible miner reappears in a subsequent snapshot. The cycle is **not** a failure; it is a deliberate no-op. |

For the full catalog (binding-ledger, snapshot storage, the five signature primitives, the typed-details payloads) see [`security.md` § Failure Code Catalog](./security.md#failure-code-catalog).

### Subnet-owner resolution — disable commit-reveal

This is the operational fix for `chain.commit_reveal_enabled` when **you hold the subnet-owner / sudo coldkey** for the affected netuid. Tracked in [#68](https://github.com/NousIntelligence/prometheon_v1/issues/68) as the chosen path for the live-incident response.

Run this with the subnet-owner coldkey wallet on the right network (the example below targets testnet 481):

```bash
btcli sudo set \
    --netuid 481 \
    --param commit_reveal_weights_enabled \
    --value False \
    --network test \
    --wallet-name <subnet_owner_coldkey_wallet_name>
```

Recommended order of operations:

1. Stop the running validators against this netuid first. They are not making forward progress while commit-reveal is on, and you do not want them attempting `set_weights` during the hyperparameter-change finalisation window.
2. Confirm the wallet you are about to unlock is the subnet owner:
   ```bash
   btcli subnets info --netuid <N> --network <net>
   ```
   The output prints the subnet-owner SS58. Match it against `btcli wallet overview --wallet.name <wallet>`.
3. Execute the sudo call. `btcli` prompts for the coldkey passphrase and prints the extrinsic finalisation message.
4. Verify the on-chain value before restarting anything:
   ```bash
   btcli sudo get --netuid <N> --network <net> | grep commit_reveal_weights_enabled
   ```
   Expect `False`.
5. Restart validators. The first `cycle_submitted` event in `events.ndjson` confirms the runtime resumed normal `set_weights` submissions.

The validator's `read_hyperparameters` reads `commit_reveal_weights_enabled` from `subtensor.get_subnet_hyperparameters(netuid)` on every cycle. Even if step 3 did not take, step 4 catches it before any cycle runs, and the runtime still fails closed cleanly if commit-reveal flips back on at any point in the future.

---

## Decentralized Validation (event stream)

The event-stream ingest + open-recomputation program (the successor to the
trusted-snapshot data source) has its own operator guide:
[`decentralized-validation.md`](./decentralized-validation.md) — ingest
endpoint setup and registration, catch-up and day-digest completeness,
scoring, shadow mode, and the cutover procedure.

---

## Operational Notes

- **Snapshot key rotation**: the platform team will publish new `platform_key_id` entries before retiring an old one. Add the new entry to your `[platform.snapshot_keys]` config block before the platform starts signing with it. Multiple active keys may coexist.
- **`weights_version`**: changes when the subnet owner bumps the on-chain weight version. The runtime detects a mismatch at startup and fails closed by default on `finney`.
- **Commit-reveal**: not supported in Phase 1. If the subnet enables commit-reveal at the chain level the runner will fail closed (`chain.commit_reveal_enabled`).
- **Activity cutoff**: respected by the scheduler. A cycle that arrives too close to the cutoff window will be skipped to avoid an out-of-bounds submission.

For deployment on each environment see the dedicated guides under [`deployment/`](./deployment/).
