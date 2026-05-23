# Operator Runbook

This runbook covers the production scenarios validator operators are most likely to encounter. Each entry has a **detection** signal (what you see), a **diagnosis** path (what to check), and an **action** (what to do).

This is operator-facing only — for internal mechanism details see [`scoring.md`](scoring.md) and [`burn-policy.md`](burn-policy.md).

---

## Snapshot signature failed (`SNAPSHOT_*` errors)

### `SNAPSHOT_UNKNOWN_KEY_ID`

- **Detection:** `cycle_failed` events with code `SNAPSHOT_UNKNOWN_KEY_ID` in `.validator-state/events.ndjson`. Validator stops submitting.
- **Diagnosis:** The platform is signing snapshots with a `platform_key_id` your config does not list under `[platform.snapshot_keys.*]`. Most common cause: a routine platform key rotation announced but not yet applied to your config.
- **Action:** Pull the latest `platform_key_id` + public key from the platform team's announcement channel and add the new entry under `[platform.snapshot_keys.*]`. Multiple active keys may coexist. Restart the validator.

### `SNAPSHOT_KEY_REVOKED`

- **Detection:** `cycle_failed` events with code `SNAPSHOT_KEY_REVOKED`.
- **Diagnosis:** A key in your trusted map has `status = "revoked"`. The snapshot is signed by it.
- **Action:** Treat as a security incident: stop accepting snapshots signed by the revoked key (the runtime already refuses), confirm with the platform team that the rotation is complete, and remove the revoked entry from your config.

### `SNAPSHOT_KEY_OUTSIDE_VALIDITY`

- **Detection:** Same event type, code `SNAPSHOT_KEY_OUTSIDE_VALIDITY`.
- **Diagnosis:** The snapshot's `generated_at` is before `not_before` or after `not_after` of the matching trusted key.
- **Action:** Verify your system clock is correct (NTP drift can cause spurious failures). If the clock is right, the key really is past its validity window and the platform team is signing with an expired key — coordinate immediately.

---

## `cycle_no_valid_weight_target` events

- **Detection:** Validator runs cleanly but does not submit weights; events log shows `cycle_no_valid_weight_target` with `burn_case="D"`.
- **Diagnosis:** Case D — no eligible miners passed the snapshot's filters AND the configured burn hotkey is not in the current metagraph. The runtime fails closed here by design.
- **Action:** Check whether the burn hotkey from `[burn].burn_hotkey` is registered on the netuid (`btcli`). If not, work with the subnet owner to register it; the runtime cannot route Case A or Case C weights without it. If the burn hotkey *is* registered, then the snapshot legitimately had zero eligible miners — verify with the platform team that snapshot generation is working before assuming the validator is at fault.

---

## `chain.weights_version_mismatch`

- **Detection:** `cycle_failed` with code `chain.weights_version_mismatch`.
- **Diagnosis:** Chain's current `weights_version` differs from `chain.version_key` in your config. This is the subnet owner's force-rotation mechanism — they've bumped the on-chain value and your config is stale.
- **Action:** Get the new `version_key` from the subnet owner, update your config, restart. Do **not** set `fail_on_weights_version_mismatch = false` on mainnet to bypass — that just hides the underlying skew and your submissions may then be silently rejected on chain.

---

## `chain.commit_reveal_enabled`

- **Detection:** `cycle_failed` with code `chain.commit_reveal_enabled`.
- **Diagnosis:** The subnet has commit-reveal turned on, but Phase 1 only implements plain `set_weights`.
- **Action:** Coordinate with the subnet owner to disable commit-reveal on the netuid, OR wait for a future Prometheon release that adds commit-reveal support. Phase 1 cannot run against a commit-reveal-enabled subnet by design.

---

## Validator runs but no `cycle_submitted` events appear

- **Detection:** `prometheon status` shows the validator started, but `events.ndjson` only shows `cycle_no_valid_weight_target` or `cycle_dry_run` entries.
- **Diagnosis:** Either every cycle hit Case D (see above) or `validator.dry_run = true` / `validator.submit_weights = false` is in the config.
- **Action:** Re-read the config and confirm both flags are set to the intended values for the network you're running.

---

## Validator dies repeatedly under systemd / supervisord

- **Detection:** Process keeps restarting; `journalctl -u prometheon-validator` shows the same error each iteration.
- **Diagnosis:** A configuration or environment issue that does not self-heal.
- **Action:** Run one cycle in the foreground with `prometheon validator run --config <path> --once` to capture the full stack trace, then resolve the root cause (most often: missing `PROMETHEON_VALIDATOR_API_TOKEN` env var, unreachable platform `base_url`, or wallet hotkey not loadable).

---

## Pre-flight checklist before any production deployment

- [ ] `prometheon verify-validator` was run successfully against the platform.
- [ ] The wallet hotkey is registered on the netuid with a chain-issued validator permit.
- [ ] `PROMETHEON_VALIDATOR_API_TOKEN` is set via the supervisor, never via shell history.
- [ ] At least one full cycle ran cleanly with `--once` in dry-run mode before enabling submission.
- [ ] Every Ed25519 signing key currently in use by the platform is listed under `[platform.snapshot_keys.*]`.
- [ ] System clock is synchronised (NTP healthy).

---

For deployment-specific setup see [`deployment/mainnet.md`](deployment/mainnet.md), [`deployment/testnet.md`](deployment/testnet.md), and [`deployment/localnet.md`](deployment/localnet.md).
