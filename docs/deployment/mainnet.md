# Mainnet Deployment

Mainnet runs against the production Bittensor chain (`finney`) and the production BitFan platform (`bitfan-production`). The default posture is **fail-closed** on every policy switch — production validators do not silently relax safety checks.

This guide is the operational checklist; the underlying mechanism is described in [`../scoring.md`](../scoring.md) and [`../burn-policy.md`](../burn-policy.md).

---

## Prerequisites

- A Bittensor wallet registered on the Prometheon mainnet netuid, with a chain-issued validator permit.
- A validator API token issued by the **production** BitFan platform.
- The production platform's current Ed25519 signing public key(s) + `platform_key_id`(s).
- The operator-provided `version_key`.

---

## Setup

```bash
git clone https://github.com/NousIntelligence/prometheon_v1
cd prometheon_v1
uv sync
cp configs/finney.example.toml ~/prometheon-finney.toml
```

Edit `~/prometheon-finney.toml`. **Do not relax fail-closed defaults**:

```toml
[chain]
network = "finney"
netuid = <mainnet_netuid>
version_key = <operator_provided_version_key>
fail_on_weights_version_mismatch = true   # leave as true
allow_legacy_sdk_without_mechid = false   # leave as false; this is local-only

[platform]
base_url = "https://subnet-api.bitfan.ai"
platform_instance_id = "bitfan-production"
api_token_env = "PROMETHEON_VALIDATOR_API_TOKEN"

[platform.snapshot_keys."platform-main-2026-05"]
public_key = "0x<production_ed25519_public_key>"
not_before = "2026-05-01T00:00:00Z"
not_after  = "2026-09-01T00:00:00Z"
status     = "active"
```

The runtime refuses to start when:

- `allow_legacy_sdk_without_mechid` is true on any non-local network.
- The `[platform.snapshot_keys]` map is empty.
- Any locked Phase 1 constant is overridden.

---

## Token and Secret Handling

- Inject `PROMETHEON_VALIDATOR_API_TOKEN` via your process supervisor / secret manager, not via shell history.
- Never commit `.validator-state/`, `~/.bittensor/wallets/`, or any config file containing real values.
- Restrict filesystem permissions on the wallet directory and the state directory to the validator service user only.

---

## Run As a Long-Running Service

The runner is a single Python process. Wrap it with your supervisor of choice (systemd, runit, supervisord). Example systemd unit:

```ini
[Unit]
Description=Prometheon validator
After=network.target

[Service]
Type=simple
User=prometheon
WorkingDirectory=/opt/prometheon
Environment=PROMETHEON_VALIDATOR_API_TOKEN_FILE=/run/secrets/prometheon-validator-token
ExecStart=/opt/prometheon/.venv/bin/prometheon validator run \
    --config /etc/prometheon/finney.toml \
    --state-directory /var/lib/prometheon/state
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
```

(Substitute your own secret-injection mechanism for `EnvironmentFile=` or a `systemd-creds`-backed solution as appropriate.)

---

## Monitoring

| Signal | Where | Action |
|---|---|---|
| `cycle_submitted` events | NDJSON event log | Healthy. Expected at the configured cadence. |
| `cycle_no_valid_weight_target` | NDJSON event log | Investigate: either every candidate failed eligibility, or the burn hotkey is missing from the metagraph at the moment of submission. |
| `cycle_failed` | NDJSON event log + state file | Investigate immediately. Codes starting with `chain.` or `SNAPSHOT_` indicate categorical failures that won't self-heal. |
| Lack of new events for > 1 hour | Tail `.validator-state/events.ndjson` | Process probably died; check `journalctl -u prometheon-validator`. |

Run `prometheon status` as a quick read-only sanity check.

---

## Snapshot Key Rotation

When the platform rotates its Ed25519 signing key:

1. The platform team announces the new `platform_key_id`, public key, and validity window in advance.
2. Add the new entry to `[platform.snapshot_keys.*]` in your config **before** the platform switches to it. Multiple active keys may coexist.
3. The validator automatically picks up the new key on the next config reload (or on the next restart).
4. The old key remains trusted until the platform-side retention window expires; its config entry can then be removed (or marked `status = "revoked"`).

If a key compromise is announced, mark the affected `platform_key_id` as `status = "revoked"` immediately — revoked keys are rejected regardless of the validity window.

---

## `version_key` Mismatch Handling

`fail_on_weights_version_mismatch = true` is the default on mainnet. If the chain's `weights_version` differs from your configured `version_key`:

- The runner emits `chain.weights_version_mismatch` and fails closed.
- Coordinate with the subnet owner before relaxing the policy. A wrong `version_key` likely means your config is out of date with respect to a subnet-level change.

---

## Commit-Reveal

Phase 1 does not implement commit-reveal. If the chain enables commit-reveal at the subnet level the runner fails closed (`chain.commit_reveal_enabled`). Commit-reveal support is reserved for a future implementation.

---

## When To Restart

- After updating the validator config (the runtime does not yet hot-reload config; restart is the safe path).
- After adding or revoking a snapshot key.
- After a `chain.weights_version_mismatch` is resolved upstream.

A clean restart preserves the persisted state and resumes from the most recent cycle's outputs.
