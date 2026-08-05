# Mainnet Deployment

Mainnet runs against the production Bittensor chain (`finney`) and the production BitFan platform (`bitfan-production`). The default posture is **fail-closed** on every policy switch — production validators do not silently relax safety checks.

This guide is the operational checklist; the underlying mechanism is described in [`../scoring.md`](../scoring.md) and [`../burn-policy.md`](../burn-policy.md).

---

## Prerequisites

- A Bittensor wallet registered on the Prometheon mainnet netuid, with a chain-issued validator permit.
- A validator API token issued by the **production** BitFan platform, carrying `ingest:register` and `events:read` (the live weight path) — plus `snapshot:read:*` if you intend to keep the fallback usable.
- **A running, registered ingest endpoint.** The live weight source is the local event store; without it the runner cannot produce weights. Follow [`decentralized-validation.md`](../decentralized-validation.md) before the first `validator run`, and make `[validator] events_db` match the path given to `ingest serve --db`.
- The production platform's current Ed25519 signing public key(s) + `platform_key_id`(s).
- The operator-provided `version_key`.

---

## Setup

```bash
git clone https://github.com/BitSpaceorganization/prometheon_v1
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

A validator is **two** processes, not one: `ingest serve` writes the event
store, `validator run` reads it and submits weights. Ready-made units for both
are in [`deploy/systemd/`](../../deploy/systemd/) — copy them, adjust `User`
and the paths, and enable both:

```bash
# 1. Service user and directories. The units run as `prometheon`; nothing in
#    this sequence works until that account exists.
sudo useradd --system --create-home --home-dir /home/prometheon \
    --shell /usr/sbin/nologin prometheon
sudo install -d -m 0755 -o prometheon -g prometheon /var/lib/prometheon
# -o/-g matter: without them the directory is root:root 0750 and the
# service user cannot traverse it, so neither process ever reaches the
# config however permissive the file itself is.
sudo install -d -m 0750 -o root -g prometheon /etc/prometheon

# 2. Deploy the code where the units expect it (/opt/prometheon/.venv/bin).
sudo git clone https://github.com/BitSpaceorganization/prometheon_v1 /opt/prometheon
sudo chown -R prometheon:prometheon /opt/prometheon
sudo -u prometheon sh -c 'cd /opt/prometheon && uv sync --no-dev'

# 3. Config and token. The token is the runner's only secret; mode 0600 keeps
#    it out of `systemctl show` and the process table.
sudo install -m 0640 -o root -g prometheon \
    ~/prometheon-finney.toml /etc/prometheon/validator.toml
sudo install -m 0600 /dev/null /etc/prometheon/validator.env
printf 'PROMETHEON_VALIDATOR_API_TOKEN=%s\n' "<token>" \
    | sudo tee /etc/prometheon/validator.env >/dev/null

# 4. The wallet must be readable by the service user, not by you.
sudo cp -r ~/.bittensor /home/prometheon/.bittensor
sudo chown -R prometheon:prometheon /home/prometheon/.bittensor

# 5. Install and start both units.
sudo cp /opt/prometheon/deploy/systemd/prometheon-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now prometheon-ingest prometheon-validator
```

Three things to get right, all of which fail quietly rather than loudly:

- **`[validator] events_db` must be an absolute path**, identical to the
  `ingest serve --db` argument. Relative paths resolve against each unit's
  working directory, so a mismatch gives the runner an empty store to score.
- **Only the runner needs the API token.** `ingest serve` authenticates each
  push by the platform's publisher signature; it holds no token of yours.
  Keep the secret out of the unit file — `EnvironmentFile=` with mode `0600`,
  or `systemd-creds`. There is no `..._TOKEN_FILE` variant; the runtime reads
  the variable named by `[platform] api_token_env`.
- **The ingest listener needs a TLS reverse proxy.** It binds loopback; the
  platform dials a public HTTPS URL and treats a redirect as delivery failure.

If you would rather not manage units, compose runs the same pair:

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<token>"
export PROMETHEON_CONFIG="$HOME/prometheon-finney.toml"
# Required: compose runs the containers as you, so your wallet and the state
# directory stay readable. Omitting them fails at project load.
export PROMETHEON_UID=$(id -u) PROMETHEON_GID=$(id -g)
mkdir -p ./validator-state
docker compose -f docker/compose.yaml up -d
```

---

## Monitoring

| Signal | Where | Action |
|---|---|---|
| `cycle_submitted` events | NDJSON event log | Healthy. Expected at the configured cadence. |
| `cycle_no_valid_weight_target` | NDJSON event log | Investigate: either every candidate failed eligibility, or the burn hotkey is missing from the metagraph at the moment of submission. |
| `cycle_failed` | NDJSON event log + state file | Investigate immediately. Codes starting with `chain.` or `SNAPSHOT_` indicate categorical failures that won't self-heal. |
| Lack of new events for > 1 hour | Tail `/var/lib/prometheon/state/events.ndjson` | Process probably died; check `journalctl -u prometheon-validator`. |

Run `prometheon status --state-directory /var/lib/prometheon/state` as a quick read-only sanity check.

---

## Snapshot Key Rotation

When the platform rotates its Ed25519 signing key:

1. The platform team announces the new `platform_key_id`, public key, and validity window in advance.
2. Add the new entry to `[platform.snapshot_keys.*]` in your config **before** the platform switches to it. Multiple active keys may coexist.
3. Restart **both** processes. The runtime does not reload config while running, and
   `ingest serve` and `validator run` read the same `[platform.snapshot_keys]` table.
   Restarting only the runner leaves ingest rejecting every push signed by the new key,
   so the store quietly stops advancing while the runner keeps scoring a stale window.
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
