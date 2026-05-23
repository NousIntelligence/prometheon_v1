# Testnet Deployment

Testnet brings real Bittensor consensus into the loop while the BitFan platform still points at its staging environment. Use it for cross-team integration testing before any mainnet deployment.

---

## Prerequisites

- A Bittensor wallet registered on the Prometheon testnet netuid.
- A validator API token issued against the BitFan **staging** platform (`bitfan-staging`).
- The staging platform's current Ed25519 signing public key + `platform_key_id`.

---

## Setup

```bash
git clone https://github.com/NousIntelligence/prometheon_v1
cd prometheon_v1
uv sync
cp configs/testnet.example.toml ~/prometheon-testnet.toml
```

Edit `~/prometheon-testnet.toml`:

```toml
[chain]
network = "test"
netuid = <testnet_netuid>
version_key = <operator_provided_version_key>
fail_on_weights_version_mismatch = false   # relaxed on testnet by default
allow_legacy_sdk_without_mechid = false    # local-only flag; do not relax

[platform]
base_url = "https://stg.api.bitfan.example"
platform_instance_id = "bitfan-staging"
api_token_env = "PROMETHEON_VALIDATOR_API_TOKEN"

[platform.snapshot_keys."platform-staging-2026"]
public_key = "0x<staging_ed25519_public_key>"
not_before = "2026-01-01T00:00:00Z"
not_after  = "2027-01-01T00:00:00Z"
status     = "active"
```

---

## Verify Your Validator Account

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<staging_token>"
uv run prometheon verify-validator \
    --username <user> --email <email> \
    --wallet-name <wallet> --wallet-hotkey <hotkey> \
    --platform-base-url https://stg.api.bitfan.example \
    --platform-instance-id bitfan-staging \
    --chain-network test \
    --netuid <testnet_netuid>
```

---

## Run

For multiple cycles with default sleep cadence:

```bash
uv run prometheon validator run --config ~/prometheon-testnet.toml
```

For N cycles:

```bash
uv run prometheon validator run --config ~/prometheon-testnet.toml --cycles 5
```

The runner persists state to `.validator-state/` in the current working directory by default. Override with `--state-directory` if needed.

---

## What Testnet Lets You Validate

- End-to-end snapshot fetch and verification against the real staging platform.
- Real metagraph synchronisation against the testnet chain.
- Real `set_weights` extrinsic submission on testnet.
- Cross-team interop on the shared fixture suite (the platform-side fixtures should now match your subnet-side fixtures byte-for-byte).

---

## Operational Checklist Before Promoting to Mainnet

- [ ] At least one full week of clean cycles with no `cycle_failed` events.
- [ ] At least one snapshot key rotation exercised: platform pre-deploys new `platform_key_id`, validator config updated, platform switches to new key, old key is later marked `revoked`.
- [ ] At least one `Case D` (no-eligible-miner + no-burn-hotkey) event handled correctly: runner did not submit, state recorded `no_valid_weight_target`, NDJSON log captured the event.
- [ ] At least one engine cycle that hits each of Cases A, B, and C, confirmed against the fixture matrix.
- [ ] `weights_version` and `mechid` policy switches behave as expected against testnet hyperparameters.

---

For mainnet operational discipline see [`mainnet.md`](./mainnet.md).
