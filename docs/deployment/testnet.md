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

Edit `~/prometheon-testnet.toml` — only the `[wallet]` section needs to change to your own wallet name + hotkey. Every other field is the subnet-wide testnet baseline already filled in:

```toml
[chain]
network = "test"
netuid = 481
version_key = 0
fail_on_weights_version_mismatch = false   # relaxed on testnet by default
allow_legacy_sdk_without_mechid = false    # local-only flag; do not relax

[wallet]
name = "<your wallet name>"
hotkey = "<your hotkey name>"

[platform]
base_url = "https://subnet-api.bitfan.ai"
platform_instance_id = "bitfan-staging"
api_token_env = "PROMETHEON_VALIDATOR_API_TOKEN"

[platform.snapshot_keys."platform-staging-2026-05"]
public_key = "0xff6ebda35c55062e4caa4551e844dbfe7af11ab72cfc713bd6d8edaa20cb4028"
not_before = "2026-05-10T00:00:00Z"
not_after  = "2026-11-22T00:00:00Z"
status     = "active"

[burn]
# INERT — nothing reads this section. The live burn target is the subnet
# owner hotkey read from chain (which is this same value on 481) and the
# rate is a locked constant. Retained only so an existing TOML parses.
enabled = true
burn_hotkey = "5GTCFZ5YNUNUF5XdoFP4gnFMrEud3ddmvu8HGEMHf97npHfZ"
manual_burn_rate_ppm = 150000
```

---

## Verify Your Validator Account

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<staging_token>"
uv run prometheon verify-validator \
    --username <user> --email <email> \
    --wallet-name <wallet> --wallet-hotkey <hotkey> \
    --platform-base-url https://subnet-api.bitfan.ai \
    --platform-instance-id bitfan-staging \
    --chain-network test \
    --netuid 481
```

---

## Run the ingest service first

The live weight path (`weight_source = "events"`, the default) scores from
a local event store that the platform pushes into. **Without it the runner
cannot produce weights at all** — the first cycle fails with
`validator.event_weight_source` before any chain call.

So before `validator run`, stand up the ingest endpoint and register it:

```bash
uv run prometheon ingest serve \
    --config ~/prometheon-testnet.toml \
    --db .validator-state/events.sqlite \
    --host 127.0.0.1 --port 8541

uv run prometheon ingest register-endpoint \
    --ingest-url https://ingest.<your-domain>/ \
    --config ~/prometheon-testnet.toml
```

Full setup — TLS reverse proxy, registration, catch-up, completeness
checks — is in the [Decentralized Validation guide](../decentralized-validation.md).
`events_db` in your config must be the same path you pass to `ingest serve`.

*(To run without the event stream, set `weight_source = "snapshot"`. That is
the retained incident fallback, not the supported steady state.)*

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
