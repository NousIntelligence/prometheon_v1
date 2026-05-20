# Localnet Deployment

Localnet is for development against a local Bittensor subtensor process. Use it to exercise the full validator cycle without touching testnet or mainnet.

---

## Prerequisites

- A local Bittensor subtensor (typically run from the upstream Bittensor repository).
- A local BitFan platform mock or staging instance reachable at a known base URL.
- Python `>=3.10,<3.15`, `uv` (or `pip`).

---

## Setup

```bash
git clone https://github.com/NousIntelligence/prometheon_v1
cd prometheon_v1
uv sync --group dev
cp configs/localnet.example.toml ~/prometheon-local.toml
```

Edit `~/prometheon-local.toml`. Local-only overrides are accepted here:

```toml
[chain]
network = "local"
netuid = 1
version_key = 0
fail_on_weights_version_mismatch = false
allow_legacy_sdk_without_mechid = false   # set true if you must run an older SDK locally

[platform]
base_url = "http://127.0.0.1:8080"
platform_instance_id = "bitfan-local"
api_token_env = "PROMETHEON_VALIDATOR_API_TOKEN"

[platform.snapshot_keys."platform-local-2026"]
public_key = "0x<your_local_platform_ed25519_public_key>"
not_before = "2026-01-01T00:00:00Z"
not_after  = "2027-01-01T00:00:00Z"
status     = "active"
```

Register a hotkey on your local subnet via `btcli` against your local node.

---

## Run

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<local_token>"
uv run prometheon validator run --config ~/prometheon-local.toml --once
```

`--once` is the recommended shape for development — it runs exactly one cycle and prints the resulting `WeightPlan`.

Inspect state:

```bash
uv run prometheon status
```

---

## What Local Lets You Skip

- The 7-day rotation cooldown and 14-day recovery cooldown are still enforced by the platform mock; configure the mock to short-circuit them if you need to test rotation flows quickly.
- The chain hyperparameter checks still run; configure your local subtensor to expose plausible values for `weights_version`, `min_allowed_weights`, `max_weights_limit`, `weights_rate_limit`, `activity_cutoff`.

---

## Troubleshooting

- **`could not connect to subtensor`** — the SDK could not reach your local node; verify `bittensor.Subtensor(network="local")` works in a Python REPL first.
- **`SNAPSHOT_UNKNOWN_KEY_ID`** — the `platform_key_id` your mock signs with is not in the config's `[platform.snapshot_keys.*]` table.
- **`chain.commit_reveal_enabled`** — your local subtensor has commit-reveal turned on; disable it on the local chain or run the runner with a fresh local subtensor that does not enable it.
