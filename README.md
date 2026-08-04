# Prometheon — Phase 1

A Bittensor subnet that converts BitFan platform-qualified user activity into deterministic on-chain weights.

> **Phase scope.** This repository implements **Phase 1** only — the growth-incentive mechanism that converts BitFan Fan Group activity into deterministic on-chain weights. Future phases will ship in their own repositories (`prometheon_v2`, `prometheon_v3`, `prometheon_v4`) when those phase boundaries become active.

---

## What This Subnet Does

Prometheon does not score miner-submitted model output. Instead, the rewarded work is **real growth of BitFan Fan Groups**:

1. **A BitFan user creates and leads a Fan Group** and brings users into it. Leading a Fan Group requires only a platform account — not miner status.
2. **That Fan Group leader becomes a miner** by registering a Bittensor hotkey and running `verify-miner`, which requires they already lead a Fan Group and binds the hotkey to their account.
3. **BitFan** records every reward-relevant user action into four gap-free, publisher-signed event streams and pushes them to every registered validator.
4. **Validators** keep their own copy of those streams, **recompute** scores from the frozen open formula over a rolling 14-day window ending at the present moment, run a pure deterministic integer weight engine against the current metagraph, and submit one weight vector to Bittensor.

The full data flow is:

```text
Platform-authenticated identity
+ Platform-signed gap-free event streams (pushed to every validator)
+ Validator-side independent recomputation + deterministic integer transformation
+ Metagraph hotkey-to-UID resolution
+ Bittensor weight submission
```

Given the same stored records, the same metagraph state, and the same configuration, every compliant validator produces the same weight vector. Because each validator recomputes from records it holds itself, the platform cannot quietly change a number: doing so would require forging signatures held by many independent parties, or leaving a detectable gap in a monotonic sequence.

---

## High-Level Mechanism

On each cycle the validator:

1. Drops miners not currently registered in the metagraph.
2. Drops miners with fewer than 3 active members (a member is active when their 14-day score is strictly greater than 50).
3. Drops the burn target — the subnet owner hotkey, read from chain — from the regular candidate pool, and drops miners with non-positive score.
4. Ranks the remaining candidates by `(score DESC, active_members DESC, hotkey ASC)`.
5. Selects the top `min(10, candidate_count)` winners.
6. Applies the burn policy (one of four deterministic cases) and allocates a fixed pool of integer weight units across winners and the burn target using largest-remainder allocation.
7. Resolves all targets to current UIDs and submits via `set_weights`.

Detailed scoring, the four burn cases, the event-stream contract, and the platform integration contract are described under [`docs/`](./docs/).

---

## Repository Layout

```text
src/prometheon/   # Python package (security, identity, platform, chain, mechanisms, validator, miner, telemetry)
neurons/          # Bittensor entrypoints (miner.py, validator.py)
configs/          # Example TOML configuration files (placeholders for deployment values)
deploy/           # systemd units for the two validator processes
docs/             # Public documentation
tests/            # Unit, contract, integration test suites and fixtures
docker/           # Container image for the validator
```

See [`docs/overview.md`](./docs/overview.md) for a walkthrough.

---

## Installation

Requirements:

- Python `>=3.10,<3.15` (development target: 3.11)
- A Bittensor wallet (`btcli`-managed)
- Docker (only required for the containerised deployment path)

### Recommended: `uv`

[`uv`](https://github.com/astral-sh/uv) handles the virtual environment, Python interpreter, and dependency resolution in one step. Install `uv` if you do not have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then, from the repository root:

```bash
uv sync
```

All subsequent commands in this guide assume `uv run` in front of `prometheon` (for example, `uv run prometheon validator run …`). This keeps the project's pinned dependencies isolated from the system Python.

### Alternative: `pip` in a virtual environment

Modern Debian/Ubuntu (PEP 668) blocks `pip install` against the system Python. Use a venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

After activating the venv, `prometheon` is available directly on the path (no `uv run` prefix).

> **Do not** run `pip install -e . --break-system-packages` against the system Python; it can break apt-managed packages on the host.

---

## Prerequisites

Before either the miner or validator quick-start works, you need:

- [ ] A **BitFan account** on the appropriate environment (testnet uses the staging instance documented in [`configs/testnet.example.toml`](./configs/testnet.example.toml)).
- [ ] For miners only: **ownership of a Fan Group** on BitFan. Any signed-in user can create one — it does not require miner status — but `verify-miner` rejects you unless you already lead one.
- [ ] A **bootstrap token** for the **first verify** call only — issued through the BitFan portal at https://bitfan.ai/me/prometheon. Click *Get bootstrap token* with your role (miner or validator). The token is one-time, scoped to `identity:verify`, expires after one hour, and is auto-revoked the moment `verify-miner` / `verify-validator` succeeds.
- [ ] A **Bittensor wallet** created via `btcli` (coldkey + at least one hotkey).
- [ ] The hotkey **registered on the target netuid** (`btcli subnet register`).
- [ ] For validators only: a **chain-issued validator permit** on that netuid (the chain grants this after enough stake; check via `btcli wallet overview`).
- [ ] The target subnet must be operating in **plain `set_weights` mode** — i.e. the `commit_reveal_weights_enabled` hyperparameter on that netuid must be `False`. Phase 1 deliberately does not implement the commit-reveal weight submission scheme; if the subnet owner enables it, the runtime fails closed with `chain.commit_reveal_enabled`. See [`docs/validator.md` § Troubleshooting](./docs/validator.md#troubleshooting) for the operator-side fix.

The platform-side values you will need (URL, `platform_instance_id`, signing key, burn hotkey) are all pre-filled for testnet 481 in [`configs/testnet.example.toml`](./configs/testnet.example.toml) — you do not need to obtain them separately.

After the first `verify-*` succeeds, the bootstrap token is gone and your account holds the verified-role flag; subsequent operational tokens (for `snapshot:read`, etc.) are issued through the same BitFan portal under your now-verified role.

---

## Quick Start (testnet, subnet 481)

The flow below targets the live testnet deployment (`netuid = 481` on `chain_network = test`). For mainnet, see [`docs/deployment/mainnet.md`](./docs/deployment/mainnet.md).

### Miner

Phase 1 miners **do not run a daemon**. The reward path is real BitFan Fan Group growth, scored off-chain by the platform; the subnet-side miner command exists to (a) verify the hotkey against the platform once and (b) print status diagnostics.

**Order matters: own a Fan Group first.** `verify-miner` requires that you already lead a Fan Group on BitFan (any platform user can create one — no miner status needed). It binds your hotkey to that existing leadership; it does not create a Fan Group.

```bash
# 1. On the BitFan web app: create and grow a Fan Group (no miner status required).

# 2. Register your hotkey on the subnet.
btcli subnet register --netuid 481 --network test --wallet.name <wallet> --wallet.hotkey <hotkey>

# 3. Make your bootstrap token available via env var
#    (obtained from the BitFan portal — see Prerequisites above)
export PROMETHEON_MINER_API_TOKEN="<bootstrap token from BitFan portal>"

# 4. Verify your miner hotkey with the platform (one-time per hotkey).
#    The platform rejects this unless you already lead a Fan Group.
uv run prometheon verify-miner \
  --username <bitfan_username> \
  --email <bitfan_email> \
  --wallet-name <wallet> \
  --wallet-hotkey <hotkey> \
  --platform-base-url https://subnet-api.bitfan.ai \
  --platform-instance-id bitfan-staging \
  --chain-network test \
  --netuid 481
```

After successful verification your Fan Group's scored activity flows into the event streams validators score. See [`docs/miner.md`](./docs/miner.md).

### Validator

The validator is config-driven: every chain, wallet, and platform setting lives in a TOML file, and `prometheon validator run` only takes `--config`. Pre-pinned values for testnet 481 are already in [`configs/testnet.example.toml`](./configs/testnet.example.toml); you need to override `[wallet]` with your own wallet name and hotkey.

> **The ingest service is a prerequisite — a validator is two processes, not one.**
> The live weight source is a local event store the platform *pushes* into over a
> public HTTPS endpoint you operate, so `validator run` cannot produce weights until
> `prometheon ingest serve` is running and that endpoint is registered. Set that up
> first with [`docs/decentralized-validation.md`](./docs/decentralized-validation.md),
> then come back here. Skipping it gets you `validator.event_weight_source` on the
> first cycle.

```bash
# 1. Copy the pre-pinned testnet config to a local file
cp configs/testnet.example.toml ~/prometheon-testnet.toml
# Then edit the [wallet] section in ~/prometheon-testnet.toml to your wallet.

# 2. Make your bootstrap token available via env var
#    (obtained from the BitFan portal — see Prerequisites above)
export PROMETHEON_VALIDATOR_API_TOKEN="<bootstrap token from BitFan portal>"

# 3. Verify your validator hotkey with the platform (one-time per hotkey)
uv run prometheon verify-validator \
  --username <bitfan_username> \
  --email <bitfan_email> \
  --wallet-name <wallet> \
  --wallet-hotkey <hotkey> \
  --platform-base-url https://subnet-api.bitfan.ai \
  --platform-instance-id bitfan-staging \
  --chain-network test \
  --netuid 481

# 4. Run the validator
uv run prometheon validator run --config ~/prometheon-testnet.toml
```

`prometheon validator run` accepts `--once` (single cycle then exit, useful for sanity checks) and `--cycles N`. Without those flags, it loops on the schedule configured in `[scheduler]`.

See [`docs/validator.md`](./docs/validator.md) and [`docs/deployment/testnet.md`](./docs/deployment/testnet.md) for the operational details.

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/overview.md`](./docs/overview.md) | Architecture and end-to-end data flow |
| [`docs/miner.md`](./docs/miner.md) | Miner setup, Fan Group operation, expected rewards |
| [`docs/validator.md`](./docs/validator.md) | Validator setup, running both services, weight submission |
| [`docs/platform-api.md`](./docs/platform-api.md) | Public-facing description of the BitFan ↔ subnet API contract |
| [`docs/scoring.md`](./docs/scoring.md) | 14-day window, active-member threshold, top-K selection |
| [`docs/burn-policy.md`](./docs/burn-policy.md) | Burn target, four allocation cases, missing-target fallback |
| [`docs/hotkey-rotation.md`](./docs/hotkey-rotation.md) | Normal rotation, coldkey recovery, manual recovery |
| [`docs/security.md`](./docs/security.md) | Signing primitives, replay defenses, key rotation |
| [`docs/decentralized-validation.md`](./docs/decentralized-validation.md) | Event-stream ingest, open score recomputation, shadow mode |
| [`docs/deployment/`](./docs/deployment/) | Localnet, testnet, mainnet deployment guides |

---

## Project Status

Phase 1 is live on Bittensor testnet as **netuid 481**. The mechanism is fixed and the testnet baseline values are pinned in [`configs/testnet.example.toml`](./configs/testnet.example.toml).

| Phase | Repository | Status |
|---|---|---|
| Phase 1 — growth incentive | `NousIntelligence/prometheon_v1` | **Testnet (netuid 481)** |
| Phase 2 | future | Reserved |
| Phase 3 | future | Reserved |
| Phase 4 | future | Reserved |

---

## License

[MIT](./LICENSE) — © 2026 NousIntelligence.

## Reporting Vulnerabilities

See [`SECURITY.md`](./SECURITY.md).
