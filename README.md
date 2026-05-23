# Prometheon — Phase 1

A Bittensor subnet that converts BitFan platform-qualified user activity into deterministic on-chain weights.

> **Phase scope.** This repository implements **Phase 1** only. Future phases will ship in their own repositories (`prometheon_v2`, `prometheon_v3`, `prometheon_v4`) when those phase boundaries become active.

---

## What This Subnet Does

Prometheon does not score miner-submitted model output. Instead, the rewarded work is **real growth of BitFan Fan Groups**:

1. **Miners** verify a BitFan account, register a Bittensor hotkey, create a Fan Group, and bring users into it.
2. **BitFan** scores user activity over a rolling 14-day window with a daily score cap, produces a daily signed snapshot, and exposes it through an authenticated API.
3. **Validators** download the snapshot, verify its platform signature and integrity, run a pure deterministic integer weight engine against the current metagraph, and submit one weight vector to Bittensor.

The full data flow is:

```text
Platform-authenticated identity
+ Platform-signed daily activity snapshot
+ Validator-side deterministic integer transformation
+ Metagraph hotkey-to-UID resolution
+ Bittensor weight submission
```

Given the same signed snapshot, the same metagraph state, and the same configuration, every compliant validator produces the same weight vector. This is by design.

---

## High-Level Mechanism

For each daily snapshot the validator:

1. Drops miners not currently registered in the metagraph.
2. Drops miners with fewer than 3 active members (a member is active when their 14-day score is strictly greater than 50).
3. Drops the configured burn hotkey from the regular candidate pool and drops miners with non-positive score.
4. Ranks the remaining candidates by `(score DESC, active_members DESC, hotkey ASC)`.
5. Selects the top `min(10, candidate_count)` winners.
6. Applies the burn policy (one of four deterministic cases) and allocates a fixed pool of integer weight units across winners and the burn target using largest-remainder allocation.
7. Resolves all targets to current UIDs and submits via `set_weights`.

Detailed scoring, the four burn cases, snapshot formats, and the platform integration contract are described under [`docs/`](./docs/).

---

## Repository Layout

```text
src/prometheon/   # Python package (security, identity, platform, chain, mechanisms, validator, miner, telemetry)
neurons/          # Bittensor entrypoints (miner.py, validator.py)
configs/          # Example TOML configuration files (placeholders for deployment values)
docs/             # Public documentation
tests/            # Unit, contract, integration test suites and fixtures
scripts/          # Operational shell scripts
docker/           # Container images for miner and validator
```

See [`docs/overview.md`](./docs/overview.md) for a walkthrough.

---

## Installation

Requirements:

- Python `>=3.10,<3.15` (development target: 3.11)
- A Bittensor wallet (`btcli`-managed)
- Docker (only required for the containerised deployment path)

Using [uv](https://github.com/astral-sh/uv):

```bash
uv sync
```

Using pip:

```bash
pip install -e .
```

---

## Quick Start

### Miner

```bash
prometheon verify-miner \
  --username <bitfan_username> \
  --email <bitfan_email> \
  --api-token <bitfan_api_token> \
  --wallet.name <wallet> \
  --wallet.hotkey <hotkey> \
  --netuid <netuid> \
  --network <local|test|finney>
```

After verification, create and grow your BitFan Fan Group. The miner is rewarded through scored activity from the users you bring in, not through running a daemon. See [`docs/miner.md`](./docs/miner.md).

### Validator

```bash
prometheon verify-validator \
  --username <bitfan_username> \
  --email <bitfan_email> \
  --api-token <bitfan_api_token> \
  --wallet.name <wallet> \
  --wallet.hotkey <hotkey> \
  --netuid <netuid> \
  --network <local|test|finney>

prometheon validator run \
  --config configs/finney.example.toml \
  --wallet.name <wallet> \
  --wallet.hotkey <hotkey> \
  --netuid <netuid> \
  --network <local|test|finney>
```

See [`docs/validator.md`](./docs/validator.md) and [`docs/deployment/`](./docs/deployment/).

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/overview.md`](./docs/overview.md) | Architecture and end-to-end data flow |
| [`docs/miner.md`](./docs/miner.md) | Miner setup, Fan Group operation, expected rewards |
| [`docs/validator.md`](./docs/validator.md) | Validator setup, snapshot modes, weight submission |
| [`docs/platform-api.md`](./docs/platform-api.md) | Public-facing description of the BitFan ↔ subnet API contract |
| [`docs/scoring.md`](./docs/scoring.md) | 14-day window, active-member threshold, top-K selection |
| [`docs/burn-policy.md`](./docs/burn-policy.md) | Burn target, four allocation cases, missing-target fallback |
| [`docs/hotkey-rotation.md`](./docs/hotkey-rotation.md) | Normal rotation, coldkey recovery, manual recovery |
| [`docs/security.md`](./docs/security.md) | Signing primitives, replay defenses, key rotation |
| [`docs/deployment/`](./docs/deployment/) | Localnet, testnet, mainnet deployment guides |

---

## Project Status

Phase 1 — under active development. Mechanism is fixed; deployment values are placeholders pending the testnet bring-up.

| Phase | Repository | Status |
|---|---|---|
| Phase 1 — growth incentive | `NousIntelligence/prometheon_v1` | **In development** |
| Phase 2 | future | Reserved |
| Phase 3 | future | Reserved |
| Phase 4 | future | Reserved |

---

## License

[MIT](./LICENSE) — © 2026 NousIntelligence.

## Reporting Vulnerabilities

See [`SECURITY.md`](./SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
