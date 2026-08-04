# Security Policy

This document describes how to report vulnerabilities affecting the Prometheon Phase 1 subnet code and what falls inside its responsibility boundary.

## Reporting a Vulnerability

Please report security issues **privately** rather than through public GitHub issues:

- Open a **GitHub Security Advisory** at https://github.com/BitSpaceorganization/prometheon_v1/security/advisories/new, or
- Email the project maintainers at the contact address listed on the [BitSpaceorganization](https://github.com/BitSpaceorganization) profile.

When reporting, please include:

1. A description of the issue and its impact.
2. Reproduction steps or a proof-of-concept.
3. The affected commit, branch, or release.
4. Any suggested remediation, if known.

We aim to acknowledge reports within **72 hours** and to provide a remediation timeline within **7 days** of confirming the issue.

## Coordinated Disclosure

We follow a coordinated-disclosure process. Once a fix is available and validators have had a reasonable window to upgrade, we publish a Security Advisory describing the issue and the remediation. We do not publish details before a fix is available and deployed.

## Supported Versions

| Branch / tag | Status | Receives security fixes |
|---|---|---|
| `main` | Active development | Yes |
| `release/testnet` | Pre-release | Yes |
| `release/mainnet` | Released | Yes |
| Other branches | Feature work | No |

## Scope

In scope for this project:

- The Python code under `src/prometheon/`, `neurons/`, and `scripts/`.
- The container images defined under `docker/`.
- The Bittensor weight submission path used by the validator.
- The cryptographic primitives used to sign and verify identity, rotation, recovery, and API request payloads.
- Snapshot signature verification and `records_hash` / `page_hash` integrity checks on the validator side.
- Resource isolation and credential handling on the validator host.

Out of scope for this repository:

- The BitFan platform itself (account systems, anti-farming detection, snapshot generation, Ops Console, Audit Console).
- The Bittensor chain and its consensus.
- The `bittensor`, `bittensor_wallet`, `substrateinterface`, `cryptography`, and `rfc8785` upstream packages; please report issues there to their respective projects.

If a vulnerability spans the subnet and the BitFan platform, report it through the channels above and we will coordinate with the platform team.

## Operational Reminders for Validators

- Never commit wallet directories, seed phrases, private keys, API tokens, or snapshot signing keys to any repository — public or private.
- Run validators with non-privileged users where possible and restrict filesystem permissions on `.bittensor/`, `.validator-state/`, and any credential files.
- Validate the `platform_key_id` configuration against the announcement channel before trusting a new Platform signing key.
- Treat any unexpected `chain.commit_reveal_enabled` change as a high-severity event and stop submissions until investigated.

## License

This security policy is published under the same [MIT License](./LICENSE) as the rest of the repository.
