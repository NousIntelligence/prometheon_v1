# Security

This document summarises Prometheon Phase 1's security posture: what is signed, what is hashed, what is verified, how the validator defends against the most likely attacks, and the operator-facing failure code catalog.

The full cryptographic specification is the source of truth — what follows is a readable companion.

---

## Signed Trust Roles

| Algorithm | Used by | Purpose |
|---|---|---|
| **SR25519** (Bittensor) | Miners, validators | Hotkey and coldkey signatures over identity, rotation, recovery, and API request payloads. |
| **Ed25519** | BitFan platform | Snapshot signatures over daily snapshot envelopes and detailed-mode manifests. |

These two trust roles are intentionally separate. A Bittensor hotkey can never be used to sign a snapshot; a platform Ed25519 key can never be used to sign an identity payload. The two algorithms make accidental misuse cryptographically impossible.

---

## Canonical JSON

Every signed and every internally hashed payload uses **RFC 8785 JSON Canonicalization Scheme (JCS)**. Both the subnet and the platform must produce byte-identical canonical bytes from the same logical object.

Rules enforced on the subnet side:

- UTF-8 bytes only.
- Deterministic object-key sort.
- Arrays preserve input order.
- **Floats are rejected** in every signed and hashed payload. All numeric fields are integers.
- `NaN`, `Infinity`, and `-Infinity` are rejected at parse time.
- Duplicate JSON object keys are rejected at parse time.

The validator side uses the pinned `rfc8785==0.1.4` package. The platform side may use any conforming implementation in any language as long as the byte output matches against the shared fixture suite.

---

## Domain-Prefixed Bytes

Every signed payload is wrapped in a domain prefix before signing or hashing:

```text
bytes_to_sign_or_hash = ASCII(domain) + b"\n" + JCS(payload_object)
```

The `domain` is also embedded inside `payload_object["domain"]`. The verifier checks both. This double binding intentionally defends against cross-protocol replay — if a future implementer accidentally omits the embedded-domain check on one layer, the prefix-domain check on the other still catches the mismatch.

Domains in Phase 1:

```text
PROMETHEON_IDENTITY_VERIFY_V1
PROMETHEON_HOTKEY_ROTATION_V1
PROMETHEON_HOTKEY_RECOVERY_V1
PROMETHEON_API_REQUEST_V1
PROMETHEON_SNAPSHOT_V1
PROMETHEON_RECORD_SET_V1
PROMETHEON_RECORD_PAGE_V1
PROMETHEON_WEIGHT_PLAN_V1
```

---

## Encoding

| Field | Format |
|---|---|
| SHA-256 hash | `"0x"` + 64 lowercase hex characters |
| SR25519 / Ed25519 signature | `"0x"` + 128 lowercase hex characters |
| Ed25519 public key | `"0x"` + 64 lowercase hex characters |
| Timestamp | `YYYY-MM-DDTHH:MM:SSZ` (UTC, no fractional seconds, no offsets other than `Z`) |
| Date | `YYYY-MM-DD` |

Base64 and uppercase hex are rejected everywhere.

---

## Cross-Environment Replay Defense

Every signed object carries **both**:

```text
chain_network         ∈ { "local", "test", "finney" }
platform_instance_id  stable string, e.g. "bitfan-staging" / "bitfan-production"
```

The validator (and the platform) reject any object whose pair does not match the configured environment. A staging-signed snapshot replayed against a production validator is rejected before any signature or hash check. A finney-signed identity payload replayed against a testnet validator is rejected for the same reason.

---

## Snapshot Verification

For every snapshot the validator runs, in this order:

1. **Parse**: Pydantic strict validation; locked policy constants (`daily_score_cap`, `active_member_score_threshold`, `min_active_members_for_reward`, `top_k`) must match the Phase 1 values; floats are rejected.
2. **Trusted key lookup**: `platform_key_id` must be configured, `status == "active"`, and the snapshot's `generated_at` must fall inside `[not_before, not_after]`.
3. **Ed25519 signature**: `verify(public_key, signature, b"PROMETHEON_SNAPSHOT_V1\n" + JCS(snapshot_without_platform_signature))`.
4. **`records_hash`**: recomputed from the canonical record-set envelope and compared.
5. **(Detailed mode only)**: every page's `page_hash` matches the manifest entry; cross-page record ordering is preserved; no duplicate `user_ref` appears in the stream.

Any failure aborts the cycle and is recorded in the persisted state plus the NDJSON event log.

---

## API Request Signing

Every validator request to the snapshot endpoints is signed under `PROMETHEON_API_REQUEST_V1`. Headers:

```text
Authorization: Bearer <api_token>
X-Prometheon-Hotkey: <validator_hotkey_ss58>
X-Prometheon-Nonce: 0x<≥16 random bytes>
X-Prometheon-Timestamp: <ISO 8601 UTC Z>
X-Prometheon-Request-Signature: 0x<128 lowercase hex chars>
```

Skew window: **300 seconds**. Nonce TTL: **600 seconds**.

The signed canonical payload binds: method, exact path, query hash, body hash, timestamp, nonce, `chain_network`, `platform_instance_id`, netuid, role, mode, validator hotkey, API token hash. Tampering with any of these (header, body, path, or query) invalidates the signature.

---

## Defenses At a Glance

| Attack | Defense |
|---|---|
| Replay | Nonce + timestamp + `chain_network` + `platform_instance_id` in every signed object. |
| Wrong-environment replay | `chain_network` + `platform_instance_id` mismatch rejects before any crypto. |
| Stale UID hijack | UIDs re-resolved against the current metagraph immediately before submission. |
| Burn-target hijack | Burn target configured as `burn_hotkey`; missing-hotkey cases fall through to B/D. |
| API token theft | Snapshot endpoints require both the token AND a fresh hotkey signature; the token alone is insufficient. |
| Hotkey theft | Platform-state mutation requires the API token AND the hotkey signature AND a valid nonce; the hotkey alone is insufficient. |
| Snapshot tampering | Ed25519 signature + `records_hash` + (detailed) per-page hashes. Any byte change invalidates the chain. |
| Cross-protocol reuse | Eight distinct signing domains, double-bound (external prefix + embedded field). |
| Floating-point divergence | All in-engine arithmetic is integer-only; chain-boundary u16 conversion is also integer largest-remainder. |
| Commit-reveal silent fallback | Detection at startup; fail closed if commit-reveal is enabled on the chain. |
| Missing `mechid` silent fallback | Detection at startup; fail closed outside `local` development. |
| Platform key compromise | Per-key `status` field; revoking marks the key inactive immediately, no waiting for `not_after`. |
| Manual recovery abuse | 2FA + Discord handle hash + Ops Console approval + 24-hour pending + 14-day cooldown. |

---

## Failure Code Catalog

### Identity / Platform errors

```text
AUTH_INVALID_TOKEN          API token unknown / expired / revoked.
AUTH_TOKEN_SCOPE_MISSING    Token lacks the required scope for this action.
ACCOUNT_NOT_VERIFIED        Account has not been verified for the requested role.
ACCOUNT_LOCKED_OUT          10 failed verification attempts → 24-hour lockout.
NONCE_MISSING / NONCE_EXPIRED / NONCE_ALREADY_USED / NONCE_CONTEXT_MISMATCH
SIGNATURE_INVALID
HOTKEY_ALREADY_LINKED       New hotkey is already linked to another account for that role.
HOTKEY_NOT_LINKED           Old hotkey does not match the platform-side state for that role.
ROTATION_COOLDOWN_ACTIVE    7-day cooldown not yet elapsed.
RECOVERY_COOLDOWN_ACTIVE    14-day recovery cooldown not yet elapsed.
RECOVERY_PENDING            Earlier recovery has not yet activated.
SNAPSHOT_NOT_READY / SNAPSHOT_MODE_INVALID / SNAPSHOT_DATE_INVALID / SNAPSHOT_ACCESS_DENIED
ENVIRONMENT_MISMATCH        chain_network or platform_instance_id mismatch.
PATH_MISMATCH               Request path does not match the signed payload's path.
```

### Validator runtime errors

```text
SNAPSHOT_SIGNATURE_ERROR    Ed25519 signature did not verify.
SNAPSHOT_SCHEMA_ERROR       Snapshot failed Pydantic validation (missing field, locked-constant deviation, etc.).
SNAPSHOT_RECORDS_HASH_ERROR records_hash recomputation mismatch.
SNAPSHOT_PAGE_HASH_ERROR    Detailed-mode page hash mismatch.
SNAPSHOT_PAGE_ORDER_ERROR   Detailed records out of (miner_hotkey ASC, user_ref ASC) order.
SNAPSHOT_DUPLICATE_USER_REF One user_ref appeared on more than one page.
SNAPSHOT_UNKNOWN_KEY_ID     platform_key_id not in trusted-key map.
SNAPSHOT_KEY_REVOKED        Trusted-key entry has status != "active".
SNAPSHOT_KEY_OUTSIDE_VALIDITY  generated_at outside [not_before, not_after].
NO_VALID_WEIGHT_TARGET      Engine returned status=no_valid_weight_target (Case D).
chain.commit_reveal_enabled      Subnet has commit-reveal on; Phase 1 fails closed.
chain.weights_version_mismatch   Chain's weights_version differs from configured version_key.
chain.mechid_missing             Installed SDK lacks mechid and legacy override is not allowed.
chain.set_weights_failed         SDK-level submission error.
```

### Signature primitive errors

```text
signature.invalid_format       Hex shape wrong (length, prefix, case).
signature.verification_failed  Cryptographic check failed.
signature.address_mismatch     SS58 cannot be parsed or does not match payload.
signature.domain_mismatch      Embedded domain does not match expected domain.
```

---

## Operator Hygiene

- Never commit wallet directories, seed phrases, private keys, API tokens, snapshot signing keys, or `.validator-state/` to any repository.
- Pin dependencies via `uv.lock` and prefer hash-verified installs in production builds.
- Run validators with non-privileged users where possible and restrict filesystem permissions on `.bittensor/`, `.validator-state/`, and any credential files.
- Watch the NDJSON event log; any `cycle_failed` deserves investigation, not a silent retry.

---

For the reporting procedure for vulnerabilities, see [`../SECURITY.md`](../SECURITY.md).
