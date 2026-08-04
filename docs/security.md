# Security

This document summarises Prometheon Phase 1's security posture: what is signed, what is hashed, what is verified, how the validator defends against the most likely attacks, and the operator-facing failure code catalog.

The full cryptographic specification is the source of truth — what follows is a readable companion. **The CLI error renderer references the subsection anchors below by URL**; the subsection structure is therefore part of the public contract and should not be renamed without updating `src/prometheon/cli/renderer.py`.

---

## Signed Trust Roles

| Algorithm | Used by | Purpose |
|---|---|---|
| **SR25519** (Bittensor) | Miners, validators | Hotkey and coldkey signatures over identity, rotation, recovery, and API request payloads; the validator hotkey also countersigns sealed day digests under `PROMETHEON_DIGEST_ATTESTATION_V1`. |
| **Ed25519** | BitFan platform | Push-envelope signatures on the live event stream (`PROMETHEON_INGEST_PUSH_V1`) and sealed day-digest signatures (`PROMETHEON_DAY_DIGEST_V1`); on the snapshot fallback, signatures over daily snapshot envelopes and detailed-mode manifests. |

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

## API Tokens

Every request to the BitFan platform carries a Platform-issued bearer token:

```text
Authorization: Bearer <api_token>
```

API tokens are issued by the BitFan portal under the user's existing platform session. Tokens are role-scoped (miner / validator) and purpose-scoped (verify / rotate / recover / snapshot read / status read). The platform enforces scope server-side, so a stolen miner token cannot read a validator-only snapshot endpoint even if the rest of the request is otherwise well-formed.

The CLI never echoes a raw token to stdout/stderr and never persists one to the validator's `state.json` or `events.ndjson`. The CLI's `--verbose` trailer additionally redacts any value whose shape matches a known credential pattern (`github_pat_…`, `ghp_…`, `gho_…`, JWT, long opaque base64url, ≥64-char hex).

### Token Scopes

Phase 1 scope strings (used by `AUTH_TOKEN_SCOPE_MISSING`'s typed `details.required_scope` field):

```text
identity:verify:<miner|validator>
identity:rotate:<miner|validator>
identity:recover:<miner|validator>
snapshot:read:<aggregate|detailed>
status:read
```

A miner token must not grant snapshot access; a validator token must not grant miner identity mutation.

### API Request Signing

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

## Identity Payloads

The three identity flows (`verify-{miner,validator}`, `rotate-hotkey`, `recover-hotkey`) each carry a strictly-typed canonical payload. The CLI builds the payload, validates it against a Pydantic schema locally, then signs the canonical bytes. Any local validation failure surfaces as a subnet-side identity error (e.g., `identity.payload_invalid`) and never leaves the operator's machine.

### Identity Envelopes

The wire form of an identity request is the **envelope**:

```json
{
  "payload": { "...canonical payload object..." },
  "signatures": { "<key>": "0x..." , ... },
  "client": { "name": "prometheon-cli", "version": "x.y.z" }
}
```

The envelope's top-level shape is independently checked at parse time (`identity.envelope_invalid`); a malformed envelope is rejected before any signature is verified.

### Signatures

Phase 1 uses two signature primitives, applied separately depending on direction:

- **Outbound (CLI → platform)**: SR25519, produced by the operator's Bittensor wallet keypair. The platform verifies these and may reject with one of the `signature.*` codes documented under [Failure Code Catalog](#failure-code-catalog).
- **Inbound (platform → CLI)**: Ed25519, produced by the platform's signing key for snapshots and detailed-mode manifests. The CLI verifies these locally and may raise one of the local-side `signature.*` errors with **opposite** remediation guidance — see [Snapshot Integrity](#snapshot-integrity).

The CLI renderer dispatches platform-origin and local-origin signature errors to distinct templates so the operator-facing remediation matches the actual side that failed.

### Signature Domains

Every signed payload binds itself to one of the following domain literals, both as the external prefix (see [Domain-Prefixed Bytes](#domain-prefixed-bytes)) and as the embedded `domain` field:

```text
PROMETHEON_IDENTITY_VERIFY_V1
PROMETHEON_HOTKEY_ROTATION_V1
PROMETHEON_HOTKEY_RECOVERY_V1
PROMETHEON_API_REQUEST_V1
PROMETHEON_SNAPSHOT_V1
PROMETHEON_RECORD_SET_V1
PROMETHEON_RECORD_PAGE_V1
PROMETHEON_WEIGHT_PLAN_V1

# Event stream (Decentralized Validation)
PROMETHEON_INGEST_PUSH_V1
PROMETHEON_EVENT_RECORD_V1
PROMETHEON_EVENT_V1
PROMETHEON_DAY_DIGEST_V1

# Day-digest attestation (validator countersignature)
PROMETHEON_DIGEST_ATTESTATION_V1
```

Cross-domain reuse is rejected by both sides. The platform's `signature.domain_mismatch` payload includes `details.expected_domain` so the operator can see which domain the platform expected for the endpoint that was called.

### Nonces

Every state-mutating identity request carries a nonce that the platform issued moments earlier. Nonce TTL is **10 minutes** (identity flows) or **600 seconds** (API request signing). The CLI re-fetches a fresh nonce per attempt; a slow operator or a multi-step manual flow that exceeds the TTL trips `NONCE_EXPIRED`.

Nonces bind `(account, role, action, netuid, hotkey)` at issue time. A nonce issued for `verify-miner` cannot be replayed against `rotate-hotkey`; a nonce issued for one wallet cannot be replayed for another. Mismatch surfaces as `NONCE_CONTEXT_MISMATCH`.

Each nonce is single-use; the platform rejects re-presentation with `NONCE_ALREADY_USED`. A missing nonce header (e.g., because the CLI flow was interrupted between the nonce call and the verify call) trips `NONCE_MISSING`.

### Timestamps

Identity and API-request payloads carry `issued_at` and `expires_at` fields in UTC `YYYY-MM-DDTHH:MM:SSZ` form. The CLI rejects payloads whose `expires_at` is in the past relative to the local clock (`identity.payload_expired`) or whose `issued_at` is in the future beyond a small skew tolerance (`identity.payload_not_yet_valid`). The skew tolerance defends against forward-dated payload construction while still tolerating ordinary clock drift between well-behaved peers.

### Coldkey Ownership Proof

Sensitive flows (coldkey recovery, future high-trust operations) require an additional proof that the operator controls the coldkey matching the hotkey being bound. The CLI builds a canonical proof envelope, signs it with both the coldkey and the new hotkey, and submits both signatures together. The platform recomputes and verifies the bind; failure surfaces as `COLDKEY_OWNERSHIP_NOT_PROVEN`.

### Path Binding

Every signed envelope carries the intended endpoint path inside the canonical payload. The platform refuses to consume an envelope whose embedded path does not match the URL it was POSTed to (`PATH_MISMATCH`). This defends against a forwarding proxy or operator misconfiguration that silently rewrites the request path between signing and submission.

---

## Cross-Environment Replay Defense

Every signed **identity, API-request, and snapshot** object carries **both**:

```text
chain_network         ∈ { "local", "test", "finney" }
platform_instance_id  stable string, e.g. "bitfan-staging" / "bitfan-production"
```

Event-stream artifacts are bound differently, and it matters when you go
looking for the pair: it rides on the **ingest push envelope** (checked
before the replay defences, rejected as `environment_mismatch`) and on the
**read-API request headers**. It is not inside a signed day digest, a
validator attestation, or an event record — those are bound by the key that
signed them and by the epoch they name.

The validator (and the platform) reject any object whose pair does not match the configured environment. A staging-signed snapshot replayed against a production validator is rejected before any signature or hash check. A finney-signed identity payload replayed against a testnet validator is rejected for the same reason.

Subnet-side detection raises `ENVIRONMENT_MISMATCH` from the identity layer; the platform side may emit the same `ENVIRONMENT_MISMATCH` wire code with a typed `details` payload pointing the operator at the expected `chain_network` and `platform_instance_id`.

---

## Account Lockout

The platform tracks failed verification attempts on a per-account basis. After ten consecutive failures within the platform's lockout window, the account enters a 24-hour cooldown during which further verification attempts are refused with `ACCOUNT_LOCKED_OUT`. Operators who unexpectedly hit this should review their recent attempts (likely a typo in `--platform-instance-id` or a stale `PROMETHEON_*_API_TOKEN`) and wait for the cooldown to clear; the platform also exposes the lockout state through the BitFan portal.

---

## Snapshot Integrity

For every snapshot the validator runs, in this order:

1. **Parse**: Pydantic strict validation; locked policy constants (`daily_score_cap`, `active_member_score_threshold`, `min_active_members_for_reward`, `top_k`) must match the Phase 1 values; floats are rejected.
2. **Trusted key lookup**: `platform_key_id` must be configured, `status == "active"`, and the snapshot's `generated_at` must fall inside `[not_before, not_after]`.
3. **Ed25519 signature**: `verify(public_key, signature, b"PROMETHEON_SNAPSHOT_V1\n" + JCS(snapshot_without_platform_signature))`.
4. **`records_hash`**: recomputed from the canonical record-set envelope and compared.
5. **(Detailed mode only)**: every page's `page_hash` matches the manifest entry; cross-page record ordering is preserved; no duplicate `user_ref` appears in the stream.

Any failure aborts the cycle and is recorded in the persisted state plus the NDJSON event log. The renderer surfaces these as local-side signature errors (`signature.verification_failed`, `signature.invalid_format`, etc.) — note that the same wire code emitted by the **platform** has the opposite cause (server rejected our request signature) and a different remediation, which is why the renderer dispatches by exception class first.

---

## Typed Details and Privacy Backstop

Six of the catalogued wire codes carry a typed `details` payload alongside the human-readable `message`:

| Wire code | `details` shape |
|---|---|
| `ROTATION_COOLDOWN_ACTIVE` | `{ "cooldown_until": "<ISO 8601 UTC Z>" }` |
| `RECOVERY_COOLDOWN_ACTIVE` | `{ "cooldown_until": "<ISO 8601 UTC Z>" }` |
| `AUTH_TOKEN_SCOPE_MISSING` | `{ "required_scope": "<scope string>" }` |
| `PROFILE_ALREADY_HAS_HOTKEY` | `{ "recommended_action": "rotate" | "recover" }` |
| `ENVIRONMENT_MISMATCH` | `{ "expected_chain_network": "<network>", "expected_platform_instance_id": "<id>" }` |
| `signature.domain_mismatch` | `{ "expected_domain": "PROMETHEON_*_V1" }` |

The CLI's renderer surfaces these structured fields directly in the remediation block so the operator does not have to scrape them out of the human message.

**Privacy backstop.** The platform commits never to emit cross-user information through the `details` field. As defence-in-depth, the CLI drops any key whose name matches one of the following patterns at parse time, **before** the exception instance is constructed:

```text
conflicting_*
*_owner_id
*_user_id
other_account_*
other_user_*
current_holder_*
current_owner_*
```

A stderr warning is emitted the first time a previously-unseen key is dropped (per-process dedup) so the platform team is notified of a future regression without overwhelming operators with repeated noise. A secondary, render-time guard further redacts any **value** whose shape matches a known credential pattern (see [API Tokens](#api-tokens)).

---

## Defenses At a Glance

| Attack | Defense |
|---|---|
| Replay | Nonce + timestamp + `chain_network` + `platform_instance_id` in every signed object. |
| Wrong-environment replay | `chain_network` + `platform_instance_id` mismatch rejects before any crypto. |
| Stale UID hijack | UIDs re-resolved against the current metagraph immediately before submission. |
| Burn-target hijack | Burn target is the subnet owner hotkey read from chain (or, on the snapshot fallback, the signed snapshot's value) — never operator config; missing-hotkey cases fall through to B/D. |
| API token theft | Snapshot endpoints require both the token AND a fresh hotkey signature; the token alone is insufficient. |
| Hotkey theft | Platform-state mutation requires the API token AND the hotkey signature AND a valid nonce; the hotkey alone is insufficient. |
| Snapshot tampering | Ed25519 signature + `records_hash` + (detailed) per-page hashes. Any byte change invalidates the chain. |
| Cross-protocol reuse | Thirteen distinct signing domains, double-bound (external prefix + embedded field). |
| Floating-point divergence | All in-engine arithmetic is integer-only; chain-boundary u16 conversion is also integer largest-remainder. |
| Commit-reveal silent fallback | Detection at startup; fail closed if commit-reveal is enabled on the chain. |
| Missing `mechid` silent fallback | Detection at startup; fail closed outside `local` development. |
| Platform key compromise | Per-key `status` field; revoking marks the key inactive immediately, no waiting for `not_after`. |
| Manual recovery abuse | 2FA + Discord handle hash + Ops Console approval + 24-hour pending + 14-day cooldown. |
| Cross-user PII leakage | Privacy-backstop key-name filter on every `details` payload at parse time; secret-shape value redaction at render time. |

---

## Failure Code Catalog

### Identity / Platform errors

```text
AUTH_INVALID_TOKEN          API token unknown / expired / revoked.
AUTH_TOKEN_SCOPE_MISSING    Token lacks the required scope. details: {required_scope}.
ACCOUNT_NOT_VERIFIED        Account has not been verified for the requested role.
ACCOUNT_LOCKED_OUT          10 failed verification attempts → 24-hour lockout.
NONCE_MISSING               No nonce present on the verify submission.
NONCE_EXPIRED               Nonce TTL elapsed.
NONCE_ALREADY_USED          Nonce already consumed.
NONCE_CONTEXT_MISMATCH      Envelope context differs from nonce-issue-time context.
HOTKEY_ALREADY_LINKED       Hotkey is already linked to a different account for that role.
HOTKEY_NOT_LINKED           Old hotkey does not match the platform-side state for that role.
ROTATION_COOLDOWN_ACTIVE    7-day rotation cooldown active. details: {cooldown_until}.
RECOVERY_COOLDOWN_ACTIVE    14-day recovery cooldown active. details: {cooldown_until}.
RECOVERY_PENDING            Earlier recovery has not yet activated.
ENVIRONMENT_MISMATCH        chain_network / platform_instance_id mismatch.
                            details: {expected_chain_network, expected_platform_instance_id}.
PATH_MISMATCH               Request path does not match the signed payload's path.
```

### Binding-ledger errors

```text
PROFILE_ALREADY_HAS_HOTKEY        verify-* called on an already-bound account.
                                  details: {recommended_action: "rotate" | "recover"}.
MINER_FAN_GROUP_REQUIRED          verify-miner called without leading a Fan Group.
COLDKEY_OWNERSHIP_NOT_PROVEN      Coldkey-ownership proof missing or invalid.
DISCORD_HANDLE_MISSING            Recovery flow requires a Discord handle on the profile.
TWO_FACTOR_PROOF_INVALID          2FA proof missing, expired, or did not verify.
```

### Snapshot read errors

```text
SNAPSHOT_NOT_READY              No snapshot published for the requested activity_date.
SNAPSHOT_MODE_INVALID           Requested mode not supported by the platform.
SNAPSHOT_DATE_INVALID           activity_date is not in the supported window.
SNAPSHOT_ACCESS_DENIED          Account/role does not have access to this snapshot.
```

### Snapshot storage errors

```text
SNAPSHOT_PAGE_NOT_FOUND         Manifest referenced a page storage could not return.
SNAPSHOT_STORAGE_ACCESS_DENIED  Infrastructure-level access policy refused the read.
SNAPSHOT_STORAGE_ERROR          Generic upstream failure from the storage backend.
SNAPSHOT_PAGE_HASH_ERROR        Platform-side page-hash recomputation failed.
```

### Signature primitive errors

The same wire codes appear with **opposite causes and remediations** depending on which side emitted them. The CLI renderer dispatches by exception class first so the operator-facing guidance always matches reality.

```text
signature.invalid_format       Signature hex / surrounding envelope structure did not decode.
signature.verification_failed  Cryptographic check failed.
signature.address_mismatch     SS58 derived from the signing key did not match the payload.
signature.unsupported_key_type Crypto type outside the Phase 1 accepted set.
signature.domain_mismatch      Embedded domain did not match expected.
                               details: {expected_domain}.
```

### Validator runtime errors

These are subnet-internal failure conditions; they never appear on the wire.

```text
identity.payload_invalid           Local validation rejected the payload before send.
identity.envelope_invalid          Envelope shape mismatch detected locally.
identity.payload_expired           Received payload's expires_at is in the past.
identity.payload_not_yet_valid     Received payload's issued_at is in the future.
NO_VALID_WEIGHT_TARGET             Engine returned status=no_valid_weight_target (Case D).
chain.commit_reveal_enabled        Subnet has commit-reveal on; Phase 1 fails closed.
chain.weights_version_mismatch     Chain weights_version differs from configured version_key.
chain.mechid_missing               Installed SDK lacks mechid and legacy override is not allowed.
chain.set_weights_failed           set_weights extrinsic rejected or reported
                                   failure by the SDK.
chain.subtensor_error              Any other subtensor-side failure: connect,
                                   metagraph sync, hyperparameter read.
chain.wallet_error                 Wallet or keypair could not be loaded.
chain.weight_submission_error      Submission path failed outside the extrinsic
                                   itself (e.g. UID resolution).
validator.event_weight_source      Local event store missing or unreadable, so
                                   the live path cannot score. Raised before any
                                   weight submission.
validator.config_error             Validator TOML rejected at load.
validator.runner_error             Base code for other runner-side failures.
identity.error                     Base code for identity-flow failures whose
                                   subclass code is listed above.
signature.error                    Signing or verification failed locally.
record_invalid                     An event record failed shape validation on
                                   ingest.
```

### Unrecognised codes

If the platform emits a code this CLI build does not know about, the renderer prints the wire code verbatim and a link to a labelled issue template at `.github/ISSUE_TEMPLATE/unrecognised-platform-code.md`. The fallback path preserves the offending code verbatim so the operator can copy-paste it into a report without re-typing.

---

## Operator Hygiene

- Never commit wallet directories, seed phrases, private keys, API tokens, snapshot signing keys, or `.validator-state/` to any repository.
- Pin dependencies via `uv.lock` and prefer hash-verified installs in production builds.
- Run validators with non-privileged users where possible and restrict filesystem permissions on `.bittensor/`, `.validator-state/`, and any credential files.
- Watch the NDJSON event log; any `cycle_failed` deserves investigation, not a silent retry.
- When pasting a `--verbose` trailer into an issue, give it a quick read first: the renderer drops cross-user keys and credential-shape values, but operator-specific fields (your hotkey SS58, custom hostnames) come through verbatim.

---

For the reporting procedure for vulnerabilities, see [`../SECURITY.md`](../SECURITY.md).
