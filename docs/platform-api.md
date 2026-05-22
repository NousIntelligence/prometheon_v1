# BitFan Platform API — Public Reference

This document describes the **public** subset of the BitFan Platform API that the Prometheon CLI and validator talk to. Admin endpoints, operator runbooks, and snapshot-generation internals are intentionally out of scope.

The contract is described from the **subnet** side: what the CLI sends, what it expects back, and what it does with the response. For the formal cross-implementation byte-level contract, refer to the canonical specification.

---

## Authentication

Every request carries a Platform-issued bearer token:

```text
Authorization: Bearer <api_token>
```

API tokens are scoped. Phase 1 scopes:

```text
identity:verify:<miner|validator>
identity:rotate:<miner|validator>
identity:recover:<miner|validator>
snapshot:read:<aggregate|detailed>
status:read
```

A miner token must not grant snapshot access; a validator token must not grant miner identity mutation. The Platform enforces scope server-side.

---

## Encoding Rules

| Field | Format |
|---|---|
| Hashes | `0x` + 64 lowercase hex characters (SHA-256). |
| Signatures | `0x` + 128 lowercase hex characters (SR25519 or Ed25519). |
| Timestamps | `YYYY-MM-DDTHH:MM:SSZ` (UTC, no fractional seconds, no offsets other than `Z`). |
| Dates | `YYYY-MM-DD`. |
| Canonical JSON | RFC 8785 JCS. |

Every signed payload is wrapped in a domain prefix before signing: `ASCII(domain) + b"\n" + JCS(payload_object)`.

Both sides must produce byte-identical canonical bytes against the shared fixture suite.

---

## Identity Endpoints

### `POST /api/v1/prometheon/identity/nonce`

Request body:

```json
{
  "role": "miner",
  "netuid": 123,
  "username": "example_user",
  "email": "user@example.com",
  "hotkey_ss58": "5F..."
}
```

Headers: `Authorization: Bearer <api_token>`.

Response:

```json
{
  "platform_account_id": "acct_...",
  "username_hash": "0x...",
  "email_hash": "0x...",
  "nonce": "nonce_...",
  "issued_at": "2026-05-20T00:00:00Z",
  "expires_at": "2026-05-20T00:10:00Z"
}
```

The Platform owns username and email canonicalization; the CLI signs the returned hashes verbatim and never re-normalises locally.

Nonce TTL: 10 minutes. The nonce is bound to `(account, role, action, netuid, hotkey)`.

---

### `POST /api/v1/prometheon/identity/verify`

Body shape (envelope):

```json
{
  "payload": { "...canonical PROMETHEON_IDENTITY_VERIFY_V1 payload..." },
  "signatures": { "hotkey": "0x..." },
  "client": { "name": "prometheon-cli", "version": "0.1.0" }
}
```

The payload's `domain` field must equal `"PROMETHEON_IDENTITY_VERIFY_V1"` and the hotkey signature must verify against `b"PROMETHEON_IDENTITY_VERIFY_V1\n" + JCS(payload)`.

On success the Platform sets `<role>_verified = true` for the linked account, consumes the nonce, and returns a success envelope.

---

### `POST /api/v1/prometheon/identity/rotate-hotkey`

Body shape:

```json
{
  "payload": { "...canonical PROMETHEON_HOTKEY_ROTATION_V1 payload..." },
  "signatures": {
    "old_hotkey": "0x...",
    "new_hotkey": "0x..."
  },
  "client": { "name": "prometheon-cli", "version": "0.1.0" }
}
```

Both signatures cover the same canonical bytes. Platform enforces a 7-day cooldown after a successful rotation.

---

### `POST /api/v1/prometheon/identity/recover-hotkey`

Two payload variants share the same endpoint, discriminated by `recovery_method`:

- `"coldkey"` — `signatures.coldkey` and `signatures.new_hotkey` both required.
- `"manual_2fa_ops"` — `signatures.new_hotkey` only; the request additionally requires platform-side 2FA, a Discord handle hash, and Ops Console approval (out of band).

Both variants enter a 24-hour pending state before activation; both start a 14-day recovery cooldown after activation.

---

## Snapshot Endpoints

Validators must include extra signed headers on every snapshot call:

```text
Authorization: Bearer <validator_api_token>
X-Prometheon-Hotkey: <validator_hotkey_ss58>
X-Prometheon-Nonce: 0x<≥16 random bytes lowercase hex>
X-Prometheon-Timestamp: <ISO 8601 UTC Z>
X-Prometheon-Request-Signature: 0x<128 lowercase hex chars>
```

The signature is computed over the `PROMETHEON_API_REQUEST_V1` canonical payload (which binds method, exact path, query hash, body hash, timestamp, nonce, environment fields, role, mode, validator hotkey, and API-token hash).

Skew window: 300 seconds. Nonce TTL: 600 seconds.

---

### `GET /api/v1/prometheon/phase1/snapshots/{activity_date}/aggregate`

`{activity_date}` is either `latest` (Platform-authoritative latest) or a literal `YYYY-MM-DD`.

Response: a full aggregate snapshot. The validator verifies:

- The `domain`, `schema_version`, `mechanism`, `mechid`, and `mode` literal fields.
- `chain_network` and `platform_instance_id` match the validator's configured environment.
- The locked Phase 1 policy constants match (`daily_score_cap=20`, `active_member_score_threshold=50`, `min_active_members_for_reward=3`, `top_k=10`).
- `platform_key_id` is in the validator's trusted-key map, has `status="active"`, and `generated_at` falls inside the key's `[not_before, not_after]` window.
- The Ed25519 `platform_signature` verifies against `b"PROMETHEON_SNAPSHOT_V1\n" + JCS(snapshot_without_platform_signature)`.
- `records_hash` recomputes from the canonical record-set envelope.
- `miners` is sorted by `miner_hotkey` ascending and contains no duplicates.

---

### `GET /api/v1/prometheon/phase1/snapshots/{activity_date}/detailed/manifest`

Returns the **signed** detailed-mode manifest. The manifest carries the same locked-policy and environment fields as the aggregate response, plus:

```text
record_count   total user records across all pages
page_size      records per page (last page may be shorter)
page_count     number of page bodies to fetch
pages          [ { page_index, record_count, page_hash } ]
```

Validator-side checks include `page_count == len(pages)`, sequential page indices starting at 0, every non-last page exactly `page_size` records, sum of per-page record counts equals top-level `record_count`.

---

### `GET /api/v1/prometheon/phase1/snapshots/{activity_date}/detailed/pages/{page_index}`

Page body shape includes its own `page_hash`. The validator recomputes the hash from the page body minus `page_hash` and asserts it matches the manifest's entry. Pages themselves are **not** Ed25519-signed — the signed manifest's `page_hash` references are the trust root.

Cross-page invariants the validator enforces:

- Pages arrive in `page_index` order, exactly one of each, from 0 to `page_count - 1`.
- Records are globally sorted by `(miner_hotkey ASC, user_ref ASC)` across the entire stream.
- No `user_ref` appears on more than one page.
- No `user_score_14d_points` exceeds `DAILY_SCORE_CAP × 14 = 280` or is negative.

---

## Error Envelope

Every non-2xx response carries a small JSON envelope:

```json
{
  "error": "<CODE>",
  "detail": "<human readable explanation>"
}
```

The set of codes used by Phase 1 is documented in [`security.md`](./security.md#failure-code-catalog).

---

## Versioning

- `domain` discriminates the payload type and binds the signature.
- `schema_version` discriminates schema revisions inside a domain. Phase 1 ships `"1.0"` across the board.
- `mechanism` + `mechid` discriminate the on-chain mechanism slot; Phase 1 ships `phase1_growth` / `0`.

Any change to a wire shape is a signed-version bump and a coordinated rollout between the platform and the subnet.
