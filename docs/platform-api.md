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

Event-stream (Decentralized Validation) scopes ride the same long-lived validator token:

```text
ingest:register
events:read
```

### Environment binding (required)

A bearer token alone is not enough. Every authenticated call must also identify
the environment it belongs to, and the Platform rejects a call that does not
with `400 ENVIRONMENT_MISMATCH`. This is what stops a testnet validator from
ever reading or writing production state.

The binding travels one of two ways, and exactly one of them applies per call:

- **In the body**, when the body is a signed envelope — the verify, rotate, and
  recover payloads each carry `chain_network` and `platform_instance_id`
  themselves, and the nonce request body carries them too. Those calls need no
  extra headers.
- **In headers**, for everything else — any `GET` (no body to carry them) and
  any `POST` whose body is not one of those envelopes:

  ```text
  X-Prometheon-Chain-Network: <finney|test|local>
  X-Prometheon-Platform-Instance-Id: <bitfan-production|bitfan-staging|bitfan-local>
  ```

Endpoints in the header group today: the snapshot reads, the event read API
(`GET /events/backfill`, `GET /events/digest`), and ingest-endpoint
registration (`POST /identity/ingest-endpoint`, whose body carries the ingest
URL **and** `chain_network` + `platform_instance_id` — the contract requires the
binding in the body on every `/identity/*` route, and the subnet client sends it
in both places).
The signed-request header set is a *separate*, additional requirement that only
the snapshot API imposes — see below.

`GET /keys` is the one endpoint that takes no authentication at all: it is
public by design, so revoked keys stay verifiable to anyone.

When in doubt, send the headers. They are free, they cannot conflict with a
body that repeats them, and omitting them is the single most common way a new
call site fails its first live request.

### Bootstrap tokens (first verify)

`/api/v1/prometheon/identity/verify` is now the canonical first-time entry: a fresh BitFan user does not need any pre-existing `*_verified` flag to call it. The flow:

1. The user signs into the BitFan web app and opens the BitFan portal at `https://bitfan.ai/me/prometheon`.
2. They click *Get bootstrap token* with their role (`miner` or `validator`). The Platform issues a token under the existing BitFan session:

   ```http
   POST /api/partner/v1/prometheon/api-tokens/bootstrap
   Authorization: <partner session cookie>
   Content-Type: application/json

   { "role": "miner" | "validator" }
   ```

   ```json
   {
     "raw_token":           "<43-char base64url>",
     "subnet_api_token_id": "<uuid>",
     "api_token_hash":      "0x<64 hex>",
     "expires_at":          "<ISO-8601 UTC Z>"
   }
   ```

3. The user exports the `raw_token` into `PROMETHEON_{MINER,VALIDATOR}_API_TOKEN` and runs `prometheon verify-{miner,validator}`.
4. `/identity/verify` creates the role profile, grants the role flag, and revokes the bootstrap token atomically. The CLI never calls the bootstrap endpoint directly — that lives entirely in the BitFan portal UI.

Bootstrap tokens are one-time, scoped to `identity:verify:<role>` only, expire after one hour, and cannot be used for snapshot or rotation calls. If the viewer already holds the requested role flag the bootstrap endpoint returns `409 already_verified`; clients should use the regular issue endpoint instead. Re-verifying with a fresh bootstrap token is idempotent for already-verified accounts (the role flag stays set; the hotkey link is refreshed).

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
  "chain_network": "finney",
  "platform_instance_id": "bitfan-production",
  "username": "example_user",
  "email": "user@example.com",
  "hotkey_ss58": "5F..."
}
```

Headers: `Authorization: Bearer <api_token>`. The environment binding rides in
the body here, so the binding headers are not needed (see
[Environment binding](#environment-binding-required)).

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
X-Prometheon-Chain-Network: <finney|test|local>
X-Prometheon-Platform-Instance-Id: <bitfan-production|bitfan-staging|bitfan-local>
```

The signature is computed over the `PROMETHEON_API_REQUEST_V1` canonical payload (which binds method, exact path, query hash, body hash, timestamp, nonce, environment fields, role, mode, validator hotkey, and API-token hash).

The last two are the environment binding: a snapshot call is a `GET` with no
body, so there is nothing else to carry it. The same values are inside the
signed payload, so sending them changes no signature coverage.

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

## Event Stream Endpoints

The Decentralized Validation endpoints the validator calls. Delivery itself runs
the other way — the Platform `POST`s signed batches to the validator's
registered ingest URL — and is documented in
[the operator guide](./decentralized-validation.md).

All three carry `Authorization: Bearer` **plus the binding headers**; none of
them require the signed-request header set.

### `POST /api/v1/prometheon/identity/ingest-endpoint`

Scope: `ingest:register`. Body:

```json
{
  "ingest_endpoint_url": "https://ingest.example.com/",
  "chain_network": "test",
  "platform_instance_id": "bitfan-staging"
}
```

The two environment fields are **required in the body** — every `/identity/*`
route sits behind the environment guard, and a body without them (or with
values that do not match the instance you are calling) is
`400 ENVIRONMENT_MISMATCH`, whose payload echoes the expected values.

`data`: `{ endpoint_id, rotated, unchanged }`. The Platform binds the endpoint
server-side to the token's verified hotkey. Re-registering the same URL is a
no-op (`unchanged: true`); a different URL rotates atomically (`rotated: true`).
The URL must be public HTTPS with a publicly-trusted certificate — an SSRF guard
refuses anything else, and redirects count as delivery failure. Its hostname
must have an **IPv4 A record**: dual-stack is fine, AAAA-only is not supported
(the platform's dialer prefers IPv4 and its IPv6 egress is not guaranteed).

### `GET /api/v1/prometheon/events/backfill?family=&from_seq=&limit=`

Scope: `events:read`. `data`:

```text
{ family, from_seq, records: [ { seq, event_id, canonical_bytes } ], next_seq }
```

`canonical_bytes` is the `0x`-hex of the *same* bytes delivery pushes — stored
once, byte-identical — so a backfilled record and a pushed one are
indistinguishable at rest, and either can be hashed into the day digest.
`from_seq` is inclusive. The page is contiguous and gap-free: it stops at the
first gap or not-yet-materialized record. `limit` defaults to 500, capped at 1000.

**Exactly three outcomes, and they are not interchangeable:**

| Response | Meaning | Client action |
|---|---|---|
| `200`, `records` non-empty | a contiguous run ending at the first gap | store, continue from `next_seq` |
| `200`, `records: []`, `next_seq == from_seq` | nothing materialized at `from_seq` yet | retry later, same `from_seq` |
| `410`, `error.code = "backfill_range_unavailable"` | `from_seq` is below the family's earliest retained seq — gone permanently | **stop retrying**; escalate, or resume deliberately from `details.earliest_available_seq` and record a permanent gap |

The `410` payload carries
`details: { family, requested_from_seq, earliest_available_seq }`. A `410`
never means "you are ahead" and never means "wait". The Platform never serves
a page across a gap, so the only forward jump in `next_seq` you will ever be
handed is that explicit `earliest_available_seq` — any other is an incident.
The backfill hot window is 30 days.

### `GET /api/v1/prometheon/events/digest?family=&epoch=YYYY-MM-DD`

Scope: `events:read`. `data`:

```text
{ family, epoch_id, records_hash, record_count, signature, platform_key_id, signed_at }
```

The signed day digest, published by ~00:45 UTC for the previous day.
`records_hash` is `SHA-256` over the concatenated record canonical bytes in
`seq` order (an empty day hashes the empty string), and `signature` covers
`b"PROMETHEON_DAY_DIGEST_V1\n" + JCS({domain, family, epoch_id, records_hash,
record_count})`.

Verify against the key valid at `signed_at`, **not** against whichever key is
currently active: revoked keys stay listed precisely so historical digests keep
verifying across a rotation. The opposite holds for push batches, which are
always signed by the active key.

**An absent digest answers one of two codes** (both `404` — branch on
`error.code`, never on the message):

| `error.code` | When | Meaning |
|---|---|---|
| `digest_not_sealed` | the Platform's DB clock is before the epoch's seal deadline | expected — wait, do not alarm |
| `digest_not_found` | at or after the deadline, with no digest | anomaly — the completeness proof is missing; alarm |

The worker seals epoch `D` for all four families at **00:40 UTC on D+1**, and
the deadline is that plus a 20-minute grace, i.e. **D+1 01:00:00 UTC**. Both
responses carry `details.seal_deadline` and `details.now` (the Platform's DB
clock — the same clock that stamps `epoch_id`), so a check at 00:50 is told to
wait and one at 01:30 alarms.

### `POST /api/v1/prometheon/events/parity-report`

Scope: `events:read`; the token's role must be `validator` and its hotkey must
already be verified. **Advisory only** — nothing submitted or returned is an
input to scoring, weighting, ranking, or validator standing.

```json
{
  "epoch": "2026-07-29",
  "scores": [ { "user_ref_evt": "usr_evt_<64 hex>", "daily_score": 1 } ],
  "scores_hash": "0x<64 hex>",
  "chain_network": "test",
  "platform_instance_id": "bitfan-staging"
}
```

`epoch` must be a **closed** day. `scores` are sorted ascending by
`user_ref_evt`, no duplicates, integer scores, at most 10 000 rows; absence
means zero, and an explicit `0` row is equivalent. `scores_hash` is
`"0x" + sha256(JCS({epoch, scores}))` — a plain hash, no domain prefix and no
signature; the Platform recomputes it and rejects a mismatch with
`parity_scores_hash_mismatch`.

`data` returns `{ advisory_only, report_id, epoch, scores_received,
scores_hash, status, received_at, diffed_at, verdict, epoch_agreement }`.
The diff is **asynchronous** — the pseudonym key that maps `user_ref_evt` to a
user exists only in the Platform's worker process — so a fresh submission is
`status: "pending"` and **re-POSTing the identical report is how you poll**.
Re-posting different bytes for the same epoch replaces the row and re-queues
the diff. Verdict counts are `{ agreed_count, score_mismatches, platform_only,
report_only }`; `status` is `match` only when all three divergence counts are
zero.

### `GET /api/v1/prometheon/keys`

Unauthenticated by design — revoked-key transparency means anyone can check a
signature. Returns the Ed25519 registry used for both snapshot signing and
event-stream publishing; it is one registry, not two.

---

## Response Envelopes

Every response — success or failure — is wrapped. **Payload fields are never at
the top level of the body.** A reader that skips the unwrap sees
`success`/`data`/`meta` where it expected content, and reports the payload as
malformed rather than as enveloped; that mistake has cost this repo two
live-broken releases.

### Success

```json
{
  "success": true,
  "data": { "...the endpoint's payload..." },
  "meta": {}
}
```

Read the payload from `data`. Do not infer success from the HTTP status alone:
treat a `2xx` whose body says `"success": false` as the failure it declares.

### Error

Every non-2xx response carries a JSON envelope of the following shape:

```json
{
  "success": false,
  "error": {
    "code": "<UPPER_SNAKE or dotted.lowercase wire code>",
    "message": "<human readable explanation>",
    "details": { "...optional typed payload..." }
  }
}
```

`details` is omitted for the majority of codes; six codes carry a structured payload — see [`security.md` § Typed Details and Privacy Backstop](./security.md#typed-details-and-privacy-backstop) for the per-code field list and the privacy-backstop key-pattern filter the CLI applies at parse time.

Wire codes match one of two shapes:

- `UPPER_SNAKE` — identity, hotkey, snapshot, binding-ledger, and cross-environment codes.
- `dotted.lowercase` — the five granular `signature.*` primitives.
- `lowercase_snake` — the event-stream read and parity codes
  (`backfill_range_unavailable`, `digest_not_sealed`, `digest_not_found`,
  `parity_*`). Some carry a typed `details` payload — see the endpoint.

The CLI validates the wire-code shape against `^[a-zA-Z0-9._-]{1,64}$` at parse time; anything outside this shape is refused verbatim and the CLI surfaces a malformed-code error instead, so a corrupt or hostile payload can never inject terminal control sequences via the operator-facing trailer.

The full code catalog is in [`security.md` § Failure Code Catalog](./security.md#failure-code-catalog). Codes the CLI does not yet know about route through a fallback path that prints the wire code verbatim and links to the labelled issue template at `.github/ISSUE_TEMPLATE/unrecognised-platform-code.md`.

---

## Versioning

- `domain` discriminates the payload type and binds the signature.
- `schema_version` discriminates schema revisions inside a domain. Phase 1 ships `"1.0"` across the board.
- `mechanism` + `mechid` discriminate the on-chain mechanism slot; Phase 1 ships `phase1_growth` / `0`.

Any change to a wire shape is a signed-version bump and a coordinated rollout between the platform and the subnet.
