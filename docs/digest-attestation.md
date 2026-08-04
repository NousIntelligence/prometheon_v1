# Day-Digest Attestation

A day's records become canonical for a validator only when two independent
keys have signed them: the platform's, over the digest it publishes, and the
validator's own, over the digest it verified against the records it holds.

This document specifies the record, the signing envelope, the verification
rules, and the endpoint the platform must expose.

---

## Why a second signature

The platform signs each per-family day digest when it seals the day. That
signature establishes authorship. A validator can add something the platform
cannot produce for itself: it holds the records that were actually delivered
to it, so it can recompute `records_hash` and state, under its own key, that
the two agree.

The result is a two-signature artifact. No single party produced it.

Each validator signs independently. There is no quorum, no threshold, and no
collection point — a validator that is offline blocks nothing, and no party
outside the validator can stall a day.

---

## The signed envelope

A validator signs the domain-prefixed JCS bytes of exactly this object:

```json
{
  "domain": "PROMETHEON_DIGEST_ATTESTATION_V1",
  "family": "activity",
  "epoch_id": "2026-07-14",
  "records_hash": "0x…",
  "record_count": 128,
  "platform_key_id": "bitfan-ed25519-2026-05",
  "platform_signature": "0x…",
  "validator_hotkey": "5F…",
  "attested_at": "2026-07-15T01:04:11Z"
}
```

Signed bytes are `ASCII(domain) + b"\n" + JCS(object)`, the same construction
every other Prometheon signature uses.

Two details are load-bearing:

- **`PROMETHEON_DIGEST_ATTESTATION_V1` is its own domain.** A platform digest
  signature can never be replayed as a validator attestation, or the reverse.
- **`platform_signature` is inside the envelope.** The attestation binds to
  the exact signed artifact the validator verified, not merely to its
  contents. Across a key rotation two platform keys can sign identical digest
  contents; an attestation names which one it saw.

The signature is SR25519 by the validator's Bittensor **hotkey** — the key
already bound to its account by `verify-validator` and already published in
the metagraph. No new key distribution, and anyone can verify an attestation
from the body alone.

## Wire body

The submission body is the envelope plus two fields:

```json
{
  "domain": "PROMETHEON_DIGEST_ATTESTATION_V1",
  "…": "… envelope fields as above …",
  "signature": "0x…",
  "version": "digest-attestation/v1"
}
```

`version` is informational. `signature` is not part of the signed bytes.

---

## Verification

Any party — the platform, another validator, an auditor — verifies with no
side channel:

1. All envelope fields present and well-formed; `record_count` a non-negative
   integer.
2. Rebuild the envelope from the body, drop `signature` and `version`.
3. Verify `signature` against `validator_hotkey` under
   `PROMETHEON_DIGEST_ATTESTATION_V1`.

`prometheon.events.attestation.verify_attestation` implements exactly this.

An attestation says what the validator held. It does **not** re-verify the
platform's own signature — a verifier that cares checks
`platform_signature` against the key registry itself.

---

## When a validator signs

Signing happens only after the local recomputation matches:

1. Fetch the digest for `(family, epoch)` from the read API.
2. Verify the platform's signature and that the answer is for the day that
   was asked for.
3. Recompute `records_hash` and the record count over locally stored
   canonical bytes.
4. **If they match**, sign. If they do not, sign nothing and raise
   `attestation.digest_mismatch`.

Step 4 is what makes the signature meaningful. A mismatch is the signal the
mechanism exists to produce.

---

## Operator surface

The validator runner does this automatically once per cycle, for every sealed
day in the scoring window it has not yet signed. It is the only long-running
process holding an unlocked hotkey, so no operator action is involved and a
transient failure is retried on the next cycle.

Attestations are appended to `attestations.ndjson` in the state directory,
one JSON object per line: the wire body above plus `delivered`, which records
whether the platform has accepted it. That file is the validator's own
evidence and its dedupe index — a restart re-reads it and does not re-sign
days already covered. `delivered` sits outside the signed envelope, so it
changes nothing a verifier reconstructs, and a later line for the same day
supersedes an earlier one.

Two bounds keep the sweep out of the way of weight submission:

- **A wall-clock budget per cycle** (30 s by default). Fourteen days across
  four families is 56 round trips; against a slow read API an unbounded sweep
  would add minutes to a 15-minute cycle. When the budget runs out the sweep
  returns `deferred` and resumes where it stopped on the next pass — an
  unsigned day simply stays out of the log. The `ingest attest` command has
  no budget, because an operator is present and waiting is the point.
- **Per-day isolation.** One day that cannot be verified — an unrecognised
  `platform_key_id` after a platform key rotation, say — is reported as
  `error` for that day only. It never ends the sweep, so later days in the
  window are still signed, and the failing day is retried every cycle.

A submission that fails leaves the attestation signed and stored with
`delivered: false`, and the next sweep re-POSTs it. Delivery is retried
indefinitely; the signature itself is already complete.

Configuration, in `[validator]`:

| Key | Default | Effect |
|---|---|---|
| `attest_digests` | `true` | Produce and store attestations locally. |
| `submit_attestations` | `false` | Also POST them to the platform. |

Submission is delivery, not validity — an attestation is complete and
verifiable the moment it is signed, and the local copy is kept either way.

Manual use, for a one-off or after a backfill:

```bash
uv run prometheon ingest attest \
    --config ~/prometheon-validator.toml \
    --wallet-name <wallet> --wallet-hotkey <hotkey> \
    --date 2026-07-14
```

Exit 3 means a digest did not match local records, or a sealed digest was
missing. Exit 0 with `pending_seal` means the day has closed but the platform
has not sealed it yet — re-run after the seal deadline.

---

## What the platform provides

**`POST /api/v1/prometheon/events/digest/attestation`**

- Auth: the validator's bearer token, plus the `X-Prometheon-Chain-Network`
  and `X-Prometheon-Platform-Instance-Id` binding headers carried on every
  authenticated call.
- Body: the wire body above.
- Response: any 2xx. The subnet reads nothing from it.
- Storage: at most one attestation per `(validator_hotkey, family, epoch_id)`.
  A repeat delivery of the same attestation is a no-op — the client retries
  transient failures, so the endpoint must be idempotent.

Rejecting an attestation whose signature does not verify is the platform's
choice; the subnet neither requires nor relies on it. The same applies to
attestations from a hotkey that is not a registered validator.

**Volume.** Four per validator per day — one per family — arriving shortly
after the day's digests are sealed, so expect a burst rather than a trickle.

**Transport.**

- **No redirects.** The client does not follow them; a `301`/`302` is a
  delivery failure, and the attestation is simply re-sent next cycle.
- **Retries** happen only on `429`, `502`, `503`, `504`, at most 3 of them,
  honouring `Retry-After` when present. Other 5xx responses are retried on a
  later sweep; 4xx responses are not retried at all.
- **Timeout** is the validator's `request_timeout_seconds` (default 30 s).

**Token scope: `events:read`.** Same as `POST /events/parity-report`, on the
same reasoning — an attestation cannot affect scoring, and validators already
hold the scope. Existing operational tokens work unchanged.

**Rotating your hotkey invalidates pending attestations.** The platform
checks that the signing hotkey is a registered validator, so after a rotation
two things happen: attestations already signed by the old hotkey but not yet
delivered are refused permanently, and new ones succeed only once the
platform holds the new binding. Rotate, let `verify-validator` complete, and
expect a handful of `rejected` entries for the old key — they are evidence
you still hold locally, not data loss. See
[`hotkey-rotation.md`](./hotkey-rotation.md).

**Rejection is permanent; failure is not.** The platform verifies the
signature and checks that the hotkey is a registered validator, refusing
anything that fails with a 4xx. A 4xx other than `429` is treated as final:
the attestation is marked rejected in the local log, never re-sent, and
surfaced as a problem — it means this validator's signature or its
registration is wrong, and neither fixes itself. `429`, any 5xx, and
transport failures stay retryable.
