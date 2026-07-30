# Decentralized Validation — Operator Guide

Decentralized Validation replaces the pull-based trusted daily snapshot with an
"honest postman" model: the BitFan platform records every reward-relevant event
into four **gap-free, per-family, publisher-signed streams** and **pushes** them
to every registered validator. Each validator stores its own copy and
**recomputes miner weights independently** from the frozen open formula. The
platform can no longer quietly change a number — doing so would require forging
signatures held by many independent parties, or leaving a detectable gap in a
monotonic sequence.

What does **not** change: Yuma consensus, `set_weights`, the WeightPlan/burn
logic, and the identity/hotkey verification flows. This adds a new **data
source** (the event stream) and a new **scoring input** (open recomputation).

The wire contract is byte-gated by the shared fixture suite vendored under
[`tests/fixtures/decentralized-validation/`](../tests/fixtures/decentralized-validation/VENDORED.md);
every layer described below is verified against it in CI.

---

## The stream model in one minute

- **Four families**, each with its own gap-free `seq` (1, 2, 3, …):
  `activity` (reward events), `identity` (hotkey bindings, device keys),
  `group` (fan-group creation + membership), `exclusion` (anti-fraud
  verdicts + the per-epoch `verdicts_complete` marker).
- **`epoch_id`** — the UTC day stamped by the platform's database clock at
  sequencing time, uniformly in every family. It buckets digests, retention,
  and backfill. Scoring joins verdicts on `core.applies_to_epoch`.
- **Signatures** — every push batch is Ed25519-signed by the platform
  publisher key (the same key registry as snapshot signing, `/keys`).
  Individual activity records may additionally carry a per-user P-256 device
  signature; unsigned records are normal and score normally. A record with a
  non-null **invalid or unregistered** signature is excluded from scoring and
  alarmed — inside the publisher-signed stream it is durable evidence of
  injection.
- **Day digests** — per (family, epoch) the platform signs
  `records_hash = SHA-256(concat(record canonical bytes in seq order))`. Your
  local recompute must match; a mismatch is a completeness alarm, identical
  for every validator.

---

## Setting up the ingest endpoint

The platform pushes to a **public HTTPS URL** you operate. The service itself
binds locally; front it with a TLS reverse proxy (Caddy shown — it manages
certificates automatically):

```text
# Caddyfile
ingest.<your-domain> {
    reverse_proxy 127.0.0.1:8541
}
```

Run the service against your existing validator TOML config (the environment
binding and the trusted platform keys are read from it — the publisher keys
ARE the snapshot signing keys, one registry):

```bash
uv run prometheon ingest serve \
    --config ~/prometheon-validator.toml \
    --db .validator-state/events.sqlite \
    --host 127.0.0.1 --port 8541
```

Then register the public URL with the platform. This needs your long-lived
validator token carrying the `ingest:register` scope (issued from the BitFan
portal; if your current token predates the scope, issue a new token and revoke
the old one):

```bash
export PROMETHEON_VALIDATOR_API_TOKEN="<long-lived token>"
uv run prometheon ingest register-endpoint \
    --ingest-url https://ingest.<your-domain>/ \
    --config ~/prometheon-validator.toml
```

The registration call carries the same environment-binding headers
(`X-Prometheon-Chain-Network` / `X-Prometheon-Platform-Instance-Id`) as every
other authenticated platform call — the CLI reads them, and the platform base
URL, from the config. The signed-request header set is not required for this
endpoint; bearer token plus the binding headers is sufficient.

Re-running with the same URL is a no-op; a new URL rotates atomically.
**Register before the platform enables delivery** so you receive the stream
from `seq 1`; a later joiner catches up via backfill (below).

What the service enforces on every push, in contract order: publisher
signature → environment binding → replay defence (fresh nonce, ±300 s
`sent_at` window) → envelope shape → the four-case contiguity rule
(exact-next stores all; an overlap stores the new tail; a full duplicate acks
without storing; a forward gap is rejected so the backfill client fills it).
A `2xx` always reports `received_through_seq` — the only field the platform
reads.

---

## Catch-up and completeness

Both are **operator-run today** — nothing schedules them yet. Run them by
hand after an incident, and from cron during the shadow phase; automatic
scheduling arrives with the runtime automation glue.

**Backfill** pulls what you are missing: pages of `GET /events/backfill`
deliver the exact same canonical bytes push would have, validated and
appended through the same store primitive — pushed and backfilled records
are byte-indistinguishable at rest. Reads use your validator token's
`events:read` scope.

```bash
# all four families; add --family activity (repeatable) to narrow
uv run prometheon ingest backfill \
    --config ~/prometheon-validator.toml \
    --db .validator-state/events.sqlite
```

Run it after a `409 {"code": "gap"}` ack, after any outage, and once when
joining a stream that is already running. It is safe to re-run: each pass
resumes from your stored cursor and stops when the platform has nothing
more (an empty page whose `next_seq` equals your position means "not
materialized yet — retry later").

**Day digests** are published by ~00:45 UTC for the previous day. The
completeness check recomputes the local hash and count per (family, epoch)
and compares them against the platform's signature:

```bash
uv run prometheon ingest check-day \
    --config ~/prometheon-validator.toml \
    --db .validator-state/events.sqlite \
    --date 2026-07-14
```

Exit `0` means every family matched; **exit `3` is the completeness alarm**
and prints the local vs digest hash and count on stderr. Check at 00:50 and
alarm at 01:30 on a missing or mismatched digest.
**Retention** policy: `activity`/`exclusion` records are prunable after 23
epochs (the scoring window needs 21); `identity`/`group` are state families
and keep full history. Pruning never moves the stream cursor, so a pruned
store still knows where it is in each stream.

Nothing prunes automatically yet — the store implements the policy but no
scheduler calls it, so expect the database and the replay-nonce table to
grow until the automation glue lands. That costs disk, never correctness.
Note the interaction to come: `check-day` compares against what is stored,
so once pruning is active a day older than the retention window will read
as incomplete. Keep completeness checks inside the window.

---

## Scoring and shadow mode

Recompute miner records for an epoch from your local store:

```bash
uv run prometheon ingest score \
    --db .validator-state/events.sqlite \
    --date 2026-07-14
```

Rules the pipeline enforces:

- **The cutoff**: epoch `D` is scored only after `verdicts_complete(D)` has
  arrived (sealed by the platform at ~00:05 UTC on D+1). If the marker is
  more than ~2 hours late, `--allow-missing-marker` scores with full default
  weights and prints an alarm — the missing marker is publicly visible and
  identical for every validator, and it self-heals next epoch.
- **Alarms to stderr, records to stdout**: verdict-count mismatches and
  signature-injection evidence are printed as `ALARM:` lines; the JSON miner
  records go to stdout for scripting.

During the **shadow phase**, validators keep submitting snapshot-derived
weights while comparing the recomputation daily:

```bash
uv run prometheon ingest score --db … --date … \
    --snapshot-json snapshot-miners.json
```

exits `0` on parity and `3` on mismatch, printing per-miner evidence. Known,
bounded, non-alarming delta sources during shadow: the 21-day genesis ramp
(windows spanning Stage-1 start converge only after 21 days of stream
history) and the documented ~5-minute day-close attribution edge. Anything
else is a parity incident — report it with the epoch and the diff lines.

The switch to event-derived weights is a **coordinated date** agreed with the
platform after 14 consecutive clean shadow days — never a per-validator
decision. Snapshots keep being produced through the fallback window after the
flip.

---

## Security notes

- The committed **test publisher key is publicly derivable** — anyone can
  sign with it. The service and digest verification refuse it everywhere
  except the `local` development network, even if it appears in your trusted
  key config. Never add it to a staging or production config.
- The ingest URL must be reachable from the internet, but your **database
  never is** — only the HTTP endpoint is public, and it writes locally.
- The service carries no authentication of its own: the publisher signature
  is the trust anchor. The platform has no stable egress IPs, so run
  signature verification + your own rate limiting; IP allowlisting is not
  available as a layer.

## Failure modes at a glance

| Symptom | Meaning | Action |
|---|---|---|
| `409 {"code": "gap"}` acks in the service log | You are behind the frontier | Run `ingest backfill` to fill the range; investigate only if the gap persists after a successful catch-up |
| `ALARM: injection evidence at seq N` | A record with an invalid/unregistered device signature is inside the signed stream | Report to the platform team with the seq — only the platform could have put it there |
| `ALARM: verdict count mismatch` | Held verdicts for an epoch disagree with the sealed marker | Report with the epoch; do not suppress |
| `ingest check-day` exits 3 | Local bytes differ from the signed day digest | Run `ingest backfill` first (a gap explains most mismatches); if it survives a clean catch-up it is a wire-contract incident — report `family + epoch + local vs digest hash` |
| `ENVIRONMENT_MISMATCH` from any platform call | The environment-binding headers are missing or name the wrong environment | Check `chain.network` and `platform.platform_instance_id` in your config match the environment your token was issued for |
| `verdicts_complete` missing past ~02:05 UTC | Platform sealing run is late | Score later, or `--allow-missing-marker` per the documented fallback |
| `test_publisher_key_refused` | The derivable fixture key reached a live config | Remove it from the trusted keys — it must never sign live traffic |
