# Prometheon Phase 1 — Shared Fixture Suite

This directory is the shared, byte-identical fixture suite that gates merges in **both**
the BitFan platform repo (TypeScript, this repo) and the subnet validator repo
(`BitSpaceorganization/prometheon_v1`, Python). Every JCS canonical artefact, hash, and
signature here MUST round-trip across both implementations.

Subdirectories:

* `test-keys/` — deterministic, clearly-labelled TEST KEYS ONLY.
* `canonical-json/` — positive RFC 8785 round-trip cases.
* `json-parser-rejection/` — negative cases the strict parser must reject (duplicate keys,
  prototype-poisoning escape variants, etc.).
* `identity-verify-v1/`, `hotkey-rotation-v1/`, `hotkey-recovery-v1-coldkey/`,
  `hotkey-recovery-v1-manual/`, `api-request-v1/` — signed identity-flow payloads.
* `snapshot-aggregate/`, `snapshot-detailed-manifest/`, `snapshot-detailed-page/` —
  Platform-signed daily snapshot artefacts.
* `weight-plan/` — validator-side WeightPlan hash fixtures.
* `query-canonicalization/` — RFC 3986 uppercase percent-encoding cases.
* `signature-rejection/` — negative signature-verification cases.
* `event-record/`, `ingest-push/` — Decentralized Validation record + delivery bytes.
* `score-kernel/`, `attribution/` — the open scoring formula: exhaustive composition
  table, end-to-end qualification vectors, streak derivation, and per-day miner
  attribution (incl. the r4 dual-role leader case — attribution follows the MINER
  binding, never a validator one).
* `parity-report/` — the advisory parity-report `scores_hash` (r4).

**Regeneration.** Run `pnpm --filter @bitfan/domain-prometheon-subnet gen:fixtures` to
regenerate the entire tree from the locked seed labels in `test-keys/seeds.json`. The
test suite at `packages/domain-prometheon-subnet/src/__tests__/fixtures.test.ts` then
asserts every file round-trips byte-for-byte.

**Signature determinism.** Ed25519 (Platform snapshot signatures) is deterministic per
RFC 8032 — `platform_signature.hex` files do NOT change between regenerations for the
same payload. SR25519 (Bittensor hotkey/coldkey signatures) is randomised by design
(Schnorr scheme nonce), so `signature.<role>.hex` files DO change between regenerations
even though every regenerated signature still verifies. The wire-contract property the
fixture suite enforces is *verifiability*, not byte-identity, for SR25519 signatures.

**Releases.** The subnet repo vendors a PINNED copy of this tree, so every change ships
as one coherent drop: re-pin the WHOLE suite at the release commit rather than merging
individual files. Current release: **r4** (dual-role leader attribution + the `role`
field on `attribution/01-vectors` `binding_events`; contract-side, the digest
`not_sealed`/`not_found` split, the permanently-unavailable backfill range, and the
advisory parity-report endpoint).

**Coordination.** Once the subnet team hands over their `rfc8785==0.1.4` reference outputs,
their CI loads this same directory and runs the symmetric Python round-trip. Any byte
divergence is a wire-contract incident.
