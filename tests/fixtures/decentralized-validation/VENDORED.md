# Vendored fixture suite — Decentralized Validation

**Source:** BitFan platform repo, `docs/specs/Subnet/fixtures/`
**Pinned revision:** fixture release **r5** = BitFan commit `a0243b47`
(r6 = `2cb40e23` is docs-only — its fixture tree is byte-identical to r5,
verified by extracting both tarballs and diffing, so the pin does not move)
**Vendored:** 2026-08-04 (supersedes r4 = `2a36285f`)

r5 is the one release that is **additive rather than a regeneration**: every
r4 file is byte-identical and only `exclusion-tightening/` is new. Verified by
extracting both tarballs and diffing the trees — the sole other difference is
this repo's own org-rename edit to `README.md`, which is deliberately kept.

`exclusion-tightening/01-multi-tightening-day` pins the continuous-emission
model: several verdicts for one (user, epoch), each distinct weight its own
record, effective weight the minimum, and `verdicts_complete.verdict_count`
counting records keyed on `applies_to_epoch` rather than distinct users or
the `epoch_id` bucket.

The r4 release added `parity-report/01-scores-hash/` and gave
`attribution/01-vectors` a `role` field on `binding_events` plus a dual-role
leader case.

This directory is the shared, byte-identical conformance suite for the
Decentralized Validation program (event-stream ingest + open score
recomputation). Both implementations — the BitFan platform (TypeScript) and
this repo (Python) — gate merges on it. Every JCS canonical artefact, hash,
and deterministic signature here must round-trip byte-for-byte across both
implementations; randomized signatures (SR25519, ECDSA P-256) are
verify-asserted rather than byte-asserted, as documented in `README.md`.

## Re-pin protocol

The platform announces each fixture release with its commit hash. A release is
always a **full regeneration**: randomized signatures re-roll (and the
deterministic files that embed them change with them), so partial updates are
never valid. To re-pin:

1. Replace this directory's contents wholesale with the new release.
2. Update the pinned revision above.
3. Run the contract suite (`uv run pytest tests/contract -m contract`). Every
   deterministic assertion must reproduce; any divergence is a wire-contract
   incident to raise with the platform team (report
   `fixture path + computed vs expected bytes`).

Do not hand-edit any file under this directory. A local edit silently detaches
this repo from the cross-implementation contract.

## Consumers

- `tests/contract/test_dv_wire_contract.py` — canonical JSON corpus, event
  records, day digests, ingest-push envelope + overlap scenario, test-key
  derivation.
- `tests/contract/test_dv_score_contract.py` — daily-score kernel table,
  end-to-end qualification vectors, streak vectors, attribution vectors,
  replayed through the reference scorer in `tests/contract/_dv_reference.py`.
- Production modules added by later PRs gate against the same files; the
  test-local reference implementation remains as an independent cross-check.
