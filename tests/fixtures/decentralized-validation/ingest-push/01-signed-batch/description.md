# ingest-push 01-signed-batch

The INGEST_PUSH_V1 delivery unit: a contiguous 2-record `activity` batch (the event-record/01 record at seq 4207 plus its seq-4208 sibling) in the environment-bound envelope, signed by the platform publisher test key (`platform-test-2026-05`).

Assertions for a conforming validator implementation:

1. `wire.bytes.hex` is exactly `JCS({envelope, publisher_key_id, sig})` — reproduce it byte-for-byte from `signed_batch.json`.
2. `sig` verifies (Ed25519) over `"PROMETHEON_INGEST_PUSH_V1" + 0x0A + JCS(envelope)` against the test platform public key (`test-keys/ed25519-platform.json`).
3. `from_seq`/`to_seq` equal 4207/4208 and the records are strictly contiguous.
4. Record 1 re-verifies exactly as in `event-record/01` (same bytes, same device signature).

The `platform_instance_id` here is `bitfan-local` (the fixture environment). Live environments use `bitfan-staging` / `bitfan-production`; a validator MUST reject a batch whose environment binding does not match its own configuration — this fixture doubles as the cross-env rejection input for that test.
