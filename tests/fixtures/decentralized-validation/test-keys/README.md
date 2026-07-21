# TEST KEYS ONLY — Prometheon Phase 1 fixture suite

These keypairs exist solely to make the shared fixture suite deterministic and reconcilable
across both the BitFan platform (TypeScript) and the subnet validator (Python). They MUST
NEVER be used in any production deployment, on any chain, for any account, for any purpose.

Every key here is derived from a labelled SHA-256 seed (see `seeds.json`) so anyone can
verify the test material independently. If you ever discover one of these keys signing a
real on-chain action, treat it as a serious operational incident.
