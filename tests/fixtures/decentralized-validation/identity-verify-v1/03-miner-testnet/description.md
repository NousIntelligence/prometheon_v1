# identity-verify 03-miner-testnet

Signed-payload fixture for domain `PROMETHEON_IDENTITY_VERIFY_V1`. The strict parser MUST accept `payload.json`; the JCS canonicalizer over the payload MUST produce exactly `canonical.bytes.hex`; the domain-prefixed signed bytes (ASCII(domain) + 0x0A + canonical) MUST equal `signed.bytes.hex`; each `signature.<role>.hex` MUST verify against the matching `signer.<role>.ss58`.
