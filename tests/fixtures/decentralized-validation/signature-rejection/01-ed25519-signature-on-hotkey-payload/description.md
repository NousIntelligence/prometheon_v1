# signature-rejection 01-ed25519-signature-on-hotkey-payload

The payload bytes are identical to the corresponding `identity-verify-v1` fixture, but the signature was produced by an Ed25519 keypair and `claimed_signer.ss58` is the SS58 encoding of that Ed25519 public key — the key-type-confusion case (a non-sr25519 wallet submitted as a hotkey). The signature is VALID under ed25519, so the verifier MUST throw `signature.unsupported_key_type` rather than reporting a plain verification failure.
