# signature-rejection 05-bytes-wrapped-sr25519-signature

A genuine SR25519 signature by the miner hotkey — but over `<Bytes>`-wrapped message bytes (`<Bytes>` + raw + `</Bytes>`, the polkadot-js extension default). The protocol commits to the RAW domain-prefixed JCS bytes; the verifier MUST treat this as a plain verification failure (`signature.verification_failed` on the wire), never accept it via implicit-wrapping detection. Python validators verifying raw bytes reject this signature identically.
