# event-record 02-platform-authored-verdict-record

An `exclusion`-family verdict record. Platform-authored: `device_pubkey` and `user_sig` are `null`, and `core` carries the verdict payload (`weight_bp` ∈ the locked set, `reason_codes` from the fixed vocabulary). Canonical bytes MUST match byte-for-byte; there is no device signature to verify.
