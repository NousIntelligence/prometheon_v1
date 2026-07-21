# signature-rejection 02-truncated-signature

A valid SR25519 signature was truncated to half its hex length. `verifySr25519HotkeySignature` MUST reject with `signature.invalid_format` at the format-validation step before the WASM verifier runs.
