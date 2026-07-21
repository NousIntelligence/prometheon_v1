# signature-rejection 04-domain-mismatch

The embedded `domain` field disagrees with the verifier's expected domain. `verifyEmbeddedDomain` MUST throw with `signature.domain_mismatch` BEFORE any cryptographic verification runs.
