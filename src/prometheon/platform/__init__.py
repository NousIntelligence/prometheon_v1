"""BitFan platform integration: HTTP client, schemas, and snapshot verification.

This module is the boundary between the subnet code and the BitFan platform.
It owns:

- Pydantic schemas for every request and response on the platform contract.
- ``PROMETHEON_API_REQUEST_V1`` request signing.
- Snapshot Ed25519 signature verification.
- ``records_hash`` and ``page_hash`` recomputation and integrity checks.
- The detailed-mode streaming accumulator over signed pages.
- A typed HTTP client with retry, timeout, and structured error handling.

The platform module does not consume Bittensor or chain state. It consumes a
configured ``ValidatorRuntimeContext`` plus the trusted ``platform_key_id`` map
from configuration. Downstream code receives validated, signature-verified
objects that are safe to pass into ``prometheon.mechanisms.phase1_growth``.
"""
