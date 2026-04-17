"""Identity protocol: canonical payloads, verifiers, rotation, and recovery.

The identity module owns the four signed payload families:

- ``PROMETHEON_IDENTITY_VERIFY_V1``    miner / validator identity verification
- ``PROMETHEON_HOTKEY_ROTATION_V1``    normal rotation with old + new hotkey signatures
- ``PROMETHEON_HOTKEY_RECOVERY_V1``    coldkey recovery and manual recovery
- (API requests use ``PROMETHEON_API_REQUEST_V1`` from ``prometheon.platform``)

Payload construction, envelope construction, and verification helpers live
here. The HTTP wire shapes that wrap these payloads are constructed in
``prometheon.platform``.
"""
