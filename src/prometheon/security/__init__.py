"""Cryptographic and canonicalization primitives shared by the rest of the
package.

This module is the trust root of the implementation. It exposes:

- ``prometheon.security.canonical``    RFC 8785 JSON Canonicalization Scheme
                                       and the domain-prefixed signing/hashing envelope
- ``prometheon.security.hashes``       SHA-256 helpers, API-token hash, body/query hash
- ``prometheon.security.nonce``        cryptographic nonce generation for API requests
- ``prometheon.security.signatures``   SR25519 (Bittensor hotkey/coldkey) and
                                       Ed25519 (Platform snapshot) sign/verify wrappers

Every other module depends on these primitives rather than implementing crypto
inline. No code in this package may roll its own canonicalization or its own
curve maths.
"""
