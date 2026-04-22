"""Unit tests for ``prometheon.security.signatures``.

Covers both the SR25519 (Bittensor) and Ed25519 (Platform) verification
paths, plus the strict hex format helpers that gate every signature
operation in the protocol.
"""

from __future__ import annotations

import pytest
from bittensor_wallet import Keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.security.canonical import (
    DOMAIN_API_REQUEST,
    DOMAIN_HOTKEY_ROTATION,
    DOMAIN_IDENTITY_VERIFY,
    DOMAIN_SNAPSHOT,
    CanonicalEncodingError,
    domain_prefixed_bytes,
)
from prometheon.security.signatures import (
    SignatureAddressMismatchError,
    SignatureError,
    SignatureFormatError,
    SignatureVerificationError,
    public_key_bytes_to_hex,
    public_key_hex_to_bytes,
    sign_with_bittensor_keypair,
    signature_bytes_to_hex,
    signature_hex_to_bytes,
    verify_bittensor_signature,
    verify_ed25519_signature,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures — deterministic test keys
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_hotkey() -> Keypair:
    """Well-known Substrate test keypair derived from ``//Alice``.

    Using a derivation URI gives a deterministic SR25519 keypair without
    bringing real wallet material into the test suite.
    """
    return Keypair.create_from_uri("//Alice")


@pytest.fixture
def bob_hotkey() -> Keypair:
    """A second well-known test keypair to verify cross-key rejection."""
    return Keypair.create_from_uri("//Bob")


@pytest.fixture
def ed25519_test_keypair() -> tuple[Ed25519PrivateKey, str]:
    """A deterministic Ed25519 keypair for Platform-snapshot tests.

    Returns a tuple of (private_key, public_key_hex).
    """
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, "0x" + public_bytes.hex()


# ---------------------------------------------------------------------------
# Hex encoding helpers
# ---------------------------------------------------------------------------


class TestSignatureHexHelpers:
    def test_round_trip(self) -> None:
        sig = b"\x01" * 64
        encoded = signature_bytes_to_hex(sig)
        assert encoded.startswith("0x")
        assert len(encoded) == 130
        assert signature_hex_to_bytes(encoded) == sig

    def test_lowercase_only(self) -> None:
        sig = bytes(range(64))
        encoded = signature_bytes_to_hex(sig)
        # All hex characters after "0x" are lowercase.
        assert encoded[2:] == encoded[2:].lower()

    def test_wrong_byte_length_rejected_on_encode(self) -> None:
        with pytest.raises(SignatureFormatError, match="must be 64 bytes"):
            signature_bytes_to_hex(b"\x00" * 63)

    def test_non_bytes_input_rejected_on_encode(self) -> None:
        with pytest.raises(SignatureFormatError, match="must be bytes"):
            signature_bytes_to_hex("0x" + "00" * 64)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "bad_hex",
        [
            "00" * 64,  # missing 0x prefix
            "0X" + "00" * 64,  # uppercase X
            "0x" + "FF" * 64,  # uppercase hex characters
            "0x" + "00" * 63,  # too short
            "0x" + "00" * 65,  # too long
            "0x" + "zz" * 64,  # non-hex characters
        ],
    )
    def test_invalid_hex_rejected_on_decode(self, bad_hex: str) -> None:
        with pytest.raises(SignatureFormatError):
            signature_hex_to_bytes(bad_hex)

    def test_non_str_input_rejected_on_decode(self) -> None:
        with pytest.raises(SignatureFormatError, match="must be str"):
            signature_hex_to_bytes(b"0x" + b"00" * 64)  # type: ignore[arg-type]


class TestPublicKeyHexHelpers:
    def test_round_trip(self) -> None:
        pk = b"\xab" * 32
        encoded = public_key_bytes_to_hex(pk)
        assert len(encoded) == 66
        assert public_key_hex_to_bytes(encoded) == pk

    def test_wrong_byte_length_rejected(self) -> None:
        with pytest.raises(SignatureFormatError, match="must be 32 bytes"):
            public_key_bytes_to_hex(b"\x00" * 31)

    @pytest.mark.parametrize(
        "bad_hex",
        [
            "00" * 32,
            "0x" + "AA" * 32,  # uppercase
            "0x" + "00" * 31,
            "0x" + "00" * 33,
        ],
    )
    def test_invalid_hex_rejected_on_decode(self, bad_hex: str) -> None:
        with pytest.raises(SignatureFormatError):
            public_key_hex_to_bytes(bad_hex)


# ---------------------------------------------------------------------------
# SR25519 sign/verify round trip
# ---------------------------------------------------------------------------


class TestSr25519SignAndVerify:
    """Sign with a deterministic test keypair and verify with the matching SS58."""

    def test_round_trip_for_identity_payload(self, alice_hotkey: Keypair) -> None:
        payload = {
            "domain": DOMAIN_IDENTITY_VERIFY,
            "role": "miner",
            "netuid": 123,
            "hotkey_ss58": alice_hotkey.ss58_address,
        }
        signature_hex = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_IDENTITY_VERIFY, payload)
        # The matching SS58 verifies; no exception is raised.
        verify_bittensor_signature(
            alice_hotkey.ss58_address, signature_hex, DOMAIN_IDENTITY_VERIFY, payload
        )

    def test_signature_is_canonical_hex(self, alice_hotkey: Keypair) -> None:
        payload = {"domain": DOMAIN_API_REQUEST, "method": "GET"}
        signature_hex = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_API_REQUEST, payload)
        assert signature_hex.startswith("0x")
        assert len(signature_hex) == 130
        assert signature_hex[2:] == signature_hex[2:].lower()

    def test_two_signatures_over_same_envelope_both_verify(self, alice_hotkey: Keypair) -> None:
        # SR25519 produces non-deterministic signatures by default. Two
        # signatures over the same envelope may differ, but both must verify.
        payload = {"domain": DOMAIN_API_REQUEST, "method": "GET", "path": "/x"}
        sig_a = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_API_REQUEST, payload)
        sig_b = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_API_REQUEST, payload)
        for sig in (sig_a, sig_b):
            verify_bittensor_signature(alice_hotkey.ss58_address, sig, DOMAIN_API_REQUEST, payload)

    def test_unknown_domain_rejected_on_sign(self, alice_hotkey: Keypair) -> None:
        # The envelope builder rejects unknown domains; the signer surfaces
        # that as a CanonicalEncodingError.
        with pytest.raises(CanonicalEncodingError):
            sign_with_bittensor_keypair(alice_hotkey, "PROMETHEON_NOT_REAL_V1", {"x": 1})


class TestSr25519VerifyRejections:
    """Every variation that would let an attacker forge a signed payload."""

    def test_wrong_ss58_rejected(self, alice_hotkey: Keypair, bob_hotkey: Keypair) -> None:
        payload = {"domain": DOMAIN_IDENTITY_VERIFY, "x": 1}
        sig = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_IDENTITY_VERIFY, payload)
        # Bob's SS58 cannot verify Alice's signature.
        with pytest.raises(SignatureVerificationError):
            verify_bittensor_signature(
                bob_hotkey.ss58_address, sig, DOMAIN_IDENTITY_VERIFY, payload
            )

    def test_modified_payload_rejected(self, alice_hotkey: Keypair) -> None:
        payload = {"domain": DOMAIN_IDENTITY_VERIFY, "x": 1}
        sig = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_IDENTITY_VERIFY, payload)
        tampered = {"domain": DOMAIN_IDENTITY_VERIFY, "x": 2}
        with pytest.raises(SignatureVerificationError):
            verify_bittensor_signature(
                alice_hotkey.ss58_address, sig, DOMAIN_IDENTITY_VERIFY, tampered
            )

    def test_modified_domain_rejected(self, alice_hotkey: Keypair) -> None:
        payload = {"domain": DOMAIN_IDENTITY_VERIFY, "x": 1}
        sig = sign_with_bittensor_keypair(alice_hotkey, DOMAIN_IDENTITY_VERIFY, payload)
        # Using a different signing domain for verification flips the
        # external prefix and breaks the signature even though the payload
        # bytes are identical.
        with pytest.raises(SignatureVerificationError):
            verify_bittensor_signature(
                alice_hotkey.ss58_address, sig, DOMAIN_HOTKEY_ROTATION, payload
            )

    def test_malformed_signature_hex_rejected(self, alice_hotkey: Keypair) -> None:
        with pytest.raises(SignatureFormatError):
            verify_bittensor_signature(
                alice_hotkey.ss58_address,
                "0x" + "FF" * 64,  # uppercase, will be rejected
                DOMAIN_IDENTITY_VERIFY,
                {"x": 1},
            )

    def test_invalid_ss58_rejected(self) -> None:
        with pytest.raises(SignatureAddressMismatchError):
            verify_bittensor_signature(
                "not-a-valid-ss58-address",
                "0x" + "00" * 64,
                DOMAIN_IDENTITY_VERIFY,
                {"x": 1},
            )


# ---------------------------------------------------------------------------
# Ed25519 verification (Platform snapshot signatures)
# ---------------------------------------------------------------------------


class TestEd25519Verify:
    def test_valid_signature_verifies(
        self, ed25519_test_keypair: tuple[Ed25519PrivateKey, str]
    ) -> None:
        private_key, public_key_hex = ed25519_test_keypair
        # Sign the canonical snapshot envelope shape so the test mirrors
        # production usage.
        snapshot_obj = {
            "domain": DOMAIN_SNAPSHOT,
            "mechanism": "phase1_growth",
            "snapshot_id": "phase1:2026-05-18:aggregate",
        }
        envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, snapshot_obj)
        sig_bytes = private_key.sign(envelope)
        sig_hex = "0x" + sig_bytes.hex()

        # No exception means the signature verified.
        verify_ed25519_signature(public_key_hex, sig_hex, envelope)

    def test_modified_message_rejected(
        self, ed25519_test_keypair: tuple[Ed25519PrivateKey, str]
    ) -> None:
        private_key, public_key_hex = ed25519_test_keypair
        sig_bytes = private_key.sign(b"original message")
        sig_hex = "0x" + sig_bytes.hex()
        with pytest.raises(SignatureVerificationError):
            verify_ed25519_signature(public_key_hex, sig_hex, b"tampered message")

    def test_wrong_public_key_rejected(
        self, ed25519_test_keypair: tuple[Ed25519PrivateKey, str]
    ) -> None:
        private_key, _ = ed25519_test_keypair
        # Use a different valid Ed25519 public key for verification.
        other_private_key = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
        other_public_hex = "0x" + other_private_key.public_key().public_bytes_raw().hex()

        sig_bytes = private_key.sign(b"message")
        sig_hex = "0x" + sig_bytes.hex()
        with pytest.raises(SignatureVerificationError):
            verify_ed25519_signature(other_public_hex, sig_hex, b"message")

    def test_malformed_public_key_rejected(self) -> None:
        with pytest.raises(SignatureFormatError):
            verify_ed25519_signature(
                "0xnot-hex",
                "0x" + "00" * 64,
                b"message",
            )

    def test_malformed_signature_rejected(
        self, ed25519_test_keypair: tuple[Ed25519PrivateKey, str]
    ) -> None:
        _, public_key_hex = ed25519_test_keypair
        with pytest.raises(SignatureFormatError):
            verify_ed25519_signature(public_key_hex, "0x" + "00" * 63, b"message")

    def test_non_bytes_message_rejected(
        self, ed25519_test_keypair: tuple[Ed25519PrivateKey, str]
    ) -> None:
        _, public_key_hex = ed25519_test_keypair
        with pytest.raises(SignatureFormatError, match="must be bytes"):
            verify_ed25519_signature(
                public_key_hex,
                "0x" + "00" * 64,
                "string-not-bytes",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_all_specific_errors_inherit_from_signature_error(self) -> None:
        # Code paths that catch SignatureError should catch every specific
        # subclass too; the hierarchy guarantees a single base for telemetry.
        assert issubclass(SignatureFormatError, SignatureError)
        assert issubclass(SignatureVerificationError, SignatureError)
        assert issubclass(SignatureAddressMismatchError, SignatureError)

    @pytest.mark.parametrize(
        "exc_cls, expected_code",
        [
            (SignatureFormatError, "signature.invalid_format"),
            (SignatureVerificationError, "signature.verification_failed"),
            (SignatureAddressMismatchError, "signature.address_mismatch"),
        ],
    )
    def test_codes_match_catalog(self, exc_cls: type[SignatureError], expected_code: str) -> None:
        assert exc_cls.code == expected_code
