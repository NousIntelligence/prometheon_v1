"""Unit tests for ``prometheon.security.nonce``.

Verifies cryptographic-quality nonce generation, canonical-format
validation, and the strict input rules around byte length.
"""

from __future__ import annotations

import re

import pytest

from prometheon.security.nonce import (
    NonceError,
    assert_valid_api_request_nonce,
    generate_api_request_nonce,
    is_valid_api_request_nonce,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


class TestGenerateApiRequestNonce:
    def test_default_length_is_16_bytes(self) -> None:
        nonce = generate_api_request_nonce()
        # 16 bytes = 32 hex characters, plus "0x" prefix = 34 total.
        assert len(nonce) == 34
        assert nonce.startswith("0x")

    def test_output_is_lowercase_hex(self) -> None:
        nonce = generate_api_request_nonce()
        # The two-character prefix is lowercase; the body is lowercase hex.
        assert nonce == nonce.lower()
        assert re.match(r"^0x[0-9a-f]{32}$", nonce)

    @pytest.mark.parametrize("byte_length", [16, 17, 24, 32, 48, 63, 64])
    def test_custom_lengths_accepted(self, byte_length: int) -> None:
        nonce = generate_api_request_nonce(byte_length)
        # Output length: 2 (prefix) + 2 * byte_length (hex chars).
        assert len(nonce) == 2 + 2 * byte_length

    @pytest.mark.parametrize("byte_length", [0, 1, 8, 15])
    def test_too_short_rejected(self, byte_length: int) -> None:
        with pytest.raises(NonceError, match=r"must be in \[16, 64\]"):
            generate_api_request_nonce(byte_length)

    @pytest.mark.parametrize("byte_length", [65, 128, 1024])
    def test_too_long_rejected(self, byte_length: int) -> None:
        with pytest.raises(NonceError, match=r"must be in \[16, 64\]"):
            generate_api_request_nonce(byte_length)

    def test_non_int_rejected(self) -> None:
        with pytest.raises(NonceError, match="must be int"):
            generate_api_request_nonce("32")  # type: ignore[arg-type]

    def test_bool_rejected(self) -> None:
        # bool is a subclass of int in Python; the generator must reject it
        # because True/False would otherwise pass through as 1/0.
        with pytest.raises(NonceError, match="must be int"):
            generate_api_request_nonce(True)  # type: ignore[arg-type]

    def test_nonces_are_unique(self) -> None:
        # 100 draws from a 16-byte (128-bit) CSPRNG must not collide.
        draws = {generate_api_request_nonce() for _ in range(100)}
        assert len(draws) == 100


# ---------------------------------------------------------------------------
# is_valid_api_request_nonce
# ---------------------------------------------------------------------------


class TestIsValidApiRequestNonce:
    def test_accepts_minimum_length(self) -> None:
        assert is_valid_api_request_nonce("0x" + "a" * 32)

    def test_accepts_maximum_length(self) -> None:
        assert is_valid_api_request_nonce("0x" + "a" * 128)

    def test_accepts_self_generated_nonces(self) -> None:
        for _ in range(20):
            assert is_valid_api_request_nonce(generate_api_request_nonce(32))

    @pytest.mark.parametrize(
        "bad",
        [
            "a" * 32,  # no 0x prefix
            "0X" + "a" * 32,  # uppercase X
            "0x" + "A" * 32,  # uppercase hex characters
            "0x" + "a" * 31,  # one character too short (15.5 bytes)
            "0x" + "a" * 129,  # one character too long
            "0x" + "g" * 32,  # non-hex characters
            "",
        ],
    )
    def test_rejects_invalid_strings(self, bad: str) -> None:
        assert not is_valid_api_request_nonce(bad)

    @pytest.mark.parametrize(
        "bad",
        [None, 123, b"0x" + b"a" * 32, ["0x" + "a" * 32]],
    )
    def test_rejects_non_strings(self, bad: object) -> None:
        assert not is_valid_api_request_nonce(bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# assert_valid_api_request_nonce
# ---------------------------------------------------------------------------


class TestAssertValidApiRequestNonce:
    def test_valid_nonce_does_not_raise(self) -> None:
        # Round-trip a generated nonce through the strict validator.
        assert_valid_api_request_nonce(generate_api_request_nonce(32))

    def test_non_str_raises(self) -> None:
        with pytest.raises(NonceError, match="must be str"):
            assert_valid_api_request_nonce(123)  # type: ignore[arg-type]

    def test_malformed_raises_with_pattern(self) -> None:
        with pytest.raises(NonceError, match="canonical form"):
            assert_valid_api_request_nonce("0x" + "A" * 32)
