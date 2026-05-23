"""Unit tests for ``prometheon.security.hashes``.

Covers the small set of helpers that every other module uses for SHA-256
hashing and the spec-mandated query-string canonicalization.
"""

from __future__ import annotations

import hashlib

import pytest

from prometheon.security.canonical import (
    DOMAIN_API_REQUEST,
    DOMAIN_RECORD_SET,
    CanonicalEncodingError,
)
from prometheon.security.hashes import (
    EMPTY_SHA256_HEX,
    api_token_hash,
    body_hash,
    domain_prefixed_hash,
    query_hash,
    sha256_hex,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# sha256_hex
# ---------------------------------------------------------------------------


class TestSha256Hex:
    def test_empty_bytes_hex(self) -> None:
        # Well-known SHA-256 of the empty byte string.
        assert sha256_hex(b"") == (
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_matches_reference_implementation(self) -> None:
        data = b"prometheon"
        assert sha256_hex(data) == "0x" + hashlib.sha256(data).hexdigest()

    def test_output_is_lowercase(self) -> None:
        digest = sha256_hex(b"abc")
        # The "0x" prefix is lowercase; the 64 hex characters are lowercase.
        assert digest == digest.lower()

    def test_output_length_is_66_characters(self) -> None:
        assert len(sha256_hex(b"x")) == 66

    def test_empty_hash_constant_matches_function(self) -> None:
        assert EMPTY_SHA256_HEX == sha256_hex(b"")


# ---------------------------------------------------------------------------
# domain_prefixed_hash
# ---------------------------------------------------------------------------


class TestDomainPrefixedHash:
    def test_matches_manual_envelope_hash(self) -> None:
        payload = {"domain": DOMAIN_RECORD_SET, "snapshot_id": "phase1:2026-05-18:aggregate"}
        # The helper composes envelope bytes and hashes them; the test
        # recomputes that composition manually to verify equivalence.
        import rfc8785

        manual = (
            DOMAIN_RECORD_SET.encode("ascii") + b"\n" + rfc8785.dumps(payload)
        )
        assert domain_prefixed_hash(DOMAIN_RECORD_SET, payload) == sha256_hex(manual)

    def test_unknown_domain_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            domain_prefixed_hash("PROMETHEON_NOT_REAL_V1", {"x": 1})

    def test_float_in_payload_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            domain_prefixed_hash(DOMAIN_RECORD_SET, {"score": 0.1})


# ---------------------------------------------------------------------------
# api_token_hash
# ---------------------------------------------------------------------------


class TestApiTokenHash:
    def test_known_token_hashes_correctly(self) -> None:
        token = "pmt_test_token_12345"
        expected = "0x" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        assert api_token_hash(token) == expected

    def test_unicode_token_hashed_as_utf8(self) -> None:
        token = "ünîcödë-token"
        expected = "0x" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        assert api_token_hash(token) == expected

    def test_bytes_input_rejected(self) -> None:
        with pytest.raises(TypeError, match="api_token must be a str"):
            api_token_hash(b"not-a-string")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# body_hash
# ---------------------------------------------------------------------------


class TestBodyHash:
    def test_empty_body_matches_empty_hash_constant(self) -> None:
        assert body_hash(b"") == EMPTY_SHA256_HEX

    def test_non_empty_body_matches_sha256(self) -> None:
        body = b'{"hello":"world"}'
        assert body_hash(body) == "0x" + hashlib.sha256(body).hexdigest()

    def test_bytearray_accepted(self) -> None:
        assert body_hash(bytearray(b"abc")) == body_hash(b"abc")

    def test_str_input_rejected(self) -> None:
        with pytest.raises(TypeError, match="body must be bytes"):
            body_hash("not-bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# query_hash
# ---------------------------------------------------------------------------


class TestQueryHash:
    def test_none_query_hashes_to_empty(self) -> None:
        assert query_hash(None) == EMPTY_SHA256_HEX

    def test_empty_query_hashes_to_empty(self) -> None:
        assert query_hash({}) == EMPTY_SHA256_HEX

    def test_single_param(self) -> None:
        # Manually compute expected canonical query string and hash.
        canonical = b"page=3"
        assert query_hash({"page": "3"}) == sha256_hex(canonical)

    def test_sorts_keys_lexicographically(self) -> None:
        # Two equivalent dicts with different insertion orders must produce
        # the same canonical bytes.
        a = query_hash({"b": "2", "a": "1"})
        b = query_hash({"a": "1", "b": "2"})
        assert a == b
        # And the canonical order is alphabetical: a=1&b=2
        expected = sha256_hex(b"a=1&b=2")
        assert a == expected

    def test_sorts_duplicate_values_lexicographically(self) -> None:
        # Multi-value entries sort their values; with values "1" and "0",
        # canonical order is "0" before "1".
        expected = sha256_hex(b"k=0&k=1")
        assert query_hash({"k": ["1", "0"]}) == expected

    def test_percent_encoding_uses_uppercase_hex(self) -> None:
        # Space (0x20) is percent-encoded as %20 (uppercase hex octets per
        # RFC 3986 normalization). The "/" must also be encoded because we
        # pass safe="".
        digest = query_hash({"q": "a b/c"})
        # canonical query string is the bytes "q=a%20b%2Fc"
        expected = sha256_hex(b"q=a%20b%2Fc")
        assert digest == expected

    def test_unicode_values_percent_encoded(self) -> None:
        # "ü" is two UTF-8 bytes (0xC3 0xBC), so percent-encoded as %C3%BC.
        digest = query_hash({"city": "Zürich"})
        expected = sha256_hex(b"city=Z%C3%BCrich")
        assert digest == expected

    def test_non_string_value_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="must be str"):
            query_hash({"n": 5})  # type: ignore[dict-item]

    def test_non_string_key_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="name must be str"):
            query_hash({1: "value"})  # type: ignore[dict-item]

    def test_unsupported_value_type_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="must be str or list/tuple"):
            query_hash({"key": {"nested": "dict"}})  # type: ignore[dict-item]

    def test_tuple_value_accepted(self) -> None:
        # Tuples are accepted alongside lists.
        assert query_hash({"k": ("a", "b")}) == query_hash({"k": ["a", "b"]})


# ---------------------------------------------------------------------------
# Integration: domain envelope hash matches manual recompute
# ---------------------------------------------------------------------------


def test_domain_envelope_hash_matches_sha256_of_envelope() -> None:
    payload = {
        "domain": DOMAIN_API_REQUEST,
        "method": "GET",
        "path": "/v1/prometheon/phase1/snapshots/latest/aggregate",
        "netuid": 123,
    }
    import rfc8785

    envelope = DOMAIN_API_REQUEST.encode("ascii") + b"\n" + rfc8785.dumps(payload)
    assert domain_prefixed_hash(DOMAIN_API_REQUEST, payload) == (
        "0x" + hashlib.sha256(envelope).hexdigest()
    )
