"""Unit tests for ``prometheon.security.canonical``.

These tests exercise the RFC 8785 wrapper and the Prometheon-specific rules
on top of it: float rejection, NaN/Infinity rejection at parse time,
duplicate-key rejection, and the domain-prefixed envelope layout.
"""

from __future__ import annotations

import json

import pytest

from prometheon.security import canonical
from prometheon.security.canonical import (
    ALL_DOMAINS,
    DOMAIN_API_REQUEST,
    DOMAIN_IDENTITY_VERIFY,
    DOMAIN_SNAPSHOT,
    CanonicalEncodingError,
    domain_prefixed_bytes,
    parse_canonical_json,
    to_canonical_bytes,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Domain catalogue
# ---------------------------------------------------------------------------


class TestSigningDomains:
    """The twelve Prometheon signing domains must be exact, complete, and ASCII."""

    def test_all_twelve_domains_are_declared(self) -> None:
        assert (
            frozenset(
                {
                    "PROMETHEON_IDENTITY_VERIFY_V1",
                    "PROMETHEON_HOTKEY_ROTATION_V1",
                    "PROMETHEON_HOTKEY_RECOVERY_V1",
                    "PROMETHEON_API_REQUEST_V1",
                    "PROMETHEON_SNAPSHOT_V1",
                    "PROMETHEON_RECORD_SET_V1",
                    "PROMETHEON_RECORD_PAGE_V1",
                    "PROMETHEON_WEIGHT_PLAN_V1",
                    "PROMETHEON_INGEST_PUSH_V1",
                    "PROMETHEON_EVENT_RECORD_V1",
                    "PROMETHEON_EVENT_V1",
                    "PROMETHEON_DAY_DIGEST_V1",
                }
            )
            == ALL_DOMAINS
        )

    @pytest.mark.parametrize("domain", sorted(ALL_DOMAINS))
    def test_every_domain_is_pure_ascii(self, domain: str) -> None:
        # The envelope encodes the domain as ASCII; any non-ASCII byte would
        # silently change the prefix length and break verifiers in other
        # languages.
        domain.encode("ascii")  # must not raise


# ---------------------------------------------------------------------------
# to_canonical_bytes
# ---------------------------------------------------------------------------


class TestToCanonicalBytes:
    """Basic JCS behaviour delegated to ``rfc8785``, plus Prometheon checks."""

    def test_empty_object_canonicalizes_to_braces(self) -> None:
        assert to_canonical_bytes({}) == b"{}"

    def test_empty_array_canonicalizes_to_brackets(self) -> None:
        assert to_canonical_bytes([]) == b"[]"

    def test_object_keys_are_sorted(self) -> None:
        result = to_canonical_bytes({"b": 1, "a": 2})
        assert result == b'{"a":2,"b":1}'

    def test_array_order_is_preserved(self) -> None:
        # Arrays in JSON are ordered; canonicalization must not sort them.
        assert to_canonical_bytes([3, 1, 2]) == b"[3,1,2]"

    def test_ascii_string_round_trip(self) -> None:
        assert to_canonical_bytes({"msg": "hello"}) == b'{"msg":"hello"}'

    def test_utf8_string_emits_utf8_bytes(self) -> None:
        # Non-ASCII strings must come out as their UTF-8 byte sequence;
        # canonical JSON does not \\u-escape printable BMP characters.
        out = to_canonical_bytes({"city": "Zürich"})
        assert b"Z\xc3\xbcrich" in out

    def test_integers_emit_as_decimal_digits(self) -> None:
        assert to_canonical_bytes({"n": 1_000_000_000}) == b'{"n":1000000000}'

    def test_booleans_and_null_are_accepted(self) -> None:
        assert to_canonical_bytes({"a": True, "b": False, "c": None}) == (
            b'{"a":true,"b":false,"c":null}'
        )

    def test_nested_object_keys_are_sorted_at_every_level(self) -> None:
        nested = {"outer_b": {"inner_b": 1, "inner_a": 2}, "outer_a": 9}
        assert to_canonical_bytes(nested) == (b'{"outer_a":9,"outer_b":{"inner_a":2,"inner_b":1}}')


# ---------------------------------------------------------------------------
# Float rejection
# ---------------------------------------------------------------------------


class TestFloatRejection:
    """Floats are forbidden at any depth in Prometheon signed payloads."""

    def test_top_level_float_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            to_canonical_bytes({"score": 1.5})

    def test_float_in_nested_dict_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            to_canonical_bytes({"a": {"b": {"c": 0.1}}})

    def test_float_in_list_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            to_canonical_bytes({"weights": [1, 2, 3.0, 4]})

    def test_float_in_tuple_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            to_canonical_bytes({"weights": (1, 2, 3.0, 4)})

    def test_boolean_not_treated_as_float(self) -> None:
        # bool is a subclass of int in Python; the rejection logic must not
        # misclassify True/False as numeric.
        assert to_canonical_bytes({"flag": True}) == b'{"flag":true}'

    def test_non_string_object_key_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="object keys must be strings"):
            to_canonical_bytes({1: "value"})


# ---------------------------------------------------------------------------
# domain_prefixed_bytes
# ---------------------------------------------------------------------------


class TestDomainPrefixedBytes:
    """The signed-bytes envelope must always be ``ASCII(domain) + b"\\n" + JCS(obj)``."""

    def test_envelope_layout_matches_specification(self) -> None:
        payload = {"domain": DOMAIN_IDENTITY_VERIFY, "role": "miner"}
        envelope = domain_prefixed_bytes(DOMAIN_IDENTITY_VERIFY, payload)
        assert envelope == (b"PROMETHEON_IDENTITY_VERIFY_V1\n" + to_canonical_bytes(payload))

    def test_separator_is_exactly_one_newline_byte(self) -> None:
        payload = {"x": 1}
        envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, payload)
        # The separator is the byte immediately after the domain prefix and
        # immediately before the canonical JSON. It must be exactly b"\n".
        prefix_len = len(b"PROMETHEON_SNAPSHOT_V1")
        assert envelope[prefix_len : prefix_len + 1] == b"\n"

    @pytest.mark.parametrize("domain", sorted(ALL_DOMAINS))
    def test_each_known_domain_is_accepted(self, domain: str) -> None:
        # The payload object's "domain" field is conventionally set to the
        # same value; the envelope helper does not enforce that — verifiers
        # do — so the test only asserts the helper accepts the domain string.
        domain_prefixed_bytes(domain, {"domain": domain, "x": 1})

    def test_unknown_domain_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="unknown Prometheon signing domain"):
            domain_prefixed_bytes("PROMETHEON_FUTURE_PHASE_V1", {"x": 1})

    def test_empty_domain_rejected(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            domain_prefixed_bytes("", {"x": 1})

    def test_object_with_float_rejected_inside_envelope(self) -> None:
        with pytest.raises(CanonicalEncodingError):
            domain_prefixed_bytes(DOMAIN_API_REQUEST, {"domain": DOMAIN_API_REQUEST, "broken": 0.1})


# ---------------------------------------------------------------------------
# parse_canonical_json
# ---------------------------------------------------------------------------


class TestParseCanonicalJson:
    """The canonical parser must reject anything that would break byte stability."""

    def test_accepts_valid_canonical_object(self) -> None:
        canonical_bytes = b'{"a":1,"b":[1,2,3],"c":true,"d":null}'
        parsed = parse_canonical_json(canonical_bytes)
        assert parsed == {"a": 1, "b": [1, 2, 3], "c": True, "d": None}

    def test_accepts_str_input_and_bytes_input(self) -> None:
        text = '{"a":1}'
        assert parse_canonical_json(text) == parse_canonical_json(text.encode("utf-8"))

    def test_rejects_duplicate_object_keys(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="duplicate JSON object key"):
            parse_canonical_json('{"a":1,"a":2}')

    def test_rejects_duplicate_keys_at_nested_level(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="duplicate JSON object key"):
            parse_canonical_json('{"outer":{"k":1,"k":2}}')

    def test_rejects_float_with_decimal_point(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="float literal forbidden"):
            parse_canonical_json('{"score":1.5}')

    def test_rejects_float_in_exponent_form(self) -> None:
        # Numbers with an exponent are parsed as floats by Python's json
        # parser even when they are integer-valued; Prometheon requires
        # integer literals without exponent.
        with pytest.raises(CanonicalEncodingError, match="float literal forbidden"):
            parse_canonical_json('{"n":1e3}')

    def test_rejects_nan(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="non-canonical JSON token"):
            parse_canonical_json('{"n":NaN}')

    def test_rejects_positive_infinity(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="non-canonical JSON token"):
            parse_canonical_json('{"n":Infinity}')

    def test_rejects_negative_infinity(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="non-canonical JSON token"):
            parse_canonical_json('{"n":-Infinity}')

    def test_rejects_syntactically_invalid_json(self) -> None:
        with pytest.raises(CanonicalEncodingError, match="invalid JSON"):
            parse_canonical_json('{"a":')


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Canonicalize → parse round-trips an integer-only object losslessly."""

    def test_simple_round_trip(self) -> None:
        original = {"a": 1, "b": [1, 2, 3], "c": "hello", "d": True, "e": None}
        canonical_bytes = to_canonical_bytes(original)
        parsed = parse_canonical_json(canonical_bytes)
        assert parsed == original

    def test_round_trip_preserves_array_order(self) -> None:
        original = {"items": [{"i": 3}, {"i": 1}, {"i": 2}]}
        round_tripped = parse_canonical_json(to_canonical_bytes(original))
        assert [item["i"] for item in round_tripped["items"]] == [3, 1, 2]

    def test_canonicalization_is_idempotent(self) -> None:
        original = {"b": 2, "a": 1}
        once = to_canonical_bytes(original)
        twice = to_canonical_bytes(json.loads(once))
        assert once == twice


# ---------------------------------------------------------------------------
# Domain catalogue end-to-end smoke test
# ---------------------------------------------------------------------------


def test_envelope_domains_exposed_for_downstream_modules() -> None:
    """The downstream identity and platform modules import these constants by
    name. The names must be importable from the package surface that downstream
    code targets."""
    assert canonical.DOMAIN_IDENTITY_VERIFY == "PROMETHEON_IDENTITY_VERIFY_V1"
    assert canonical.DOMAIN_HOTKEY_ROTATION == "PROMETHEON_HOTKEY_ROTATION_V1"
    assert canonical.DOMAIN_HOTKEY_RECOVERY == "PROMETHEON_HOTKEY_RECOVERY_V1"
    assert canonical.DOMAIN_API_REQUEST == "PROMETHEON_API_REQUEST_V1"
    assert canonical.DOMAIN_SNAPSHOT == "PROMETHEON_SNAPSHOT_V1"
    assert canonical.DOMAIN_RECORD_SET == "PROMETHEON_RECORD_SET_V1"
    assert canonical.DOMAIN_RECORD_PAGE == "PROMETHEON_RECORD_PAGE_V1"
    assert canonical.DOMAIN_WEIGHT_PLAN == "PROMETHEON_WEIGHT_PLAN_V1"
