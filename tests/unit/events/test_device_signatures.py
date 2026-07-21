"""Unit tests for device-key registry windows and signature classification."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from prometheon.events.device_signatures import (
    DeviceKeyRegistry,
    DeviceSignatureError,
    SignatureStatus,
    classify_signature,
    verify_core_signature,
)
from prometheon.events.records import core_canonical_bytes

pytestmark = pytest.mark.unit

USER = "usr_evt_" + "ab" * 32


def _keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    # Deterministic test key. 30 bytes of digest = a 240-bit scalar, always
    # inside the P-256 group order and non-zero for this fixed label.
    scalar = int.from_bytes(hashlib.sha256(b"prometheon-unit-device-key").digest()[:30], "big")
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    point = private.public_key().public_numbers()
    pub_hex = "0x04" + point.x.to_bytes(32, "big").hex() + point.y.to_bytes(32, "big").hex()
    return private, pub_hex


def _sign_core(private: ec.EllipticCurvePrivateKey, core: dict[str, Any]) -> str:
    der = private.sign(core_canonical_bytes(core), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def _core() -> dict[str, Any]:
    return {
        "domain": "PROMETHEON_EVENT_V1",
        "kind": "login",
        "target": {},
        "scoring_fields": {},
        "client_ts": "2026-07-10T08:00:00Z",
        "client_nonce": "0x0102030405060708",
    }


def _record(pub_hex: str | None, sig_hex: str | None, epoch: str = "2026-07-10") -> dict[str, Any]:
    return {
        "family": "activity",
        "seq": 1,
        "epoch_id": epoch,
        "user_ref_evt": USER,
        "core": _core(),
        "device_pubkey": pub_hex,
        "user_sig": sig_hex,
    }


def _registry(*events: dict[str, Any]) -> DeviceKeyRegistry:
    registry = DeviceKeyRegistry()
    for event in events:
        registry.apply_identity_record(event)
    return registry


def _register(pub_hex: str, epoch: str, user: str = USER) -> dict[str, Any]:
    return {
        "user_ref_evt": user,
        "epoch_id": epoch,
        "core": {"kind": "device_key_register", "public_key": pub_hex},
    }


def _revoke(pub_hex: str, epoch: str, user: str = USER) -> dict[str, Any]:
    return {
        "user_ref_evt": user,
        "epoch_id": epoch,
        "core": {"kind": "device_key_revoke", "public_key": pub_hex},
    }


class TestRegistryWindows:
    def test_unregistered_key_not_covered(self) -> None:
        registry = _registry()
        assert not registry.covers(USER, "0x04" + "aa" * 64, "2026-07-10")

    def test_open_interval_covers_from_register_epoch(self) -> None:
        registry = _registry(_register("0x04" + "aa" * 64, "2026-07-05"))
        assert registry.covers(USER, "0x04" + "aa" * 64, "2026-07-05")
        assert registry.covers(USER, "0x04" + "aa" * 64, "2026-12-31")
        assert not registry.covers(USER, "0x04" + "aa" * 64, "2026-07-04")

    def test_revoke_epoch_is_inclusive(self) -> None:
        registry = _registry(
            _register("0x04" + "aa" * 64, "2026-07-01"),
            _revoke("0x04" + "aa" * 64, "2026-07-05"),
        )
        assert registry.covers(USER, "0x04" + "aa" * 64, "2026-07-05")
        assert not registry.covers(USER, "0x04" + "aa" * 64, "2026-07-06")

    def test_reregistration_opens_a_new_interval(self) -> None:
        registry = _registry(
            _register("0x04" + "aa" * 64, "2026-07-01"),
            _revoke("0x04" + "aa" * 64, "2026-07-03"),
            _register("0x04" + "aa" * 64, "2026-07-08"),
        )
        assert registry.covers(USER, "0x04" + "aa" * 64, "2026-07-02")
        assert not registry.covers(USER, "0x04" + "aa" * 64, "2026-07-05")
        assert registry.covers(USER, "0x04" + "aa" * 64, "2026-07-09")

    def test_key_is_per_user(self) -> None:
        other = "usr_evt_" + "ff" * 32
        registry = _registry(_register("0x04" + "aa" * 64, "2026-07-01", user=other))
        assert not registry.covers(USER, "0x04" + "aa" * 64, "2026-07-02")

    def test_genesis_import_wrapper_is_unwrapped(self) -> None:
        registry = _registry(
            {
                "user_ref_evt": USER,
                "epoch_id": "2026-07-01",
                "core": {
                    "kind": "genesis_import",
                    "genesis_kind": "device_key_register",
                    "public_key": "0x04" + "aa" * 64,
                },
            }
        )
        assert registry.covers(USER, "0x04" + "aa" * 64, "2026-07-02")


class TestClassification:
    def test_unsigned_record(self) -> None:
        assert classify_signature(_record(None, None), _registry()) is SignatureStatus.UNSIGNED

    def test_verified_record(self) -> None:
        private, pub_hex = _keypair()
        record = _record(pub_hex, None)
        record["user_sig"] = _sign_core(private, record["core"])
        registry = _registry(_register(pub_hex, "2026-07-01"))
        assert classify_signature(record, registry) is SignatureStatus.VERIFIED

    def test_registered_but_bad_signature_is_invalid(self) -> None:
        private, pub_hex = _keypair()
        record = _record(pub_hex, None)
        record["user_sig"] = _sign_core(private, record["core"])
        record["core"]["client_nonce"] = "0x1111111111111111"
        registry = _registry(_register(pub_hex, "2026-07-01"))
        assert classify_signature(record, registry) is SignatureStatus.INVALID

    def test_unregistered_key(self) -> None:
        private, pub_hex = _keypair()
        record = _record(pub_hex, None)
        record["user_sig"] = _sign_core(private, record["core"])
        assert classify_signature(record, _registry()) is SignatureStatus.UNREGISTERED

    def test_post_revoke_epoch_is_unregistered(self) -> None:
        private, pub_hex = _keypair()
        record = _record(pub_hex, None, epoch="2026-07-09")
        record["user_sig"] = _sign_core(private, record["core"])
        registry = _registry(_register(pub_hex, "2026-07-01"), _revoke(pub_hex, "2026-07-08"))
        assert classify_signature(record, registry) is SignatureStatus.UNREGISTERED

    def test_same_day_as_revoke_still_verifies(self) -> None:
        private, pub_hex = _keypair()
        record = _record(pub_hex, None, epoch="2026-07-08")
        record["user_sig"] = _sign_core(private, record["core"])
        registry = _registry(_register(pub_hex, "2026-07-01"), _revoke(pub_hex, "2026-07-08"))
        assert classify_signature(record, registry) is SignatureStatus.VERIFIED


class TestVerifyCoreSignature:
    def test_malformed_pubkey_raises(self) -> None:
        with pytest.raises(DeviceSignatureError):
            verify_core_signature("0x04" + "zz" * 64, "0x" + "00" * 64, _core())

    def test_wrong_length_signature_raises(self) -> None:
        _, pub_hex = _keypair()
        with pytest.raises(DeviceSignatureError):
            verify_core_signature(pub_hex, "0x" + "00" * 63, _core())

    def test_float_in_core_raises(self) -> None:
        _private, pub_hex = _keypair()
        core = _core()
        core["scoring_fields"] = {"dwell_seconds": 1.5}
        with pytest.raises(DeviceSignatureError):
            verify_core_signature(pub_hex, "0x" + "00" * 64, core)
