"""Device-signature verification and signature-status classification.

Activity records may carry an optional per-user attestation: an ECDSA P-256
signature by a **device key** over the record's core
(``PROMETHEON_EVENT_V1`` domain bytes). Device keys are registered and
revoked through the ``identity`` family, so trust in a signature is a
function of both cryptography and identity-family state.

Two layers, matching the contract's two vocabularies:

- **Ingest-time annotation** (never blocks storage): a signed record is
  ``verified`` / ``pending`` (key not yet seen — the identity family lags) /
  ``failed``; an unsigned record is ``absent``. The batch publisher
  signature is the trust anchor; nothing here rejects a record.
- **Scoring-time classification** (fixture-pinned by ``score-kernel/02``):
  evaluated against identity-family state complete through the scored
  epoch, every record resolves to ``unsigned`` / ``verified`` /
  ``invalid`` / ``unregistered``. The scoring engine excludes ``invalid``
  and ``unregistered`` records — which an honest platform structurally
  never emits — and raises a high-severity alarm, since their presence in
  the publisher-signed stream is durable evidence of injection.

The attestation window is ``register.epoch_id <= e <= revoke.epoch_id``,
revoke-epoch **inclusive** (the platform verifies against an active key at
recording time and never stores a signature made after revocation, so a
legitimate same-day-as-revoke signature must not be classified as bad).
Families are sequenced independently — registration is matched by
identity-family *state*, never by cross-family seq comparison.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from prometheon.events.records import core_canonical_bytes
from prometheon.security.canonical import CanonicalEncodingError


class SignatureStatus(str, Enum):
    """Scoring-time classification of a record's device signature."""

    UNSIGNED = "unsigned"
    VERIFIED = "verified"
    INVALID = "invalid"
    UNREGISTERED = "unregistered"


class DeviceSignatureError(ValueError):
    """A device-signature input was malformed beyond classification.

    Raised only for inputs that violate the wire shape (bad hex, wrong
    lengths). A well-formed signature that simply does not verify is a
    *classification* (``invalid``), not an error.
    """


class DeviceKeyRegistry:
    """Attestation windows derived from identity-family device-key events.

    Feed identity-family records (raw mappings) in seq order via
    :meth:`apply_identity_record`; ``genesis_import`` wrappers are
    unwrapped. Each ``device_key_register`` opens an interval at its
    ``epoch_id``; a subsequent ``device_key_revoke`` for the same
    ``(user_ref_evt, public_key)`` closes it at the revoke ``epoch_id``,
    inclusive. Re-registration after a revoke opens a new interval, so
    coverage is "epoch falls inside any interval".
    """

    def __init__(self) -> None:
        # (user_ref_evt, public_key) -> list of [start_epoch, end_epoch | None]
        self._intervals: dict[tuple[str, str], list[list[str | None]]] = {}

    def apply_identity_record(self, record: dict[str, Any]) -> None:
        """Consume one identity-family record; ignores non-key kinds."""
        core = record.get("core", record)
        kind = core.get("kind")
        payload = core
        if kind == "genesis_import":
            kind = core.get("genesis_kind")
            payload = core
        if kind not in ("device_key_register", "device_key_revoke"):
            return

        user = record.get("user_ref_evt") or payload.get("user_ref_evt")
        public_key = payload.get("public_key")
        epoch = record.get("epoch_id") or payload.get("epoch_id")
        if not (isinstance(user, str) and isinstance(public_key, str) and isinstance(epoch, str)):
            return

        intervals = self._intervals.setdefault((user, public_key), [])
        if kind == "device_key_register":
            intervals.append([epoch, None])
        else:
            for interval in reversed(intervals):
                if interval[1] is None:
                    interval[1] = epoch
                    break

    def covers(self, user_ref_evt: str, public_key: str, epoch_id: str) -> bool:
        """True when ``epoch_id`` falls inside any attestation interval."""
        for start, end in self._intervals.get((user_ref_evt, public_key), []):
            if start is not None and start <= epoch_id and (end is None or epoch_id <= end):
                return True
        return False


def verify_core_signature(device_pubkey: str, user_sig: str, core: dict[str, Any]) -> bool:
    """Cryptographically verify a P-256 ``r||s`` signature over the core bytes.

    Returns ``True`` when the signature verifies, ``False`` when it is
    well-formed but does not verify. Raises :class:`DeviceSignatureError`
    on malformed inputs (the record model normally rejects those first).
    """
    try:
        pub_raw = bytes.fromhex(device_pubkey[2:])
        sig_raw = bytes.fromhex(user_sig[2:])
    except ValueError as exc:
        raise DeviceSignatureError(f"malformed hex in signature fields: {exc}") from exc
    if len(pub_raw) != 65 or pub_raw[0] != 0x04:
        raise DeviceSignatureError("device_pubkey must be a 65-byte SEC1 uncompressed point")
    if len(sig_raw) != 64:
        raise DeviceSignatureError("user_sig must be a 64-byte r||s pair")

    try:
        message = core_canonical_bytes(core)
    except CanonicalEncodingError as exc:
        raise DeviceSignatureError(f"core cannot be canonicalized: {exc}") from exc

    try:
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_raw)
    except ValueError as exc:
        raise DeviceSignatureError(f"device_pubkey is not a valid P-256 point: {exc}") from exc

    der = encode_dss_signature(
        int.from_bytes(sig_raw[:32], "big"), int.from_bytes(sig_raw[32:], "big")
    )
    try:
        pubkey.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def classify_signature(record: dict[str, Any], registry: DeviceKeyRegistry) -> SignatureStatus:
    """Scoring-time classification of one record against registry state.

    The caller guarantees the registry reflects identity-family state
    complete through the record's epoch (the scoring gate already requires
    this), so ``pending`` cannot occur here: an unmatched key is
    definitively ``unregistered``.
    """
    device_pubkey = record.get("device_pubkey")
    user_sig = record.get("user_sig")
    if device_pubkey is None and user_sig is None:
        return SignatureStatus.UNSIGNED

    user = record.get("user_ref_evt")
    if (
        not isinstance(user, str)
        or not isinstance(device_pubkey, str)
        or not isinstance(user_sig, str)
    ):
        return SignatureStatus.INVALID

    if not registry.covers(user, device_pubkey, record["epoch_id"]):
        return SignatureStatus.UNREGISTERED

    try:
        verified = verify_core_signature(device_pubkey, user_sig, record["core"])
    except DeviceSignatureError:
        return SignatureStatus.INVALID
    return SignatureStatus.VERIFIED if verified else SignatureStatus.INVALID


__all__ = [
    "DeviceKeyRegistry",
    "DeviceSignatureError",
    "SignatureStatus",
    "classify_signature",
    "verify_core_signature",
]
