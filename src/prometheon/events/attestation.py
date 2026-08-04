"""Validator countersignatures over platform day digests.

The platform signs each day's per-family digest when it seals the day. A
validator that has received that day's records can do something the
platform cannot do for itself: recompute ``records_hash`` from the bytes it
actually holds and state, under its own key, that the two agree.

That statement is this module. An attestation is produced only after the
local recomputation matches, so it says::

    validator <hotkey> holds records for (family, epoch) whose canonical
    hash equals the one the platform signed in <platform_signature>

Two properties follow from how it is built:

- **Two independent keys.** The artifact a validator treats as canonical
  carries the platform's signature and its own, over the same digest. No
  single party produced it.
- **Per validator, independently.** There is no quorum, threshold, or
  collection point. Each validator signs what it received, on its own, and
  a validator that is offline blocks nothing.

The attestation binds the platform's *signature*, not just the digest
contents: across a key rotation two platform keys can sign identical
contents, and an attestation should name the artifact it verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

from bittensor_wallet import Keypair

from prometheon.events.backfill import (
    BackfillClient,
    CompletenessReport,
    SignedDayDigest,
    compare_day,
)
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore
from prometheon.security.canonical import DOMAIN_DIGEST_ATTESTATION
from prometheon.security.signatures import (
    SignatureError,
    sign_with_bittensor_keypair,
    verify_bittensor_signature,
)

ATTESTATION_PATH: Final[str] = "/api/v1/prometheon/events/digest/attestation"

#: Schema marker carried on every persisted attestation line.
ATTESTATION_VERSION: Final[str] = "digest-attestation/v1"


class AttestationError(Exception):
    """An attestation could not be produced or did not verify."""

    code: str = "attestation.error"


class DigestMismatchError(AttestationError):
    """Local records disagree with the signed digest, so nothing is signed.

    This is the case the whole mechanism exists to make visible. A validator
    that signed here would be attesting to bytes it does not hold.
    """

    code: str = "attestation.digest_mismatch"

    def __init__(self, report: CompletenessReport) -> None:
        super().__init__(
            f"local records for {report.family.value}/{report.epoch_id} do not match the "
            f"signed digest (local {report.local_records_hash} records, count {report.local_record_count}; "
            f"digest {report.digest_records_hash} records, count {report.digest_record_count})"
        )
        self.report = report


@dataclass(frozen=True)
class DigestAttestation:
    """A validator's signed statement about one (family, epoch) digest."""

    family: EventFamily
    epoch_id: str
    records_hash: str
    record_count: int
    platform_key_id: str
    platform_signature: str
    validator_hotkey: str
    attested_at: str
    signature: str

    @property
    def key(self) -> str:
        """Stable ``family/epoch`` identifier for dedupe and lookup."""
        return f"{self.family.value}/{self.epoch_id}"

    def to_wire(self) -> dict[str, Any]:
        """The submission body: the signed envelope plus the signature."""
        body = attestation_envelope(
            family=self.family,
            epoch_id=self.epoch_id,
            records_hash=self.records_hash,
            record_count=self.record_count,
            platform_key_id=self.platform_key_id,
            platform_signature=self.platform_signature,
            validator_hotkey=self.validator_hotkey,
            attested_at=self.attested_at,
        )
        body["signature"] = self.signature
        body["version"] = ATTESTATION_VERSION
        return body


def attestation_envelope(
    *,
    family: EventFamily,
    epoch_id: str,
    records_hash: str,
    record_count: int,
    platform_key_id: str,
    platform_signature: str,
    validator_hotkey: str,
    attested_at: str,
) -> dict[str, Any]:
    """The canonical dict a validator signs.

    Field set is fixed and ordered by the canonical encoder, so any
    conforming implementation reconstructs identical bytes from a wire
    body. Adding a field here is a wire-format change.
    """
    return {
        "domain": DOMAIN_DIGEST_ATTESTATION,
        "family": family.value,
        "epoch_id": epoch_id,
        "records_hash": records_hash,
        "record_count": record_count,
        "platform_key_id": platform_key_id,
        "platform_signature": platform_signature,
        "validator_hotkey": validator_hotkey,
        "attested_at": attested_at,
    }


def build_attestation(
    *,
    digest: SignedDayDigest,
    report: CompletenessReport,
    keypair: Keypair,
    attested_at: str | None = None,
) -> DigestAttestation:
    """Sign ``digest`` with ``keypair`` once local records are known to match.

    Raises :class:`DigestMismatchError` when they do not. The check is here
    rather than at the call site so no code path can produce a signature
    without it.
    """
    if not report.matches:
        raise DigestMismatchError(report)
    if report.family is not digest.family or report.epoch_id != digest.epoch_id:
        raise AttestationError(
            f"completeness report is for {report.family.value}/{report.epoch_id}, "
            f"digest is for {digest.family.value}/{digest.epoch_id}"
        )

    moment = attested_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    envelope = attestation_envelope(
        family=digest.family,
        epoch_id=digest.epoch_id,
        records_hash=digest.records_hash,
        record_count=digest.record_count,
        platform_key_id=digest.platform_key_id,
        platform_signature=digest.signature,
        validator_hotkey=keypair.ss58_address,
        attested_at=moment,
    )
    signature = sign_with_bittensor_keypair(keypair, DOMAIN_DIGEST_ATTESTATION, envelope)
    return DigestAttestation(
        family=digest.family,
        epoch_id=digest.epoch_id,
        records_hash=digest.records_hash,
        record_count=digest.record_count,
        platform_key_id=digest.platform_key_id,
        platform_signature=digest.signature,
        validator_hotkey=keypair.ss58_address,
        attested_at=moment,
        signature=signature,
    )


def verify_attestation(payload: dict[str, Any]) -> DigestAttestation:
    """Verify a wire body against the hotkey it names, and return it typed.

    Anyone can call this — the platform, another validator, an auditor —
    with nothing but the body: the signing key is the ``validator_hotkey``
    inside it, and Bittensor hotkeys are public.
    """
    required = {
        "family",
        "epoch_id",
        "records_hash",
        "record_count",
        "platform_key_id",
        "platform_signature",
        "validator_hotkey",
        "attested_at",
        "signature",
    }
    missing = required - set(payload)
    if missing:
        raise AttestationError(f"attestation missing fields: {sorted(missing)}")

    try:
        family = EventFamily(payload["family"])
    except ValueError as exc:
        raise AttestationError(f"unknown family {payload['family']!r}") from exc

    record_count = payload["record_count"]
    if not isinstance(record_count, int) or isinstance(record_count, bool) or record_count < 0:
        raise AttestationError("record_count malformed")
    for field in ("epoch_id", "records_hash", "platform_key_id", "platform_signature"):
        if not isinstance(payload[field], str) or not payload[field]:
            raise AttestationError(f"{field} malformed")

    hotkey = payload["validator_hotkey"]
    signature = payload["signature"]
    if not isinstance(hotkey, str) or not isinstance(signature, str):
        raise AttestationError("validator_hotkey or signature malformed")

    envelope = attestation_envelope(
        family=family,
        epoch_id=payload["epoch_id"],
        records_hash=payload["records_hash"],
        record_count=record_count,
        platform_key_id=payload["platform_key_id"],
        platform_signature=payload["platform_signature"],
        validator_hotkey=hotkey,
        attested_at=payload["attested_at"],
    )
    try:
        verify_bittensor_signature(
            ss58_address=hotkey,
            signature_hex=signature,
            domain=DOMAIN_DIGEST_ATTESTATION,
            payload=envelope,
        )
    except SignatureError as exc:
        # Collapsed to one code on purpose: a caller checking an
        # attestation wants "this is not a valid statement by that hotkey",
        # and the distinction between a malformed signature and a
        # non-verifying one is a detail for the message, not a branch.
        raise AttestationError(f"attestation signature did not verify: {exc}") from exc

    return DigestAttestation(
        family=family,
        epoch_id=payload["epoch_id"],
        records_hash=payload["records_hash"],
        record_count=record_count,
        platform_key_id=payload["platform_key_id"],
        platform_signature=payload["platform_signature"],
        validator_hotkey=hotkey,
        attested_at=payload["attested_at"],
        signature=signature,
    )


def attest_day(
    *,
    client: BackfillClient,
    store: EventStore,
    family: EventFamily,
    epoch_id: str,
    keypair: Keypair,
    attested_at: str | None = None,
) -> DigestAttestation:
    """Fetch, verify, compare, and countersign one (family, epoch) digest.

    The order is load-bearing: the platform's signature is verified by
    :meth:`BackfillClient.fetch_digest`, the local recomputation happens
    next, and only a match reaches the signing step.
    """
    digest = client.fetch_digest(family, epoch_id)
    report = compare_day(store, digest)
    return build_attestation(digest=digest, report=report, keypair=keypair, attested_at=attested_at)


def submit_attestation(client: BackfillClient, attestation: DigestAttestation) -> dict[str, Any]:
    """POST an attestation to the platform.

    Submission is delivery, not validity: the attestation is already
    complete and verifiable the moment it is signed, and the validator
    keeps its own copy regardless of what the platform does with this.
    """
    return client.post_json(ATTESTATION_PATH, attestation.to_wire())


__all__ = [
    "ATTESTATION_PATH",
    "ATTESTATION_VERSION",
    "AttestationError",
    "DigestAttestation",
    "DigestMismatchError",
    "attest_day",
    "attestation_envelope",
    "build_attestation",
    "submit_attestation",
    "verify_attestation",
]
