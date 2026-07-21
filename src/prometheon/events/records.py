"""Event-record wire model and canonical bytes.

The delivery unit of the Decentralized Validation stream is the **record**:
a family-tagged, gap-free-sequenced envelope around a family-specific
``core``. This module owns:

- :class:`EventRecord` — strict validation of the record envelope shape
  (field formats, family/kind consistency, signature-field pairing).
- :func:`record_canonical_bytes` / :func:`core_canonical_bytes` — the exact
  byte sequences the day digest hashes and the device signature covers.
  Both operate on the **raw parsed mapping**, never on a model round-trip,
  so canonicalization is byte-stable against the wire regardless of model
  defaults or field ordering.
- :func:`parse_event_record` — strict-parse (duplicate/forbidden-key and
  float rejection) followed by validation, returning both the raw mapping
  (for canonicalization, storage, and digests) and the validated view.

Scoring semantics live elsewhere: cores are validated here only to the
envelope contract (a known ``kind`` for the family, integer-only values via
the canonical encoder). The scoring engine interprets ``scoring_fields``.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, ClassVar, Final

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from prometheon.security.canonical import (
    DOMAIN_EVENT,
    DOMAIN_EVENT_RECORD,
    CanonicalEncodingError,
    domain_prefixed_bytes,
    parse_canonical_json,
)


class EventFamily(str, Enum):
    """The four independently-sequenced stream families."""

    ACTIVITY = "activity"
    IDENTITY = "identity"
    GROUP = "group"
    EXCLUSION = "exclusion"


# Reward kinds carried by activity cores (scoring-port contract §2).
ACTIVITY_KINDS: Final[frozenset[str]] = frozenset(
    {
        "login",
        "service_detail_view",
        "category_exploration",
        "watchlist_add",
        "service_follow_add",
        "service_news_click",
        "compare_session",
        "demo_l1",
        "demo_l2",
        "demo_l3",
    }
)

IDENTITY_KINDS: Final[frozenset[str]] = frozenset(
    {
        "miner_hotkey_bind",
        "miner_hotkey_unbind",
        "validator_hotkey_bind",
        "validator_hotkey_unbind",
        "device_key_register",
        "device_key_revoke",
        "genesis_import",
    }
)

GROUP_KINDS: Final[frozenset[str]] = frozenset(
    {
        "group_created",
        "member_joined",
        "genesis_import",
    }
)

EXCLUSION_KINDS: Final[frozenset[str]] = frozenset(
    {
        "verdict",
        "verdicts_complete",
    }
)

KINDS_BY_FAMILY: Final[dict[EventFamily, frozenset[str]]] = {
    EventFamily.ACTIVITY: ACTIVITY_KINDS,
    EventFamily.IDENTITY: IDENTITY_KINDS,
    EventFamily.GROUP: GROUP_KINDS,
    EventFamily.EXCLUSION: EXCLUSION_KINDS,
}

# Wire-shape patterns (ingest-contract §3.2). All hex is lowercase with the
# 0x prefix; base64 and uppercase hex are rejected everywhere in Prometheon.
_EVENT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-f]{64}$")
_USER_REF_EVT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^usr_evt_[0-9a-f]{64}$")
_DEVICE_PUBKEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^0x04[0-9a-f]{128}$")
_USER_SIG_PATTERN: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-f]{128}$")
_EPOCH_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RECEIVED_TS_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class EventRecordError(ValueError):
    """A wire record failed envelope validation.

    Carries a stable ``code`` so the ingest layer can classify rejections
    without string matching.
    """

    def __init__(self, message: str, *, code: str = "record_invalid") -> None:
        super().__init__(message)
        self.code = code


class EventRecord(BaseModel):
    """Validated view of one stream record's envelope.

    The model checks shape and cross-field consistency. It is a *view*:
    canonicalization, hashing, and storage always use the raw parsed
    mapping the record arrived as (see :func:`parse_event_record`), never a
    re-serialization of this model.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    domain: str
    family: EventFamily
    seq: int
    epoch_id: str
    event_id: str
    user_ref_evt: str | None
    group_id: str | None
    received_ts: str
    category_id: str | None
    core: dict[str, Any]
    device_pubkey: str | None
    user_sig: str | None

    @field_validator("domain")
    @classmethod
    def _domain_is_record_domain(cls, value: str) -> str:
        if value != DOMAIN_EVENT_RECORD:
            raise ValueError(f"record domain must be {DOMAIN_EVENT_RECORD!r}, got {value!r}")
        return value

    @field_validator("seq", mode="before")
    @classmethod
    def _seq_is_positive(cls, value: Any) -> Any:
        # mode="before" so a JSON boolean is seen as bool, not coerced to int.
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"seq must be a positive integer, got {value!r}")
        return value

    @field_validator("epoch_id")
    @classmethod
    def _epoch_shape(cls, value: str) -> str:
        if not _EPOCH_ID_PATTERN.match(value):
            raise ValueError(f"epoch_id must be YYYY-MM-DD, got {value!r}")
        return value

    @field_validator("event_id")
    @classmethod
    def _event_id_shape(cls, value: str) -> str:
        if not _EVENT_ID_PATTERN.match(value):
            raise ValueError(f"event_id must be 0x + 64 lowercase hex, got {value!r}")
        return value

    @field_validator("user_ref_evt")
    @classmethod
    def _user_ref_shape(cls, value: str | None) -> str | None:
        if value is not None and not _USER_REF_EVT_PATTERN.match(value):
            raise ValueError(f"user_ref_evt must be usr_evt_ + 64 hex, got {value!r}")
        return value

    @field_validator("received_ts")
    @classmethod
    def _received_ts_shape(cls, value: str) -> str:
        if not _RECEIVED_TS_PATTERN.match(value):
            raise ValueError(
                f"received_ts must be strict ISO-8601 Z (no milliseconds), got {value!r}"
            )
        return value

    @field_validator("device_pubkey")
    @classmethod
    def _device_pubkey_shape(cls, value: str | None) -> str | None:
        if value is not None and not _DEVICE_PUBKEY_PATTERN.match(value):
            raise ValueError(
                f"device_pubkey must be 0x04 + 128 lowercase hex (SEC1 uncompressed), got {value!r}"
            )
        return value

    @field_validator("user_sig")
    @classmethod
    def _user_sig_shape(cls, value: str | None) -> str | None:
        if value is not None and not _USER_SIG_PATTERN.match(value):
            raise ValueError(f"user_sig must be 0x + 128 lowercase hex (r||s), got {value!r}")
        return value

    @model_validator(mode="after")
    def _cross_field_consistency(self) -> EventRecord:
        # Signature fields are both-or-neither: an unsigned record carries
        # explicit nulls in both; a signed one carries both.
        if (self.device_pubkey is None) != (self.user_sig is None):
            raise ValueError("device_pubkey and user_sig must both be set or both be null")

        kind = self.core.get("kind")
        if not isinstance(kind, str):
            raise ValueError("core.kind must be a string")
        allowed = KINDS_BY_FAMILY[self.family]
        if kind not in allowed:
            raise ValueError(f"core.kind {kind!r} is not a {self.family.value}-family kind")

        # Activity cores are the device-signable unit and must carry the
        # EVENT_V1 domain; platform-authored families carry no core domain.
        if self.family is EventFamily.ACTIVITY:
            core_domain = self.core.get("domain")
            if core_domain != DOMAIN_EVENT:
                raise ValueError(
                    f"activity core domain must be {DOMAIN_EVENT!r}, got {core_domain!r}"
                )
        elif self.device_pubkey is not None:
            raise ValueError(f"{self.family.value}-family records are never device-signed")

        # Only the exclusion-family epoch-close marker is user-less.
        if self.user_ref_evt is None and kind != "verdicts_complete":
            raise ValueError(f"user_ref_evt may be null only on verdicts_complete, not {kind!r}")

        return self


def record_canonical_bytes(record: dict[str, Any]) -> bytes:
    """The bytes the day digest hashes: ``EVENT_RECORD_V1 domain + JCS(record)``.

    Operates on the raw mapping so the output is byte-stable against the
    wire. Raises :class:`~prometheon.security.canonical.CanonicalEncodingError`
    if the mapping contains floats or cannot be canonicalized.
    """
    return domain_prefixed_bytes(DOMAIN_EVENT_RECORD, record)


def core_canonical_bytes(core: dict[str, Any]) -> bytes:
    """The bytes a device signature covers: ``EVENT_V1 domain + JCS(core)``."""
    return domain_prefixed_bytes(DOMAIN_EVENT, core)


def parse_event_record(raw: str | bytes) -> tuple[dict[str, Any], EventRecord]:
    """Strict-parse and validate one wire record.

    Returns ``(raw_mapping, validated_view)``. The raw mapping is what must
    be stored, canonicalized, and digest-hashed; the view is for typed
    access. Raises :class:`EventRecordError` (with ``code``) on strict-parse
    failures (``duplicate_key`` / ``forbidden_key`` / ``float_literal`` /
    ``invalid_json``) and on envelope-validation failures
    (``record_invalid``).
    """
    try:
        parsed = parse_canonical_json(raw)
    except CanonicalEncodingError as exc:
        raise EventRecordError(str(exc), code=exc.code) from exc
    return validate_event_record(parsed)


def validate_event_record(parsed: Any) -> tuple[dict[str, Any], EventRecord]:
    """Validate an already-parsed record mapping (see :func:`parse_event_record`)."""
    if not isinstance(parsed, dict):
        raise EventRecordError(f"event record must be a JSON object, got {type(parsed).__name__}")
    try:
        view = EventRecord.model_validate(parsed)
    except Exception as exc:
        raise EventRecordError(f"event record failed validation: {exc}") from exc
    return parsed, view


__all__ = [
    "ACTIVITY_KINDS",
    "EXCLUSION_KINDS",
    "GROUP_KINDS",
    "IDENTITY_KINDS",
    "KINDS_BY_FAMILY",
    "EventFamily",
    "EventRecord",
    "EventRecordError",
    "core_canonical_bytes",
    "parse_event_record",
    "record_canonical_bytes",
    "validate_event_record",
]
