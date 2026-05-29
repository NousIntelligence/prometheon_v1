"""Unit tests for ``prometheon.platform`` foundational helpers.

Covers:

- The platform error code catalog and response → exception mapping.
- Endpoint path constants, ``aggregate_path`` / ``detailed_manifest_path``
  / ``detailed_page_path`` helpers, and ``SnapshotMode`` enum.
- ``TokenScope`` enum membership.
"""

from __future__ import annotations

import pytest

import prometheon.platform.errors as platform_errors_module
from prometheon.platform.endpoints import (
    AGGREGATE_PATH_TEMPLATE,
    DETAILED_MANIFEST_PATH_TEMPLATE,
    DETAILED_PAGE_PATH_TEMPLATE,
    LATEST,
    NONCE_PATH,
    RECOVER_HOTKEY_PATH,
    ROTATE_HOTKEY_PATH,
    VERIFY_PATH,
    SnapshotMode,
    aggregate_path,
    detailed_manifest_path,
    detailed_page_path,
)
from prometheon.platform.errors import (
    AccountLockedOutError,
    AuthInvalidTokenError,
    AuthTokenScopeMissingError,
    ColdkeyOwnershipNotProvenError,
    DiscordHandleMissingError,
    EnvironmentMismatchPlatformError,
    MinerFanGroupRequiredError,
    NonceAlreadyUsedError,
    NonceExpiredError,
    PlatformBadRequestError,
    PlatformError,
    PlatformServerError,
    ProfileAlreadyHasHotkeyError,
    RotationCooldownActiveError,
    SignatureAddressMismatchError,
    SignatureDomainMismatchError,
    SignatureInvalidFormatError,
    SignaturePlatformError,
    SignatureUnsupportedKeyTypeError,
    SignatureVerificationFailedError,
    SnapshotNotReadyError,
    SnapshotPageHashError,
    SnapshotPageNotFoundError,
    SnapshotStorageAccessDeniedError,
    SnapshotStorageError,
    TwoFactorProofInvalidError,
    exception_for_code,
    platform_error_from_response_body,
)
from prometheon.platform.tokens import TokenScope

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# PlatformError catalog
# ---------------------------------------------------------------------------


class TestPlatformErrorCatalog:
    @pytest.mark.parametrize(
        "code, expected_cls",
        [
            ("AUTH_INVALID_TOKEN", AuthInvalidTokenError),
            ("ACCOUNT_LOCKED_OUT", AccountLockedOutError),
            ("NONCE_EXPIRED", NonceExpiredError),
            ("NONCE_ALREADY_USED", NonceAlreadyUsedError),
            ("ROTATION_COOLDOWN_ACTIVE", RotationCooldownActiveError),
            ("SNAPSHOT_NOT_READY", SnapshotNotReadyError),
        ],
    )
    def test_known_codes_resolve_to_specific_class(
        self, code: str, expected_cls: type[PlatformError]
    ) -> None:
        assert exception_for_code(code) is expected_cls

    def test_unknown_code_falls_back_to_platform_error(self) -> None:
        assert exception_for_code("SOMETHING_UNREAL") is PlatformError

    def test_each_subclass_inherits_from_base(self) -> None:
        assert issubclass(AuthInvalidTokenError, PlatformError)
        assert issubclass(SnapshotNotReadyError, PlatformError)


class TestPlatformErrorFromResponseBody:
    def test_known_code_returns_specific_instance(self) -> None:
        body = {"code": "NONCE_EXPIRED", "message": "Nonce TTL elapsed."}
        exc = platform_error_from_response_body(body, status_code=401)
        assert isinstance(exc, NonceExpiredError)
        assert exc.status_code == 401
        assert exc.detail == "Nonce TTL elapsed."

    def test_unknown_code_returns_generic_platform_error(self) -> None:
        body = {"code": "NEW_FUTURE_CODE", "message": "Reserved."}
        exc = platform_error_from_response_body(body, status_code=400)
        assert isinstance(exc, PlatformError)
        # Falls through to the base class, not a more specific subclass.
        assert type(exc) is PlatformError
        assert exc.status_code == 400

    def test_4xx_without_envelope_preserves_raw_body_in_detail(self) -> None:
        body = {"something_else": "yes"}
        exc = platform_error_from_response_body(body, status_code=403)
        assert isinstance(exc, PlatformBadRequestError)
        assert exc.status_code == 403
        # Operator should still see what the platform actually said.
        assert "something_else" in (exc.detail or "")

    def test_5xx_without_envelope_returns_server_error(self) -> None:
        exc = platform_error_from_response_body(None, status_code=503)
        assert isinstance(exc, PlatformServerError)
        assert exc.status_code == 503

    def test_non_dict_body_4xx_preserves_text(self) -> None:
        exc = platform_error_from_response_body("plain text", status_code=400)
        assert isinstance(exc, PlatformBadRequestError)
        assert exc.detail == "plain text"

    def test_long_raw_body_is_truncated(self) -> None:
        # Defensive: a huge raw body should not blow up the error message.
        body = {"k": "x" * 2000}
        exc = platform_error_from_response_body(body, status_code=400)
        assert exc.detail is not None
        assert len(exc.detail) <= 500


# ---------------------------------------------------------------------------
# Binding-ledger / snapshot-storage / signature subclasses
# ---------------------------------------------------------------------------


class TestExtendedCatalog:
    """Codes added to support the platform team's typed-details contract.

    These five binding-ledger codes, four snapshot-storage codes, and
    five granular signature.* primitives replace the older single
    SIGNATURE_INVALID code on the wire.
    """

    @pytest.mark.parametrize(
        "code, expected_cls",
        [
            # Binding-ledger
            ("PROFILE_ALREADY_HAS_HOTKEY", ProfileAlreadyHasHotkeyError),
            ("MINER_FAN_GROUP_REQUIRED", MinerFanGroupRequiredError),
            ("COLDKEY_OWNERSHIP_NOT_PROVEN", ColdkeyOwnershipNotProvenError),
            ("DISCORD_HANDLE_MISSING", DiscordHandleMissingError),
            ("TWO_FACTOR_PROOF_INVALID", TwoFactorProofInvalidError),
            # Snapshot storage
            ("SNAPSHOT_PAGE_NOT_FOUND", SnapshotPageNotFoundError),
            ("SNAPSHOT_STORAGE_ACCESS_DENIED", SnapshotStorageAccessDeniedError),
            ("SNAPSHOT_STORAGE_ERROR", SnapshotStorageError),
            ("SNAPSHOT_PAGE_HASH_ERROR", SnapshotPageHashError),
            # Auth scope (typed details)
            ("AUTH_TOKEN_SCOPE_MISSING", AuthTokenScopeMissingError),
            # Signature primitives — dotted lowercase wire codes
            ("signature.invalid_format", SignatureInvalidFormatError),
            ("signature.unsupported_key_type", SignatureUnsupportedKeyTypeError),
            ("signature.verification_failed", SignatureVerificationFailedError),
            ("signature.address_mismatch", SignatureAddressMismatchError),
            ("signature.domain_mismatch", SignatureDomainMismatchError),
        ],
    )
    def test_new_codes_resolve_to_specific_class(
        self, code: str, expected_cls: type[PlatformError]
    ) -> None:
        assert exception_for_code(code) is expected_cls

    def test_signature_classes_share_abstract_base(self) -> None:
        # `except SignaturePlatformError` must catch every concrete
        # signature.* class without enumerating them.
        for cls in (
            SignatureInvalidFormatError,
            SignatureUnsupportedKeyTypeError,
            SignatureVerificationFailedError,
            SignatureAddressMismatchError,
            SignatureDomainMismatchError,
        ):
            assert issubclass(cls, SignaturePlatformError)
            assert issubclass(cls, PlatformError)

    def test_signature_platform_error_base_has_no_wire_code(self) -> None:
        # The abstract base is intentionally absent from the wire catalog
        # — only concrete subclasses appear on the wire.
        assert SignaturePlatformError.code == ""

    def test_signature_invalid_legacy_code_no_longer_catalogued(self) -> None:
        # Platform deleted SIGNATURE_INVALID — must fall through to the
        # generic base, not resolve to a removed subclass.
        assert exception_for_code("SIGNATURE_INVALID") is PlatformError
        assert not hasattr(platform_errors_module, "SignatureInvalidError")

    def test_environment_mismatch_resolves_to_platform_side_class(self) -> None:
        # ``ENVIRONMENT_MISMATCH`` is shared with the identity layer's
        # local-origin error; the catalog must resolve to the platform-
        # side class so the renderer routes through the platform path.
        assert exception_for_code("ENVIRONMENT_MISMATCH") is EnvironmentMismatchPlatformError


class TestDetailsPropagation:
    def test_details_dict_is_attached_to_instance(self) -> None:
        body = {
            "code": "ROTATION_COOLDOWN_ACTIVE",
            "message": "Wait before rotating again.",
            "details": {"cooldown_until": "2026-05-30T00:00:00Z"},
        }
        exc = platform_error_from_response_body(body, status_code=409)
        assert isinstance(exc, RotationCooldownActiveError)
        assert exc.details == {"cooldown_until": "2026-05-30T00:00:00Z"}

    def test_missing_details_is_none(self) -> None:
        body = {"code": "MINER_FAN_GROUP_REQUIRED", "message": "Own a Fan Group first."}
        exc = platform_error_from_response_body(body, status_code=403)
        assert exc.details is None

    def test_typed_details_for_scope_missing(self) -> None:
        body = {
            "code": "AUTH_TOKEN_SCOPE_MISSING",
            "message": "Token does not carry the required scope.",
            "details": {"required_scope": "identity:verify:miner"},
        }
        exc = platform_error_from_response_body(body, status_code=403)
        assert isinstance(exc, AuthTokenScopeMissingError)
        assert exc.details == {"required_scope": "identity:verify:miner"}

    def test_typed_details_for_signature_domain_mismatch(self) -> None:
        body = {
            "code": "signature.domain_mismatch",
            "message": "Domain string did not match.",
            "details": {"expected_domain": "PROMETHEON_API_REQUEST_V1"},
        }
        exc = platform_error_from_response_body(body, status_code=403)
        assert isinstance(exc, SignatureDomainMismatchError)
        assert isinstance(exc, SignaturePlatformError)
        assert exc.details == {"expected_domain": "PROMETHEON_API_REQUEST_V1"}


class TestPrivacyBackstop:
    """Cross-user keys must be dropped at parse time.

    The platform commits never to emit cross-user information; this list
    is defence-in-depth in case a future regression slips one through.
    The CLI must drop these keys before the exception is constructed so
    they never reach the renderer or the validator's on-disk event log.
    """

    @pytest.mark.parametrize(
        "sensitive_key",
        [
            "conflicting_username",
            "conflicting_user_id",
            "profile_owner_id",
            "registered_user_id",
            "other_account_username",
            "other_user_id",
            "current_holder_username",
            "current_owner_id",
        ],
    )
    def test_drops_known_sensitive_key(self, sensitive_key: str) -> None:
        body = {
            "code": "HOTKEY_ALREADY_LINKED",
            "message": "Hotkey is already linked.",
            "details": {sensitive_key: "alice", "benign_field": 1},
        }
        exc = platform_error_from_response_body(body, status_code=409)
        assert exc.details is not None
        assert sensitive_key not in exc.details
        assert exc.details.get("benign_field") == 1

    def test_preserves_benign_keys(self) -> None:
        body = {
            "code": "RECOVERY_COOLDOWN_ACTIVE",
            "message": "Cooldown active.",
            "details": {"cooldown_until": "2026-05-30T00:00:00Z", "elapsed_seconds": 7200},
        }
        exc = platform_error_from_response_body(body, status_code=409)
        assert exc.details == {
            "cooldown_until": "2026-05-30T00:00:00Z",
            "elapsed_seconds": 7200,
        }

    def test_warns_to_stderr_on_first_drop(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Reset the dedup set so the warning fires deterministically.
        monkeypatch.setattr(
            platform_errors_module, "_SANITISE_WARN_SEEN", set()
        )
        body = {
            "code": "HOTKEY_ALREADY_LINKED",
            "message": "Hotkey is already linked.",
            "details": {"conflicting_username": "alice"},
        }
        platform_error_from_response_body(body, status_code=409)
        captured = capsys.readouterr()
        assert "conflicting_username" in captured.err
        assert "dropped sensitive detail key" in captured.err


class TestCodeShapeGuard:
    """Wire codes outside the strict regex must not display verbatim.

    The operator-facing trailer the renderer emits puts the wire code in
    a tight position; a malicious or buggy server returning terminal
    control sequences or absurdly long codes would corrupt the operator's
    terminal. The CLI validates the shape at parse time and falls through
    to the generic bucket, preserving the offending code (truncated) in
    ``detail`` so debugging is still possible.
    """

    def test_valid_dotted_lowercase_code_passes(self) -> None:
        body = {"code": "signature.invalid_format", "message": "ok"}
        exc = platform_error_from_response_body(body, status_code=403)
        assert isinstance(exc, SignatureInvalidFormatError)

    @pytest.mark.parametrize(
        "bad_code",
        [
            "code with space",
            "code\x1b[31mwith-ansi",
            "code\nnewline",
            "x" * 65,  # exceeds 64-char cap
            "",
        ],
    )
    def test_malformed_code_drops_to_generic_bucket(self, bad_code: str) -> None:
        body = {"code": bad_code, "message": "something"}
        exc = platform_error_from_response_body(body, status_code=400)
        # Generic fall-through, not the specific subclass.
        assert type(exc) is PlatformBadRequestError


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


class TestIdentityEndpointConstants:
    def test_paths_are_absolute_and_versioned(self) -> None:
        assert NONCE_PATH == "/api/v1/prometheon/identity/nonce"
        assert VERIFY_PATH == "/api/v1/prometheon/identity/verify"
        assert ROTATE_HOTKEY_PATH == "/api/v1/prometheon/identity/rotate-hotkey"
        assert RECOVER_HOTKEY_PATH == "/api/v1/prometheon/identity/recover-hotkey"

    def test_all_identity_paths_start_with_slash(self) -> None:
        for path in (NONCE_PATH, VERIFY_PATH, ROTATE_HOTKEY_PATH, RECOVER_HOTKEY_PATH):
            assert path.startswith("/")
            assert not path.endswith("/")


class TestSnapshotMode:
    def test_string_values(self) -> None:
        assert SnapshotMode.AGGREGATE == "aggregate"
        assert SnapshotMode.DETAILED == "detailed"

    def test_only_two_members(self) -> None:
        assert {m.value for m in SnapshotMode} == {"aggregate", "detailed"}


class TestAggregatePath:
    def test_latest_by_default(self) -> None:
        assert aggregate_path() == "/api/v1/prometheon/phase1/snapshots/latest/aggregate"

    def test_specific_date(self) -> None:
        path = aggregate_path("2026-05-18")
        assert path == "/api/v1/prometheon/phase1/snapshots/2026-05-18/aggregate"

    def test_template_renders_to_real_path(self) -> None:
        # Format string + helper output stay in lockstep.
        assert AGGREGATE_PATH_TEMPLATE.format(activity_date="x") == aggregate_path("x")

    @pytest.mark.parametrize("bad", ["", "2026/05/18", "with space", 123])
    def test_rejects_malformed_inputs(self, bad: object) -> None:
        with pytest.raises(ValueError):
            aggregate_path(bad)  # type: ignore[arg-type]


class TestDetailedManifestPath:
    def test_latest_by_default(self) -> None:
        assert (
            detailed_manifest_path()
            == "/api/v1/prometheon/phase1/snapshots/latest/detailed/manifest"
        )

    def test_specific_date(self) -> None:
        assert detailed_manifest_path("2026-05-18") == (
            "/api/v1/prometheon/phase1/snapshots/2026-05-18/detailed/manifest"
        )

    def test_template_renders_to_real_path(self) -> None:
        assert DETAILED_MANIFEST_PATH_TEMPLATE.format(activity_date="x") == detailed_manifest_path(
            "x"
        )


class TestDetailedPagePath:
    def test_well_formed_inputs(self) -> None:
        path = detailed_page_path("2026-05-18", 0)
        assert path == "/api/v1/prometheon/phase1/snapshots/2026-05-18/detailed/pages/0"

    def test_higher_page_index(self) -> None:
        path = detailed_page_path("2026-05-18", 3)
        assert path == "/api/v1/prometheon/phase1/snapshots/2026-05-18/detailed/pages/3"

    def test_rejects_latest_segment(self) -> None:
        # Pages must reference the concrete date returned by the manifest.
        with pytest.raises(ValueError, match="concrete activity_date"):
            detailed_page_path(LATEST, 0)

    def test_rejects_negative_page_index(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            detailed_page_path("2026-05-18", -1)

    def test_rejects_non_int_page_index(self) -> None:
        with pytest.raises(ValueError, match="must be int"):
            detailed_page_path("2026-05-18", "0")  # type: ignore[arg-type]

    def test_rejects_bool_page_index(self) -> None:
        # bool is an int subclass in Python — explicit guard.
        with pytest.raises(ValueError, match="must be int"):
            detailed_page_path("2026-05-18", True)  # type: ignore[arg-type]

    def test_template_renders_to_real_path(self) -> None:
        assert DETAILED_PAGE_PATH_TEMPLATE.format(
            activity_date="2026-05-18", page_index=7
        ) == detailed_page_path("2026-05-18", 7)


# ---------------------------------------------------------------------------
# Token scopes
# ---------------------------------------------------------------------------


class TestTokenScope:
    def test_string_values(self) -> None:
        assert TokenScope.IDENTITY_VERIFY_MINER == "identity:verify:miner"
        assert TokenScope.SNAPSHOT_READ_AGGREGATE == "snapshot:read:aggregate"
        assert TokenScope.SNAPSHOT_READ_DETAILED == "snapshot:read:detailed"

    def test_known_members(self) -> None:
        assert {s.value for s in TokenScope} == {
            "identity:verify:miner",
            "identity:verify:validator",
            "identity:rotate:miner",
            "identity:rotate:validator",
            "identity:recover:miner",
            "identity:recover:validator",
            "snapshot:read:aggregate",
            "snapshot:read:detailed",
            "status:read",
        }
