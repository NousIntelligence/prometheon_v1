"""Unit tests for ``prometheon.platform`` foundational helpers.

Covers:

- The platform error code catalog and response → exception mapping.
- Endpoint path constants, ``aggregate_path`` / ``detailed_manifest_path``
  / ``detailed_page_path`` helpers, and ``SnapshotMode`` enum.
- ``TokenScope`` enum membership.
"""

from __future__ import annotations

import pytest

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
    NonceAlreadyUsedError,
    NonceExpiredError,
    PlatformBadRequestError,
    PlatformError,
    PlatformServerError,
    RotationCooldownActiveError,
    SnapshotNotReadyError,
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
        body = {"error": "NONCE_EXPIRED", "detail": "Nonce TTL elapsed."}
        exc = platform_error_from_response_body(body, status_code=401)
        assert isinstance(exc, NonceExpiredError)
        assert exc.status_code == 401
        assert exc.detail == "Nonce TTL elapsed."

    def test_unknown_code_returns_generic_platform_error(self) -> None:
        body = {"error": "NEW_FUTURE_CODE", "detail": "Reserved."}
        exc = platform_error_from_response_body(body, status_code=400)
        assert isinstance(exc, PlatformError)
        # Falls through to the base class, not a more specific subclass.
        assert type(exc) is PlatformError
        assert exc.status_code == 400

    def test_4xx_without_envelope_returns_bad_request(self) -> None:
        body = {"something_else": "yes"}
        exc = platform_error_from_response_body(body, status_code=403)
        assert isinstance(exc, PlatformBadRequestError)
        assert exc.status_code == 403

    def test_5xx_without_envelope_returns_server_error(self) -> None:
        exc = platform_error_from_response_body(None, status_code=503)
        assert isinstance(exc, PlatformServerError)
        assert exc.status_code == 503

    def test_non_dict_body_4xx_returns_bad_request(self) -> None:
        exc = platform_error_from_response_body("plain text", status_code=400)
        assert isinstance(exc, PlatformBadRequestError)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


class TestIdentityEndpointConstants:
    def test_paths_are_absolute_and_versioned(self) -> None:
        assert NONCE_PATH == "/v1/prometheon/identity/nonce"
        assert VERIFY_PATH == "/v1/prometheon/identity/verify"
        assert ROTATE_HOTKEY_PATH == "/v1/prometheon/identity/rotate-hotkey"
        assert RECOVER_HOTKEY_PATH == "/v1/prometheon/identity/recover-hotkey"

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
        assert aggregate_path() == "/v1/prometheon/phase1/snapshots/latest/aggregate"

    def test_specific_date(self) -> None:
        path = aggregate_path("2026-05-18")
        assert path == "/v1/prometheon/phase1/snapshots/2026-05-18/aggregate"

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
            detailed_manifest_path() == "/v1/prometheon/phase1/snapshots/latest/detailed/manifest"
        )

    def test_specific_date(self) -> None:
        assert detailed_manifest_path("2026-05-18") == (
            "/v1/prometheon/phase1/snapshots/2026-05-18/detailed/manifest"
        )

    def test_template_renders_to_real_path(self) -> None:
        assert DETAILED_MANIFEST_PATH_TEMPLATE.format(activity_date="x") == detailed_manifest_path(
            "x"
        )


class TestDetailedPagePath:
    def test_well_formed_inputs(self) -> None:
        path = detailed_page_path("2026-05-18", 0)
        assert path == "/v1/prometheon/phase1/snapshots/2026-05-18/detailed/pages/0"

    def test_higher_page_index(self) -> None:
        path = detailed_page_path("2026-05-18", 3)
        assert path == "/v1/prometheon/phase1/snapshots/2026-05-18/detailed/pages/3"

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
