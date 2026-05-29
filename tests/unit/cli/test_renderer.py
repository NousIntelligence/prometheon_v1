"""Unit tests for the CLI error renderer.

Covers:

- The catalog/template invariant: every wire code routable through
  ``platform_error_from_response_body`` must have a matching template.
- Dispatch fidelity: platform-side and local-side errors that share a
  wire code (e.g., ``signature.verification_failed``) must route to
  distinct templates so the operator sees the right remediation.
- Typed-details renderers: codes that carry a structured detail payload
  surface the relevant fields (``cooldown_until``, ``required_scope``,
  ``recommended_action``, ``expected_domain``, ``expected_chain_network``).
- Unknown-code path: the wire code appears verbatim in the rendered
  block and in a URL-encoded issue-template link.
- Display sanitisation: C0 control characters never reach the rendered
  output, regardless of where they came from.
- Verbose payload caps: 4 KiB byte cap, depth-4 truncation,
  secret-shape redaction for credential-looking values.
"""

from __future__ import annotations

import re
import urllib.parse

import pytest

from prometheon.cli.renderer import (
    _CATALOG,
    _LOCAL_TEMPLATES,
    _PLATFORM_TEMPLATES,
    _REDACTED_MARKER,
    _VERBOSE_PAYLOAD_CAP_BYTES,
    _VERBOSE_TRUNCATED_MARKER,
    _platform_catalog_template_invariant,
    render_error,
)
from prometheon.identity.errors import (
    EnvironmentMismatchError,
    IdentityDomainMismatchError,
    PayloadExpiredError,
)
from prometheon.platform.errors import (
    AuthTokenScopeMissingError,
    EnvironmentMismatchPlatformError,
    HotkeyAlreadyLinkedError,
    NonceExpiredError,
    PlatformError,
    ProfileAlreadyHasHotkeyError,
    RotationCooldownActiveError,
    SignatureDomainMismatchError,
    SignatureVerificationFailedError,
)
from prometheon.security.signatures import (
    SignatureFormatError,
    SignatureVerificationError,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Catalog ⊆ Templates invariant — the regression that protects future PRs
# ---------------------------------------------------------------------------


class TestCatalogTemplateInvariant:
    """Adding a wire code without a template silently routes the operator
    to the unknown-code path, which is a worse experience than even a
    minimal template. The invariant fails fast at import time and a test
    pins it in the suite as the explicit guard.
    """

    def test_every_catalog_code_has_a_template(self) -> None:
        for code in _CATALOG:
            assert code in _PLATFORM_TEMPLATES, (
                f"platform wire code {code!r} appears in _CATALOG but has no "
                f"template in cli.renderer._PLATFORM_TEMPLATES"
            )

    def test_invariant_function_runs_clean(self) -> None:
        # _platform_catalog_template_invariant raises on any mismatch.
        _platform_catalog_template_invariant()

    def test_generic_bucket_codes_also_have_templates(self) -> None:
        # The three bucket codes are produced by status-based fallback,
        # not via the catalog, but they must still have templates because
        # the renderer dispatches on .code regardless of origin.
        for bucket_code in (
            "PLATFORM_UNAUTHORIZED",
            "PLATFORM_BAD_REQUEST",
            "PLATFORM_SERVER_ERROR",
        ):
            assert bucket_code in _PLATFORM_TEMPLATES


# ---------------------------------------------------------------------------
# Dispatch by isinstance + code
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_platform_error_renders_platform_origin(self) -> None:
        exc = NonceExpiredError(status_code=401, detail="ttl exceeded")
        rendered = render_error(exc, verbose=False)
        assert "Error: NONCE_EXPIRED" in rendered
        assert "(platform, HTTP 401)" in rendered

    def test_local_identity_error_renders_local_origin(self) -> None:
        exc = PayloadExpiredError("issued_at + ttl < now")
        rendered = render_error(exc, verbose=False)
        assert "(local verification)" in rendered

    def test_local_signature_error_renders_local_origin(self) -> None:
        exc = SignatureVerificationError("signature did not verify")
        rendered = render_error(exc, verbose=False)
        assert "(local verification)" in rendered

    def test_platform_signature_and_local_signature_share_wire_code_but_render_differently(
        self,
    ) -> None:
        # signature.verification_failed exists on BOTH sides. The two
        # hierarchies must produce different remediation language; this
        # is the entire point of option (b) — two registries — over
        # collapsing them into a single template.
        platform_exc = SignatureVerificationFailedError(
            status_code=403, detail="server rejected signature"
        )
        local_exc = SignatureVerificationError("could not verify platform's signature")

        platform_rendered = render_error(platform_exc, verbose=False)
        local_rendered = render_error(local_exc, verbose=False)

        # Same wire code...
        assert "signature.verification_failed" in platform_rendered
        # ...but distinct origin labels.
        assert "(platform" in platform_rendered
        assert "(local verification)" in local_rendered
        # And distinct remediation guidance.
        assert "wallet" in platform_rendered.lower()  # check hotkey/wallet
        assert "trusted" in local_rendered.lower()  # check trusted-key config

    def test_local_subclass_walks_mro_to_parent_template(self) -> None:
        # SignatureFormatError has its own template; a hypothetical
        # subclass without one should walk the MRO and still render.
        class _BespokeFormatError(SignatureFormatError):
            code = "signature.invalid_format"

        rendered = render_error(_BespokeFormatError("custom"), verbose=False)
        assert "(local verification)" in rendered
        assert "signature" in rendered.lower()

    def test_generic_exception_falls_through_to_unexpected_block(self) -> None:
        rendered = render_error(RuntimeError("boom"), verbose=False)
        assert "(unexpected)" in rendered
        assert "RuntimeError" in rendered


# ---------------------------------------------------------------------------
# Typed details renderers
# ---------------------------------------------------------------------------


class TestDetailsRendering:
    def test_rotation_cooldown_surfaces_cooldown_until(self) -> None:
        exc = RotationCooldownActiveError(
            status_code=409,
            detail="Rotation cooldown active.",
            details={"cooldown_until": "2026-05-30T00:00:00Z"},
        )
        rendered = render_error(exc, verbose=False)
        assert "Cooldown clears at: 2026-05-30T00:00:00Z" in rendered

    def test_scope_missing_surfaces_required_scope(self) -> None:
        exc = AuthTokenScopeMissingError(
            status_code=403,
            detail="missing scope",
            details={"required_scope": "identity:verify:miner"},
        )
        rendered = render_error(exc, verbose=False)
        assert "Required scope: identity:verify:miner" in rendered

    def test_profile_already_has_hotkey_rotate_action(self) -> None:
        exc = ProfileAlreadyHasHotkeyError(
            status_code=409,
            detail="already linked",
            details={"recommended_action": "rotate"},
        )
        rendered = render_error(exc, verbose=False)
        assert "rotate-hotkey" in rendered

    def test_profile_already_has_hotkey_recover_action(self) -> None:
        exc = ProfileAlreadyHasHotkeyError(
            status_code=409,
            detail="lost the hotkey",
            details={"recommended_action": "recover"},
        )
        rendered = render_error(exc, verbose=False)
        assert "recover-hotkey" in rendered

    def test_environment_mismatch_surfaces_expected_values(self) -> None:
        exc = EnvironmentMismatchPlatformError(
            status_code=400,
            detail="env mismatch",
            details={
                "expected_chain_network": "finney",
                "expected_platform_instance_id": "bitfan-production",
            },
        )
        rendered = render_error(exc, verbose=False)
        assert "chain_network = finney" in rendered
        assert "platform_instance_id = bitfan-production" in rendered

    def test_signature_domain_mismatch_surfaces_expected_domain(self) -> None:
        exc = SignatureDomainMismatchError(
            status_code=403,
            detail="domain wrong",
            details={"expected_domain": "PROMETHEON_API_REQUEST_V1"},
        )
        rendered = render_error(exc, verbose=False)
        assert "PROMETHEON_API_REQUEST_V1" in rendered

    def test_missing_details_skips_renderer_silently(self) -> None:
        exc = RotationCooldownActiveError(status_code=409, detail="no details payload")
        rendered = render_error(exc, verbose=False)
        # Static body still present.
        assert "ROTATION_COOLDOWN_ACTIVE" in rendered
        # But no Cooldown clears line — there is nothing to substitute.
        assert "Cooldown clears at" not in rendered

    def test_details_renderer_exception_does_not_crash_dispatch(self) -> None:
        # A buggy details renderer must not break the parent block.
        exc = RotationCooldownActiveError(
            status_code=409,
            detail="ok",
            details={"cooldown_until": None},  # type: ignore[dict-item]
        )
        rendered = render_error(exc, verbose=False)
        # Renderer skipped the bad field but produced the full block.
        assert "ROTATION_COOLDOWN_ACTIVE" in rendered


# ---------------------------------------------------------------------------
# Unknown-code path
# ---------------------------------------------------------------------------


class TestUnknownCodePath:
    def test_wire_code_appears_verbatim(self) -> None:
        # Force dispatch into the unknown path: subclass PlatformError so
        # exc.code is novel and not in _PLATFORM_TEMPLATES.
        class _UnknownCodeError(PlatformError):
            code = "GENUINELY_UNKNOWN"

        unknown_exc = _UnknownCodeError(
            status_code=400,
            detail="server is on a future build",
            wire_code="GENUINELY_UNKNOWN",
        )
        rendered = render_error(unknown_exc, verbose=False)
        assert "GENUINELY_UNKNOWN" in rendered
        assert "does not recognise" in rendered.lower()

    def test_issue_template_url_is_url_encoded(self) -> None:
        class _WeirdCodeError(PlatformError):
            code = "weird code: 2026"

        exc = _WeirdCodeError(status_code=400, detail="x", wire_code="weird code: 2026")
        rendered = render_error(exc, verbose=False)
        # Spaces and the colon are percent-encoded in the title parameter.
        title_param = urllib.parse.quote("weird code: 2026", safe="")
        assert title_param in rendered
        # The template filename is also percent-encoded.
        assert "unrecognised-platform-code.md" in rendered

    def test_unknown_code_includes_wire_detail_when_present(self) -> None:
        class _UnknownCodeError(PlatformError):
            code = "X"

        exc = _UnknownCodeError(status_code=400, detail="something specific", wire_code="X")
        rendered = render_error(exc, verbose=False)
        assert "something specific" in rendered

    def test_unknown_code_handles_missing_detail(self) -> None:
        class _UnknownCodeError(PlatformError):
            code = "Y"

        exc = _UnknownCodeError(status_code=400, wire_code="Y")
        rendered = render_error(exc, verbose=False)
        # No crash; block still mentions the wire code.
        assert "Y" in rendered


# ---------------------------------------------------------------------------
# Display sanitisation
# ---------------------------------------------------------------------------


class TestDisplaySanitisation:
    @pytest.mark.parametrize(
        "control_char",
        ["\x00", "\x07", "\x08", "\x0b", "\x0c", "\x1b", "\x1f", "\x7f"],
    )
    def test_control_chars_in_detail_are_stripped(self, control_char: str) -> None:
        exc = NonceExpiredError(
            status_code=401,
            detail=f"before{control_char}after",
        )
        rendered = render_error(exc, verbose=False)
        assert control_char not in rendered

    def test_tab_survives_in_verbose_payload(self) -> None:
        # Tab is preserved by _strip_for_display so a detail line with a
        # tab survives into the --verbose trailer.
        exc = NonceExpiredError(status_code=401, detail="col1\tcol2")
        rendered_v = render_error(exc, verbose=True)
        assert "col1\\tcol2" in rendered_v or "col1\tcol2" in rendered_v

    def test_ansi_sequence_in_wire_code_is_stripped(self) -> None:
        class _AnsiCodeError(PlatformError):
            code = "X"

        exc = _AnsiCodeError(
            status_code=400,
            wire_code="ansi\x1b[31mbomb",
        )
        rendered = render_error(exc, verbose=False)
        assert "\x1b" not in rendered

    def test_details_renderer_strips_control_chars(self) -> None:
        exc = RotationCooldownActiveError(
            status_code=409,
            detail="ok",
            details={"cooldown_until": "2026\x00-05-30\x1bT00:00:00Z"},
        )
        rendered = render_error(exc, verbose=False)
        assert "\x00" not in rendered
        assert "\x1b" not in rendered


# ---------------------------------------------------------------------------
# Verbose payload — caps + secret redaction
# ---------------------------------------------------------------------------


class TestVerbosePayload:
    def test_verbose_includes_exception_metadata(self) -> None:
        exc = HotkeyAlreadyLinkedError(status_code=409, detail="taken")
        rendered = render_error(exc, verbose=True)
        assert "[verbose]" in rendered
        assert "HOTKEY_ALREADY_LINKED" in rendered
        assert "status_code" in rendered

    def test_non_verbose_omits_trailer(self) -> None:
        exc = HotkeyAlreadyLinkedError(status_code=409, detail="taken")
        rendered = render_error(exc, verbose=False)
        assert "[verbose]" not in rendered

    @pytest.mark.parametrize(
        "secret_value",
        [
            "github_pat_" + ("A1B2c3" * 10),  # 60-char fine-grained PAT shape
            "ghp_" + ("a" * 40),  # classic PAT
            "gho_" + ("b" * 40),  # OAuth-issued PAT
            "eyJabcdef0123456789ABCDEF.eyJqwerty.SIGNATURE",  # JWT-ish
            "a" * 96,  # opaque base64-ish
            "F" * 64,  # 64-char hex secret/hash
        ],
    )
    def test_secret_shape_values_in_details_are_redacted(self, secret_value: str) -> None:
        exc = HotkeyAlreadyLinkedError(
            status_code=409,
            detail="taken",
            details={"some_field": secret_value},
        )
        rendered = render_error(exc, verbose=True)
        assert secret_value not in rendered
        assert _REDACTED_MARKER in rendered

    def test_short_innocuous_strings_are_not_redacted(self) -> None:
        exc = HotkeyAlreadyLinkedError(
            status_code=409,
            detail="taken",
            details={"recommended_action": "rotate", "page": "1"},
        )
        rendered = render_error(exc, verbose=True)
        assert "rotate" in rendered

    def test_verbose_payload_respects_byte_cap(self) -> None:
        # Wide-not-deep payload: each value is too short to trip the
        # secret-shape redactor, but the JSON serialisation crosses the
        # 4 KiB cap because there are many fields. This is the realistic
        # shape that exercises the byte cap rather than the redactor.
        wide_details = {f"k{i:04d}": f"v{i}" for i in range(800)}
        exc = HotkeyAlreadyLinkedError(
            status_code=409,
            detail="ok",
            details=wide_details,
        )
        rendered = render_error(exc, verbose=True)
        trailer = rendered.split("[verbose]", 1)[1]
        assert len(trailer.encode("utf-8")) < _VERBOSE_PAYLOAD_CAP_BYTES + 1024
        assert _VERBOSE_TRUNCATED_MARKER in rendered

    def test_deeply_nested_dict_is_truncated(self) -> None:
        # Construct a nested dict exceeding depth 4.
        nested: dict = {"k": "v"}
        current = nested
        for i in range(10):
            current["next"] = {"k": f"depth-{i}"}
            current = current["next"]
        exc = HotkeyAlreadyLinkedError(
            status_code=409,
            detail="taken",
            details=nested,
        )
        rendered = render_error(exc, verbose=True)
        assert _VERBOSE_TRUNCATED_MARKER in rendered


# ---------------------------------------------------------------------------
# Local template registry coverage
# ---------------------------------------------------------------------------


class TestLocalTemplateRegistry:
    def test_all_identity_errors_have_templates(self) -> None:
        # Touch each catalogued local class to confirm template lookup
        # works. (Local templates are by class, not by code, so we just
        # confirm membership.)
        for cls in (
            IdentityDomainMismatchError,
            EnvironmentMismatchError,
            PayloadExpiredError,
        ):
            assert cls in _LOCAL_TEMPLATES

    def test_local_signature_template_present(self) -> None:
        assert SignatureVerificationError in _LOCAL_TEMPLATES


# ---------------------------------------------------------------------------
# Rendered-block structural shape
# ---------------------------------------------------------------------------


class TestRenderedShape:
    def test_top_line_starts_with_error_code(self) -> None:
        exc = NonceExpiredError(status_code=401, detail="ttl")
        rendered = render_error(exc, verbose=False)
        assert rendered.startswith("Error: NONCE_EXPIRED")

    def test_remediation_section_present(self) -> None:
        exc = NonceExpiredError(status_code=401, detail="ttl")
        rendered = render_error(exc, verbose=False)
        assert "Remediation:" in rendered

    def test_docs_link_present_when_template_provides_anchor(self) -> None:
        exc = NonceExpiredError(status_code=401, detail="ttl")
        rendered = render_error(exc, verbose=False)
        assert "More info:" in rendered
        assert re.search(r"https://github.com/.*/docs/security\.md", rendered)

    def test_output_ends_with_newline(self) -> None:
        exc = NonceExpiredError(status_code=401, detail="ttl")
        rendered = render_error(exc, verbose=False)
        assert rendered.endswith("\n")
