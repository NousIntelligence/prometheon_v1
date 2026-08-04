"""Operator-facing error renderer.

Maps an exception caught at the CLI boundary to a multi-line block of
text suitable for printing to stderr. Dispatches between three families:

1. :class:`prometheon.platform.errors.PlatformError` and its subclasses
   — errors returned by the BitFan platform over the wire. Each
   catalogued wire code maps to a :class:`ErrorTemplate` that knows how
   to explain the failure and propose remediation. Codes the catalog
   does not recognise route through the unknown-code path, which still
   prints the wire code verbatim and links to a labelled issue template
   so the operator can flag the gap.
2. :class:`prometheon.identity.errors.IdentityError` subclasses —
   subnet-side identity-layer errors raised before any platform call.
3. :class:`prometheon.security.signatures.SignatureError` subclasses —
   subnet-side signature verification errors raised when the CLI fails
   to verify a signature *the platform produced* (snapshot, recovery
   pages, etc.).

The platform and local hierarchies share several wire codes — most
notably the five ``signature.*`` primitives — but with **opposite**
causes and remediations. For example,
``signature.verification_failed`` raised from
:mod:`prometheon.platform.errors` means *"the platform rejected our
signature"* (remediation: re-check hotkey, scope, payload), while the
same code raised from :mod:`prometheon.security.signatures` means
*"we could not verify a signature the platform sent us"* (remediation:
re-fetch the snapshot, check trusted-key configuration). The renderer
therefore dispatches on :func:`isinstance` first, then on ``code``, so
the two hierarchies never collide.

All operator output passes through :func:`_strip_for_display` (drops C0
control characters except tab/newline) before being printed, and the
verbose-mode payload trailer is capped at 4 KiB / depth 4 with
secret-shape redaction as a defence-in-depth layer on top of the
parse-time privacy backstop in :mod:`prometheon.platform.errors`.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from prometheon.identity.errors import (
    EnvironmentMismatchError,
    IdentityDomainMismatchError,
    IdentityEnvelopeStructureError,
    IdentityError,
    IdentityPayloadValidationError,
    PayloadExpiredError,
    PayloadNotYetValidError,
)
from prometheon.platform.errors import (
    _CATALOG,
    AccountLockedOutError,
    AccountNotVerifiedError,
    AuthInvalidTokenError,
    AuthTokenScopeMissingError,
    ColdkeyOwnershipNotProvenError,
    DiscordHandleMissingError,
    EnvironmentMismatchPlatformError,
    HotkeyAlreadyLinkedError,
    HotkeyNotLinkedError,
    MinerFanGroupRequiredError,
    NonceAlreadyUsedError,
    NonceContextMismatchError,
    NonceExpiredError,
    NonceMissingError,
    PathMismatchError,
    PlatformBadRequestError,
    PlatformError,
    PlatformServerError,
    PlatformUnauthorizedError,
    ProfileAlreadyHasHotkeyError,
    RecoveryCooldownActiveError,
    RecoveryPendingError,
    RotationCooldownActiveError,
    SignatureAddressMismatchError,
    SignatureDomainMismatchError,
    SignatureInvalidFormatError,
    SignatureUnsupportedKeyTypeError,
    SignatureVerificationFailedError,
    SnapshotAccessDeniedError,
    SnapshotDateInvalidError,
    SnapshotModeInvalidError,
    SnapshotNotReadyError,
    SnapshotPageHashError,
    SnapshotPageNotFoundError,
    SnapshotStorageAccessDeniedError,
    SnapshotStorageError,
    TwoFactorProofInvalidError,
)
from prometheon.security.signatures import (
    SignatureAddressMismatchError as LocalSignatureAddressMismatchError,
)
from prometheon.security.signatures import (
    SignatureError,
    SignatureFormatError,
    SignatureVerificationError,
    UnsupportedKeyTypeError,
)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Where unknown-code reports go. The labelled template ships in
# .github/ISSUE_TEMPLATE/ so the reporter only fills in the wire payload.
_REPO_SLUG: str = "BitSpaceorganization/prometheon_v1"
_ISSUE_TEMPLATE_NAME: str = "unrecognised-platform-code.md"
_DOCS_ROOT: str = f"https://github.com/{_REPO_SLUG}/blob/main/docs"

# Defence-in-depth caps on the --verbose payload trailer. The
# privacy backstop in prometheon.platform.errors already drops cross-user
# keys at parse time; these caps are the final guard against runaway
# size and shapes the operator should never see verbatim.
_VERBOSE_PAYLOAD_CAP_BYTES: int = 4096
_VERBOSE_DEPTH_CAP: int = 4
_VERBOSE_TRUNCATED_MARKER: str = "<... truncated ...>"

# C0 control characters we strip from rendered output. Tab and newline
# survive because operators legitimately use them; everything below 0x20
# else (plus DEL at 0x7F) is treated as terminal-corruption hazard.
_CONTROL_CHAR_PATTERN: re.Pattern[str] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Values whose *shape* suggests they are credentials we never want to
# print, even when a future platform regression slips them through the
# parse-time backstop. Order matters: longest / most specific first so
# the more permissive hex pattern does not shadow the prefixed forms.
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^github_pat_[A-Za-z0-9_]{40,}$"),
    re.compile(r"^ghp_[A-Za-z0-9]{36,}$"),
    re.compile(r"^gho_[A-Za-z0-9]{36,}$"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)?$"),
    re.compile(r"^[A-Fa-f0-9]{64,}$"),
    # base64url-shaped opaque values >= 40 chars (covers raw API tokens).
    re.compile(r"^[A-Za-z0-9_-]{40,}$"),
)
_REDACTED_MARKER: str = "<redacted>"


# ---------------------------------------------------------------------------
# Template data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ErrorTemplate:
    """The structured fields a renderer turns into operator-facing text.

    ``headline`` is the one-line summary printed just below the error
    code; ``explanation`` is the longer paragraph that follows;
    ``remediation`` is the imperative "do this" block. ``docs_anchor``
    points at a specific doc page so the operator can read more.

    ``details_renderer`` is invoked when the exception carries a typed
    ``details`` dict; it returns an optional bullet that gets stitched
    into the remediation block. Used for codes whose remediation
    references a server-supplied field (e.g.,
    ``RotationCooldownActiveError`` cites ``cooldown_until``).
    """

    headline: str
    explanation: str
    remediation: str
    docs_anchor: str | None = None
    details_renderer: Callable[[Mapping[str, Any]], str | None] | None = field(
        default=None, repr=False
    )


# ---------------------------------------------------------------------------
# Platform template registry — one per catalogued wire code
# ---------------------------------------------------------------------------


def _render_cooldown_until(details: Mapping[str, Any]) -> str | None:
    value = details.get("cooldown_until")
    if isinstance(value, str):
        return f"Cooldown clears at: {_strip_for_display(value)}"
    return None


def _render_required_scope(details: Mapping[str, Any]) -> str | None:
    value = details.get("required_scope")
    if isinstance(value, str):
        return f"Required scope: {_strip_for_display(value)}"
    return None


def _render_recommended_action(details: Mapping[str, Any]) -> str | None:
    value = details.get("recommended_action")
    if value == "rotate":
        return "Recommended action: rotate the existing hotkey via `prometheon rotate-hotkey`."
    if value == "recover":
        return "Recommended action: recover this account via `prometheon recover-hotkey`."
    return None


def _render_environment_expected(details: Mapping[str, Any]) -> str | None:
    chain = details.get("expected_chain_network")
    instance = details.get("expected_platform_instance_id")
    lines: list[str] = []
    if isinstance(chain, str):
        lines.append(f"Platform expects chain_network = {_strip_for_display(chain)}")
    if isinstance(instance, str):
        lines.append(f"Platform expects platform_instance_id = {_strip_for_display(instance)}")
    return "\n".join(lines) if lines else None


def _render_expected_domain(details: Mapping[str, Any]) -> str | None:
    value = details.get("expected_domain")
    if isinstance(value, str):
        return f"Platform expected the signature domain string: {_strip_for_display(value)}"
    return None


_PLATFORM_TEMPLATES: dict[str, ErrorTemplate] = {
    # ------------------- Authentication / authorisation -------------------
    AuthInvalidTokenError.code: ErrorTemplate(
        headline="The platform rejected your API token.",
        explanation=(
            "Either the token has expired, has been revoked, or was never valid "
            "for this platform instance."
        ),
        remediation=(
            "Open the BitFan portal, issue a fresh bootstrap token for your role, "
            "export it into the documented environment variable, and re-run the "
            "command."
        ),
        docs_anchor="security.md#api-tokens",
    ),
    AuthTokenScopeMissingError.code: ErrorTemplate(
        headline="Your API token is missing the scope this endpoint requires.",
        explanation=(
            "Tokens issued by the BitFan portal are scoped to one role and one "
            "purpose (verify, rotate, recover, snapshot read, status). The "
            "endpoint you called requires a scope the token does not carry."
        ),
        remediation=(
            "Issue a token with the scope reported below from the BitFan portal "
            "and export it under the same environment variable name."
        ),
        docs_anchor="security.md#token-scopes",
        details_renderer=_render_required_scope,
    ),
    AccountNotVerifiedError.code: ErrorTemplate(
        headline="Your BitFan account is not yet verified for this role.",
        explanation=(
            "This account has not completed the role-specific verification flow "
            "(verify-miner or verify-validator) on this platform instance."
        ),
        remediation=(
            "Run the matching `prometheon verify-{miner,validator}` command with "
            "a bootstrap token from the BitFan portal."
        ),
        docs_anchor="miner.md#step-2-register-a-hotkey-and-verify-as-a-miner",
    ),
    AccountLockedOutError.code: ErrorTemplate(
        headline="The platform has temporarily locked this account.",
        explanation=(
            "Repeated invalid attempts (or an explicit operator action) put the "
            "account into a cooldown state. Further calls will be refused until "
            "the lockout clears."
        ),
        remediation=(
            "Wait for the cooldown to expire (see Wire detail below). If the "
            "lockout was unexpected, contact the platform operators."
        ),
        docs_anchor="security.md#account-lockout",
    ),
    # ------------------------------ Nonce ---------------------------------
    NonceMissingError.code: ErrorTemplate(
        headline="The platform did not find a nonce for this verify attempt.",
        explanation=(
            "The CLI must request a nonce immediately before signing the "
            "envelope. A missing nonce usually means the CLI flow was "
            "interrupted between the nonce call and the verify call."
        ),
        remediation="Re-run the command from scratch.",
        docs_anchor="security.md#nonces",
    ),
    NonceExpiredError.code: ErrorTemplate(
        headline="The nonce expired before the CLI could submit the envelope.",
        explanation=(
            "Nonces are short-lived (~10 minutes). A slow network or a long "
            "manual delay between the nonce request and the verify submission "
            "will trip this."
        ),
        remediation="Re-run the command from scratch.",
        docs_anchor="security.md#nonces",
    ),
    NonceAlreadyUsedError.code: ErrorTemplate(
        headline="This nonce has already been consumed.",
        explanation=(
            "Nonces are single-use. The platform refuses to accept the same "
            "nonce twice; this is the replay defence."
        ),
        remediation=(
            "Re-run the command from scratch — the CLI will request a fresh nonce automatically."
        ),
        docs_anchor="security.md#nonces",
    ),
    NonceContextMismatchError.code: ErrorTemplate(
        headline="The nonce was issued for a different context than the envelope claims.",
        explanation=(
            "Nonces bind chain_network, platform_instance_id, role, and hotkey "
            "at issue time. The envelope you submitted disagrees with one of "
            "those fields — typically a chain_network or platform_instance_id "
            "typo between two CLI invocations."
        ),
        remediation=(
            "Re-run the verify command and double-check the --chain-network, "
            "--platform-instance-id, --netuid, and --wallet-hotkey flags."
        ),
        docs_anchor="security.md#nonces",
    ),
    # --------------------------- Hotkey state -----------------------------
    HotkeyAlreadyLinkedError.code: ErrorTemplate(
        headline="This hotkey is already linked to a different account.",
        explanation=(
            "The platform refuses to bind a single hotkey to more than one "
            "BitFan account. This usually means either the wrong wallet is "
            "loaded, or this hotkey was previously registered under another "
            "account."
        ),
        remediation=(
            "Either pick a different hotkey, or — if this is your own hotkey "
            "that needs to move to a new account — run `prometheon recover-"
            "hotkey` to formally take ownership."
        ),
        docs_anchor="hotkey-rotation.md",
    ),
    HotkeyNotLinkedError.code: ErrorTemplate(
        headline="The platform has no record of this hotkey for your account.",
        explanation=(
            "The endpoint you called (rotate, snapshot read, etc.) requires a "
            "verified hotkey already bound to your account. This account does "
            "not currently have one."
        ),
        remediation="Run `prometheon verify-{miner,validator}` first.",
        docs_anchor="miner.md#step-2-register-a-hotkey-and-verify-as-a-miner",
    ),
    RotationCooldownActiveError.code: ErrorTemplate(
        headline="A hotkey rotation is currently rate-limited for this account.",
        explanation=(
            "The platform enforces a cooldown between hotkey rotations to "
            "limit churn-based attacks. Another rotation cannot proceed until "
            "the cooldown clears."
        ),
        remediation=(
            "Wait for the cooldown to clear (timestamp below) before retrying, "
            "or — if your hotkey is compromised right now — run "
            "`prometheon recover-hotkey` which bypasses the rotation cooldown."
        ),
        docs_anchor="hotkey-rotation.md#cooldowns",
        details_renderer=_render_cooldown_until,
    ),
    RecoveryCooldownActiveError.code: ErrorTemplate(
        headline="An account recovery is currently rate-limited.",
        explanation=(
            "Recovery uses a longer cooldown than ordinary rotation. The "
            "platform refuses repeated recovery attempts within that window."
        ),
        remediation=(
            "Wait for the cooldown to clear before retrying. If you are "
            "blocked by an active compromise, contact the platform operators "
            "via the Ops Console flow."
        ),
        docs_anchor="hotkey-rotation.md#cooldowns",
        details_renderer=_render_cooldown_until,
    ),
    RecoveryPendingError.code: ErrorTemplate(
        headline="A recovery for this account is already pending activation.",
        explanation=(
            "The platform queues recovery transitions so the new hotkey "
            "becomes active only after the required waiting period. A second "
            "recovery cannot start while one is in flight."
        ),
        remediation=(
            "Wait for the pending recovery to activate. The activation "
            "timestamp is visible in the platform's account dashboard."
        ),
        docs_anchor="hotkey-rotation.md#recovery",
    ),
    # ---------------------- Binding-ledger guards -------------------------
    ProfileAlreadyHasHotkeyError.code: ErrorTemplate(
        headline="Your account already has a hotkey linked.",
        explanation=(
            "`verify-{miner,validator}` binds a fresh hotkey to a not-yet-bound "
            "account. The platform reports that your account is already bound; "
            "you should use the rotate or recover flow instead of re-running "
            "verify."
        ),
        remediation=(
            "Use the action the platform recommended in the details payload "
            "(see Recommended action below). Generally: `rotate-hotkey` when "
            "you still control the old hotkey, `recover-hotkey` when you do "
            "not."
        ),
        docs_anchor="hotkey-rotation.md",
        details_renderer=_render_recommended_action,
    ),
    MinerFanGroupRequiredError.code: ErrorTemplate(
        headline="You must lead a Fan Group before verifying as a miner.",
        explanation=(
            "Phase 1 miners are Fan Group leaders. `verify-miner` only "
            "succeeds for an account that already leads a Fan Group on the "
            "BitFan platform; it does not create one for you."
        ),
        remediation=(
            "Sign into the BitFan web app, create and grow a Fan Group, then "
            "re-run `verify-miner` once you lead one."
        ),
        docs_anchor="miner.md#step-1-create-and-grow-your-fan-group",
    ),
    ColdkeyOwnershipNotProvenError.code: ErrorTemplate(
        headline="The platform could not confirm your coldkey ownership.",
        explanation=(
            "Some flows require proof that the operator controls the coldkey "
            "matching the hotkey being bound. The platform reports that proof "
            "was missing or did not verify."
        ),
        remediation=(
            "Re-run the command — the CLI will re-issue the coldkey ownership "
            "proof. If the failure repeats, confirm the loaded wallet matches "
            "the hotkey you intend to bind."
        ),
        docs_anchor="security.md#coldkey-ownership-proof",
    ),
    DiscordHandleMissingError.code: ErrorTemplate(
        headline="Your BitFan account does not yet have a Discord handle on file.",
        explanation=(
            "Some flows require a Discord handle for out-of-band recovery "
            "communication. The platform reports your account does not have "
            "one set."
        ),
        remediation=(
            "Sign into the BitFan web app, attach a Discord handle to your profile, and retry."
        ),
        docs_anchor="hotkey-rotation.md#recovery",
    ),
    TwoFactorProofInvalidError.code: ErrorTemplate(
        headline="The 2FA proof for this operation did not verify.",
        explanation=(
            "Sensitive flows (recovery especially) require a 2FA proof in "
            "addition to the signed envelope. The platform reports the proof "
            "was missing, expired, or did not match the configured factor."
        ),
        remediation=(
            "Re-run the command and supply a fresh code from your authenticator "
            "app or hardware token."
        ),
        docs_anchor="hotkey-rotation.md#recovery",
    ),
    # ---------------------------- Snapshot read ---------------------------
    SnapshotNotReadyError.code: ErrorTemplate(
        headline="No published snapshot exists for the requested date.",
        explanation=(
            "The platform produces one signed snapshot per UTC day. The "
            "requested activity_date either falls before the platform began "
            "publishing or is not yet available."
        ),
        remediation=(
            "Try again after the platform's publish cadence completes for the "
            "day, or pass `--activity-date` to target a known-published date."
        ),
        docs_anchor="platform-api.md#snapshot-endpoints",
    ),
    SnapshotModeInvalidError.code: ErrorTemplate(
        headline="The requested snapshot mode is not supported by the platform.",
        explanation=(
            "Validators may request `aggregate` or `detailed`. The platform "
            "reports it cannot serve the mode this CLI requested for this "
            "activity_date."
        ),
        remediation=(
            "Switch the configured mode in `[validator]` to one the platform "
            "supports (typically `aggregate`)."
        ),
        docs_anchor="validator.md#snapshot-modes",
    ),
    SnapshotDateInvalidError.code: ErrorTemplate(
        headline="The requested snapshot date is not a valid value.",
        explanation=(
            "Activity dates must be UTC `YYYY-MM-DD` strings within the "
            "platform's publishing window."
        ),
        remediation=(
            "Check the `--activity-date` flag (or the validator config) and "
            "retry with a date in `YYYY-MM-DD` form within the supported range."
        ),
        docs_anchor="platform-api.md#snapshot-endpoints",
    ),
    SnapshotAccessDeniedError.code: ErrorTemplate(
        headline="The platform refuses to serve this snapshot to your account.",
        explanation=(
            "Snapshot reads require a verified validator account with the "
            "correct scope. The platform reports your account does not meet "
            "those requirements for this snapshot."
        ),
        remediation=(
            "Confirm you have run `verify-validator` and that the token in use "
            "carries the `snapshot:read:*` scope. Operators may also gate "
            "specific snapshots."
        ),
        docs_anchor="validator.md#snapshot-reads",
    ),
    # --------------------------- Snapshot storage -------------------------
    SnapshotPageNotFoundError.code: ErrorTemplate(
        headline="The platform cannot locate a snapshot page the manifest referenced.",
        explanation=(
            "Detailed-mode snapshots are split into pages described by a "
            "manifest. The platform's manifest pointed at a page that storage "
            "could not return — usually a transient publish-pipeline race."
        ),
        remediation="Retry the operation. If the failure persists, contact platform operators.",
        docs_anchor="platform-api.md#snapshot-endpoints",
    ),
    SnapshotStorageAccessDeniedError.code: ErrorTemplate(
        headline="Snapshot storage refused the platform's read on your behalf.",
        explanation=(
            "An infrastructure-level access policy blocked the read. This is a "
            "platform-operator-side condition, not something the CLI can "
            "remediate."
        ),
        remediation="Contact the platform operators — the issue is on their side.",
        docs_anchor="platform-api.md#snapshot-endpoints",
    ),
    SnapshotStorageError.code: ErrorTemplate(
        headline="The platform's snapshot storage backend reported an error.",
        explanation=("Generic upstream failure from the storage layer. Usually transient."),
        remediation=(
            "Retry the operation. If the failure persists across several "
            "minutes, contact the platform operators."
        ),
        docs_anchor="platform-api.md#snapshot-endpoints",
    ),
    SnapshotPageHashError.code: ErrorTemplate(
        headline="A snapshot page failed the platform's own integrity check.",
        explanation=(
            "The platform recomputes per-page hashes server-side and refuses "
            "to ship a page that does not match its expected hash. This is "
            "the platform catching its own corruption before the validator "
            "consumes it."
        ),
        remediation=(
            "Retry the operation after a short wait. If the failure repeats, "
            "the platform team needs to re-publish the snapshot — file the "
            "issue with them."
        ),
        docs_anchor="security.md#snapshot-integrity",
    ),
    # ----------------------- Cross-environment / path ---------------------
    EnvironmentMismatchPlatformError.code: ErrorTemplate(
        headline="The platform rejected the envelope's chain_network / instance_id.",
        explanation=(
            "Envelopes are bound to a specific chain_network and "
            "platform_instance_id at signing time. The platform refused this "
            "envelope because the values it carried do not match what this "
            "platform instance accepts."
        ),
        remediation=(
            "Update your `--chain-network` and `--platform-instance-id` flags "
            "(or your validator config) to match the values the platform "
            "expects (shown below)."
        ),
        docs_anchor="security.md#cross-environment-replay-defense",
        details_renderer=_render_environment_expected,
    ),
    PathMismatchError.code: ErrorTemplate(
        headline="The signed envelope's intended endpoint does not match the URL.",
        explanation=(
            "Envelopes carry the API path they were signed for as part of the "
            "replay defence. The platform rejected this submission because "
            "the envelope's path differs from the URL it was POSTed to."
        ),
        remediation=(
            "Re-run the command without manual URL rewriting. If you front "
            "the platform with a reverse proxy, ensure it does not rewrite the "
            "request path."
        ),
        docs_anchor="security.md#path-binding",
    ),
    # ----------------- Platform-side signature primitives -----------------
    # Platform → CLI direction: the platform rejected the signature on a
    # request *we* sent. Remediation focuses on our keypair / payload.
    SignatureInvalidFormatError.code: ErrorTemplate(
        headline="The platform could not parse the signature on your request.",
        explanation=(
            "The signature hex or its surrounding envelope structure did not "
            "decode. This is usually a CLI bug rather than an operator error."
        ),
        remediation=(
            "Ensure you are on the latest CLI build. If the issue persists "
            "on a current build, file an issue."
        ),
        docs_anchor="security.md#signatures",
    ),
    SignatureUnsupportedKeyTypeError.code: ErrorTemplate(
        headline="The platform refuses your signing key's crypto type.",
        explanation=(
            "Phase 1 accepts SR25519 hotkeys for request signing. The hotkey "
            "you loaded reports a different crypto type."
        ),
        remediation="Use a hotkey with crypto type SR25519 (the btcli default).",
        docs_anchor="security.md#signatures",
    ),
    SignatureVerificationFailedError.code: ErrorTemplate(
        headline="The platform rejected the signature on your request.",
        explanation=(
            "The signature decoded but did not verify against the hotkey "
            "address declared in the payload. Common causes: the wallet "
            "loaded does not match the address in the payload; the payload "
            "was mutated after signing; the hotkey was rotated server-side."
        ),
        remediation=(
            "Confirm the wallet loaded matches the hotkey on your account, "
            "then re-run the command. If you have rotated keys recently, "
            "run rotate-hotkey / recover-hotkey before retrying."
        ),
        docs_anchor="security.md#signatures",
    ),
    SignatureAddressMismatchError.code: ErrorTemplate(
        headline="The hotkey SS58 in your payload does not match the signature.",
        explanation=(
            "The platform recomputed the SS58 address from the signing key "
            "and got a different value than the envelope's declared "
            "`hotkey_ss58` field."
        ),
        remediation=(
            "Re-run the command — the CLI fills the hotkey field from the "
            "loaded wallet, so a fresh run will not exhibit drift unless the "
            "wallet itself has changed mid-flight."
        ),
        docs_anchor="security.md#signatures",
    ),
    SignatureDomainMismatchError.code: ErrorTemplate(
        headline="The platform expected a different signature domain string.",
        explanation=(
            "Signatures are bound to a per-endpoint domain literal to prevent "
            "cross-endpoint reuse. The platform reports the envelope's "
            "domain does not match the endpoint it was POSTed to."
        ),
        remediation=(
            "Re-run the command — the CLI picks the domain by endpoint, so "
            "this should not recur. If it does, file an issue."
        ),
        docs_anchor="security.md#signature-domains",
        details_renderer=_render_expected_domain,
    ),
    # --------------------------- Generic buckets --------------------------
    PlatformUnauthorizedError.code: ErrorTemplate(
        headline="The platform refused the request as unauthorised.",
        explanation=(
            "A 4xx that the platform did not surface a specific catalogued "
            "code for. Most likely token / scope / verification."
        ),
        remediation=(
            "Check your API token environment variable, scope, and that your "
            "account has completed verify-{miner,validator}."
        ),
        docs_anchor="security.md#api-tokens",
    ),
    PlatformBadRequestError.code: ErrorTemplate(
        headline="The platform rejected the request as malformed.",
        explanation=(
            "A 4xx that the platform did not surface a specific catalogued "
            "code for. Read the wire detail below."
        ),
        remediation=(
            "Re-run with `--verbose` and review the wire detail. If the cause "
            "is unclear, file an issue."
        ),
    ),
    PlatformServerError.code: ErrorTemplate(
        headline="The platform reported an internal server error.",
        explanation=("A 5xx returned by the platform. The condition is on their side, not yours."),
        remediation=(
            "Retry after a short wait. If the failure persists, contact platform operators."
        ),
    ),
    PlatformError.code: ErrorTemplate(
        headline="The platform returned a generic platform error.",
        explanation="Catch-all template for the base PlatformError class.",
        remediation="Re-run with `--verbose` and inspect the wire detail.",
    ),
}


# ---------------------------------------------------------------------------
# Local-origin template registry
# ---------------------------------------------------------------------------


_LOCAL_TEMPLATES: dict[type[Exception], ErrorTemplate] = {
    # ---------------------------- Identity layer --------------------------
    IdentityPayloadValidationError: ErrorTemplate(
        headline="The CLI built an identity payload that did not pass local validation.",
        explanation=(
            "Before signing or sending, the CLI cross-checks the payload it "
            "constructed against the canonical schema. The check failed locally."
        ),
        remediation=(
            "This is almost always a CLI bug. Re-run with `--verbose` to capture "
            "the failure detail and file an issue."
        ),
        docs_anchor="security.md#identity-payloads",
    ),
    IdentityEnvelopeStructureError: ErrorTemplate(
        headline="The identity envelope the CLI assembled is structurally wrong.",
        explanation=(
            "The CLI built an envelope whose top-level fields do not match the "
            "expected shape. This is a CLI-side problem."
        ),
        remediation="File an issue with the `--verbose` output.",
        docs_anchor="security.md#identity-envelopes",
    ),
    IdentityDomainMismatchError: ErrorTemplate(
        headline="The CLI detected a domain mismatch before sending the request.",
        explanation=(
            "Each canonical payload embeds a domain literal that ties it to one "
            "endpoint. The CLI's local pre-flight check found the payload's "
            "embedded domain does not match the endpoint it is about to call."
        ),
        remediation=(
            "Re-run the command. If the mismatch recurs, the CLI build is at fault — file an issue."
        ),
        docs_anchor="security.md#signature-domains",
    ),
    EnvironmentMismatchError: ErrorTemplate(
        headline="The CLI detected a chain_network / platform_instance_id mismatch.",
        explanation=(
            "The CLI verifies the chain_network and platform_instance_id carried "
            "by a received payload (e.g., a platform-signed snapshot) against "
            "its own configured environment, before trusting any of the "
            "payload's contents. The check failed."
        ),
        remediation=(
            "Check your validator config — the `[chain]` and `[platform]` blocks "
            "must point at the same environment the platform is signing for."
        ),
        docs_anchor="security.md#cross-environment-replay-defense",
    ),
    PayloadExpiredError: ErrorTemplate(
        headline="A received payload has already expired.",
        explanation=(
            "The CLI rejects payloads whose `expires_at` is in the past relative "
            "to the local clock. This is the freshness guarantee that prevents "
            "stale envelopes from being consumed."
        ),
        remediation=(
            "Re-fetch the payload. If your local clock is correct and the "
            "platform keeps serving expired payloads, raise it with platform "
            "operators."
        ),
        docs_anchor="security.md#timestamps",
    ),
    PayloadNotYetValidError: ErrorTemplate(
        headline="A received payload's `issued_at` is in the future.",
        explanation=(
            "The CLI applies a small clock-skew tolerance, but a payload whose "
            "`issued_at` is too far in the future is treated as suspicious."
        ),
        remediation=(
            "Check that your machine's clock is correct (NTP). If it is, the "
            "platform's clock is the one that has drifted — contact operators."
        ),
        docs_anchor="security.md#timestamps",
    ),
    # ----------------- Local signature verification family ----------------
    # CLI → platform direction here is *receiving*: the CLI tried to verify
    # a signature *the platform produced* (snapshot, recovery page) and the
    # check failed. Remediations therefore focus on the trusted-key
    # configuration and re-fetching, never on our keypair.
    SignatureFormatError: ErrorTemplate(
        headline="A signature received from the platform did not parse.",
        explanation=(
            "The CLI tried to decode an Ed25519 / SR25519 signature on a "
            "platform-produced artifact (typically a snapshot) and could not. "
            "The artifact is either truncated or carries a malformed signature."
        ),
        remediation=(
            "Re-fetch the artifact. If the failure recurs, the platform may "
            "have published a corrupted file — contact operators."
        ),
        docs_anchor="security.md#snapshot-integrity",
    ),
    SignatureVerificationError: ErrorTemplate(
        headline="A signature received from the platform did not verify.",
        explanation=(
            "The signature decoded but did not verify against the trusted "
            "public key for this domain. Possible causes: in-transit "
            "corruption; trusted-key configuration is stale; the platform's "
            "signing key rotated and your config has not caught up."
        ),
        remediation=(
            "Re-fetch the artifact. If the failure persists, confirm your "
            "`platform.snapshot_keys` config matches the platform's currently "
            "published key set."
        ),
        docs_anchor="security.md#snapshot-integrity",
    ),
    LocalSignatureAddressMismatchError: ErrorTemplate(
        headline="A signature address mismatch on platform-produced data.",
        explanation=(
            "The SS58 address derived from a received signature does not match "
            "the expected signer for this domain."
        ),
        remediation=("Confirm the trusted-key configuration is correct, then re-fetch."),
        docs_anchor="security.md#snapshot-integrity",
    ),
    UnsupportedKeyTypeError: ErrorTemplate(
        headline="A platform-produced signature uses a key type the CLI does not accept.",
        explanation=(
            "Phase 1 accepts a fixed set of crypto types for platform-signed "
            "artifacts. The artifact you fetched declares a type outside that "
            "set."
        ),
        remediation=(
            "Ensure your CLI build is current. If the platform has shipped a "
            "new accepted type, update the CLI to a matching release."
        ),
        docs_anchor="security.md#snapshot-integrity",
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_error(exc: BaseException, *, verbose: bool = False) -> str:
    """Format an exception as the multi-line operator-facing block.

    The returned string ends with a newline so callers can write it
    directly to stderr. The renderer is total: every input produces some
    output, including unknown exception classes — the unknown paths emit
    a self-explanatory block that points the operator at the issue
    template.
    """
    if isinstance(exc, PlatformError):
        template = _PLATFORM_TEMPLATES.get(exc.code)
        if template is None:
            return _render_unknown_platform_code(exc, verbose=verbose)
        return _render_with_template(
            exc=exc,
            template=template,
            origin_label=f"platform, HTTP {exc.status_code}"
            if exc.status_code is not None
            else "platform",
            wire_code=exc.wire_code,
            verbose=verbose,
        )

    if isinstance(exc, (IdentityError, SignatureError)):
        template = _lookup_local_template(type(exc))
        if template is None:
            return _render_unknown_local(exc, verbose=verbose)
        return _render_with_template(
            exc=exc,
            template=template,
            origin_label="local verification",
            wire_code=getattr(exc, "code", type(exc).__name__),
            verbose=verbose,
        )

    return _render_generic(exc, verbose=verbose)


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------


def _lookup_local_template(cls: type[Exception]) -> ErrorTemplate | None:
    """Walk the MRO so a subclass falls back to a parent's template."""
    for ancestor in cls.__mro__:
        template = _LOCAL_TEMPLATES.get(ancestor)
        if template is not None:
            return template
    return None


def _render_with_template(
    *,
    exc: BaseException,
    template: ErrorTemplate,
    origin_label: str,
    wire_code: str,
    verbose: bool,
) -> str:
    """Stitch an ErrorTemplate into the standard operator-facing block."""
    lines: list[str] = []
    lines.append(f"Error: {_strip_for_display(wire_code)}  ({origin_label})")
    lines.append("")
    lines.append(f"  {_strip_for_display(template.headline)}")
    lines.append("")
    for paragraph in _wrap_paragraphs(template.explanation):
        lines.append(f"  {paragraph}")
    lines.append("")
    lines.append("  Remediation:")
    for paragraph in _wrap_paragraphs(template.remediation):
        lines.append(f"    {paragraph}")

    details_line = _maybe_render_details(exc=exc, template=template)
    if details_line:
        lines.append("")
        for line in details_line.splitlines() or [""]:
            lines.append(f"    {line}")

    if template.docs_anchor:
        lines.append("")
        lines.append("  More info:")
        lines.append(f"    {_DOCS_ROOT}/{template.docs_anchor}")

    if verbose:
        lines.append("")
        lines.append("  [verbose]")
        for line in _build_verbose_payload(exc).splitlines():
            lines.append(f"    {line}")

    lines.append("")
    return "\n".join(lines)


def _maybe_render_details(*, exc: BaseException, template: ErrorTemplate) -> str | None:
    """Run the template's optional details renderer against ``exc.details``."""
    if template.details_renderer is None:
        return None
    details = getattr(exc, "details", None)
    if not isinstance(details, dict):
        return None
    try:
        return template.details_renderer(details)
    except Exception:
        # A template renderer must never break the parent dispatch.
        return None


def _render_unknown_platform_code(exc: PlatformError, *, verbose: bool) -> str:
    """Output block for a wire code we have no template for."""
    wire = _strip_for_display(exc.wire_code or "<missing>")
    status = exc.status_code if exc.status_code is not None else "?"
    detail = _strip_for_display(exc.detail) if exc.detail else None
    issue_url = (
        f"https://github.com/{_REPO_SLUG}/issues/new"
        f"?template={urllib.parse.quote(_ISSUE_TEMPLATE_NAME, safe='')}"
        f"&title=Unrecognised+platform+code%3A+{urllib.parse.quote(wire, safe='')}"
    )

    lines: list[str] = []
    lines.append(f"Error: {wire}  (platform, HTTP {status})")
    lines.append("")
    lines.append("  The platform returned an error code this CLI version does not recognise.")
    lines.append("")
    if detail:
        lines.append(f'  Wire detail: "{detail}"')
        lines.append("")
    lines.append("  Remediation:")
    lines.append("    1. Upgrade to the latest published prometheon release.")
    lines.append("    2. If you are already current, please open an issue so the catalog")
    lines.append("       can be extended:")
    lines.append(f"         {issue_url}")
    if verbose:
        lines.append("")
        lines.append("  [verbose]")
        for line in _build_verbose_payload(exc).splitlines():
            lines.append(f"    {line}")
    lines.append("")
    return "\n".join(lines)


def _render_unknown_local(exc: BaseException, *, verbose: bool) -> str:
    """Local-origin error whose class has no template."""
    code = _strip_for_display(getattr(exc, "code", type(exc).__name__))
    lines: list[str] = [
        f"Error: {code}  (local verification)",
        "",
        f"  {_strip_for_display(str(exc))}",
        "",
        "  This subnet-side verification check failed without a specific operator hint.",
        "",
        "  Remediation:",
        "    Re-run with `--verbose` to capture details and file an issue if unclear.",
    ]
    if verbose:
        lines.append("")
        lines.append("  [verbose]")
        for line in _build_verbose_payload(exc).splitlines():
            lines.append(f"    {line}")
    lines.append("")
    return "\n".join(lines)


def _render_generic(exc: BaseException, *, verbose: bool) -> str:
    """Anything that is not Platform / Identity / Signature family."""
    lines: list[str] = [
        f"Error: {_strip_for_display(type(exc).__name__)}  (unexpected)",
        "",
        f"  {_strip_for_display(str(exc))}",
        "",
        "  This is an unexpected error inside the CLI. Please file an issue with the",
        "  output of `--verbose`.",
    ]
    if verbose:
        lines.append("")
        lines.append("  [verbose]")
        for line in _build_verbose_payload(exc).splitlines():
            lines.append(f"    {line}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Verbose payload + sanitisation primitives
# ---------------------------------------------------------------------------


def _build_verbose_payload(exc: BaseException) -> str:
    """Produce the trailing diagnostic block shown under ``--verbose``.

    Capped at :data:`_VERBOSE_PAYLOAD_CAP_BYTES` and depth
    :data:`_VERBOSE_DEPTH_CAP`. Secret-shape values are replaced with
    ``<redacted>``. The privacy backstop in
    :mod:`prometheon.platform.errors` already drops cross-user keys at
    parse time; this layer hardens against unforeseen shapes (raw tokens
    in a future ``details`` payload, etc.).
    """
    bundle: dict[str, Any] = {
        "class": type(exc).__name__,
        "module": type(exc).__module__,
        "str": str(exc),
    }
    for attribute in ("code", "wire_code", "status_code", "detail", "details"):
        if hasattr(exc, attribute):
            bundle[attribute] = getattr(exc, attribute)
    safe = _truncate_for_verbose(bundle, depth=0)
    rendered = json.dumps(safe, indent=2, default=repr, sort_keys=True)
    if len(rendered.encode("utf-8")) > _VERBOSE_PAYLOAD_CAP_BYTES:
        head = rendered.encode("utf-8")[
            : _VERBOSE_PAYLOAD_CAP_BYTES - len(_VERBOSE_TRUNCATED_MARKER)
        ]
        rendered = head.decode("utf-8", errors="ignore") + _VERBOSE_TRUNCATED_MARKER
    return _CONTROL_CHAR_PATTERN.sub("", rendered)


def _truncate_for_verbose(value: Any, *, depth: int) -> Any:
    """Depth-bounded copy with secret-shape redaction."""
    if depth >= _VERBOSE_DEPTH_CAP:
        return _VERBOSE_TRUNCATED_MARKER
    if isinstance(value, Mapping):
        return {str(k): _truncate_for_verbose(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_truncate_for_verbose(item, depth=depth + 1) for item in value]
    if isinstance(value, str):
        return _redact_secret_shape(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return repr(value)


def _redact_secret_shape(value: str) -> str:
    """Replace token-shaped strings with a marker."""
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.fullmatch(value):
            return _REDACTED_MARKER
    return value


def _strip_for_display(value: str | None) -> str:
    """Drop terminal-corrupting control chars before printing.

    Tab and newline are preserved (operators legitimately use them). DEL
    and the other C0 controls are stripped. Returns ``""`` when input is
    ``None`` so callers do not have to special-case missing fields.
    """
    if value is None:
        return ""
    return _CONTROL_CHAR_PATTERN.sub("", value)


def _wrap_paragraphs(text: str) -> list[str]:
    """Split a multi-line block into per-line strings ready for indentation.

    Templates author free-form paragraphs; this helper preserves explicit
    newlines without adding our own word-wrap (the terminal handles
    width). Empty lines become a single blank entry so they survive the
    join in :func:`_render_with_template`.
    """
    return [_strip_for_display(line) for line in text.split("\n")]


# ---------------------------------------------------------------------------
# Internal helpers exposed for the test suite
# ---------------------------------------------------------------------------


def _platform_catalog_template_invariant() -> None:
    """Assert every catalogued PlatformError subclass has a template.

    Invoked from the test suite (and at import time as a defensive
    backstop). The renderer's contract with the rest of the codebase is
    that adding a new code to :data:`_CATALOG` is meaningless unless
    callers can render it; this check enforces that pairing.
    """
    catalog_codes = set(_CATALOG.keys())
    template_codes = set(_PLATFORM_TEMPLATES.keys())
    missing = catalog_codes - template_codes
    if missing:
        raise RuntimeError(
            f"platform error catalog has codes without renderer templates: {sorted(missing)}"
        )


# Run the invariant check on import. If a future PR adds a code to the
# catalog without a matching template, the CLI fails fast instead of
# silently dropping to the unknown-code path.
_platform_catalog_template_invariant()


__all__ = [
    "ErrorTemplate",
    "render_error",
]
