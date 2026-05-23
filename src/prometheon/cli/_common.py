"""Shared CLI helpers used by multiple sub-commands.

Centralises wallet loading, BitFan client construction, and the small
ergonomic bits (success / error pretty-printing) so the individual
command modules stay focused on their specific flow.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import click

from prometheon.chain.wallet import (
    HotkeyNotAvailableError,
    WalletError,
    get_coldkey_keypair,
    get_hotkey_keypair,
    load_wallet,
)
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.identity.verifier import ClientInfo
from prometheon.platform.client import BitFanClient
from prometheon.security.hashes import api_token_hash
from prometheon.version import __version__

# Where operators obtain a one-time bootstrap token for the first
# `verify-miner` / `verify-validator` call. The web app issues the
# token under the user's existing BitFan session and scopes it to
# `identity:verify:<role>`; `/identity/verify` revokes it on success.
PARTNER_PORTAL_URL = "https://bitfanweb-production-658c.up.railway.app/me/partner/prometheon"


def load_hotkey_or_exit(*, name: str, hotkey_name: str) -> Any:
    """Load a wallet hotkey keypair or terminate the CLI with a clear error."""
    try:
        wallet = load_wallet(name=name, hotkey_name=hotkey_name)
        return get_hotkey_keypair(wallet)
    except (WalletError, HotkeyNotAvailableError) as exc:
        raise click.ClickException(f"could not load hotkey: {exc}") from exc


def load_coldkey_or_exit(*, name: str, hotkey_name: str) -> Any:
    """Load a wallet coldkey (prompts for passphrase) or terminate cleanly."""
    try:
        wallet = load_wallet(name=name, hotkey_name=hotkey_name)
        return get_coldkey_keypair(wallet)
    except WalletError as exc:
        raise click.ClickException(f"could not load coldkey: {exc}") from exc


def read_api_token_or_exit(
    *,
    env_var: str | None,
    explicit: str | None,
    bootstrap_for_role: str | None = None,
) -> str:
    """Pick the API token from an explicit flag, an env var, or fail cleanly.

    Explicit ``--api-token`` wins (intended for one-off CLI runs); the
    environment variable is the documented operational path so secrets
    do not appear in shell history.

    When ``bootstrap_for_role`` is set to ``"miner"`` or ``"validator"``,
    a missing token raises with the bootstrap-token onboarding text
    (Partner Portal URL + paste-and-export steps) instead of the generic
    "token missing" message. Use this for the first-time verify flows.
    """
    if explicit:
        return explicit
    if env_var:
        value = os.environ.get(env_var)
        if value:
            return value

    if bootstrap_for_role is not None:
        raise click.ClickException(_bootstrap_token_help(env_var, bootstrap_for_role))

    raise click.ClickException(
        f"API token missing: pass --api-token or set the configured env var "
        f"({env_var or 'PROMETHEON_API_TOKEN'})."
    )


def _bootstrap_token_help(env_var: str | None, role: str) -> str:
    """Multi-line guidance shown when verify-{miner,validator} has no token."""
    env_display = env_var or f"PROMETHEON_{role.upper()}_API_TOKEN"
    return (
        f"no {role} API token in env ({env_display} unset)\n"
        "\n"
        "To get started:\n"
        f"  1. Open {PARTNER_PORTAL_URL}\n"
        f'  2. Click "Get bootstrap token" with role {role!r}.\n'
        "  3. Copy the token, then re-run with:\n"
        f"       export {env_display}=<paste>\n"
        "\n"
        "The bootstrap token is one-time, scoped to identity:verify, "
        "expires after one hour, and is auto-revoked on successful verify."
    )


def make_client(
    *,
    base_url: str,
    api_token: str,
    platform_instance_id: str,
    chain_network: ChainNetwork,
    netuid: int,
    validator_keypair: Any | None = None,
    role: Role | None = None,
) -> BitFanClient:
    """Construct a :class:`BitFanClient` with the supplied configuration."""
    return BitFanClient(
        base_url=base_url,
        api_token=api_token,
        platform_instance_id=platform_instance_id,
        chain_network=chain_network,
        netuid=netuid,
        validator_keypair=validator_keypair,
        role=role,
    )


def client_info() -> ClientInfo:
    """Return the standard ``ClientInfo`` block embedded in every envelope."""
    return ClientInfo(name="prometheon-cli", version=__version__)


def utc_now_iso() -> str:
    """Return the current UTC time in the canonical protocol timestamp profile."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def echo_success(message: str) -> None:
    """Print a success message to stdout in the CLI's house style."""
    click.echo(click.style("✓ ", fg="green") + message)


def echo_info(message: str) -> None:
    """Print an informational message to stdout."""
    click.echo(click.style("→ ", fg="cyan") + message)


__all__ = [
    "api_token_hash",
    "client_info",
    "echo_info",
    "echo_success",
    "load_coldkey_or_exit",
    "load_hotkey_or_exit",
    "make_client",
    "read_api_token_or_exit",
    "utc_now_iso",
]
