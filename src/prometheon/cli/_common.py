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


def read_api_token_or_exit(*, env_var: str | None, explicit: str | None) -> str:
    """Pick the API token from an explicit flag, an env var, or fail cleanly.

    Explicit ``--api-token`` wins (intended for one-off CLI runs); the
    environment variable is the documented operational path so secrets
    do not appear in shell history.
    """
    if explicit:
        return explicit
    if env_var:
        value = os.environ.get(env_var)
        if value:
            return value
    raise click.ClickException(
        "API token missing: pass --api-token or set the configured env var "
        "(default: PROMETHEON_API_TOKEN)."
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
