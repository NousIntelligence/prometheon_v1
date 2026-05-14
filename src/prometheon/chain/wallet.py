"""Wallet loading and keypair helpers.

Thin wrappers around :class:`bittensor_wallet.Wallet` so the rest of the
codebase imports from this module instead of the SDK directly. Centralising
the import surface keeps the SDK boundary swappable and gives us one place
to add operator-facing error messages (clear when the wallet directory or
hotkey file is missing) without touching call sites.

This module deliberately does **not** unlock the coldkey unless the caller
explicitly asks; the validator runtime never needs coldkey access, and the
identity rotation / recovery CLI commands prompt the user interactively at
the point of use.
"""

from __future__ import annotations

from pathlib import Path

from bittensor_wallet import Keypair, Wallet


class WalletError(Exception):
    """Raised on wallet loading or key access errors."""

    code: str = "chain.wallet_error"


class HotkeyNotAvailableError(WalletError):
    """The wallet hotkey could not be loaded."""

    code = "chain.hotkey_not_available"


class ColdkeyNotAvailableError(WalletError):
    """The wallet coldkey could not be loaded (locked, missing, or wrong path)."""

    code = "chain.coldkey_not_available"


def load_wallet(
    *,
    name: str,
    hotkey_name: str,
    path: str | Path | None = None,
) -> Wallet:
    """Load a Bittensor wallet by name and hotkey name.

    Parameters
    ----------
    name:
        Coldkey directory name under ``~/.bittensor/wallets/`` (or the
        path override).
    hotkey_name:
        Hotkey file name inside that directory.
    path:
        Optional override of the wallets directory. ``None`` means the
        default (``~/.bittensor/wallets/``).

    Returns
    -------
    Wallet
        A :class:`bittensor_wallet.Wallet` instance with the hotkey
        loaded (but the coldkey left locked).
    """
    try:
        if path is not None:
            wallet = Wallet(name=name, hotkey=hotkey_name, path=str(path))
        else:
            wallet = Wallet(name=name, hotkey=hotkey_name)
    except Exception as exc:
        raise WalletError(
            f"could not construct wallet (name={name!r}, hotkey={hotkey_name!r}): {exc}"
        ) from exc
    return wallet


def get_hotkey_keypair(wallet: Wallet) -> Keypair:
    """Return the wallet's hotkey :class:`Keypair` ready for signing.

    The hotkey is unencrypted on disk by Bittensor's default scheme, so
    no interactive password prompt is needed.
    """
    try:
        return wallet.hotkey
    except Exception as exc:
        raise HotkeyNotAvailableError(f"could not load hotkey from wallet: {exc}") from exc


def get_coldkey_keypair(wallet: Wallet) -> Keypair:
    """Return the wallet's coldkey :class:`Keypair`, unlocking if needed.

    Coldkey access requires the operator's passphrase; the Bittensor SDK
    prompts interactively. This helper exists so callers do not need to
    import the SDK Wallet class directly.
    """
    try:
        return wallet.coldkey
    except Exception as exc:
        raise ColdkeyNotAvailableError(f"could not load coldkey from wallet: {exc}") from exc


__all__ = [
    "ColdkeyNotAvailableError",
    "HotkeyNotAvailableError",
    "WalletError",
    "get_coldkey_keypair",
    "get_hotkey_keypair",
    "load_wallet",
]
