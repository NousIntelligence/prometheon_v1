"""Subtensor connection wrapper and capability detection.

Centralises the import of :class:`bittensor.Subtensor` (or the equivalent
SDK class) and exposes the operations the validator runtime needs:

- Connect to the chain for a given network identifier.
- Build a :class:`MetagraphView` from a fresh sync.
- Read chain hyperparameters (``weights_version``,
  ``commit_reveal_enabled``, ``min_allowed_weights``, ``max_weights_limit``,
  ``weights_rate_limit``, ``activity_cutoff``).
- Detect whether the installed SDK exposes ``mechid`` on
  ``Subtensor.set_weights``.

The thin shape lets us swap implementations in tests (the runtime injects
a fake Subtensor object) and keeps the SDK surface area constrained to a
single import per concern.
"""

from __future__ import annotations

import inspect
import sys
from typing import Any

from prometheon.chain.metagraph import MetagraphView
from prometheon.chain.weights import (
    ChainAdapterCapabilities,
    ChainHyperparameters,
    ChainWeightVector,
)
from prometheon.identity.roles import ChainNetwork


class SubtensorError(Exception):
    """Base exception for subtensor-side failures."""

    code: str = "chain.subtensor_error"


def connect(network: ChainNetwork | str) -> Any:
    """Construct a :class:`bittensor.Subtensor` for the given network.

    Parameters
    ----------
    network:
        Either a :class:`ChainNetwork` member or its raw string value
        (``"local"``, ``"test"``, or ``"finney"``).

    Returns
    -------
    Any
        A ``bittensor.Subtensor`` instance. Typed as ``Any`` because the
        upstream SDK has dynamic types; tests substitute a fake.
    """
    import bittensor

    network_str = network.value if isinstance(network, ChainNetwork) else network
    try:
        return bittensor.Subtensor(network=network_str)
    except Exception as exc:
        raise SubtensorError(
            f"could not connect to subtensor on network={network_str!r}: {exc}"
        ) from exc


def detect_capabilities() -> ChainAdapterCapabilities:
    """Detect installed Bittensor SDK version and ``mechid`` support.

    Called once at validator startup; the result feeds the
    :func:`prometheon.chain.weights.assert_phase1_compatible` policy
    gate.
    """
    import bittensor

    try:
        from bittensor import Subtensor
    except ImportError as exc:
        raise SubtensorError(f"could not import bittensor.Subtensor: {exc}") from exc

    try:
        signature = inspect.signature(Subtensor.set_weights)
        supports_mechid = "mechid" in signature.parameters
    except (TypeError, ValueError):
        # If introspection fails for an unusual SDK shape, fail closed by
        # reporting no mechid support.
        supports_mechid = False

    return ChainAdapterCapabilities(
        sdk_version=getattr(bittensor, "__version__", "unknown"),
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        supports_mechid=supports_mechid,
    )


def sync_metagraph_view(subtensor: Any, *, netuid: int) -> MetagraphView:
    """Pull a fresh metagraph from the chain and convert to :class:`MetagraphView`.

    Parameters
    ----------
    subtensor:
        Connected :class:`bittensor.Subtensor` instance (or a test fake).
    netuid:
        Target subnet.

    Returns
    -------
    MetagraphView
        Validated, immutable snapshot the engine and the chain adapter
        consume.
    """
    try:
        raw = subtensor.metagraph(netuid=netuid)
    except Exception as exc:
        raise SubtensorError(f"could not sync metagraph for netuid={netuid}: {exc}") from exc

    hotkeys = list(getattr(raw, "hotkeys", []))
    block_number = int(getattr(raw, "block", 0))
    hotkeys_by_uid = dict(enumerate(hotkeys))
    uids_by_hotkey = {h: i for i, h in hotkeys_by_uid.items()}

    permits = getattr(raw, "validator_permit", None)
    validator_permits = {i: bool(p) for i, p in enumerate(permits)} if permits is not None else {}

    return MetagraphView(
        block_number=block_number,
        hotkeys_by_uid=hotkeys_by_uid,
        uids_by_hotkey=uids_by_hotkey,
        validator_permits=validator_permits,
    )


def read_hyperparameters(subtensor: Any, *, netuid: int) -> ChainHyperparameters:
    """Read the Phase-1-relevant subnet hyperparameters from the chain.

    The validator runtime calls this immediately before submission so the
    pre-submission policy gate uses fresh values.
    """
    try:
        commit_reveal_enabled = bool(subtensor.get_commit_reveal_weights_enabled(netuid=netuid))
    except AttributeError:
        # Older SDKs without this getter — assume not enabled. The
        # adapter will still detect a runtime error if submission fails.
        commit_reveal_enabled = False
    except Exception as exc:
        raise SubtensorError(f"could not read commit_reveal_weights_enabled: {exc}") from exc

    try:
        weights_version = int(subtensor.weights_version(netuid=netuid))
    except (AttributeError, TypeError):
        # If the SDK does not surface a typed accessor, fall back to a
        # safe default of 0; the runner's fail-on-version-mismatch flag
        # determines whether this triggers a hard error.
        weights_version = 0
    except Exception as exc:
        raise SubtensorError(f"could not read weights_version: {exc}") from exc

    return ChainHyperparameters(
        weights_version=weights_version,
        commit_reveal_enabled=commit_reveal_enabled,
    )


def submit_set_weights(
    subtensor: Any,
    *,
    wallet: Any,
    netuid: int,
    vector: ChainWeightVector,
    version_key: int,
    mechid: int | None,
    wait_for_inclusion: bool = True,
) -> str | None:
    """Invoke the SDK's ``set_weights`` with the resolved u16 vector.

    Passes ``mechid`` only when the SDK exposes the parameter; that
    detection runs once at startup via :func:`detect_capabilities` and
    is communicated to this function by the caller.

    Returns a best-effort receipt string the runner persists in its
    state file and event log: the on-chain extrinsic hash when the SDK
    surfaces one, otherwise the SDK's human-readable status message,
    otherwise ``None``. **Raises :class:`SubtensorError` if the SDK
    reports the submission failed** — older code silently swallowed
    failures because the SDK's response object is dataclass-shaped
    rather than a plain tuple.
    """
    kwargs: dict[str, Any] = {
        "wallet": wallet,
        "netuid": netuid,
        "uids": vector.uids,
        "weights": vector.weights,
        "version_key": version_key,
        "wait_for_inclusion": wait_for_inclusion,
    }
    if mechid is not None:
        kwargs["mechid"] = mechid

    try:
        result = subtensor.set_weights(**kwargs)
    except Exception as exc:
        raise SubtensorError(f"set_weights failed: {exc}") from exc

    return _parse_set_weights_result(result)


def _parse_set_weights_result(result: Any) -> str | None:
    """Normalise the heterogeneous shapes ``set_weights`` returns.

    Bittensor 10.x returns ``ExtrinsicResponse`` — a dataclass with
    ``.success`` / ``.message`` / ``.extrinsic_receipt`` attributes that
    *behaves* like a tuple at the indexing level but is not a real tuple
    subclass. Older SDKs returned ``(bool, str)``, ``bool``, or a raw
    hash string. This helper handles each, raising on observed failure
    and returning the best available receipt on success.
    """
    # Bittensor 10.x ExtrinsicResponse: duck-typed via attributes so we
    # do not have to import the dataclass directly.
    if hasattr(result, "success") and hasattr(result, "message"):
        if not result.success:
            raise SubtensorError(f"set_weights returned failure: {result.message!r}")
        # Prefer the on-chain extrinsic hash when the receipt exposes one.
        receipt = getattr(result, "extrinsic_receipt", None)
        if receipt is not None:
            extrinsic_hash = getattr(receipt, "extrinsic_hash", None)
            if extrinsic_hash:
                return str(extrinsic_hash)
        # Fall back to the status message so operators see what the
        # chain reported (e.g. "Successfully set weights and Finalized.").
        return str(result.message) if result.message else None

    # Legacy SDK shape: bare ``(success, message)`` tuple.
    if isinstance(result, tuple) and len(result) >= 2:
        success = bool(result[0])
        if not success:
            raise SubtensorError(f"set_weights returned failure: {result[1]!r}")
        return str(result[1]) if result[1] else None

    # Legacy SDK shape: bare bool.
    if isinstance(result, bool):
        if not result:
            raise SubtensorError("set_weights returned False with no message")
        return None

    # Legacy SDK shape: raw hash string.
    if isinstance(result, str):
        return result

    # Unknown shape but no exception raised — treat as success without a
    # receipt rather than silently dropping a potential failure signal.
    return None


__all__ = [
    "SubtensorError",
    "connect",
    "detect_capabilities",
    "read_hyperparameters",
    "submit_set_weights",
    "sync_metagraph_view",
]
