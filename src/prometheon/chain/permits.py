"""Validator permit helpers.

Phase 1 does not block submission on the permit bit — Bittensor's chain
rejects unpermitted weights server-side, so a missing permit surfaces as
a submission failure in the runner. This module provides read-only
helpers the runner uses to log a warning at startup and surface a clear
diagnostic when a permit is unexpectedly missing.
"""

from __future__ import annotations

from prometheon.chain.metagraph import MetagraphView


def has_validator_permit(metagraph: MetagraphView, hotkey: str) -> bool:
    """Return ``True`` when ``hotkey`` holds a validator permit in ``metagraph``.

    Unregistered hotkeys return ``False``.
    """
    uid = metagraph.uid_for(hotkey)
    if uid is None:
        return False
    return bool(metagraph.validator_permits.get(uid, False))


__all__ = ["has_validator_permit"]
