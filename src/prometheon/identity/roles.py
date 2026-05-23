"""Stable identifiers for roles and environments used by the protocol.

These enums are the canonical strings that appear inside every signed
Prometheon payload. They are intentionally narrow:

- :class:`Role` distinguishes miner and validator. The two role states are
  kept strictly separate on the Platform side as well (separate API tokens,
  separate verification state, separate rotation cooldowns).
- :class:`ChainNetwork` distinguishes the Bittensor chain environment.
  Together with the Platform's ``platform_instance_id`` field it implements
  the cross-environment replay defense described in consolidated
  specification §6.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Why not StrEnum?
#
# ``enum.StrEnum`` is only available from Python 3.11 onward, but Phase 1
# targets ``>=3.10,<3.15``. The ``(str, Enum)`` pattern is the equivalent on
# 3.10: instances are real ``str`` subclasses (so equality with on-wire
# strings works without manual conversion), and Pydantic / JSON serialise
# them as their ``value`` automatically.
# ---------------------------------------------------------------------------


class Role(str, Enum):
    """A subject role for identity verification, rotation, and recovery.

    The string values are the on-wire representation embedded inside every
    canonical payload's ``role`` field.
    """

    MINER = "miner"
    VALIDATOR = "validator"


class ChainNetwork(str, Enum):
    """Bittensor chain environment identifier.

    The string values are the on-wire representation embedded inside every
    canonical payload's ``chain_network`` field. Validators reject any
    payload whose ``chain_network`` differs from their configured network.
    """

    LOCAL = "local"
    TEST = "test"
    FINNEY = "finney"


class RecoveryMethod(str, Enum):
    """Hotkey recovery method identifier.

    Embedded inside ``PROMETHEON_HOTKEY_RECOVERY_V1`` payloads to
    discriminate between coldkey-backed and manual-2FA-Ops recovery flows.
    """

    COLDKEY = "coldkey"
    MANUAL_2FA_OPS = "manual_2fa_ops"


__all__ = ["ChainNetwork", "RecoveryMethod", "Role"]
