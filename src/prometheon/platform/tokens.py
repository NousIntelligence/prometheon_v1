"""Platform API token scope identifiers.

Scopes are stable strings the platform embeds inside API tokens. The
subnet code does not validate scopes itself (the platform does), but the
scope names appear in CLI help text and configuration so they live here
as a single source of truth.

The two role-separated rules from the consolidated specification §14.11
are enforced server-side:

- A miner token must never grant snapshot access.
- A validator token must never grant miner identity mutation.
"""

from __future__ import annotations

from enum import Enum


class TokenScope(str, Enum):
    """Canonical scope strings supported by the platform."""

    IDENTITY_VERIFY_MINER = "identity:verify:miner"
    IDENTITY_VERIFY_VALIDATOR = "identity:verify:validator"

    IDENTITY_ROTATE_MINER = "identity:rotate:miner"
    IDENTITY_ROTATE_VALIDATOR = "identity:rotate:validator"

    IDENTITY_RECOVER_MINER = "identity:recover:miner"
    IDENTITY_RECOVER_VALIDATOR = "identity:recover:validator"

    SNAPSHOT_READ_AGGREGATE = "snapshot:read:aggregate"
    SNAPSHOT_READ_DETAILED = "snapshot:read:detailed"

    STATUS_READ = "status:read"


__all__ = ["TokenScope"]
