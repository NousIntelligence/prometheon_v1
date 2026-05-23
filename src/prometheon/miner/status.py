"""Miner-side status output.

Phase 1 miners do not run a daemon — rewards depend on real BitFan Fan
Group growth, not on subnet-side work. This module prints a guidance
block when the operator runs ``python neurons/miner.py`` so they see
exactly what the miner-side process is responsible for (and what it
isn't).
"""

from __future__ import annotations

from typing import TextIO

from prometheon.version import __version__

_GUIDANCE = """\
Prometheon Phase 1 — miner status
================================

This binary does not submit subnet-side work. Phase 1 miners are
rewarded for real growth of a BitFan Fan Group, which happens
entirely off-chain.

To participate as a miner you need to:

  1. Register a Bittensor hotkey on the subnet.
  2. Create a BitFan platform account and obtain an API token.
  3. Verify your identity with the platform:

         prometheon verify-miner \\
             --username <user>      \\
             --email <email>        \\
             --api-token <token>    \\
             --wallet-name <wallet> \\
             --wallet-hotkey <hotkey>

  4. Create a Fan Group on BitFan and grow active users.

Rewards flow from scored user activity in your Fan Group, not from
running this entrypoint. There is no scoring code running here, no
work queue, and nothing to keep online.

See the public documentation under ``docs/miner.md`` for the full
setup guide.
"""


def print_status(stream: TextIO) -> None:
    """Write the miner-side guidance block to ``stream``.

    The validator entrypoint has its own real implementation under
    :mod:`prometheon.validator.runner`; this miner entrypoint
    intentionally stops after printing.
    """
    stream.write(f"prometheon {__version__}\n\n")
    stream.write(_GUIDANCE)


__all__ = ["print_status"]
