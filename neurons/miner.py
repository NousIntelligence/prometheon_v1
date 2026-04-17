"""Bittensor-convention miner entrypoint for Prometheon Phase 1.

Phase 1 miners do not submit subnet-side work. The reward path is real growth
of a BitFan Fan Group, which happens off-chain. This entrypoint exists for
compatibility with Bittensor's neuron convention and to expose miner status.

Acceptable responsibilities for this entrypoint:

1. Print miner verification status if a wallet is configured.
2. Print linked platform account status if an API token is configured.
3. Print Fan Group setup guidance.
4. Exit cleanly with a clear message if the operator expects on-chain reward
   without platform verification.

Unacceptable responsibilities:

1. Submitting work to validators.
2. Accepting validator scoring requests.
3. Mutating platform scores.

At the scaffold stage the status helpers are not yet wired. Running this file
prints package status and exits cleanly.
"""

from __future__ import annotations

import sys

from prometheon import __version__


def main() -> int:
    """Print miner entrypoint status and exit.

    Once the miner status helpers are wired (see ``prometheon.miner.status``),
    this function will print verification state, linked platform account, and
    setup guidance.
    """
    sys.stdout.write(
        f"Prometheon Phase 1 — miner entrypoint (package version {__version__}).\n"
        "Phase 1 does not require a running miner daemon. "
        "Run 'prometheon verify-miner ...' to verify your BitFan account, then operate your Fan Group on BitFan.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
