"""Bittensor-convention miner entrypoint for Prometheon Phase 1.

Phase 1 miners do not submit subnet-side work. The reward path is real
growth of a BitFan Fan Group, which happens off-chain. This entrypoint
exists for compatibility with Bittensor's neuron convention and to
surface miner-side status diagnostics.

Acceptable responsibilities for this entrypoint:

1. Print miner verification status if a wallet is configured.
2. Print linked platform account status if an API token is configured.
3. Print Fan Group setup guidance.

Unacceptable responsibilities:

1. Submitting work to validators.
2. Accepting validator scoring requests.
3. Mutating platform scores.
"""

from __future__ import annotations

import sys

from prometheon.miner.status import print_status


def _main() -> int:
    """Print miner status guidance and exit cleanly.

    Future Phase-1 enhancements may layer richer status checks against
    the platform (e.g. fetch the linked account's current
    ``miner_verified`` flag), but Phase 1 ships only the local
    informational view.
    """
    print_status(stream=sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
