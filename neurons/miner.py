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
    """Print miner status guidance, or forward arguments to the CLI.

    Bare invocation keeps the informational view: a Phase 1 miner runs no
    daemon, so there is nothing here to keep running.

    Arguments are forwarded to ``prometheon`` rather than ignored. This
    entry point used to drop them silently and exit 0, so
    ``python neurons/miner.py verify-miner --username …`` printed status
    and reported success while doing nothing at all — the worst possible
    outcome for the one command a miner actually needs to work.
    """
    if len(sys.argv) > 1:
        from prometheon.cli.main import main

        sys.argv = ["prometheon", *sys.argv[1:]]
        main()
        return 0

    print_status(stream=sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
