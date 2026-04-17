"""Bittensor-convention validator entrypoint for Prometheon Phase 1.

This thin shim exists to support the canonical Bittensor invocation pattern:

    python neurons/validator.py [args...]

Both this entrypoint and the unified CLI (``prometheon validator run``) reach
the same runner under ``prometheon.validator.runner``. The CLI is the
preferred surface for new operators; this file is provided for compatibility
with existing Bittensor tooling and deployment conventions.

At the scaffold stage the runner is not yet wired. Running this file prints
package status and exits cleanly so the entrypoint is discoverable but cannot
do harm.
"""

from __future__ import annotations

import sys

from prometheon import __version__


def main() -> int:
    """Print package status and exit.

    Returns ``0`` on success. Once the validator runner is wired (see
    ``prometheon.validator.runner``), this function will instead parse the
    Bittensor-style CLI arguments and start the runtime loop.
    """
    sys.stdout.write(
        f"Prometheon Phase 1 — validator entrypoint (package version {__version__}).\n"
        "The runtime loop is not yet wired in this scaffold. "
        "Use 'prometheon validator run --config <path>' once the runner module lands.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
