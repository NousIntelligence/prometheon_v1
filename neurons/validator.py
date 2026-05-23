"""Bittensor-convention validator entrypoint for Prometheon Phase 1.

This shim exists to support the canonical Bittensor invocation pattern:

    python neurons/validator.py [args...]

It delegates to ``prometheon validator run``, which is the same code path
the unified CLI executes. Both invocations reach the identical
:class:`prometheon.validator.runner.ValidatorRunner`; the choice between
``python neurons/validator.py`` and ``prometheon validator run`` is
purely operational preference.
"""

from __future__ import annotations

import sys

from prometheon.cli.main import main


def _main() -> int:
    """Forward arguments to ``prometheon validator run``.

    The Bittensor convention is to expose ``python neurons/validator.py``
    as the validator's executable; ``--config <path>`` is the only
    required argument the runner needs from the operator.
    """
    sys.argv = ["prometheon", "validator", "run", *sys.argv[1:]]
    try:
        main()
    except SystemExit as exit_signal:
        return int(exit_signal.code or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
