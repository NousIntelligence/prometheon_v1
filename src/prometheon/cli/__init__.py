"""Command-line interface for Prometheon.

The CLI is built on Click. Top-level commands:

- ``prometheon verify-miner``     verify a BitFan account as a miner
- ``prometheon verify-validator`` verify a BitFan account as a validator
- ``prometheon rotate-hotkey``    normal hotkey rotation
- ``prometheon recover-hotkey``   coldkey or manual recovery
- ``prometheon validator run``    start the validator runtime loop
- ``prometheon status``           report local validator state

Command modules live as siblings of this file. The ``main`` entrypoint
assembles them into the root Click group.
"""
