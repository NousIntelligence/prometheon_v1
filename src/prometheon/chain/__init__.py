"""Bittensor chain integration: wallet, subtensor, metagraph, UID resolution,
and weight submission.

The chain module owns every interaction with the Bittensor SDK and the
underlying substrate. It exposes:

- Wallet loading from local keypair files (``bittensor_wallet`` based).
- A subtensor connection wrapper with timeout and retry handling.
- A throttled metagraph view that caches sync results for short windows.
- Hotkey-to-UID resolution against the *current* metagraph.
- The weight submission adapter, including:

  * second largest-remainder allocation from internal 1_000_000_000-unit
    weights to the chain u16 boundary,
  * ``mechid=0`` injection where the installed SDK supports it,
  * commit-reveal detection with fail-closed behaviour,
  * weights-version mismatch policy.

The mechanism engine never imports anything from this module. Chain access is
restricted to the validator runtime and the CLI.
"""
