"""Prometheon — a Bittensor subnet that converts BitFan platform-qualified
user activity into deterministic on-chain weights.

This package is the Phase 1 implementation. Future phases ship in their own
repositories (``prometheon_v2``, ``prometheon_v3``, ``prometheon_v4``) when
those phase boundaries become active.

The top-level public surface intentionally re-exports only the package version
string. Concrete functionality lives in the sub-packages:

- ``prometheon.security``      cryptographic primitives (JCS, hashing, signatures)
- ``prometheon.identity``      identity, rotation, and recovery payloads and verifiers
- ``prometheon.platform``      BitFan platform API client and snapshot verification
- ``prometheon.mechanisms``    mechanism interface and Phase 1 weight engine
- ``prometheon.chain``         Bittensor wallet, subtensor, metagraph, weight submission
- ``prometheon.validator``     validator runtime: config, scheduler, runner, state
- ``prometheon.miner``         miner-side status and configuration helpers
- ``prometheon.cli``           command-line interface (``prometheon ...``)
- ``prometheon.telemetry``     structured logging, metrics, health endpoints

See the public documentation under ``docs/`` for end-user guides.
"""

from prometheon.version import __version__

__all__ = ["__version__"]
