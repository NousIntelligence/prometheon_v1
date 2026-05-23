"""Miner-side helpers — informational status only.

Phase 1 miners do not submit subnet-side work. After verification, the miner
operates a BitFan Fan Group off-chain, and rewards flow from scored platform
activity rather than from a miner daemon.

This module provides:

- Local status reporting (verification state, linked hotkey, account).
- Lightweight configuration helpers for ``neurons/miner.py``.

The miner module does not handle work submissions or accept validator requests.
"""
