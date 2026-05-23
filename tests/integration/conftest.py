"""Pytest configuration for integration tests.

Integration tests run the validator runner end-to-end against a mock BitFan
platform and a mock Bittensor chain. They exercise the full snapshot
download, verification, mechanism execution, UID resolution, u16 conversion,
and submission path — but with deterministic, in-process stand-ins for the
external services.

Real-chain tests live under ``tests/localnet/`` and are gated by the
``localnet`` marker (declared in ``pyproject.toml``).
"""

from __future__ import annotations
