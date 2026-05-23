"""Pytest configuration for contract tests.

Contract tests validate that the byte-level shapes and signatures produced by
this implementation match the shared fixture suite agreed with the BitFan
platform team. The shared fixtures live under ``tests/fixtures/`` and are
deliberately stable; any change to them is a contract change and requires
coordination with the platform team.
"""

from __future__ import annotations
