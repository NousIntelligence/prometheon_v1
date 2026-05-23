"""Pytest configuration for unit tests.

Unit tests are fast, isolated, and never touch the network, the filesystem
(beyond temporary directories), or a real Bittensor chain. Fixtures specific
to unit testing live in this module.
"""

from __future__ import annotations
