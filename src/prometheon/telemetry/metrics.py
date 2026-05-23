"""In-process Prometheus-style metrics for the validator runtime.

A minimal counter / gauge implementation that can later be exported via
an HTTP endpoint (out of scope for this module). Keeping it dependency
free means the validator runtime does not pull in ``prometheus_client``
during normal operation; operators who want Prometheus scraping can
register a small adapter that walks :data:`REGISTRY` and renders it in
the exposition format.

Why hand-rolled rather than ``prometheus_client``:

- We want zero new runtime dependencies for the validator-only paths.
- The handful of metrics we actually track are integer counters with
  small label cardinality; the full client library is overkill.
- Tests must remain deterministic; the upstream client's default
  registry leaks state across tests.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import Lock

_LABEL_PAIR_SEPARATOR = ","


@dataclass
class Counter:
    """Monotonically increasing integer metric."""

    name: str
    description: str
    _values: dict[str, int] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def inc(self, amount: int = 1, labels: Mapping[str, str] | None = None) -> None:
        if amount < 0:
            raise ValueError(f"counter increment must be non-negative, got {amount}")
        key = _label_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0) + amount

    def value(self, labels: Mapping[str, str] | None = None) -> int:
        return self._values.get(_label_key(labels), 0)


@dataclass
class Gauge:
    """Integer metric that can move up or down."""

    name: str
    description: str
    _values: dict[str, int] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def set(self, value: int, labels: Mapping[str, str] | None = None) -> None:
        key = _label_key(labels)
        with self._lock:
            self._values[key] = value

    def value(self, labels: Mapping[str, str] | None = None) -> int:
        return self._values.get(_label_key(labels), 0)


def _label_key(labels: Mapping[str, str] | None) -> str:
    if not labels:
        return ""
    return _LABEL_PAIR_SEPARATOR.join(f"{k}={v}" for k, v in sorted(labels.items()))


# Module-level registry of metrics the validator publishes. A future PR
# will add the HTTP exporter that walks this dict.
REGISTRY: dict[str, Counter | Gauge] = {}


def counter(name: str, description: str) -> Counter:
    """Create and register a counter, idempotent on duplicate names."""
    existing = REGISTRY.get(name)
    if isinstance(existing, Counter):
        return existing
    if existing is not None:
        raise ValueError(f"metric {name!r} already registered as {type(existing).__name__}")
    c = Counter(name=name, description=description)
    REGISTRY[name] = c
    return c


def gauge(name: str, description: str) -> Gauge:
    """Create and register a gauge, idempotent on duplicate names."""
    existing = REGISTRY.get(name)
    if isinstance(existing, Gauge):
        return existing
    if existing is not None:
        raise ValueError(f"metric {name!r} already registered as {type(existing).__name__}")
    g = Gauge(name=name, description=description)
    REGISTRY[name] = g
    return g


# Pre-declared metrics the runner uses. Importing this module from the
# runner is enough to register them.
CYCLES_TOTAL = counter("prometheon_cycles_total", "Total validator cycles attempted.")
CYCLES_SUBMITTED = counter(
    "prometheon_cycles_submitted_total",
    "Cycles that produced a successful set_weights submission.",
)
CYCLES_FAILED = counter(
    "prometheon_cycles_failed_total",
    "Cycles that terminated with an error before submission.",
)

__all__ = [
    "CYCLES_FAILED",
    "CYCLES_SUBMITTED",
    "CYCLES_TOTAL",
    "REGISTRY",
    "Counter",
    "Gauge",
    "counter",
    "gauge",
]
