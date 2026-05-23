"""Structured logging, metrics, and health endpoints.

Telemetry is consumed by every other module. The conventions enforced here:

- A single structured logger configuration (``structlog``-backed).
- A redaction filter that strips API tokens, raw signatures, raw email
  addresses, raw Discord handles, wallet seeds, mnemonics, private keys, and
  any other credential material before serialization.
- Lightweight Prometheus-compatible metric helpers for the validator runner.
- A minimal HTTP health endpoint for orchestrator probes.

No module logs raw credentials. Use the helpers in ``telemetry.logging`` for
anything written to stdout, stderr, or files.
"""
