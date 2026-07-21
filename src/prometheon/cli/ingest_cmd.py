"""``prometheon ingest`` — event-stream operator commands.

Three sub-commands cover the validator side of Decentralized Validation:

- ``register-endpoint`` — one-time (per URL) registration of the public
  HTTPS ingest endpoint with the platform (long-lived token carrying
  ``ingest:register``).
- ``serve`` — run the ingest push service against the validator TOML
  config (environment binding + trusted snapshot keys are reused as the
  publisher-key registry, per the shared key system) and a local SQLite
  event store.
- ``score`` — recompute miner records for a scoring date from the local
  store, optionally diffing against a snapshot-derived record list for
  shadow-mode parity evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
import httpx

from prometheon.cli._common import echo_info, echo_success, read_api_token_or_exit
from prometheon.events.ingest import IngestConfig, create_ingest_app
from prometheon.events.pipeline import (
    MissingVerdictsError,
    diff_miner_records,
    score_event_stream,
)
from prometheon.events.registration import RegistrationError, register_ingest_endpoint
from prometheon.events.store import EventStore
from prometheon.mechanisms.phase1_growth.snapshot import MinerRecord
from prometheon.validator.config import ValidatorConfig, load_validator_config

DEFAULT_EVENTS_DB = Path(".validator-state/events.sqlite")


@click.group(name="ingest")
def ingest() -> None:
    """Event-stream (Decentralized Validation) commands."""


@ingest.command(name="register-endpoint")
@click.option(
    "--ingest-url", required=True, help="Public HTTPS URL of this validator's ingest endpoint."
)
@click.option("--platform-base-url", required=True, help="BitFan platform base URL.")
@click.option("--api-token", default=None, help="Long-lived validator token (overrides env var).")
@click.option(
    "--api-token-env",
    default="PROMETHEON_VALIDATOR_API_TOKEN",
    show_default=True,
    help="Environment variable holding the token (scope ingest:register).",
)
def register_endpoint(
    ingest_url: str,
    platform_base_url: str,
    api_token: str | None,
    api_token_env: str,
) -> None:
    """Register (or rotate to) this validator's public ingest URL."""
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)
    echo_info(f"registering ingest endpoint {ingest_url}")
    try:
        with httpx.Client(timeout=30.0) as http:
            result = register_ingest_endpoint(
                base_url=platform_base_url,
                api_token=token,
                ingest_endpoint_url=ingest_url,
                http=http,
            )
    except RegistrationError as exc:
        raise click.ClickException(str(exc)) from exc
    state = "unchanged" if result.unchanged else ("rotated" if result.rotated else "registered")
    echo_success(f"ingest endpoint {state} (endpoint_id={result.endpoint_id})")


def build_ingest_config(config: ValidatorConfig) -> IngestConfig:
    """Derive the ingest pipeline config from the validator TOML config.

    The trusted publisher keys ARE the snapshot signing keys — the platform
    uses one Ed25519 key registry for both. The publicly-derivable test
    key is only ever accepted on the local development network.
    """
    return IngestConfig(
        platform_instance_id=config.platform.platform_instance_id,
        chain_network=config.chain.network.value,
        trusted_keys=config.platform.snapshot_keys,
        allow_test_publisher_key=config.chain.network.value == "local",
    )


@ingest.command(name="serve")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validator TOML config (environment binding + trusted keys).",
)
@click.option(
    "--db",
    "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=DEFAULT_EVENTS_DB,
    show_default=True,
    help="SQLite event-store path.",
)
@click.option(
    "--host", default="127.0.0.1", show_default=True, help="Bind address (front with TLS)."
)
@click.option("--port", default=8541, show_default=True, type=int, help="Bind port.")
def serve(config_path: Path, db_path: Path, host: str, port: int) -> None:
    """Run the ingest push service (front with a TLS reverse proxy)."""
    import uvicorn

    config = load_validator_config(config_path)
    ingest_config = build_ingest_config(config)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = EventStore(db_path)
    app = create_ingest_app(store, ingest_config)
    echo_info(
        f"ingest service on {host}:{port} "
        f"(env={ingest_config.platform_instance_id}/{ingest_config.chain_network}, db={db_path})"
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


@ingest.command(name="score")
@click.option(
    "--db",
    "db_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="SQLite event-store path.",
)
@click.option("--date", "scoring_date", required=True, help="Scoring epoch (YYYY-MM-DD).")
@click.option(
    "--allow-missing-marker",
    is_flag=True,
    help="Score without the day's verdicts after the 2h grace period (alarms).",
)
@click.option(
    "--snapshot-json",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Snapshot-derived miner records (JSON list) to shadow-diff against.",
)
def score(
    db_path: Path,
    scoring_date: str,
    allow_missing_marker: bool,
    snapshot_json: Path | None,
) -> None:
    """Recompute miner records from the local stream; optionally shadow-diff."""
    with EventStore(db_path) as store:
        try:
            result = score_event_stream(
                store,
                scoring_date=scoring_date,
                allow_missing_marker=allow_missing_marker,
            )
        except MissingVerdictsError as exc:
            raise click.ClickException(str(exc)) from exc

    if result.marker_missing:
        click.echo(
            f"ALARM: scored without verdicts_complete({scoring_date}) — "
            "weights for this epoch use full default weights",
            err=True,
        )
    for epoch, (held, expected) in sorted(result.verdict_count_mismatch.items()):
        click.echo(
            f"ALARM: verdict count mismatch for {epoch}: held={held} marker={expected}",
            err=True,
        )
    for verdict in result.excluded_signature_verdicts:
        click.echo(
            f"ALARM: injection evidence at seq {verdict.seq} ({verdict.signature_status.value})",
            err=True,
        )

    click.echo(
        json.dumps(
            [record.model_dump() for record in result.miner_records],
            indent=2,
            sort_keys=True,
        )
    )

    if snapshot_json is not None:
        raw = json.loads(snapshot_json.read_text())
        snapshot_records = [MinerRecord.model_validate(item) for item in raw]
        diff = diff_miner_records(snapshot_records, result.miner_records)
        for line in diff.report_lines():
            click.echo(line, err=not diff.matches)
        if not diff.matches:
            raise click.exceptions.Exit(3)


__all__ = ["build_ingest_config", "ingest"]
