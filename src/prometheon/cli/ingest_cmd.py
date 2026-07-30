"""``prometheon ingest`` — event-stream operator commands.

Six sub-commands cover the validator side of Decentralized Validation:

- ``register-endpoint`` — one-time (per URL) registration of the public
  HTTPS ingest endpoint with the platform (long-lived token carrying
  ``ingest:register``).
- ``serve`` — run the ingest push service against the validator TOML
  config (environment binding + trusted snapshot keys are reused as the
  publisher-key registry, per the shared key system) and a local SQLite
  event store.
- ``backfill`` — pull missing records from the read API after a gap,
  outage, or late join, appending through the same store primitive the
  push path uses.
- ``check-day`` — verify local completeness for an epoch against the
  platform's signed day digests; exit 3 is the completeness alarm.
- ``score`` — recompute miner records for a scoring date from the local
  store, optionally diffing against a snapshot-derived record list for
  shadow-mode parity evidence.
- ``submit-parity`` — send one closed epoch's per-user daily scores to the
  platform's advisory parity endpoint (and poll its verdict).

``backfill`` and ``check-day`` are the operator's half of the catch-up and
completeness machinery: nothing schedules them yet, so they are run by
hand (or from cron) until the automation glue lands.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import click
import httpx

from prometheon.cli._common import echo_info, echo_success, read_api_token_or_exit
from prometheon.events.backfill import (
    BackfillClient,
    BackfillConfig,
    BackfillError,
    BackfillRangeUnavailableError,
    DigestNotFoundError,
    DigestNotSealedError,
    DigestVerificationError,
)
from prometheon.events.ingest import IngestConfig, create_ingest_app
from prometheon.events.parity import ParityReportError, submit_parity_report
from prometheon.events.pipeline import (
    MissingVerdictsError,
    build_parity_report,
    diff_miner_records,
    score_event_stream,
)
from prometheon.events.records import EventFamily
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
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validator TOML config (supplies base URL + the environment binding).",
)
@click.option(
    "--platform-base-url",
    default=None,
    help="Override the platform base URL from the config.",
)
@click.option("--api-token", default=None, help="Long-lived validator token (overrides env var).")
@click.option(
    "--api-token-env",
    default="PROMETHEON_VALIDATOR_API_TOKEN",
    show_default=True,
    help="Environment variable holding the token (scope ingest:register).",
)
def register_endpoint(
    ingest_url: str,
    config_path: Path,
    platform_base_url: str | None,
    api_token: str | None,
    api_token_env: str,
) -> None:
    """Register (or rotate to) this validator's public ingest URL.

    The registration call carries the same environment-binding headers as
    every other authenticated platform call; the validator config supplies
    ``chain_network`` and ``platform_instance_id`` (and the base URL,
    unless overridden).
    """
    config = load_validator_config(config_path)
    base_url = platform_base_url or config.platform.base_url
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)
    echo_info(
        f"registering ingest endpoint {ingest_url} "
        f"(env={config.platform.platform_instance_id}/{config.chain.network.value})"
    )
    try:
        with httpx.Client(timeout=30.0) as http:
            result = register_ingest_endpoint(
                base_url=base_url,
                api_token=token,
                ingest_endpoint_url=ingest_url,
                chain_network=config.chain.network.value,
                platform_instance_id=config.platform.platform_instance_id,
                http=http,
            )
    except RegistrationError as exc:
        raise click.ClickException(str(exc)) from exc
    state = "unchanged" if result.unchanged else ("rotated" if result.rotated else "registered")
    echo_success(f"ingest endpoint {state} (endpoint_id={result.endpoint_id})")


def build_backfill_config(
    config: ValidatorConfig,
    *,
    api_token: str,
    base_url: str | None = None,
) -> BackfillConfig:
    """Derive the read-API client config from the validator TOML config.

    Same key registry and same test-key refusal as the push path — a day
    digest is signed by the same platform keys as a push batch — plus the
    environment binding the platform requires on every authenticated call.
    """
    return BackfillConfig(
        base_url=base_url or config.platform.base_url,
        api_token=api_token,
        trusted_keys=config.platform.snapshot_keys,
        chain_network=config.chain.network.value,
        platform_instance_id=config.platform.platform_instance_id,
        allow_test_publisher_key=config.chain.network.value == "local",
    )


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


def _families(selected: tuple[str, ...]) -> list[EventFamily]:
    """Requested families, or all four in a stable order when unset."""
    if not selected:
        return list(EventFamily)
    return [EventFamily(name) for name in selected]


@ingest.command(name="backfill")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validator TOML config (base URL, environment binding, trusted keys).",
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
    "--family",
    "selected_families",
    multiple=True,
    type=click.Choice([family.value for family in EventFamily]),
    help="Family to catch up (repeatable; default all four).",
)
@click.option("--api-token", default=None, help="Validator token (overrides env var).")
@click.option(
    "--api-token-env",
    default="PROMETHEON_VALIDATOR_API_TOKEN",
    show_default=True,
    help="Environment variable holding the token (scope events:read).",
)
@click.option(
    "--platform-base-url",
    default=None,
    help="Override the platform base URL from the config.",
)
def backfill(
    config_path: Path,
    db_path: Path,
    selected_families: tuple[str, ...],
    api_token: str | None,
    api_token_env: str,
    platform_base_url: str | None,
) -> None:
    """Pull missing records from the read API until caught up.

    Run this after a rejected gap (``409 {"code": "gap"}`` in the service
    log), after an outage, or when joining an already-running stream. Each
    page is validated and appended through the same store primitive the
    push path uses, so backfilled and pushed records are byte-identical.
    """
    config = load_validator_config(config_path)
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)
    backfill_config = build_backfill_config(config, api_token=token, base_url=platform_base_url)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    with httpx.Client(timeout=60.0) as http:
        client = BackfillClient(backfill_config, http)
        with EventStore(db_path) as store:
            for family in _families(selected_families):
                before = store.last_stored_seq(family)
                try:
                    result = client.catch_up(store, family)
                except BackfillRangeUnavailableError as exc:
                    # Contract §7.1 case (iii): those records are gone for
                    # good. Resuming past them is a deliberate decision with
                    # a permanent gap attached, so it is never taken here.
                    raise click.ClickException(
                        f"{family.value}: seq {exc.requested_from_seq} is below the platform's "
                        f"earliest retained seq"
                        + (
                            f" ({exc.earliest_available_seq})"
                            if exc.earliest_available_seq is not None
                            else ""
                        )
                        + " — those records cannot be recovered. Stop retrying and escalate; "
                        "resuming past the gap is an operator decision."
                    ) from exc
                except BackfillError as exc:
                    raise click.ClickException(f"{family.value}: {exc}") from exc
                total += result.appended
                echo_info(
                    f"{family.value}: +{result.appended} records (seq {before} → {result.last_seq})"
                )
    echo_success(f"backfill complete: {total} records added")
    # Reaching the end of the stream is not proof of having all of it: the
    # read API answers "nothing at your position" identically whether you
    # are current or the platform simply has not materialized the next
    # record. Only the signed digest settles it.
    echo_info("run 'ingest check-day' to confirm a day is complete")


@ingest.command(name="check-day")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validator TOML config (base URL, environment binding, trusted keys).",
)
@click.option(
    "--db",
    "db_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="SQLite event-store path.",
)
@click.option("--date", "epoch_id", required=True, help="Epoch to verify (YYYY-MM-DD).")
@click.option(
    "--family",
    "selected_families",
    multiple=True,
    type=click.Choice([family.value for family in EventFamily]),
    help="Family to verify (repeatable; default all four).",
)
@click.option("--api-token", default=None, help="Validator token (overrides env var).")
@click.option(
    "--api-token-env",
    default="PROMETHEON_VALIDATOR_API_TOKEN",
    show_default=True,
    help="Environment variable holding the token (scope events:read).",
)
@click.option(
    "--platform-base-url",
    default=None,
    help="Override the platform base URL from the config.",
)
def check_day(
    config_path: Path,
    db_path: Path,
    epoch_id: str,
    selected_families: tuple[str, ...],
    api_token: str | None,
    api_token_env: str,
    platform_base_url: str | None,
) -> None:
    """Verify local completeness for a day against the signed day digests.

    Verifies each family's signed digest and compares the local
    ``SHA-256`` over stored canonical bytes and the record count.

    Three outcomes, because an absent digest means two different things
    (contract §7.2). The platform seals epoch D at 00:40 UTC on D+1 with
    20 minutes' grace, so before D+1 01:00 a missing digest is
    ``digest_not_sealed`` — **exit 0, wait and re-run**. At or after the
    deadline it is ``digest_not_found``, an anomaly — **exit 3, alarm**.
    A hash or count mismatch is likewise exit 3. Only the deadline
    separates "too early" from "the proof is missing", so the check is
    safe to run from cron at 00:50 and again at 01:30.
    """
    config = load_validator_config(config_path)
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)
    backfill_config = build_backfill_config(config, api_token=token, base_url=platform_base_url)

    mismatched: list[str] = []
    with httpx.Client(timeout=60.0) as http:
        client = BackfillClient(backfill_config, http)
        with EventStore(db_path) as store:
            for family in _families(selected_families):
                try:
                    report = client.check_day(store, family, epoch_id)
                except DigestNotSealedError as exc:
                    echo_info(
                        f"{family.value} {epoch_id}: digest not sealed yet"
                        + (f" (deadline {exc.seal_deadline})" if exc.seal_deadline else "")
                        + " — re-run after the seal deadline"
                    )
                    continue
                except DigestNotFoundError as exc:
                    mismatched.append(family.value)
                    click.echo(
                        f"ALARM: {family.value} {epoch_id} has no digest past its seal "
                        f"deadline{f' ({exc.seal_deadline})' if exc.seal_deadline else ''} — "
                        "the epoch closed and its completeness proof is missing",
                        err=True,
                    )
                    continue
                except (BackfillError, DigestVerificationError) as exc:
                    raise click.ClickException(f"{family.value}: {exc}") from exc
                if report.matches:
                    echo_success(
                        f"{family.value} {epoch_id}: complete "
                        f"({report.local_record_count} records, {report.local_records_hash})"
                    )
                    continue
                mismatched.append(family.value)
                click.echo(
                    f"ALARM: {family.value} {epoch_id} incomplete — "
                    f"local {report.local_record_count} records {report.local_records_hash}, "
                    f"digest {report.digest_record_count} records {report.digest_records_hash}",
                    err=True,
                )

    if mismatched:
        raise click.exceptions.Exit(3)


@ingest.command(name="submit-parity")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validator TOML config (base URL + the environment binding).",
)
@click.option(
    "--report",
    "report_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Parity report written by 'ingest score --parity-report'.",
)
@click.option("--api-token", default=None, help="Validator token (overrides env var).")
@click.option(
    "--api-token-env",
    default="PROMETHEON_VALIDATOR_API_TOKEN",
    show_default=True,
    help="Environment variable holding the token (scope events:read).",
)
@click.option(
    "--platform-base-url",
    default=None,
    help="Override the platform base URL from the config.",
)
def submit_parity(
    config_path: Path,
    report_path: Path,
    api_token: str | None,
    api_token_env: str,
    platform_base_url: str | None,
) -> None:
    """Submit a parity report for one closed epoch, or poll its verdict.

    Advisory only: nothing submitted or returned touches scoring, weights,
    ranking, or this validator's standing. The platform's diff runs
    asynchronously, so a fresh submission comes back ``pending`` —
    re-running this command with the same file is how you poll.

    Exit 3 when the platform reports a mismatch; that is a parity incident
    for the epoch, not a failure of this command.
    """
    config = load_validator_config(config_path)
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)
    report = json.loads(report_path.read_text())
    if not isinstance(report, dict):
        raise click.ClickException(f"{report_path} does not contain a report object")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        with httpx.Client(timeout=60.0) as http:
            verdict = submit_parity_report(
                base_url=platform_base_url or config.platform.base_url,
                api_token=token,
                report=report,
                chain_network=config.chain.network.value,
                platform_instance_id=config.platform.platform_instance_id,
                http=http,
                today=today,
            )
    except ParityReportError as exc:
        raise click.ClickException(str(exc)) from exc

    echo_info(
        f"{verdict.epoch}: {verdict.scores_received} scores submitted "
        f"(report {verdict.report_id}, status {verdict.status})"
    )
    if verdict.epoch_agreement is not None:
        agreement = verdict.epoch_agreement
        echo_info(
            f"epoch agreement: {agreement.get('matched')} of {agreement.get('diffed')} diffed "
            f"({agreement.get('reports')} reports submitted)"
        )

    if verdict.is_pending:
        echo_info("verdict pending — re-run this command with the same file to poll")
        return
    if verdict.status == "no_platform_data":
        echo_info("no platform data for this epoch — nothing to compare")
        return
    if verdict.is_clean:
        echo_success(f"{verdict.epoch}: parity clean")
        return

    click.echo(f"ALARM: {verdict.epoch} parity mismatch — {verdict.verdict}", err=True)
    raise click.exceptions.Exit(3)


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
@click.option(
    "--parity-report",
    "parity_report_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the per-user daily scores for the epoch to this file.",
)
def score(
    db_path: Path,
    scoring_date: str,
    allow_missing_marker: bool,
    snapshot_json: Path | None,
    parity_report_path: Path | None,
) -> None:
    """Recompute miner records from the local stream; optionally shadow-diff.

    ``--parity-report`` writes the per-user daily scores for the epoch as
    ``{epoch, scores: [{user_ref_evt, daily_score}], scores_hash}``. Use it
    rather than pulling the numbers out of the library by hand: the file
    comes from the same code path that feeds the weights, so a parity
    comparison is measuring what the validator would actually submit.
    """
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

    if parity_report_path is not None:
        report = build_parity_report(result)
        parity_report_path.parent.mkdir(parents=True, exist_ok=True)
        parity_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        echo_info(
            f"parity report: {len(report['scores'])} users scored for {scoring_date} "
            f"({report['scores_hash'][:18]}…) → {parity_report_path}"
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


__all__ = ["build_backfill_config", "build_ingest_config", "ingest"]
