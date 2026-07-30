"""Unit tests for ``prometheon ingest`` — the read-API operator commands.

``backfill`` and ``check-day`` are the operator's entry points into the
catch-up and day-digest machinery; before they existed, the classes were
unreachable from any shipped command and the completeness gate could only
be exercised by hand. These tests drive both commands through Click with a
mocked read API whose responses use the platform's real envelope and whose
handler asserts the environment-binding headers.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.cli.ingest_cmd import build_backfill_config, ingest
from prometheon.events.records import EventFamily, record_canonical_bytes
from prometheon.events.store import EventStore
from prometheon.platform.wire import CHAIN_NETWORK_HEADER, PLATFORM_INSTANCE_ID_HEADER
from prometheon.security.canonical import DOMAIN_DAY_DIGEST, to_canonical_bytes
from prometheon.validator.config import load_validator_config

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "decentralized-validation"
BATCH: dict[str, Any] = json.loads(
    (FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json").read_text()
)
DIGEST_ENV: dict[str, Any] = json.loads(
    (FIXTURES / "event-record" / "03-day-digest" / "envelope.json").read_text()
)
KEY_INFO: dict[str, Any] = json.loads(
    (FIXTURES / "test-keys" / "ed25519-platform.json").read_text()
)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY_INFO["private_key_base64"]))

TOKEN_ENV = "PROMETHEON_TEST_INGEST_TOKEN"

# chain.network = "local" so the derivable fixture publisher key is accepted;
# on any other network build_backfill_config refuses it, which a test below pins.
LOCAL_CONFIG = f"""\
[chain]
network = "local"
netuid = 1
version_key = 0
fail_on_weights_version_mismatch = false
allow_legacy_sdk_without_mechid = false

[wallet]
name = "validator"
hotkey = "default"

[platform]
base_url = "http://read.test"
platform_instance_id = "bitfan-local"
api_token_env = "{TOKEN_ENV}"
request_timeout_seconds = 30

[platform.snapshot_keys."{KEY_INFO["key_id"]}"]
public_key = "{KEY_INFO["public_key_hex"]}"
not_before = "2026-01-01T00:00:00Z"
not_after  = "2027-01-01T00:00:00Z"
status     = "active"

[validator]
mode = "aggregate"
activity_date = "latest"
submit_weights = true
dry_run = false

[phase1]
mechanism = "phase1_growth"
mechid = 0
daily_score_cap = 20
active_member_score_threshold = 50
min_active_members_for_reward = 3
top_k = 10
weight_units = 1_000_000_000

[burn]
enabled = true
burn_hotkey = "5DPLACEHOLDERburnHotkeyForLocalnetDevelopmentOnlyXXXXXXXXX"
manual_burn_rate_ppm = 0

[scheduler]
snapshot_refresh_interval_minutes = 5
metagraph_refresh_interval_minutes = 2
weight_submission_check_interval_minutes = 3

[logging]
level = "DEBUG"
"""


def _config_file(tmp_path: Path, *, network: str = "local") -> Path:
    body = LOCAL_CONFIG
    if network != "local":
        body = body.replace('network = "local"', f'network = "{network}"').replace(
            'platform_instance_id = "bitfan-local"', 'platform_instance_id = "bitfan-staging"'
        )
    target = tmp_path / f"validator-{network}.toml"
    target.write_text(body, encoding="utf-8")
    return target


def _ok(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": payload, "meta": {}})


def _entries() -> list[dict[str, Any]]:
    return [
        {
            "seq": record["seq"],
            "event_id": record["event_id"],
            "canonical_bytes": "0x" + record_canonical_bytes(record).hex(),
        }
        for record in BATCH["envelope"]["records"]
    ]


def _signed_digest(envelope: dict[str, Any]) -> dict[str, Any]:
    message = DOMAIN_DAY_DIGEST.encode("ascii") + b"\n" + to_canonical_bytes(envelope)
    return {
        "family": envelope["family"],
        "epoch_id": envelope["epoch_id"],
        "records_hash": envelope["records_hash"],
        "record_count": envelope["record_count"],
        "signature": "0x" + PRIVATE_KEY.sign(message).hex(),
        "platform_key_id": KEY_INFO["key_id"],
        "signed_at": "2026-07-15T00:40:00Z",
    }


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Replace the command's httpx.Client with one on a mock transport.

    ``real_client`` is captured before patching: the command reaches the
    class through the httpx module, so the factory must not look it up
    again or it would call itself.
    """
    real_client = httpx.Client

    def factory(*_args: Any, **_kwargs: Any) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "Client", factory)


def _assert_wire(request: httpx.Request, instance_id: str = "bitfan-local") -> None:
    assert request.headers["Authorization"] == "Bearer cli-token"
    assert request.headers[CHAIN_NETWORK_HEADER] == "local"
    assert request.headers[PLATFORM_INSTANCE_ID_HEADER] == instance_id


class TestBuildBackfillConfig:
    def test_carries_binding_keys_and_base_url(self, tmp_path: Path) -> None:
        config = load_validator_config(_config_file(tmp_path, network="test"))
        built = build_backfill_config(config, api_token="tok")

        assert built.chain_network == "test"
        assert built.platform_instance_id == "bitfan-staging"
        assert built.base_url == "http://read.test"
        assert built.trusted_keys == config.platform.snapshot_keys
        # The derivable test key must never be trusted off the local network.
        assert built.allow_test_publisher_key is False

    def test_allows_the_test_key_only_on_local(self, tmp_path: Path) -> None:
        config = load_validator_config(_config_file(tmp_path))
        assert build_backfill_config(config, api_token="tok").allow_test_publisher_key is True

    def test_base_url_override_wins(self, tmp_path: Path) -> None:
        config = load_validator_config(_config_file(tmp_path))
        built = build_backfill_config(config, api_token="tok", base_url="https://other.test")
        assert built.base_url == "https://other.test"


class TestBackfillCommand:
    def test_appends_records_and_reports_progress(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entries = _entries()
        first_seq = BATCH["envelope"]["from_seq"]

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            requested = int(request.url.params["from_seq"])
            family = request.url.params["family"]
            page = [e for e in entries if e["seq"] >= requested] if family == "activity" else []
            return _ok(
                {
                    "family": family,
                    "from_seq": requested,
                    "records": page,
                    "next_seq": requested + len(page),
                }
            )

        _install_transport(monkeypatch, handler)
        monkeypatch.setenv(TOKEN_ENV, "cli-token")
        db = tmp_path / "events.sqlite"
        with EventStore(db) as store:
            store._connection.execute(
                "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
                (EventFamily.ACTIVITY.value, first_seq - 1),
            )
            store._connection.commit()

        result = CliRunner().invoke(
            ingest,
            [
                "backfill",
                "--config",
                str(_config_file(tmp_path)),
                "--db",
                str(db),
                "--api-token-env",
                TOKEN_ENV,
            ],
        )

        assert result.exit_code == 0, result.output
        assert f"activity: +{len(entries)} records" in result.output
        assert "identity: +0 records" in result.output
        with EventStore(db) as store:
            assert store.last_stored_seq(EventFamily.ACTIVITY) == BATCH["envelope"]["to_seq"]

    def test_platform_error_code_reaches_the_operator(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The failure that blocked staging must name itself, not just 400."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400,
                json={
                    "success": False,
                    "error": {
                        "code": "ENVIRONMENT_MISMATCH",
                        "message": "Missing chain_network / platform_instance_id binding.",
                    },
                },
            )

        _install_transport(monkeypatch, handler)
        monkeypatch.setenv(TOKEN_ENV, "cli-token")

        result = CliRunner().invoke(
            ingest,
            [
                "backfill",
                "--config",
                str(_config_file(tmp_path)),
                "--db",
                str(tmp_path / "events.sqlite"),
                "--family",
                "group",
                "--api-token-env",
                TOKEN_ENV,
            ],
        )

        assert result.exit_code != 0
        assert "ENVIRONMENT_MISMATCH" in result.output


class TestCheckDayCommand:
    def test_reports_complete_day(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        entries = _entries()
        digest = _signed_digest(DIGEST_ENV)

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            if request.url.path.endswith("/backfill"):
                requested = int(request.url.params["from_seq"])
                family = request.url.params["family"]
                page = [e for e in entries if e["seq"] >= requested] if family == "activity" else []
                return _ok(
                    {
                        "family": family,
                        "from_seq": requested,
                        "records": page,
                        "next_seq": requested + len(page),
                    }
                )
            return _ok(digest)

        _install_transport(monkeypatch, handler)
        monkeypatch.setenv(TOKEN_ENV, "cli-token")
        db = tmp_path / "events.sqlite"
        with EventStore(db) as store:
            store._connection.execute(
                "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
                (EventFamily.ACTIVITY.value, BATCH["envelope"]["from_seq"] - 1),
            )
            store._connection.commit()

        config_path = str(_config_file(tmp_path))
        backfilled = CliRunner().invoke(
            ingest,
            ["backfill", "--config", config_path, "--db", str(db), "--api-token-env", TOKEN_ENV],
        )
        assert backfilled.exit_code == 0, backfilled.output

        result = CliRunner().invoke(
            ingest,
            [
                "check-day",
                "--config",
                config_path,
                "--db",
                str(db),
                "--date",
                DIGEST_ENV["epoch_id"],
                "--family",
                "activity",
                "--api-token-env",
                TOKEN_ENV,
            ],
        )

        assert result.exit_code == 0, result.output
        assert "complete" in result.output
        assert DIGEST_ENV["records_hash"] in result.output

    def test_mismatch_alarms_and_exits_three(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        digest = _signed_digest(DIGEST_ENV)

        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(digest)

        _install_transport(monkeypatch, handler)
        monkeypatch.setenv(TOKEN_ENV, "cli-token")
        db = tmp_path / "events.sqlite"
        with EventStore(db):
            pass  # empty store: the day is provably incomplete

        result = CliRunner().invoke(
            ingest,
            [
                "check-day",
                "--config",
                str(_config_file(tmp_path)),
                "--db",
                str(db),
                "--date",
                DIGEST_ENV["epoch_id"],
                "--family",
                "activity",
                "--api-token-env",
                TOKEN_ENV,
            ],
        )

        assert result.exit_code == 3, result.output
        assert "ALARM" in result.output
        assert "incomplete" in result.output


class TestScoreParityReport:
    """The parity artifact must come from the shipped command, not by hand."""

    def _store_with_one_login(self, tmp_path: Path) -> Path:
        from tests.unit.events.test_pipeline import SCORING_DATE, _populate

        db = tmp_path / "score.sqlite"
        with EventStore(db) as store:
            _populate(store, activity_kind="login")
        self.scoring_date = SCORING_DATE
        return db

    def test_writes_per_user_daily_scores(self, tmp_path: Path) -> None:
        db = self._store_with_one_login(tmp_path)
        report_path = tmp_path / "reports" / "parity.json"

        result = CliRunner().invoke(
            ingest,
            [
                "score",
                "--db",
                str(db),
                "--date",
                self.scoring_date,
                "--parity-report",
                str(report_path),
            ],
        )

        assert result.exit_code == 0, result.output
        report = json.loads(report_path.read_text())
        assert report["epoch"] == self.scoring_date
        # One login is one point — the value a hand-rolled extraction got wrong.
        assert [row["daily_score"] for row in report["scores"]] == [1]
        assert report["scores_hash"].startswith("0x")
        assert "1 users scored" in result.output

    def test_report_is_optional(self, tmp_path: Path) -> None:
        db = self._store_with_one_login(tmp_path)
        result = CliRunner().invoke(ingest, ["score", "--db", str(db), "--date", self.scoring_date])
        assert result.exit_code == 0, result.output
        assert "parity report" not in result.output
        # stdout stays the miner-record list any existing script already parses.
        assert isinstance(json.loads(result.output), list)


class TestCheckDayDigestAvailability:
    """§7.2 — 'not sealed yet' and 'proof missing' are different outcomes."""

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str) -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return httpx.Response(
                404,
                json={
                    "success": False,
                    "error": {
                        "code": code,
                        "message": "…",
                        "details": {"seal_deadline": "2026-07-15T01:00:00Z"},
                    },
                },
            )

        _install_transport(monkeypatch, handler)
        monkeypatch.setenv(TOKEN_ENV, "cli-token")
        db = tmp_path / "events.sqlite"
        EventStore(db).close()
        return CliRunner().invoke(
            ingest,
            [
                "check-day",
                "--config",
                str(_config_file(tmp_path)),
                "--db",
                str(db),
                "--date",
                "2026-07-14",
                "--family",
                "activity",
                "--api-token-env",
                TOKEN_ENV,
            ],
        )

    def test_not_sealed_waits_without_alarming(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._invoke(tmp_path, monkeypatch, "digest_not_sealed")
        assert result.exit_code == 0, result.output
        assert "not sealed yet" in result.output
        assert "ALARM" not in result.output

    def test_not_found_past_the_deadline_alarms(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._invoke(tmp_path, monkeypatch, "digest_not_found")
        assert result.exit_code == 3, result.output
        assert "ALARM" in result.output
        assert "completeness proof is missing" in result.output


class TestSubmitParityCommand:
    def _report_file(self, tmp_path: Path, epoch: str = "2026-07-29") -> Path:
        from prometheon.events.parity import scores_hash

        rows = [{"user_ref_evt": "usr_evt_" + "a" * 64, "daily_score": 1}]
        path = tmp_path / "parity.json"
        path.write_text(
            json.dumps({"epoch": epoch, "scores": rows, "scores_hash": scores_hash(epoch, rows)})
        )
        return path

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        def handler(request: httpx.Request) -> httpx.Response:
            _assert_wire(request)
            return _ok(payload)

        _install_transport(monkeypatch, handler)
        monkeypatch.setenv(TOKEN_ENV, "cli-token")
        return CliRunner().invoke(
            ingest,
            [
                "submit-parity",
                "--config",
                str(_config_file(tmp_path)),
                "--report",
                str(self._report_file(tmp_path)),
                "--api-token-env",
                TOKEN_ENV,
            ],
        )

    def test_pending_submission_tells_you_to_poll(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._invoke(
            tmp_path,
            monkeypatch,
            {
                "advisory_only": True,
                "report_id": "r-1",
                "epoch": "2026-07-29",
                "scores_received": 1,
                "status": "pending",
                "epoch_agreement": {"reports": 1, "diffed": 0, "matched": 0},
            },
        )
        assert result.exit_code == 0, result.output
        assert "re-run this command" in result.output

    def test_mismatch_exits_three(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._invoke(
            tmp_path,
            monkeypatch,
            {
                "advisory_only": True,
                "report_id": "r-1",
                "epoch": "2026-07-29",
                "scores_received": 1,
                "status": "mismatch",
                "verdict": {
                    "agreed_count": 0,
                    "score_mismatches": 1,
                    "platform_only": 0,
                    "report_only": 0,
                },
            },
        )
        assert result.exit_code == 3, result.output
        assert "ALARM" in result.output

    def test_clean_match_reports_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._invoke(
            tmp_path,
            monkeypatch,
            {
                "advisory_only": True,
                "report_id": "r-1",
                "epoch": "2026-07-29",
                "scores_received": 1,
                "status": "match",
                "verdict": {
                    "agreed_count": 1,
                    "score_mismatches": 0,
                    "platform_only": 0,
                    "report_only": 0,
                },
            },
        )
        assert result.exit_code == 0, result.output
        assert "parity clean" in result.output
