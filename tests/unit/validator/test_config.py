"""Unit tests for ``prometheon.validator.config``."""

from __future__ import annotations

from pathlib import Path

import pytest

from prometheon.identity.roles import ChainNetwork
from prometheon.platform.endpoints import SnapshotMode
from prometheon.validator.config import (
    ConfigError,
    ValidatorConfig,
    load_validator_config,
)

pytestmark = pytest.mark.unit


VALID_FINNEY_CONFIG = """\
[chain]
network = "finney"
netuid = 123
version_key = 0
fail_on_weights_version_mismatch = true
allow_legacy_sdk_without_mechid = false

[wallet]
name = "validator"
hotkey = "default"

[platform]
base_url = "https://api.bitfan.example"
platform_instance_id = "bitfan-production"
api_token_env = "PROMETHEON_VALIDATOR_API_TOKEN"
request_timeout_seconds = 30.0

[platform.snapshot_keys."platform-main-2026-05"]
public_key = "0x1111111111111111111111111111111111111111111111111111111111111111"
not_before = "2026-05-01T00:00:00Z"
not_after  = "2026-09-01T00:00:00Z"
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
burn_hotkey = "5DPlaceholderBurnHotkeyForTestsXXXXXXXXXXXXXXXX"
manual_burn_rate_ppm = 150000

[scheduler]
snapshot_refresh_interval_minutes = 60
metagraph_refresh_interval_minutes = 10
weight_submission_check_interval_minutes = 15

[logging]
level = "INFO"
"""


def _write(path: Path, body: str) -> Path:
    target = path / "validator.toml"
    target.write_text(body, encoding="utf-8")
    return target


class TestLoadValidatorConfig:
    def test_loads_valid_finney_config(self, tmp_path: Path) -> None:
        config = load_validator_config(_write(tmp_path, VALID_FINNEY_CONFIG))
        assert isinstance(config, ValidatorConfig)
        assert config.chain.network == ChainNetwork.FINNEY
        assert config.chain.netuid == 123
        assert config.validator.mode == SnapshotMode.AGGREGATE
        assert "platform-main-2026-05" in config.platform.snapshot_keys

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_validator_config(tmp_path / "missing.toml")

    def test_malformed_toml_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "this is not valid toml = [\n")
        with pytest.raises(ConfigError, match="could not read"):
            load_validator_config(path)

    def test_extra_top_level_field_rejected(self, tmp_path: Path) -> None:
        body = VALID_FINNEY_CONFIG + "\nrogue_field = 1\n"
        with pytest.raises(ConfigError, match="invalid validator config"):
            load_validator_config(_write(tmp_path, body))

    def test_legacy_sdk_override_rejected_on_finney(self, tmp_path: Path) -> None:
        body = VALID_FINNEY_CONFIG.replace(
            "allow_legacy_sdk_without_mechid = false",
            "allow_legacy_sdk_without_mechid = true",
        )
        with pytest.raises(ConfigError, match=r"permitted only on chain\.network = 'local'"):
            load_validator_config(_write(tmp_path, body))

    def test_legacy_sdk_override_accepted_on_local(self, tmp_path: Path) -> None:
        body = VALID_FINNEY_CONFIG.replace('network = "finney"', 'network = "local"').replace(
            "allow_legacy_sdk_without_mechid = false",
            "allow_legacy_sdk_without_mechid = true",
        )
        config = load_validator_config(_write(tmp_path, body))
        assert config.chain.network == ChainNetwork.LOCAL
        assert config.chain.allow_legacy_sdk_without_mechid is True

    def test_phase1_constant_mismatch_rejected(self, tmp_path: Path) -> None:
        body = VALID_FINNEY_CONFIG.replace("top_k = 10", "top_k = 15")
        with pytest.raises(ConfigError, match="invalid validator config"):
            load_validator_config(_write(tmp_path, body))

    def test_empty_snapshot_keys_rejected(self, tmp_path: Path) -> None:
        body = VALID_FINNEY_CONFIG.replace(
            '[platform.snapshot_keys."platform-main-2026-05"]\n'
            'public_key = "0x1111111111111111111111111111111111111111111111111111111111111111"\n'
            'not_before = "2026-05-01T00:00:00Z"\n'
            'not_after  = "2026-09-01T00:00:00Z"\n'
            'status     = "active"\n',
            "",
        )
        with pytest.raises(ConfigError, match="must contain at least one trusted key"):
            load_validator_config(_write(tmp_path, body))
