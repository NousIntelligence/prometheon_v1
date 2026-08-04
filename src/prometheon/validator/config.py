"""TOML configuration loader for the validator runtime.

Validates and parses ``configs/<network>.example.toml``-shape files into
typed Pydantic models. The configuration surface is the union of what the
validator runtime, the chain adapter, the platform client, and the
mechanism engine need:

- ``[chain]``      — network, netuid, version_key, fail-policy switches.
- ``[wallet]``     — wallet directory and hotkey names.
- ``[platform]``   — base_url, platform_instance_id, API token env var,
                     trusted snapshot keys (one entry per ``platform_key_id``).
- ``[validator]``  — weight source (events / snapshot fallback), event
                     store path, snapshot mode + activity date (fallback
                     only), submit flag, dry run.
- ``[scheduler]``  — refresh intervals (the snapshot one is fallback-only;
                     the event path rescores every cycle).
- ``[logging]``    — log level.

The locked Phase 1 mechanism constants live in
:mod:`prometheon.mechanisms.phase1_growth.policy` — they are not config.

The loader is strict: extra fields and malformed entries raise. Local-
development override flags (``allow_legacy_sdk_without_mechid``,
``fail_on_weights_version_mismatch=false``) are rejected when
``chain.network != "local"``.
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from prometheon.chain.weights import WeightSubmissionError
from prometheon.identity.roles import ChainNetwork
from prometheon.platform.endpoints import SnapshotMode
from prometheon.platform.signing import TrustedKey

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - branch chosen at import time
    import tomli as tomllib


class ConfigError(Exception):
    """Raised on config-file load or validation errors."""

    code: str = "validator.config_error"


class ChainConfig(BaseModel):
    """The ``[chain]`` section."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    network: ChainNetwork
    netuid: int = Field(ge=0)
    version_key: int = Field(ge=0)
    fail_on_weights_version_mismatch: bool = True
    allow_legacy_sdk_without_mechid: bool = False


class WalletConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    hotkey: str = Field(min_length=1)
    path: str | None = None


class PlatformConfig(BaseModel):
    """The ``[platform]`` section plus its ``snapshot_keys`` sub-table.

    ``snapshot_keys`` is a map of ``platform_key_id`` → :class:`TrustedKey`.
    Multiple active keys may coexist so the operator can pre-deploy a
    rotation target before the platform starts signing with it.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    base_url: str = Field(min_length=1)
    platform_instance_id: str = Field(min_length=1)
    api_token_env: str = Field(min_length=1)
    request_timeout_seconds: float = Field(default=30.0, gt=0)
    snapshot_keys: dict[str, TrustedKey] = Field(default_factory=dict)


class WeightSource(str, Enum):
    """Where a cycle's miner records come from.

    ``events`` is the live path: recompute from the validator's own event
    store over the rolling window. ``snapshot`` is the pull-based
    predecessor, kept as an incident fallback — not a supported steady
    state, and not where new work goes.
    """

    EVENTS = "events"
    SNAPSHOT = "snapshot"


class ValidatorRuntimeConfig(BaseModel):
    """The ``[validator]`` section."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    mode: SnapshotMode
    activity_date: str = Field(min_length=1, default="latest")
    submit_weights: bool = True
    dry_run: bool = False
    weight_source: WeightSource = WeightSource.EVENTS
    events_db: Path = Path(".validator-state/events.sqlite")


class SchedulerConfig(BaseModel):
    """The ``[scheduler]`` section.

    ``snapshot_refresh_interval_minutes`` applies to the **snapshot
    fallback only**. The live event path has nothing to refresh on an
    interval: the rolling window ends at "now", so it differs on every
    tick and each cycle recomputes from the local store by construction.
    Caching a scored window would mean submitting a stale one.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    snapshot_refresh_interval_minutes: int = Field(default=60, gt=0)
    metagraph_refresh_interval_minutes: int = Field(default=10, gt=0)
    weight_submission_check_interval_minutes: int = Field(default=15, gt=0)


class LoggingConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"


class Phase1ConfigSection(BaseModel):
    """The ``[phase1]`` section.

    Carried in config as a sanity check against the spec constants; the
    actual mechanism engine uses the values pinned in
    :mod:`prometheon.mechanisms.phase1_growth.policy`. Any deviation
    here means the operator changed the constants by mistake, and the
    validator must refuse to start.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    mechanism: Literal["phase1_growth"] = "phase1_growth"
    mechid: Literal[0] = 0
    daily_score_cap: Literal[20] = 20
    active_member_score_threshold: Literal[50] = 50
    min_active_members_for_reward: Literal[3] = 3
    top_k: Literal[10] = 10
    weight_units: Literal[1_000_000_000] = 1_000_000_000


class BurnConfigSection(BaseModel):
    """The ``[burn]`` section — inert placeholders. **Nothing reads these.**

    No code path consumes this section: the live values are resolved at
    submission time from chain (the burn target) and from the locked
    :data:`~prometheon.mechanisms.phase1_growth.policy.MANUAL_BURN_RATE_PPM`
    constant, or on the snapshot fallback from the signed snapshot header
    (consolidated specification §16.3).

    It is retained only so an existing operator TOML still parses. Editing
    it changes nothing — which is the point: a burn target an operator
    could set per-validator would let two validators route emissions
    differently with nothing to reveal the divergence.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    burn_hotkey: str = Field(min_length=1)
    manual_burn_rate_ppm: int = Field(ge=0, le=1_000_000)


class ValidatorConfig(BaseModel):
    """Top-level validator configuration loaded from TOML."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    chain: ChainConfig
    wallet: WalletConfig
    platform: PlatformConfig
    validator: ValidatorRuntimeConfig
    phase1: Phase1ConfigSection
    burn: BurnConfigSection
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @model_validator(mode="after")
    def _reject_local_only_overrides_outside_local(self) -> ValidatorConfig:
        """Reject ``allow_legacy_sdk_without_mechid`` on non-local networks.

        Consolidated specification §24.2 limits the legacy-SDK override to
        ``chain.network == "local"``. A misconfigured production run that
        relaxes the fail-closed defaults would silently break the chain
        contract; this validator catches the mistake at startup.
        """
        if self.chain.allow_legacy_sdk_without_mechid and self.chain.network != ChainNetwork.LOCAL:
            raise ValueError(
                "allow_legacy_sdk_without_mechid is permitted only on "
                "chain.network = 'local'; got "
                f"chain.network = {self.chain.network.value!r}"
            )
        return self

    @model_validator(mode="after")
    def _require_at_least_one_snapshot_key(self) -> ValidatorConfig:
        """Reject configs that ship without any trusted Platform Ed25519 key."""
        if not self.platform.snapshot_keys:
            raise ValueError("platform.snapshot_keys must contain at least one trusted key")
        return self


def load_validator_config(path: str | Path) -> ValidatorConfig:
    """Load and validate a validator configuration TOML file.

    Parameters
    ----------
    path:
        Path to a TOML file shaped like ``configs/finney.example.toml``.

    Returns
    -------
    ValidatorConfig
        Immutable, validated config tree.

    Raises
    ------
    ConfigError
        If the file is missing, unparseable, or fails validation.
    """
    target = Path(path)
    if not target.exists():
        raise ConfigError(f"validator config not found at {target}")

    try:
        with target.open("rb") as fh:
            raw: dict[str, Any] = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read validator config {target}: {exc}") from exc

    try:
        return ValidatorConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"invalid validator config {target}: {exc}") from exc


__all__ = [
    "BurnConfigSection",
    "ChainConfig",
    "ConfigError",
    "LoggingConfig",
    "Phase1ConfigSection",
    "PlatformConfig",
    "SchedulerConfig",
    "ValidatorConfig",
    "ValidatorRuntimeConfig",
    "WalletConfig",
    "WeightSource",
    "WeightSubmissionError",
    "load_validator_config",
]
