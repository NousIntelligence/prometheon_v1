"""Integration test: full ValidatorRunner cycle with mocked external services.

Composes a real :class:`ValidatorRunner` against:

- A fake :class:`BitFanClient` that returns a real Ed25519-signed
  aggregate snapshot (built with a test private key).
- A fake :class:`SubtensorProtocol` implementation that returns a
  realistic :class:`MetagraphView` and a clean :class:`ChainHyperparameters`.
- A captured ``set_weights`` call so we can assert the final u16 vector.

This is the canonical happy-path integration test for Case A.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from bittensor_wallet import Keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.chain.metagraph import MetagraphView
from prometheon.chain.weights import (
    CHAIN_WEIGHT_UNITS,
    ChainAdapterCapabilities,
    ChainHyperparameters,
    ChainWeightVector,
)
from prometheon.identity.roles import ChainNetwork
from prometheon.mechanisms.phase1_growth.policy import WEIGHT_UNITS
from prometheon.platform.client import BitFanClient
from prometheon.platform.endpoints import SnapshotMode
from prometheon.platform.schemas import AggregateSnapshot
from prometheon.platform.signing import (
    TrustedKey,
    compute_aggregate_records_hash,
)
from prometheon.security.canonical import DOMAIN_SNAPSHOT, domain_prefixed_bytes
from prometheon.validator.config import (
    BurnConfigSection,
    ChainConfig,
    LoggingConfig,
    Phase1ConfigSection,
    PlatformConfig,
    SchedulerConfig,
    ValidatorConfig,
    ValidatorRuntimeConfig,
    WalletConfig,
)
from prometheon.validator.runner import SubtensorProtocol, ValidatorRunner

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ss58(uri: str) -> str:
    return Keypair.create_from_uri(uri).ss58_address


MINER_A = _ss58("//integration/miner/0")
MINER_B = _ss58("//integration/miner/1")
MINER_C = _ss58("//integration/miner/2")
BURN = _ss58("//integration/burn")
VALIDATOR = _ss58("//integration/validator")
KEY_ID = "platform-integration-2026"


@pytest.fixture
def platform_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)


@pytest.fixture
def trusted_keys(platform_private_key: Ed25519PrivateKey) -> dict[str, TrustedKey]:
    public_hex = "0x" + platform_private_key.public_key().public_bytes_raw().hex()
    return {
        KEY_ID: TrustedKey(
            public_key=public_hex,
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            status="active",
        )
    }


@pytest.fixture
def validator_keypair() -> Keypair:
    return Keypair.create_from_uri("//integration/validator")


def _build_signed_aggregate(
    private_key: Ed25519PrivateKey,
    *,
    miners: list[dict[str, Any]],
    burn_hotkey: str = BURN,
    burn_ppm: int = 150_000,
) -> AggregateSnapshot:
    raw = {
        "domain": "PROMETHEON_SNAPSHOT_V1",
        "schema_version": "1.0",
        "mechanism": "phase1_growth",
        "mechid": 0,
        "mode": "aggregate",
        "snapshot_id": "phase1:2026-05-18:aggregate",
        "chain_network": "finney",
        "platform_instance_id": "bitfan-integration",
        "netuid": 123,
        "activity_date": "2026-05-18",
        "generated_at": "2026-05-19T00:20:31Z",
        "window_start_date": "2026-05-05",
        "window_end_date": "2026-05-18",
        "daily_score_cap": 20,
        "active_member_score_threshold": 50,
        "min_active_members_for_reward": 3,
        "top_k": 10,
        "burn_hotkey": burn_hotkey,
        "manual_burn_rate_ppm": burn_ppm,
        "platform_key_id": KEY_ID,
        "miners": miners,
    }
    placeholder = {
        **raw,
        "records_hash": "0x" + "00" * 32,
        "platform_signature": "0x" + "00" * 64,
    }
    tmp = AggregateSnapshot.model_validate(placeholder)
    records_hash = compute_aggregate_records_hash(tmp)
    raw_with_hash = {**raw, "records_hash": records_hash}
    envelope = domain_prefixed_bytes(DOMAIN_SNAPSHOT, raw_with_hash)
    signature_hex = "0x" + private_key.sign(envelope).hex()
    return AggregateSnapshot.model_validate({**raw_with_hash, "platform_signature": signature_hex})


class _FakeBitFanClient:
    """Just enough of the BitFanClient surface to drive the runner."""

    def __init__(self, snapshot: AggregateSnapshot) -> None:
        self._snapshot = snapshot
        self.aggregate_calls: int = 0

    def get_aggregate_snapshot(self, activity_date: str) -> AggregateSnapshot:
        self.aggregate_calls += 1
        return self._snapshot

    def __enter__(self) -> _FakeBitFanClient:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


class _FakeSubtensor:
    """SubtensorProtocol stub that returns deterministic chain state."""

    def __init__(self, metagraph: MetagraphView) -> None:
        self._metagraph = metagraph
        self.submitted_vector: ChainWeightVector | None = None
        self.submitted_version_key: int | None = None
        self.submitted_mechid: int | None = None

    def sync_metagraph(self, netuid: int) -> MetagraphView:
        return self._metagraph

    def read_hyperparameters(self, netuid: int) -> ChainHyperparameters:
        return ChainHyperparameters(weights_version=0, commit_reveal_enabled=False)

    def submit_set_weights(
        self,
        *,
        netuid: int,
        vector: ChainWeightVector,
        version_key: int,
        mechid: int | None,
    ) -> str | None:
        self.submitted_vector = vector
        self.submitted_version_key = version_key
        self.submitted_mechid = mechid
        return "0xfake_extrinsic"


def _config(snapshot_keys: dict[str, TrustedKey]) -> ValidatorConfig:
    return ValidatorConfig(
        chain=ChainConfig(
            network=ChainNetwork.FINNEY,
            netuid=123,
            version_key=0,
            fail_on_weights_version_mismatch=True,
            allow_legacy_sdk_without_mechid=False,
        ),
        wallet=WalletConfig(name="validator", hotkey="default"),
        platform=PlatformConfig(
            base_url="https://example.test",
            platform_instance_id="bitfan-integration",
            api_token_env="UNUSED_FOR_RUNNER",
            snapshot_keys=snapshot_keys,
        ),
        validator=ValidatorRuntimeConfig(
            mode=SnapshotMode.AGGREGATE,
            activity_date="latest",
            submit_weights=True,
            dry_run=False,
        ),
        phase1=Phase1ConfigSection(),
        burn=BurnConfigSection(
            enabled=True,
            burn_hotkey=BURN,
            manual_burn_rate_ppm=150_000,
        ),
        scheduler=SchedulerConfig(),
        logging=LoggingConfig(level="INFO"),
    )


# ---------------------------------------------------------------------------
# The integration test
# ---------------------------------------------------------------------------


def test_aggregate_end_to_end_case_a(
    platform_private_key: Ed25519PrivateKey,
    trusted_keys: dict[str, TrustedKey],
    validator_keypair: Keypair,
    tmp_path: Path,
) -> None:
    """End-to-end Case A: three eligible miners + burn hotkey present.

    Verifies:
    - Snapshot signature + records_hash verify.
    - Engine produces a ready plan with burn_case=A.
    - u16 vector sums to CHAIN_WEIGHT_UNITS.
    - Subtensor receives the right uids/weights and ``mechid=0``.
    - Validator state is persisted with submission status="success".
    """
    snapshot = _build_signed_aggregate(
        platform_private_key,
        miners=sorted(
            [
                {"miner_hotkey": MINER_A, "miner_score_points": 400, "active_member_count": 6},
                {"miner_hotkey": MINER_B, "miner_score_points": 600, "active_member_count": 8},
                {"miner_hotkey": MINER_C, "miner_score_points": 200, "active_member_count": 4},
            ],
            key=lambda m: cast(str, m["miner_hotkey"]),
        ),
    )

    metagraph = MetagraphView(
        block_number=1_234_567,
        hotkeys_by_uid={1: MINER_A, 2: MINER_B, 3: MINER_C, 4: BURN, 5: VALIDATOR},
        uids_by_hotkey={MINER_A: 1, MINER_B: 2, MINER_C: 3, BURN: 4, VALIDATOR: 5},
    )

    fake_subtensor = _FakeSubtensor(metagraph)
    fake_client = _FakeBitFanClient(snapshot)
    capabilities = ChainAdapterCapabilities(
        sdk_version="10.3.2", python_version="3.11", supports_mechid=True
    )

    runner = ValidatorRunner(
        config=_config(trusted_keys),
        platform_client=cast(BitFanClient, fake_client),
        subtensor=cast(SubtensorProtocol, fake_subtensor),
        wallet_hotkey=validator_keypair,
        capabilities=capabilities,
        state_directory=tmp_path,
    )

    result = runner.run_once()

    # Plan invariants.
    assert result.plan.status == "ready"
    assert result.plan.burn_case == "A"
    assert result.plan.total_weight_units == WEIGHT_UNITS
    assert result.submitted is True
    assert result.extrinsic_hash == "0xfake_extrinsic"

    # Chain submission invariants.
    assert fake_subtensor.submitted_vector is not None
    assert sum(fake_subtensor.submitted_vector.weights) == CHAIN_WEIGHT_UNITS
    assert fake_subtensor.submitted_mechid == 0
    assert fake_subtensor.submitted_version_key == 0
    # All submitted UIDs come from the metagraph.
    for uid in fake_subtensor.submitted_vector.uids:
        assert uid in metagraph.hotkeys_by_uid

    # Persisted state matches the cycle outcome.
    state_file = tmp_path / "state.json"
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["last_submit_status"] == "success"
    assert persisted["last_extrinsic_hash"] == "0xfake_extrinsic"
    assert persisted["last_metagraph_block"] == 1_234_567

    # Event log line was written.
    events = (tmp_path / "events.ndjson").read_text(encoding="utf-8").strip().split("\n")
    assert any(json.loads(line)["event_type"] == "cycle_submitted" for line in events)
