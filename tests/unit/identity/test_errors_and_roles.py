"""Unit tests for ``prometheon.identity.errors`` and ``prometheon.identity.roles``.

These pieces are small but sit on the critical path for every identity
operation, so the tests pin their shape exactly: stable error codes,
matching string values for enums, no surprise members.
"""

from __future__ import annotations

import pytest

from prometheon.identity.errors import (
    EnvironmentMismatchError,
    IdentityDomainMismatchError,
    IdentityEnvelopeStructureError,
    IdentityError,
    IdentityPayloadValidationError,
    PayloadExpiredError,
    PayloadNotYetValidError,
)
from prometheon.identity.roles import ChainNetwork, RecoveryMethod, Role

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Role enum
# ---------------------------------------------------------------------------


class TestRole:
    def test_string_values(self) -> None:
        assert Role.MINER == "miner"
        assert Role.VALIDATOR == "validator"

    def test_only_two_members(self) -> None:
        assert {r.value for r in Role} == {"miner", "validator"}

    def test_constructed_from_string(self) -> None:
        # StrEnum allows the on-wire string to round-trip back into a Role.
        assert Role("miner") is Role.MINER
        assert Role("validator") is Role.VALIDATOR

    def test_unknown_string_rejected(self) -> None:
        with pytest.raises(ValueError):
            Role("operator")


# ---------------------------------------------------------------------------
# ChainNetwork enum
# ---------------------------------------------------------------------------


class TestChainNetwork:
    def test_string_values(self) -> None:
        assert ChainNetwork.LOCAL == "local"
        assert ChainNetwork.TEST == "test"
        assert ChainNetwork.FINNEY == "finney"

    def test_only_three_members(self) -> None:
        assert {n.value for n in ChainNetwork} == {"local", "test", "finney"}

    def test_unknown_string_rejected(self) -> None:
        with pytest.raises(ValueError):
            ChainNetwork("mainnet")


# ---------------------------------------------------------------------------
# RecoveryMethod enum
# ---------------------------------------------------------------------------


class TestRecoveryMethod:
    def test_string_values(self) -> None:
        assert RecoveryMethod.COLDKEY == "coldkey"
        assert RecoveryMethod.MANUAL_2FA_OPS == "manual_2fa_ops"

    def test_only_two_members(self) -> None:
        assert {m.value for m in RecoveryMethod} == {"coldkey", "manual_2fa_ops"}


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class TestIdentityErrors:
    """Every specific identity error inherits from :class:`IdentityError`."""

    @pytest.mark.parametrize(
        "exc_cls, expected_code",
        [
            (IdentityPayloadValidationError, "identity.payload_invalid"),
            (IdentityEnvelopeStructureError, "identity.envelope_invalid"),
            (IdentityDomainMismatchError, "signature.domain_mismatch"),
            (EnvironmentMismatchError, "ENVIRONMENT_MISMATCH"),
            (PayloadExpiredError, "identity.payload_expired"),
            (PayloadNotYetValidError, "identity.payload_not_yet_valid"),
        ],
    )
    def test_codes_match_catalog(self, exc_cls: type[IdentityError], expected_code: str) -> None:
        assert exc_cls.code == expected_code
        assert issubclass(exc_cls, IdentityError)

    def test_can_be_caught_via_base(self) -> None:
        # A caller handling generic identity errors via the base class must
        # catch every specific subclass.
        with pytest.raises(IdentityError):
            raise IdentityPayloadValidationError("missing nonce")

        with pytest.raises(IdentityError):
            raise EnvironmentMismatchError("wrong chain_network")
