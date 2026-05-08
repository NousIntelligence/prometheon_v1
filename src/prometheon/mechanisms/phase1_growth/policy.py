"""Phase 1 policy values — the engine's input configuration.

The locked constants come from the consolidated specification §3 and are
declared here as ``Final`` module constants so the engine and its tests
share one source of truth. ``Phase1Policy`` packages them together with
the snapshot-controlled burn fields so the engine signature stays small.

For live validation, callers build a :class:`Phase1Policy` from the
**signed snapshot** values for ``burn_hotkey`` and
``manual_burn_rate_ppm``. The other policy fields are pinned to the
Phase 1 constants and a snapshot deviating from them would already have
been rejected at parse time by the schema models.
"""

from __future__ import annotations

from typing import ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

# Locked Phase 1 constants (consolidated specification §3).
MECHANISM_ID: Final[str] = "phase1_growth"
MECHID: Final[int] = 0
DAILY_SCORE_CAP: Final[int] = 20
ACTIVE_MEMBER_SCORE_THRESHOLD: Final[int] = 50
MIN_ACTIVE_MEMBERS_FOR_REWARD: Final[int] = 3
PHASE1_TOP_K: Final[int] = 10
WEIGHT_UNITS: Final[int] = 1_000_000_000
MAX_BURN_RATE_PPM: Final[int] = 1_000_000

_SS58_LOOSE_RE: Final[str] = r"^[1-9A-HJ-NP-Za-km-z]{46,48}$"


class Phase1Policy(BaseModel):
    """Engine input: locked Phase 1 constants plus signed-snapshot burn fields.

    The Phase 1 constants (``daily_score_cap``,
    ``active_member_score_threshold``, ``min_active_members_for_reward``,
    ``top_k``, ``weight_units``) are exposed as ``Literal`` defaults so a
    caller cannot accidentally pass a wrong value. ``burn_hotkey`` and
    ``manual_burn_rate_ppm`` come from the signed snapshot's policy
    section (consolidated specification §16.3); they are the only fields
    a validator does not pin locally.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    mechanism: Literal["phase1_growth"] = "phase1_growth"
    mechid: Literal[0] = 0
    daily_score_cap: Literal[20] = 20
    active_member_score_threshold: Literal[50] = 50
    min_active_members_for_reward: Literal[3] = 3
    top_k: Literal[10] = 10
    weight_units: Literal[1_000_000_000] = 1_000_000_000

    burn_hotkey: str = Field(pattern=_SS58_LOOSE_RE)
    manual_burn_rate_ppm: int = Field(ge=0, le=MAX_BURN_RATE_PPM)


__all__ = [
    "ACTIVE_MEMBER_SCORE_THRESHOLD",
    "DAILY_SCORE_CAP",
    "MAX_BURN_RATE_PPM",
    "MECHANISM_ID",
    "MECHID",
    "MIN_ACTIVE_MEMBERS_FOR_REWARD",
    "PHASE1_TOP_K",
    "WEIGHT_UNITS",
    "Phase1Policy",
]
