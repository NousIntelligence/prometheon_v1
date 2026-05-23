"""Mechanism interface — minimal abstract base for subnet mechanisms.

Phase 1 is the only mechanism implemented in this repository. Future
phases live in their own repositories (per the multi-phase repo strategy
in the consolidated specification §1.1), each with their own implementation
of this interface.

The interface is deliberately small: a stable identifier pair
(``mechanism_id`` / ``mechid``) and a single method that turns the
mechanism's inputs into a weight plan. Concrete mechanisms can accept
whatever input types they need; the abstract signature uses ``object`` so
the base class does not over-constrain its descendants.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Mechanism(ABC):
    """Abstract base for every subnet mechanism.

    Subclasses set ``mechanism_id`` (string, used for logging and
    telemetry) and ``mechid`` (integer, the on-chain mechanism slot
    identifier). Phase 1 sets ``mechid = 0``.
    """

    mechanism_id: str
    mechid: int

    @abstractmethod
    def compute_weight_plan(self, *args: Any, **kwargs: Any) -> Any:
        """Transform mechanism inputs into a weight plan.

        Concrete mechanisms declare their own input and output types.
        See ``prometheon.mechanisms.phase1_growth.engine`` for the
        Phase 1 implementation.
        """
        raise NotImplementedError


__all__ = ["Mechanism"]
