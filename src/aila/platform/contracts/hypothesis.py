"""Hypothesis projection contract, shared by the investigation engine (RFC-01).

Hypotheses live inside ``ReasoningCaseState.hypotheses`` on each branch's
encoded ``case_state_json`` blob. They are not a persistent table -- they are
a derived view computed by aggregating branches. This contract exposes the
aggregate shape served by ``GET /<module>/investigations/{id}/hypotheses`` so
a frontend can render them without parsing private engine state.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from aila.platform.contracts.enums import HypothesisState

__all__ = [
    "HypothesisProjection",
    "HypothesisState",
]


class HypothesisProjection(BaseModel):
    """One hypothesis aggregated across an investigation's branches."""

    model_config = ConfigDict(extra="forbid")

    id: str
    claim: str
    why_plausible: str = ""
    kill_criterion: str = ""

    state: HypothesisState
    rejection_reason: str | None = None
    resolution_note: str | None = None

    # Branch attribution: which branches currently host this hypothesis
    # (live) and which host it as rejected or resolved. Operator clicks into
    # a branch to see the engine state in context.
    live_in_branches: list[str] = Field(default_factory=list)
    rejected_in_branches: list[str] = Field(default_factory=list)
    resolved_in_branches: list[str] = Field(default_factory=list)
