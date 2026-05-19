"""Hypothesis projection contracts (08_FRONTEND_UX.md §2.3).

Hypotheses live inside ``ReasoningCaseState.hypotheses`` on each
branch's encoded ``case_state_json`` blob. They aren't a persistent
table — they're a derived view computed by aggregating branches.

This contract exposes the aggregate shape served by
``GET /vr/investigations/{id}/hypotheses`` so the
``HypothesisDetailRail`` component on the frontend can render them
without parsing private engine state.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "HypothesisProjection",
    "HypothesisState",
]


class HypothesisState(StrEnum):
    """Lifecycle of a hypothesis across the branches it appears on."""

    LIVE = "live"          # still in case_state.hypotheses on >=1 branch
    REJECTED = "rejected"  # moved to case_state.rejected on >=1 branch
    RESOLVED = "resolved"  # auto-bucketed on terminal — see canonical outcome
    MIXED = "mixed"        # state differs across branches


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
    # (live) and which host it as rejected or resolved. Operator clicks
    # into a branch to see the engine state in context.
    live_in_branches: list[str] = Field(default_factory=list)
    rejected_in_branches: list[str] = Field(default_factory=list)
    resolved_in_branches: list[str] = Field(default_factory=list)
