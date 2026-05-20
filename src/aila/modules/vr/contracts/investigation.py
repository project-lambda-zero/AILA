"""Investigation contracts (M3.R-1).

A VRInvestigation is one operator-initiated reasoning session against
one primary target. Per D-50 it binds to exactly one primary target +
optional secondary references. Per D-43 it produces typed outcomes
(DirectFinding / VariantHuntOrder / AuditMemo / etc.) consumed by
downstream dispatchers.

Variant hunts are sibling investigations (D-43 GA-28) — separate
investigations linked by ``parent_investigation_id``, not branches.
Branches stay inside one investigation.

This module is schema-only. The reasoning agent + workflow + dispatcher
land in M3.R-2 through M3.R-8.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "InvestigationKind",
    "InvestigationPauseReason",
    "InvestigationStatus",
    "VRInvestigationCreate",
    "VRInvestigationSummary",
]


class InvestigationKind(StrEnum):
    """What kind of investigation this is (drives default strategy + budget)."""

    DISCOVERY = "discovery"
    VARIANT_HUNT = "variant_hunt"
    TRIAGE = "triage"
    N_DAY = "n_day"
    AUDIT = "audit"


class InvestigationStatus(StrEnum):
    """Lifecycle states for an investigation."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class InvestigationPauseReason(StrEnum):
    """Why an investigation entered the PAUSED state.

    Used by the resumer worker (M3.R-6) to decide whether to auto-resume
    (e.g. awaiting_campaign once the campaign finishes) or wait for
    operator action.
    """

    OPERATOR = "operator"
    LOW_CONFIDENCE = "low_confidence"
    COST_BUDGET = "cost_budget"
    AWAITING_CAMPAIGN = "awaiting_campaign"
    AWAITING_MCP = "awaiting_mcp"


class VRInvestigationCreate(BaseModel):
    """Input payload for creating a new investigation.

    Most fields default sensibly — operator only has to provide the
    target_id and a question. Workspace is inferred from target.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=255)
    initial_question: str = Field(min_length=1)
    target_id: str = Field(min_length=1, max_length=64)
    kind: InvestigationKind = InvestigationKind.DISCOVERY
    secondary_target_ids: list[str] = Field(default_factory=list)
    parent_investigation_id: str | None = Field(
        default=None,
        description="Set when this is a spawned variant hunt or sub-investigation.",
    )
    strategy_family: str | None = Field(
        default=None,
        description=(
            "ReasoningStrategyFamily value. When omitted, the server "
            "derives it from `kind` via _KIND_DEFAULT_STRATEGY "
            "(DISCOVERY -> discovery_research, VARIANT_HUNT -> "
            "variant_hunt, TRIAGE -> triage, N_DAY -> nday). Send an "
            "explicit value only when you need to override the "
            "kind-default (rare)."
        ),
    )
    auto_pilot: bool = Field(
        default=True,
        description="When True, engine self-drives without operator pauses for ambiguity (D-43 GA-21).",
    )
    cost_budget_usd: float = Field(
        default=50.0, ge=0.0,
        description="Hard cap on total cost (LLM + MCP + fuzz infra). Engine soft-warns at 50/75/90%, hard-stops at 100%.",
    )


class VRInvestigationSummary(BaseModel):
    """Read-only projection of an investigation for list + detail views."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    target_id: str
    workspace_id: str | None = None
    parent_investigation_id: str | None = None
    kind: InvestigationKind
    status: InvestigationStatus
    pause_reason: InvestigationPauseReason | None = None
    auto_pilot: bool
    is_favorite: bool = False
    strategy_family: str
    cost_budget_usd: float
    cost_actual_usd: float = 0.0
    llm_tokens_cost_usd: float = 0.0
    mcp_calls_cost_usd: float = 0.0
    fuzz_infra_cost_usd: float = 0.0
    branch_count: int = 0
    message_count: int = 0
    outcome_count: int = 0
    primary_outcome_id: str | None = None
    primary_outcome_kind: str | None = None
    primary_outcome_confidence: str | None = None
    primary_outcome_verdict_head: str | None = None
    verifier_verdict: str | None = None
    verifier_confidence: float | None = None
    linked_campaign_ids: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
