"""Investigation outcome contracts (M3.R-1).

Per D-43 an investigation emits one of 11 typed outcomes. v0.3 v1
ships ONE base ``VROutcome`` schema with ``outcome_kind`` enum +
``payload: dict``. Per-kind payload Pydantic shapes land when downstream
dispatchers actually need typed validation (M3.R-4 outcome router).

The 11 kinds map to downstream dispatch:
  - DirectFinding         → promotes to vr_findings + disclosure tracks
  - VariantHuntOrder      → spawns sibling investigation (D-43 GA-28)
  - CampaignLaunch        → enqueues vr_launch_fuzz_campaign ARQ task
  - AuditMemo             → writes via KnowledgeService with namespace
                            vr.audit_memo.<workspace_id>
  - CrashTriageReport     → analysis of an existing crash artifact
  - PatchAssessmentReport → patch diff analysis (input to N-day workflow)
  - ProfileSpecDraft      → custom fuzzing profile (e.g. V8MapInferenceProfile)
  - StrategyDescriptor    → reusable strategy artifact (FUZZILLI/AFL++/etc)
  - ConfigDelta           → change to an existing strategy/profile
  - AssessmentReport      → investigation summary without dispatchable action
  - SubInvestigation      → spawn nested investigation (branching trigger)
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "OutcomeConfidence",
    "OutcomeDispatchStatus",
    "OutcomeKind",
    "VROutcomeCreate",
    "VROutcomeSummary",
]


class OutcomeKind(StrEnum):
    """The 11 D-43 typed outcome kinds."""

    ASSESSMENT_REPORT = "assessment_report"
    STRATEGY_DESCRIPTOR = "strategy_descriptor"
    PROFILE_SPEC_DRAFT = "profile_spec_draft"
    CONFIG_DELTA = "config_delta"
    VARIANT_HUNT_ORDER = "variant_hunt_order"
    PATCH_ASSESSMENT_REPORT = "patch_assessment_report"
    AUDIT_MEMO = "audit_memo"
    DIRECT_FINDING = "direct_finding"
    CRASH_TRIAGE_REPORT = "crash_triage_report"
    CAMPAIGN_LAUNCH = "campaign_launch"
    SUB_INVESTIGATION = "sub_investigation"


class OutcomeConfidence(StrEnum):
    """Engine's confidence in the outcome (matches ReasoningConfidence)."""

    EXACT = "exact"
    STRONG = "strong"
    MEDIUM = "medium"
    CAVEATED = "caveated"
    UNKNOWN = "unknown"


class OutcomeDispatchStatus(StrEnum):
    """State of downstream dispatch after the outcome is accepted."""

    PENDING = "pending"
    DISPATCHED = "dispatched"
    FAILED = "failed"
    SKIPPED = "skipped"


class VROutcomeCreate(BaseModel):
    """Input shape for emitting an outcome.

    Engine emits via internal API (not exposed externally as POST).
    This shape exists for typed validation inside the reasoning loop
    and for the outcome-acceptance API (operator confirms).
    """

    model_config = ConfigDict(extra="forbid")

    branch_id: str = Field(min_length=1, max_length=64)
    outcome_kind: OutcomeKind
    payload: dict[str, Any] = Field(default_factory=dict)
    confidence: OutcomeConfidence
    evidence_refs: list[str] = Field(default_factory=list)


class VROutcomeSummary(BaseModel):
    """Read-only projection of one outcome."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    branch_id: str
    outcome_kind: OutcomeKind
    payload: dict[str, Any] = Field(default_factory=dict)
    confidence: OutcomeConfidence
    evidence_refs: list[str] = Field(default_factory=list)
    accepted_by_operator: bool = False
    accepted_at: datetime | None = None
    dispatch_status: OutcomeDispatchStatus = OutcomeDispatchStatus.PENDING
    dispatch_target: str | None = Field(
        default=None,
        description="Downstream artifact id -- campaign_id / finding_id / spawned investigation_id / audit_memo_id.",
    )
    created_at: datetime | None = None
    state: str = Field(
        default="dispatched",
        description=(
            "Draft outcome lifecycle: 'draft' (pending sibling review), "
            "'approved' (quorum reached, dispatch may fire), 'rejected' "
            "(vetoed by sibling), 'dispatched' (shipped to downstream)."
        ),
    )
    approve_count: int = Field(default=0, ge=0)
    reject_count: int = Field(default=0, ge=0)
    request_edit_count: int = Field(default=0, ge=0)
    abstain_count: int = Field(default=0, ge=0)
    quorum_k: int = Field(default=0, ge=0)


class VROutcomeReviewCreate(BaseModel):
    """Operator-facing payload for submitting a sibling review.

    Reviewer branch id is the source-of-truth identity; operator review
    posts (where there's no agent branch) MAY pass any sibling branch
    id from the same investigation to register a vote on behalf of
    that reviewer (treated as a manual override of the agent's
    judgment).
    """

    model_config = ConfigDict(extra="forbid")

    reviewer_branch_id: str = Field(min_length=1, max_length=64)
    vote: str = Field(
        pattern=r"^(approve|reject|request_edit|abstain)$",
        description="approve | reject | request_edit | abstain",
    )
    comment: str = Field(default="", max_length=4096)
    suggested_edits: dict[str, Any] = Field(default_factory=dict)


class VROutcomeReviewSummary(BaseModel):
    """Read-only projection of one outcome review."""

    model_config = ConfigDict(extra="forbid")

    id: str
    outcome_id: str
    reviewer_branch_id: str
    reviewer_persona: str
    vote: str
    comment: str = ""
    suggested_edits: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
