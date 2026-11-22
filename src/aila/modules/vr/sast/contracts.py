"""Wire contracts for the staged SAST prepared audit."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.sast.models import SastPhase

__all__ = ["SastAuditAggregate", "SastAuditDispatchResponse", "SastSkillResult"]


class SastAuditDispatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_investigation_id: str
    child_investigation_ids: list[str]
    analysis_investigation_id: str
    report_investigation_id: str
    total_skills: int = Field(ge=16)
    total_detectors: int = Field(ge=14)
    sast_spec_version: str
    upstream_commit: str
    cost_budget_total_usd: float = Field(ge=0)
    enqueue_errors: dict[str, str] = Field(default_factory=dict)
    idempotent_reuse: bool = False


class SastSkillResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    skill_id: str
    title: str
    phase: SastPhase
    investigation_id: str
    status: str
    outcome_kind: str | None = None
    confidence: str | None = None
    summary: str | None = None


class SastAuditAggregate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_investigation_id: str
    target_id: str
    parent_status: str
    sast_spec_version: str
    upstream_commit: str
    results: list[SastSkillResult]
    status_counts: dict[str, int]
