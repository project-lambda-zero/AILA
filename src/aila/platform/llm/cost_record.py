"""LLMCostRecord -- durable per-call cost persistence (Phase 175 / D-01).

One record is written per LLM call, linking the call to its run, model,
task_type, and team.  Dollar amounts are derived from operator-configured
pricing in ConfigRegistry.  When pricing is not configured, cost_usd is
$0.00 and a one-time warning notification is emitted.

human_cost_hours and human_cost_usd are populated by estimate_human_cost() in
human_cost.py.  Both remain nullable for backward compatibility.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index
from sqlmodel import Field, SQLModel

from ...platform.contracts._common import utc_now
from ...storage.mixins import TeamScopedMixin


class LLMCostRecord(TeamScopedMixin, SQLModel, table=True):
    """Durable per-call LLM cost record.

    Written by: persist_cost_record() called from AilaLLMClient._call_with_retry()
    after every successful LLM call.
    Consumed by: cost reporting endpoints (Plan 175-03), budget alerting
    (Plan 175-02), pre-scan estimation (Plan 175-03).

    team_id comes from TeamScopedMixin (nullable; auto-stamped by StorageService
    or supplied directly at write time).

    RLS: team isolation enforced by migration 017 ENABLE ROW LEVEL SECURITY +
    CREATE POLICY.  The do_orm_execute listener auto-filters on team_id.
    """

    __tablename__ = "llm_cost_records"
    __table_args__ = (
        Index("ix_llmcostrecord_run_id_model_id", "run_id", "model_id"),
        Index("ix_llmcostrecord_team_created", "team_id", "created_at"),
    )

    id: str = Field(
        default_factory=lambda: str(uuid4()),
        primary_key=True,
    )
    run_id: str = Field(default="_no_run", index=True)
    # #39 observability join keys: correlate a cost record back to the
    # investigation, branch, and turn that produced it. Nullable -- calls
    # outside an agent turn (scoring, report generation) leave them unset.
    investigation_id: str | None = Field(default=None, index=True)
    branch_id: str | None = Field(default=None, index=True)
    turn_number: int | None = Field(default=None)
    # RFC-09: sha256 of the resolved system prompt template for this call so
    # cost is attributable to the exact prompt content that produced it.
    # Nullable -- calls outside an agent turn (scoring, reports) leave it unset.
    prompt_content_hash: str | None = Field(default=None, index=True)
    # Resolved prompt version (version-store key); None for inline prompts.
    prompt_version: str | None = Field(default=None, index=True)
    model_id: str = Field(index=True)
    task_type: str = Field(default="", index=True)
    prompt_tokens: int = Field(default=0)
    completion_tokens: int = Field(default=0)
    cost_usd: float = Field(default=0.0)
    # Populated by estimate_human_cost() (human_cost.py)
    human_cost_hours: float | None = Field(default=None)
    human_cost_usd: float | None = Field(default=None)
    # Plan 176e: LLM interaction log fields -- truncated previews only so the
    # admin list view payload stays tiny and we never mirror a full
    # secret-bearing prompt into a long-lived admin surface.
    prompt_preview: str | None = Field(default=None)
    response_preview: str | None = Field(default=None)
    duration_ms: int | None = Field(default=None)
    status: str = Field(default="ok")
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
