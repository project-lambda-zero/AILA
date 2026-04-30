"""Schemas for the admin LLM interaction log (Plan 176e).

The interaction log reuses the Phase 175 LLMCostRecord baseline and joins
through WorkflowRunRecord for task_type context. These schemas only expose
truncated previews -- full prompt/response bodies are never returned.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

__all__ = [
    "LLMLogEntry",
    "LLMLogResponse",
]


class LLMLogEntry(BaseModel):
    """One LLM call row as shown in the admin interaction log table."""

    id: str
    timestamp: datetime
    model: str
    task_type: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: int | None
    status: str
    run_id: str
    user_id: str | None = None
    team_id: str | None = None
    prompt_preview: str | None = None
    response_preview: str | None = None


class LLMLogResponse(BaseModel):
    """Paginated LLM interaction log response with cost aggregate."""

    items: list[LLMLogEntry]
    total: int = Field(..., description="Total matching rows, not just this page")
    limit: int
    offset: int
    total_cost_usd: float = Field(
        ...,
        description="Sum of cost_usd across all matching rows (not just this page)",
    )
