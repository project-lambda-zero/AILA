"""Schemas for the admin LLM interaction log (Plan 176e).

The interaction log reuses the Phase 175 LLMCostRecord baseline and joins
through WorkflowRunRecord for task_type context. The list endpoint returns
only truncated previews. Full prompt/response bodies are never returned by
the list endpoint; the dedicated ``GET /admin/llm-log/{id}/content`` route
resolves the paired ``AuditSealRecord`` stored bodies when available and
falls back to the preview otherwise.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

__all__ = [
    "LLMLogContent",
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


class LLMLogContent(BaseModel):
    """Full prompt/response bodies for one LLM interaction log row.

    ``source`` reports where the payload came from:

    * ``audit_seal`` -- resolved from the paired ``AuditSealRecord``; both
      bodies are present. ``config_flag`` is null (no operator action needed).
    * ``preview`` -- the seal did not store full bodies for this task type;
      the truncated preview columns are returned instead and ``config_flag``
      names the ``llm_seal_store_content_<task_type>`` toggle that would
      enable full retention.
    * ``missing`` -- neither full bodies nor previews are available;
      ``config_flag`` names the toggle as above.
    """

    prompt_content: str | None = None
    response_content: str | None = None
    source: str
    task_type: str
    config_flag: str | None = None
