"""Cost API response schemas (Phase 175).

Dependency order: base types before composite types.
All classes must be defined before they are referenced to avoid forward-reference issues.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "CostBreakdownResponse",
    "CostEstimateRequest",
    "CostEstimateResponse",
    "CostHistoryResponse",
    "HumanEstimateRequest",
    "HumanEstimateResponse",
    "MonthlyCostEntry",
    "ModelCostEntry",
    "ROIResponse",
    "TaskTypeEstimate",
]


class TaskTypeEstimate(BaseModel):
    """Per-task-type cost estimate.

    Defined BEFORE CostEstimateResponse which references it.
    """

    task_type: str
    avg_cost_usd: float
    sample_count: int


class ModelCostEntry(BaseModel):
    """Per-model cost entry within a run."""

    model_id: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    call_count: int


class CostBreakdownResponse(BaseModel):
    """Per-run cost breakdown (LLM-COST-01).

    #155 additions:

    * ``cache_hit_rate`` -- fraction of prompt tokens served from the
      provider prompt cache during this run, in ``[0.0, 1.0]``.
      Sourced from :func:`aila.platform.llm.prompt_layout.get_cache_metrics`
      (in-worker gauge) when available. Zero when the run has no
      recorded cache activity, when the caller's process has no
      RunMemory attached (e.g. an API-worker read of a worker-owned
      run), or when the provider does not surface cache tokens.
      The live Prometheus gauge ``aila_llm_cache_hit_ratio{model=...}``
      is the process-agnostic mirror.
    * ``cache_read_tokens`` / ``cache_write_tokens`` -- raw token
      counts backing the ratio.
    """

    run_id: str
    total_cost_usd: float
    total_tokens: int
    models: list[ModelCostEntry]
    cache_hit_rate: float = 0.0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


class MonthlyCostEntry(BaseModel):
    """Monthly cost aggregation entry."""

    year_month: str  # "2026-04"
    total_cost_usd: float
    total_tokens: int
    models: list[ModelCostEntry]


class CostHistoryResponse(BaseModel):
    """Historical cost data (LLM-COST-04)."""

    months: list[MonthlyCostEntry]
    grand_total_usd: float


class CostEstimateRequest(BaseModel):
    """Pre-scan estimation request (LLM-COST-03)."""

    target_count: int = Field(ge=1, le=1_000_000)
    task_types: list[str] = Field(max_length=20)

    @field_validator("task_types")
    @classmethod
    def validate_task_types(cls, v: list[str]) -> list[str]:
        for tt in v:
            if len(tt) > 100:
                msg = "task_type too long (max 100 chars)"
                raise ValueError(msg)
        return v


class CostEstimateResponse(BaseModel):
    """Pre-scan cost estimation response.

    confidence is 'historical' when team has prior scan data,
    'worst_case' when no history exists and fallback multiplier was used.
    """

    estimated_cost_usd: float
    confidence: str  # "historical" or "worst_case"
    breakdown: list[TaskTypeEstimate]


class HumanEstimateRequest(BaseModel):
    """Human-equivalent estimation request (post-scan, LLM-COST-05)."""

    run_id: str = Field(max_length=128)
    target_count: int = Field(ge=1, le=1_000_000)
    finding_count: int = Field(ge=0, le=1_000_000)
    task_types_performed: list[str] = Field(max_length=50)
    scan_duration_minutes: float = Field(ge=0, le=10_080)


class HumanEstimateResponse(BaseModel):
    """Human-equivalent estimation result."""

    estimated_hours: float
    human_cost_usd: float
    confidence: str  # "high", "medium", "low"
    reasoning: str = Field(max_length=2000)

    @field_validator("reasoning")
    @classmethod
    def sanitize_reasoning(cls, v: str) -> str:
        import html
        return html.escape(v)


class ROIResponse(BaseModel):
    """ROI comparison: LLM cost vs human-equivalent cost (LLM-COST-05).

    roi_percentage = ((human_equivalent - llm_cost) / human_equivalent) * 100
    A positive value means the platform saved money vs manual work.
    """

    period_start: str  # ISO date
    period_end: str  # ISO date
    llm_cost_usd: float
    human_equivalent_cost_usd: float
    human_equivalent_hours: float
    roi_percentage: float
    run_count: int
