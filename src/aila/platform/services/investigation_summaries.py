"""Platform investigation summary projection builders.

Pure projection from an RFC-01 investigation record to a module's
``*InvestigationSummary`` Pydantic class. The two module summary
contracts (vr, malware) are field-identical, so one builder projects
into either via ``summary_cls``; each module keeps a thin binding that
supplies its own contract class. Keeping the projection on the platform
means both modules read the same columns the same way -- a per-module
copy is how the malware cost gauge and summary drifted from vr.

No I/O and no session access: the caller passes the already-computed
join counts (branch / message / outcome), the primary-outcome
projection, and the live cost. ``live_cost_usd`` overrides the stored
``cost_actual_usd`` (a column with no writers) when provided; see
:mod:`aila.platform.services.investigation_cost` for the aggregator.
"""
from __future__ import annotations

import json
from typing import Any, TypeVar

SummaryT = TypeVar("SummaryT")

__all__ = ["build_investigation_summary"]


def build_investigation_summary(
    record: Any,
    *,
    summary_cls: type[SummaryT],
    branch_count: int = 0,
    message_count: int = 0,
    outcome_count: int = 0,
    workspace_id: str | None = None,
    primary_outcome_kind: str | None = None,
    primary_outcome_confidence: str | None = None,
    primary_outcome_verdict_head: str | None = None,
    verifier_verdict: str | None = None,
    verifier_confidence: float | None = None,
    live_cost_usd: float | None = None,
) -> SummaryT:
    """Project ``record`` into ``summary_cls``.

    ``summary_cls`` coerces the raw string columns (kind / status /
    pause_reason) into its own module enum values, so the platform never
    imports a module enum. ``is_favorite`` is read defensively for
    records predating the column.
    """
    actual_cost = (
        live_cost_usd if live_cost_usd is not None else record.cost_actual_usd
    )
    return summary_cls(
        id=record.id,
        title=record.title,
        target_id=record.target_id,
        workspace_id=workspace_id,
        parent_investigation_id=record.parent_investigation_id,
        kind=record.kind,
        status=record.status,
        pause_reason=record.pause_reason or None,
        auto_pilot=record.auto_pilot,
        is_favorite=getattr(record, "is_favorite", False),
        strategy_family=record.strategy_family,
        cost_budget_usd=record.cost_budget_usd,
        cost_actual_usd=actual_cost,
        llm_tokens_cost_usd=record.llm_tokens_cost_usd,
        mcp_calls_cost_usd=record.mcp_calls_cost_usd,
        fuzz_infra_cost_usd=record.fuzz_infra_cost_usd,
        branch_count=branch_count,
        message_count=message_count,
        outcome_count=outcome_count,
        primary_outcome_id=record.primary_outcome_id,
        primary_outcome_kind=primary_outcome_kind,
        primary_outcome_confidence=primary_outcome_confidence,
        primary_outcome_verdict_head=primary_outcome_verdict_head,
        verifier_verdict=verifier_verdict,
        verifier_confidence=verifier_confidence,
        linked_campaign_ids=json.loads(record.linked_campaign_ids_json or "[]"),
        linked_finding_ids=json.loads(record.linked_finding_ids_json or "[]"),
        started_at=record.started_at,
        stopped_at=record.stopped_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )
