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

__all__ = [
    "build_branch_summary",
    "build_investigation_summary",
    "build_message_summary",
    "build_outcome_summary",
]


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


def build_branch_summary(
    record: Any,
    *,
    summary_cls: type[SummaryT],
    cursor_state: str | None = None,
    cursor_archived_state: str | None = None,
) -> SummaryT:
    """Project a branch record row into ``summary_cls``.

    ``cursor_state`` + ``cursor_archived_state`` come from
    :class:`WorkflowStateCursor` joined by ``run_id == branch.id``.
    Callers that haven't joined the cursor table pass ``None``; the UI
    then falls back to the legacy ``status`` field for paused-state
    detection. ``fork_reason`` / ``closed_reason`` empty-string coercion
    matches the RFC-01 base's ``str`` typing when the DB stores NULL.
    """
    return summary_cls(
        id=record.id,
        investigation_id=record.investigation_id,
        parent_branch_id=record.parent_branch_id,
        status=record.status,
        persona_voice=record.persona_voice or None,
        fork_reason=record.fork_reason or "",
        fork_at_turn=record.fork_at_turn,
        turn_count=record.turn_count,
        branch_cost_usd=record.branch_cost_usd,
        closed_reason=record.closed_reason or "",
        merged_into_branch_id=record.merged_into_branch_id,
        promoted=record.promoted,
        closed_at=record.closed_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
        strategy_family=record.strategy_family,
        cursor_state=cursor_state,
        cursor_archived_state=cursor_archived_state,
    )


def build_message_summary(
    record: Any,
    *,
    summary_cls: type[SummaryT],
) -> SummaryT:
    """Project a message record row into ``summary_cls``.

    ``acked_at`` is forwarded only when ``summary_cls`` declares it
    (malware surfaces operator ACKs; VR does not). The introspection
    keeps VR's ``extra='forbid'`` contract intact -- an unconditional
    kwarg would raise on VR.
    """
    kwargs: dict[str, Any] = {
        "id": record.id,
        "investigation_id": record.investigation_id,
        "branch_id": record.branch_id,
        "sender_kind": record.sender_kind,
        "sender_id": record.sender_id,
        "payload_kind": record.payload_kind,
        "payload": json.loads(record.payload_json or "{}"),
        "operator_intent": record.operator_intent or None,
        "at_turn": record.at_turn,
        "evidence_refs": json.loads(record.evidence_refs_json or "[]"),
        "created_at": record.created_at,
    }
    if "acked_at" in summary_cls.model_fields:
        kwargs["acked_at"] = getattr(record, "acked_at", None)
    return summary_cls(**kwargs)


def build_outcome_summary(
    record: Any,
    *,
    summary_cls: type[SummaryT],
    review_counts: dict[str, int] | None = None,
) -> SummaryT:
    """Project an outcome record row into ``summary_cls``.

    ``review_counts`` supplies the sibling-review vote breakdown as a
    dict with keys ``approve``, ``reject``, ``request_edit``,
    ``abstain``, ``quorum_k``. Callers that haven't joined the review
    table (or the review pool doesn't apply) pass ``None``; each count
    defaults to 0. ``state`` falls back to ``'dispatched'`` for legacy
    NULL rows predating the draft-outcome lifecycle column.
    """
    counts = review_counts or {}
    return summary_cls(
        id=record.id,
        investigation_id=record.investigation_id,
        branch_id=record.branch_id,
        outcome_kind=record.outcome_kind,
        payload=json.loads(record.payload_json or "{}"),
        confidence=record.confidence,
        evidence_refs=json.loads(record.evidence_refs_json or "[]"),
        accepted_by_operator=record.accepted_by_operator,
        accepted_at=record.accepted_at,
        dispatch_status=record.dispatch_status,
        dispatch_target=record.dispatch_target,
        created_at=record.created_at,
        state=record.state or "dispatched",
        approve_count=int(counts.get("approve", 0)),
        reject_count=int(counts.get("reject", 0)),
        request_edit_count=int(counts.get("request_edit", 0)),
        abstain_count=int(counts.get("abstain", 0)),
        quorum_k=int(counts.get("quorum_k", 0)),
    )
