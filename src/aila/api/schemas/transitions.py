"""Pydantic schemas for workflow state transition views (Phase 181).

Shared by:
- Operator endpoint: GET /tasks/{task_id}/transitions
- Admin endpoints: GET /admin/workflows/runs/{run_id}/transitions[/{seq}]
- SSE event payloads: event: transition\\ndata: {TransitionView JSON}

D-03 (locked): ``error_message`` is pre-redacted at write time by Phase 178
``WorkflowSafeMessage`` + 2000-char truncation; the read path passes the
stored value through verbatim -- no re-redaction, no truncation.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from aila.storage.db_models import WorkflowStateTransition

__all__ = ["TransitionView"]


class TransitionView(BaseModel):
    """Read-only view of one ``workflow_state_transitions`` row.

    Fields mirror the DB columns exposed to clients. ``input_hash`` and
    ``output_hash`` are intentionally omitted: they are audit-internal
    fingerprints (D-18) with no meaning outside the engine.
    """

    run_id: str
    seq: int
    from_state: str | None
    to_state: str
    event: str
    duration_ms: int | None
    error_class: str | None
    error_message: str | None
    happened_at: datetime
    task_id: str | None = None

    @classmethod
    def from_model(cls, row: WorkflowStateTransition) -> TransitionView:
        """Build a view from a SQLModel row. ``task_id`` is not a column on
        ``WorkflowStateTransition`` itself (Phase 178's ``run_id`` doubles as
        the task id in the emitter contract -- see
        ``platform/events/emitter.py:149``). Populated by callers when they
        know the mapping.
        """
        return cls(
            run_id=row.run_id,
            seq=row.seq,
            from_state=row.from_state,
            to_state=row.to_state,
            event=row.event,
            duration_ms=row.duration_ms,
            error_class=row.error_class,
            error_message=row.error_message,
            happened_at=row.happened_at,
            task_id=row.run_id,
        )
