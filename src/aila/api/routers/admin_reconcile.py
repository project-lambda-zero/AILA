"""Admin state reconciliation router (RFC-07 phase 3).

Operator surface for on-demand :class:`StateReconciler` runs. The
reconciler heals drift between the three sources of truth for one
``task_id`` (``TaskRecord.status``, ``workflow_state_cursor.current_state``,
``arq:in-progress:<task_id>`` lock in Redis) using exactly the mutations
the periodic reaper already performs -- this endpoint just packages them
as a single per-task heal for an operator triaging a stuck run without
waiting for the cron sweep.

All endpoints require god-tier admin (team_id=None): reconciliation
touches TaskRecord + workflow_state_cursor + ARQ lock keys across every
team, so a team-scoped admin is refused rather than allowed to heal
another team's runs.

Endpoints:
    POST /admin/reconcile
        Body: {"task_id": "<id>"}
        Run one :meth:`StateReconciler.reconcile` pass. Returns the
        pre-heal signal snapshot + every action that ran, or an empty
        ``actions`` tuple when the row was already consistent.
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.tasks.state_reconciler import (
    ReconcileAction,
    ReconcileReport,
    StateReconciler,
    TaskSignals,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Reconciliation touches TaskRecord + cursor + ARQ lock keys across
    every team, so a team-scoped admin is refused; only a god-tier admin
    (team_id=None) may heal drift on a task that may belong to another
    team's investigation."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "State reconciliation is restricted to god-tier "
                "administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/admin",
    tags=["admin-reconcile"],
    dependencies=[Depends(_require_admin)],
)

# Process-wide reconciler singleton. The class carries no per-task
# state so a single instance is safe to reuse across requests; its
# Redis client lifetime is scoped per heal call inside ``_probe_lock``
# / ``_drop_lock`` so we do not leak a persistent connection.
_RECONCILER = StateReconciler()


class ReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=64)


class TaskSignalsResponse(BaseModel):
    """Pre-heal snapshot of the three sources of truth for the task."""

    task_id: str
    task_status: str | None
    task_heartbeat_at: datetime | None
    task_started_at: datetime | None
    cursor_state: str | None
    lock_present: bool | None


class ReconcileActionResponse(BaseModel):
    kind: str
    reason: str


class ReconcileReportResponse(BaseModel):
    task_id: str
    signals: TaskSignalsResponse
    healed: bool
    actions: list[ReconcileActionResponse]
    action_kinds: list[str]


def _signals_to_response(signals: TaskSignals) -> TaskSignalsResponse:
    """Render the reconciler's TaskSignals as the response contract."""
    return TaskSignalsResponse(
        task_id=signals.task_id,
        task_status=signals.task_status,
        task_heartbeat_at=signals.task_heartbeat_at,
        task_started_at=signals.task_started_at,
        cursor_state=signals.cursor_state,
        lock_present=signals.lock_present,
    )


def _action_to_response(action: ReconcileAction) -> ReconcileActionResponse:
    """Render one heal action as the response contract."""
    return ReconcileActionResponse(kind=action.kind, reason=action.reason)


def _report_to_response(report: ReconcileReport) -> ReconcileReportResponse:
    """Render a full ReconcileReport as the response contract."""
    return ReconcileReportResponse(
        task_id=report.task_id,
        signals=_signals_to_response(report.signals),
        healed=report.healed,
        actions=[_action_to_response(a) for a in report.actions],
        action_kinds=list(report.get_action_kinds()),
    )


@router.post("/reconcile", status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def reconcile(
    request: Request,
    body: ReconcileRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ReconcileReportResponse]:
    """Run one :meth:`StateReconciler.reconcile` pass for ``task_id``.

    Idempotent: a consistent-already row returns ``healed=false`` with
    an empty ``actions`` list. A row with drift returns the exact
    mutations that ran, so the operator can audit which of the three
    sources were rewritten.
    """
    del request
    _log.info(
        "admin.reconcile task_id=%s actor=%s",
        body.task_id, ctx.user_id or "unknown",
    )
    try:
        report = await _RECONCILER.reconcile(body.task_id)
    except (OSError, RuntimeError, ValueError) as exc:
        _log.warning(
            "admin.reconcile task_id=%s failed: %s",
            body.task_id, exc, exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"reconcile failed: {exc}",
        ) from exc
    return DataEnvelope(data=_report_to_response(report))
