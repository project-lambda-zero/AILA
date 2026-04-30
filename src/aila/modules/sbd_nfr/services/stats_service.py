"""Dashboard statistics service for the SbD NFR module.

Provides architect-facing summary metrics: session counts by status, recent
sessions, completion rate, and average time-to-complete.

Design references: D-48 (dashboard stats endpoint).

Security note (T-134-12): this service function is role-agnostic.  Access
control MUST be enforced at the route handler level (require_role("operator")
or higher) — not here.

Each public function manages its own database session via UnitOfWork.
"""

from __future__ import annotations

import json
import logging

from sqlmodel import select

from aila.platform.uow import UnitOfWork

from ..contracts.session import SessionSummaryResponse
from ..contracts.stats import DashboardStatsResponse
from ..db_models import SbdNfrSessionRecord

_log = logging.getLogger(__name__)

__all__ = ["get_dashboard_stats"]


async def get_dashboard_stats() -> DashboardStatsResponse:
    """Compute architect-facing dashboard statistics (D-48).

    Returns:
        DashboardStatsResponse with:
        - session_counts_by_status: count per status string for non-deleted sessions.
        - recent_sessions: 10 most recently updated non-deleted sessions.
        - completion_rate: (completed + resolved) / total non-draft, non-deleted
          sessions.  0.0 when no such sessions exist.
        - avg_time_to_complete_hours: mean hours from created_at to updated_at
          for sessions in 'completed' status.  None when no completed sessions exist.
        - total_sessions: total non-deleted session count.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        all_sessions = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.is_deleted == False)
        )).all()

        # --- Count by status ---
        counts_by_status: dict[str, int] = {}
        for session in all_sessions:
            counts_by_status[session.status] = counts_by_status.get(session.status, 0) + 1

        total_sessions = len(all_sessions)

        # --- Completion rate: (completed + resolved) / non-draft total ---
        non_draft = [s for s in all_sessions if s.status != "draft"]
        if non_draft:
            terminal = [s for s in non_draft if s.status in ("completed", "resolved")]
            completion_rate = len(terminal) / len(non_draft)
        else:
            completion_rate = 0.0

        # --- Average time-to-complete (hours) ---
        completed_sessions = [s for s in all_sessions if s.status == "completed"]
        if completed_sessions:
            total_hours = sum(
                (s.updated_at - s.created_at).total_seconds() / 3600.0
                for s in completed_sessions
            )
            avg_time_to_complete_hours: float | None = total_hours / len(completed_sessions)
        else:
            avg_time_to_complete_hours = None

        # --- Recent sessions: 10 most recently updated ---
        recent = sorted(all_sessions, key=lambda s: s.updated_at, reverse=True)[:10]
        recent_responses = [_to_summary(s) for s in recent]

        _log.info(
            "sbd_nfr: dashboard stats computed total=%d completion_rate=%.2f",
            total_sessions,
            completion_rate,
        )

        return DashboardStatsResponse(
            session_counts_by_status=counts_by_status,
            recent_sessions=recent_responses,
            completion_rate=completion_rate,
            avg_time_to_complete_hours=avg_time_to_complete_hours,
            total_sessions=total_sessions,
        )


def _to_summary(session: SbdNfrSessionRecord) -> SessionSummaryResponse:
    """Map a SbdNfrSessionRecord to a SessionSummaryResponse."""
    try:
        tags: list[str] = json.loads(session.tags_json) if session.tags_json else []
    except (json.JSONDecodeError, TypeError):
        tags = []
    return SessionSummaryResponse(
        id=session.id,
        status=session.status,
        project_name=session.project_name,
        description=session.description,
        business_unit=session.business_unit,
        requestor_name=session.requestor_name,
        requestor_email=session.requestor_email,
        target_date=session.target_date,
        is_template=session.is_template,
        template_name=session.template_name,
        tags=tags,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )
