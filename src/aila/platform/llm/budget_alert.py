"""Per-team monthly LLM budget alerting (Phase 175 / D-03, D-03a).

Checks team's monthly spend against configured ceiling and emits
a deduplicated NotificationRecord when 80% threshold is crossed.

Deduplication uses a conditional INSERT (WHERE NOT EXISTS subquery)
to prevent TOCTOU race conditions.  If two concurrent calls try to
insert the same source_entity_id, only one will succeed.

A belt-and-suspenders partial unique index on notification_records.source_entity_id
(WHERE source_entity_id IS NOT NULL) is added in Alembic migration 017
to enforce DB-level deduplication as well.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

import sqlalchemy.exc
import structlog
from sqlalchemy import func, text
from sqlmodel import select

from aila.platform.contracts._common import utc_now
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope

if TYPE_CHECKING:
    from aila.storage.registry import ConfigRegistry

_log = structlog.get_logger(__name__)


async def check_monthly_budget(team_id: str | None, registry: ConfigRegistry) -> None:
    """Check team's monthly LLM spend; emit 80% alert if threshold crossed.

    Args:
        team_id: Team identifier. None for admin/standalone calls (skipped).
        registry: ConfigRegistry for ceiling lookup (async -- uses await).

    Never raises -- all exceptions are logged and swallowed.
    Callers are guaranteed: check_monthly_budget failure never blocks cost recording.
    """
    if team_id is None:
        return

    try:
        ceiling_raw = await registry.get("platform", f"llm_monthly_budget_usd_{team_id}")
        if ceiling_raw is None:
            return
        try:
            ceiling = float(ceiling_raw)
        except (ValueError, TypeError):
            return
        # T-175-06: reject 0 and negative ceilings (0 means unlimited, negative is invalid)
        if ceiling <= 0:
            return

        now = datetime.now(UTC)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        year_month = now.strftime("%Y-%m")

        async with async_session_scope() as session:
            # Monthly spend SUM for this team
            stmt = select(func.coalesce(func.sum(LLMCostRecord.cost_usd), 0.0)).where(
                LLMCostRecord.team_id == team_id,
                LLMCostRecord.created_at >= month_start,
            )
            total_usd = (await session.exec(stmt)).one()

            if total_usd < ceiling * 0.8:
                return

            # D-03a: Atomic conditional insert -- prevents TOCTOU race condition.
            # The WHERE NOT EXISTS subquery ensures only one row per source_entity_id.
            # If two concurrent calls race, only one INSERT will find no existing row.
            alert_key = f"budget_alert:{team_id}:{year_month}:80pct"
            new_id = str(uuid4())
            await session.exec(
                text(
                    "INSERT INTO notification_records "
                    "(id, user_id, title, body, category, source_module, source_entity_id, is_read, created_at) "
                    "SELECT :id, :user_id, :title, :body, :category, :source_module, :source_entity_id, :is_read, :created_at "
                    "WHERE NOT EXISTS ("
                    "  SELECT 1 FROM notification_records WHERE source_entity_id = :source_entity_id"
                    ")"
                ),
                {
                    "id": new_id,
                    "user_id": "__system__",
                    "title": "LLM budget warning: 80% ceiling reached",
                    "body": (
                        f"Team LLM spend has reached ${total_usd:.2f} of "
                        f"${ceiling:.2f} monthly ceiling ({total_usd / ceiling * 100:.0f}%). "
                        f"Configure budget at PUT /config/platform/llm_monthly_budget_usd_{team_id}"
                    ),
                    "category": "warning",
                    "source_module": "llm_cost",
                    "source_entity_id": alert_key,
                    "is_read": False,
                    "created_at": utc_now(),
                },
            )
            await session.commit()
            _log.info(
                "budget_alert_checked",
                team_id=team_id,
                total_usd=total_usd,
                ceiling=ceiling,
            )
    except (
        sqlalchemy.exc.SQLAlchemyError,
        RuntimeError,
        ValueError,
        TypeError,
        OSError,
    ):
        # Fire-and-forget contract (docstring): budget alerting must never fail
        # cost recording, so the realistic leak set (DB, registry connection,
        # arithmetic) is logged and swallowed rather than propagated.
        _log.warning("budget_alert_check_failed", team_id=team_id, exc_info=True)
