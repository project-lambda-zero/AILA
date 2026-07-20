"""Per-team monthly LLM budget alerting (Phase 175 / D-03, D-03a).

Checks team's monthly spend against configured ceiling.  Emits a
deduplicated NotificationRecord when the 80% threshold is crossed and
raises :class:`BudgetExceededError` when spend reaches or exceeds 100%
of the configured ceiling (D-08 hard stop / design finding #38-3.3).

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
from aila.platform.llm.errors import BudgetExceededError
from aila.storage.database import async_session_scope

if TYPE_CHECKING:
    from aila.storage.registry import ConfigRegistry

__all__ = ["BudgetExceededError", "check_monthly_budget"]

_log = structlog.get_logger(__name__)


async def check_monthly_budget(team_id: str | None, registry: ConfigRegistry) -> None:
    """Check team's monthly LLM spend; alert at 80% and hard-stop at 100%.

    Args:
        team_id: Team identifier. None for admin/standalone calls (skipped).
        registry: ConfigRegistry for ceiling lookup (async -- uses await).

    Behaviour:
      * Silent no-op when ``team_id`` is None, when no ceiling is configured,
        or when the ceiling resolves to <= 0 (0 means unlimited).
      * Emits a deduplicated ``NotificationRecord`` (category='warning') when
        the team's month-to-date spend reaches or exceeds 80% of the ceiling.
      * Raises :class:`BudgetExceededError` when spend reaches or exceeds
        100% of the ceiling (D-08 hard stop / #38-3.3). The raise is emitted
        AFTER the best-effort alert-insert guard so a genuine over-budget
        signal is never swallowed by a widened infra-exception tuple.

    Infra failures (DB, registry connection, arithmetic) during the alert
    lookup or insert are logged and swallowed -- callers are guaranteed that
    a transient infra glitch never blocks cost recording. Only the explicit
    :class:`BudgetExceededError` propagates.
    """
    if team_id is None:
        return

    ceiling: float | None = None
    total_usd: float | None = None
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
        # Fire-and-forget contract for INFRA leaks: budget alerting must never
        # fail cost recording on a DB/registry/arithmetic glitch, so the
        # realistic leak set is logged and swallowed. BudgetExceededError is
        # NOT in this tuple and is raised only from the guarded block below --
        # a genuine over-budget signal always propagates.
        _log.warning("budget_alert_check_failed", team_id=team_id, exc_info=True)

    # #38-3.3: hard stop when month-to-date spend reaches or exceeds 100% of
    # the operator-configured ceiling (D-08). Raised OUTSIDE the infra-guard
    # above so BudgetExceededError is never accidentally swallowed even if a
    # future refactor widens the exception tuple. Only fires when both ceiling
    # and total_usd resolved cleanly inside the guard -- an infra failure
    # skips the check and yields the alert-only historical behaviour, keeping
    # cost recording resilient to transient DB glitches.
    if ceiling is not None and total_usd is not None and total_usd >= ceiling:
        raise BudgetExceededError(
            f"Monthly LLM budget exceeded for team {team_id}: "
            f"${total_usd:.2f} of ${ceiling:.2f}. Configure "
            f"PUT /config/platform/llm_monthly_budget_usd_{team_id} "
            f"to raise or reset the ceiling."
        )
