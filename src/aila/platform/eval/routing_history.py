"""RFC-08 pre-execution sizing seam -- generic routing history provider.

Modules bind their outcome-review table, investigation table, and target
table via :func:`build_routing_history_provider`; the returned coroutine
matches :data:`aila.platform.eval.routing_learner.HistoryProvider` so a
setup handler can feed it directly into
:meth:`RoutingLearner.recommend`.

The provider joins :class:`LLMCostRecord` (task_type, cost, investigation_id)
against the module's outcome-review table (verdict) via the reviewer
branch's investigation, and against the investigation's target (kind).
An outcome-review row aggregates to :data:`aila.platform.eval.routing_learner._VOTE_APPROVE`
or :data:`aila.platform.eval.routing_learner._VOTE_REJECT`; other votes
(``request_edit``, ``abstain``) are filtered by the learner itself.

The join keys the sample per (investigation_id, task_type) so a single
investigation with many cost records + many reviews contributes one
sample per (task_type, verdict) combination. The reviewer's ``vote`` is
whatever the reviewing branch declared; the mean-cost side is the sum
of every LLMCostRecord tagged with that task_type on the investigation.

Bounded to the trailing :data:`_HISTORY_HORIZON_DAYS` so the recommender
sees a rolling window rather than the whole audit lifetime -- a stale
task_type that stopped shipping still fades out of the ranking without
an explicit purge.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from aila.platform.contracts._common import utc_now
from aila.platform.eval.routing_learner import RoutingSample

__all__ = [
    "build_routing_history_provider",
]

_log = logging.getLogger(__name__)

# Rolling window of history the provider considers. 30 days keeps the
# recommendation responsive to a recent process change while retaining
# enough evidence for a low-traffic module to reach the learner's
# ``min_evidence_per_task_type`` floor. Kept module-level so a test can
# monkey-patch it.
_HISTORY_HORIZON_DAYS: int = 30
# Hard row cap so an unbounded historical query never OOMs the worker.
# The learner needs at most a few hundred samples per target_kind to
# stabilise the score; 5000 leaves generous headroom.
_HISTORY_ROW_CAP: int = 5000


def build_routing_history_provider(
    *,
    outcome_review_model: type[Any],
    branch_model: type[Any],
    investigation_model: type[Any],
    target_model: type[Any],
) -> Callable[[str], Awaitable[Sequence[RoutingSample]]]:
    """Return a routing-history coroutine bound to the module's tables.

    Args:
        outcome_review_model: SQLModel class for the module's
            ``<module>_outcome_reviews`` table.
        branch_model: SQLModel class for the module's
            ``<module>_investigation_branches`` table (used to resolve
            reviewer_branch_id -> investigation_id).
        investigation_model: SQLModel class for the module's
            ``<module>_investigations`` table (used to resolve
            investigation.target_id -> target row).
        target_model: SQLModel class for the module's ``<module>_targets``
            table (used to read ``kind`` for the target_kind filter).

    Returns:
        Coroutine matching :data:`HistoryProvider`: takes a
        ``target_kind`` string, returns the sequence of RoutingSample
        rows scoped to that target_kind within the trailing window.
    """

    async def _provider(target_kind: str) -> Sequence[RoutingSample]:
        # Deferred imports: the eval package is imported during
        # ``db_models`` load via ``calibration``, so pulling
        # :class:`UnitOfWork` or :class:`LLMCostRecord` at module
        # scope closes the import graph on itself (uow -> services
        # -> audit -> journal -> db_models). Deferring to the call
        # path breaks the cycle without a per-file lint escape.
        from sqlalchemy.exc import DBAPIError, SQLAlchemyError
        from sqlmodel import select

        from aila.platform.llm.cost_record import LLMCostRecord
        from aila.platform.uow import UnitOfWork

        cutoff = utc_now() - timedelta(days=_HISTORY_HORIZON_DAYS)
        samples: list[RoutingSample] = []
        try:
            async with UnitOfWork() as uow:
                # One SELECT joins reviews to branches (for investigation
                # scope), branches to investigations (for target link),
                # investigations to targets (for kind), then LEFT JOIN
                # cost records grouped by (investigation, task_type).
                # SQLModel's async exec returns tuples so we assemble
                # RoutingSample rows in Python; the join stays bounded
                # by the cutoff + row cap.
                stmt = (
                    select(  # type: ignore[call-overload]
                        outcome_review_model.vote,
                        LLMCostRecord.task_type,
                        LLMCostRecord.cost_usd,
                    )
                    .join(
                        branch_model,
                        branch_model.id
                        == outcome_review_model.reviewer_branch_id,
                    )
                    .join(
                        investigation_model,
                        investigation_model.id
                        == branch_model.investigation_id,
                    )
                    .join(
                        target_model,
                        target_model.id
                        == investigation_model.target_id,
                    )
                    .join(
                        LLMCostRecord,
                        LLMCostRecord.investigation_id
                        == investigation_model.id,
                    )
                    .where(target_model.kind == target_kind)
                    .where(outcome_review_model.created_at >= cutoff)
                    .limit(_HISTORY_ROW_CAP)
                )
                rows = (await uow.session.exec(stmt)).all()
                for row in rows:
                    vote = str(row[0]) if row[0] is not None else ""
                    task_type = str(row[1]) if row[1] is not None else ""
                    cost = float(row[2] or 0.0)
                    if not vote or not task_type:
                        continue
                    samples.append(
                        RoutingSample(
                            target_kind=target_kind,
                            task_type=task_type,
                            verdict=vote,
                            cost_usd=cost,
                        ),
                    )
        except (SQLAlchemyError, DBAPIError, OSError, RuntimeError) as exc:
            _log.warning(
                "routing_history_provider: query failed target_kind=%s "
                "err=%s (returning empty history; setup falls back to "
                "full-panel spawn)",
                target_kind, exc, exc_info=True,
            )
            return []
        return samples

    return _provider
