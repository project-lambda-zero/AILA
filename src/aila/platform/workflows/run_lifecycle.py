"""WorkflowRunRecord lifecycle for runs the durable engine drives.

``WorkflowRunRecord.status`` and ``completed_at`` summarise a run for
operators, report listings, and health probes. For a run driven by
:class:`~aila.platform.workflows.engine.DurableStateMachine` they follow the
outermost-run rule:

* The run row is ``running`` with ``completed_at`` NULL from its first attempt
  until the outermost terminal boundary.
* A terminal transition committed by the engine closes the run, except
  ``__succeeded__`` of a dispatcher definition
  (``WorkflowDefinition.is_dispatcher``). That terminal is the handoff to an
  inner definition under the same ``run_id``; the inner definition's terminal
  closes the run. When the dispatch layer cannot hand
  off (no selection, or a selection that is not a ``dispatches_to`` key) it
  closes the run ``failed`` itself
  (``aila.platform.tasks.template._run_two_phase_dispatch``).
* Terminal cursor to run status: ``__succeeded__`` -> ``completed``;
  ``__failed__`` and ``__crashed__`` -> ``failed``; ``__cancelled__`` ->
  ``cancelled``. ``completed`` and ``failed`` are the values the chat
  orchestrator's ``_finalize_run`` writes for chat runs, so both writers share
  one status vocabulary.
* Recording is idempotent: a row already in a terminal status keeps its status
  and ``completed_at``. A terminal retry or a repeated caller never moves the
  recorded outcome.
* Starting an attempt on a finalized row reopens it (:func:`reopen_run`): a
  fresh cursor after the reaper cleared a terminal one, or a phase handoff.
  Without that the new attempt's outcome would be absorbed by the previous
  terminal status.
* The task wrapper's exception exits in ``aila.platform.tasks.template``
  (``BaseException``, ``TimeoutError``, ``CancelledError``, an arq ``Retry``,
  and ``WorkflowConflictError`` from the engine's concurrency checks) do not
  finalize: the cursor stays non-terminal and ARQ may retry, so the run stays
  ``running``, matching its cursor.

Both helpers run on the caller's session and never commit, so the run row and
the cursor move in the same transaction.
"""
from __future__ import annotations

from typing import Final

import sqlalchemy as sa
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.platform.contracts._common import utc_now
from aila.storage.db_models import WorkflowRunRecord

from .types import (
    RESERVED_CANCELLED,
    RESERVED_CRASHED,
    RESERVED_FAILED,
    RESERVED_SUCCEEDED,
    WorkflowDefinition,
)

__all__ = ["finalize_run", "reopen_run"]

_RUN_STATUS_BY_TERMINAL: Final[dict[str, str]] = {
    RESERVED_SUCCEEDED: "completed",
    RESERVED_FAILED: "failed",
    RESERVED_CRASHED: "failed",
    RESERVED_CANCELLED: "cancelled",
}

# Sorted for a stable IN-list; membership, not order, drives the predicates.
_TERMINAL_RUN_STATUSES: Final[tuple[str, ...]] = tuple(
    sorted(set(_RUN_STATUS_BY_TERMINAL.values()))
)

# Core table: the UPDATE runs in the caller's transaction and leaves ORM objects
# in the caller's session untouched.
_RUNS = WorkflowRunRecord.__table__  # type: ignore[attr-defined]


async def finalize_run(
    session: AsyncSession,
    run_id: str,
    definition: WorkflowDefinition,
    terminal_cursor: str,
) -> None:
    """Record the outcome ``terminal_cursor`` maps to on the run row, once.

    No-op for a cursor with no status mapping (a custom terminal state) and for
    ``__succeeded__`` of a dispatcher definition, which hands off to an inner
    definition instead of ending the run. Otherwise the row moves to the mapped
    status with ``completed_at`` set, unless it already holds a terminal status.
    Does not commit.
    """
    status = _RUN_STATUS_BY_TERMINAL.get(terminal_cursor)
    if status is None or (definition.is_dispatcher and terminal_cursor == RESERVED_SUCCEEDED):
        return
    await session.execute(
        sa.update(_RUNS)
        .where(_RUNS.c.id == run_id, _RUNS.c.status.not_in(_TERMINAL_RUN_STATUSES))
        .values(status=status, completed_at=utc_now())
    )


async def reopen_run(session: AsyncSession, run_id: str) -> None:
    """Return a finalized run row to ``running`` with ``completed_at`` NULL.

    The engine calls this when it starts an attempt on ``run_id`` (a fresh
    cursor or a phase handoff), so that attempt's outcome is recorded instead of
    being absorbed by the previous terminal status. No-op for a row that is still
    running. Does not commit.
    """
    await session.execute(
        sa.update(_RUNS)
        .where(_RUNS.c.id == run_id, _RUNS.c.status.in_(_TERMINAL_RUN_STATUSES))
        .values(status="running", completed_at=None)
    )
