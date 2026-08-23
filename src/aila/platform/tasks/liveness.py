"""liveness -- the single "is a turn in flight" predicate for branch GC.

Both branch garbage-collection deciders consult THIS module before they
abandon or delete a branch:

  * the stale-branch abandon sweep in
    ``aila.platform.services.investigation_finalizers`` (investigation
    scope), and
  * the zero-turn loser hard-delete in
    ``aila.platform.workflows.persona_spawn`` (branch scope).

Why a shared predicate exists. A branch that is mid-turn on a slow
inference node still shows ``turn_count = 0`` and an unmoved
``updated_at`` for the whole turn, because both only advance when the
turn commits. A single recon turn on the self-hosted node measured the
better part of an hour. So ``turn_count`` and ``updated_at`` LIE about
liveness during a long turn, and a decider keying on them abandons a
live branch, which then gets hard-deleted, which FK-crashes the
in-flight message write and kills the run.

The only truthful signal is "a worker is running a task for this
investigation / branch right now". That is exactly what the worker
reaper (``worker._is_zombie``) uses to decide a ``RUNNING`` row is not a
zombie -- this module encodes the SAME two-tier freshness rule in the
SAME raw-SQL shape the reaper uses (``cursor_reaper`` /
``worker._sweep_orphan_running_tasks``), so the branch GC and the reaper
never disagree about a single running row. There is one answer to "is it
alive", not one answer per decider. When this module says a branch's
work is live, no decider may abandon or delete it; when it says the work
is gone, the normal GC proceeds.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import text as _sql_text

from aila.platform.contracts import utc_now
from aila.platform.tasks.constants import (
    REAPER_HEARTBEAT_THRESHOLD_S,
    REAPER_ZOMBIE_THRESHOLD_S,
)
from aila.platform.tasks.models import TaskStatus

__all__ = ["live_investigation_ids", "branch_has_live_task"]


# A ``RUNNING`` TaskRecord counts as live under the SAME two-tier rule
# ``worker._is_zombie`` uses, so the branch GC and the reaper agree on
# every running row:
#   * heartbeat present -> live while ``heartbeat_at`` is newer than
#     REAPER_HEARTBEAT_THRESHOLD_S (24h). ``heartbeat_at`` is stamped at
#     attempt start (hooks §90) and on every state commit, so a live turn
#     stays inside this window even when a single turn runs for many
#     minutes on the slow node.
#   * heartbeat NULL -> fall back to ``started_at`` newer than
#     REAPER_ZOMBIE_THRESHOLD_S (55m), the reaper's null-heartbeat rule.
#   * both NULL -> a row that has recorded neither timestamp is brand new;
#     treat it as live so a just-submitted turn is never GC'd out from
#     under itself.
_LIVE_TASK_SQL_PREDICATE = (
    "status = :running AND ("
    "  (heartbeat_at IS NOT NULL AND heartbeat_at > :hb_cutoff)"
    "  OR (heartbeat_at IS NULL AND started_at IS NOT NULL"
    "      AND started_at > :zombie_cutoff)"
    "  OR (heartbeat_at IS NULL AND started_at IS NULL)"
    ")"
)


def _freshness_binds() -> dict[str, Any]:
    now = utc_now()
    return {
        "running": TaskStatus.RUNNING.value,
        "hb_cutoff": now - timedelta(seconds=REAPER_HEARTBEAT_THRESHOLD_S),
        "zombie_cutoff": now - timedelta(seconds=REAPER_ZOMBIE_THRESHOLD_S),
    }


async def live_investigation_ids(
    session: Any,
    candidate_ids: Sequence[str] | None = None,
) -> set[str]:
    """Return the investigation ids that currently have a live task.

    Matches on the TYPED JSONB extract
    ``(kwargs_json::jsonb)->>'investigation_id'`` -- the same shape
    ``TaskQueue.enqueued_investigation_ids`` and the reconciler use -- so
    a UUID embedded in a different kwarg (``parent_investigation_id``
    etc.) never false-matches. ``candidate_ids`` narrows the scan to a
    known set in SQL; ``None`` returns every live investigation. The read
    runs inside the caller's ``session`` so it sees the same transaction
    the caller is about to write in.
    """
    binds = _freshness_binds()
    sql = (
        "SELECT DISTINCT (kwargs_json::jsonb)->>'investigation_id' AS inv "
        "FROM taskrecord "
        f"WHERE {_LIVE_TASK_SQL_PREDICATE} "
        "  AND (kwargs_json::jsonb)->>'investigation_id' IS NOT NULL"
    )
    if candidate_ids is not None:
        ids = [c for c in dict.fromkeys(candidate_ids) if c]
        if not ids:
            return set()
        sql += " AND (kwargs_json::jsonb)->>'investigation_id' = ANY(:cands)"
        binds["cands"] = ids
    rows = (
        await session.exec(_sql_text(sql).bindparams(**binds))
    ).mappings().all()
    return {r["inv"] for r in rows if r["inv"] is not None}


async def branch_has_live_task(session: Any, branch_id: str) -> bool:
    """True when a live task is running a turn on ``branch_id`` right now.

    Keyed on ``(kwargs_json::jsonb)->>'branch_id'`` -- sibling and
    auto-continue tasks carry the branch id on that path (the operator-
    initiated primary task carries only ``investigation_id`` and is never
    a hard-delete target, so branch-scoped is exact here). A True result
    means a hard-delete of this branch would race the turn's message
    write and FK-crash it; the caller must leave the row alone.
    """
    if not branch_id:
        return False
    binds = _freshness_binds()
    binds["bid"] = branch_id
    sql = (
        "SELECT 1 AS one FROM taskrecord "
        f"WHERE {_LIVE_TASK_SQL_PREDICATE} "
        "  AND (kwargs_json::jsonb)->>'branch_id' = :bid LIMIT 1"
    )
    row = (await session.exec(_sql_text(sql).bindparams(**binds))).first()
    return row is not None
