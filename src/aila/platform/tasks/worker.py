"""ARQ WorkerSettings + reaper + dead-letter persistence (Phase 179 rewrite)."""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from arq import cron
from arq.connections import RedisSettings
from sqlmodel import select

from aila.api.metrics import TASK_ZOMBIES_REAPED_TOTAL
from aila.platform.tasks.constants import (
    ARQ_DEAD_LETTER_KEY_TEMPLATE,
    ARQ_IN_PROGRESS_PREFIX,
    ARQ_JOB_PREFIX,
    ARQ_QUEUE_KEY_TEMPLATE,
    ARQ_RETRY_PREFIX,
    REAPER_HEARTBEAT_THRESHOLD_S,
    REAPER_ZOMBIE_THRESHOLD_S,
)
from aila.platform.tasks.hooks import _on_job_end, _on_job_start
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.template import _REGISTRY
from aila.storage.database import async_session_scope

__all__ = ["WorkerSettings", "reaper"]

# ``_persist_dead_letter`` is sibling-internal: imported by
# ``aila.platform.tasks.hooks._on_job_end`` to record terminal failures.
# It is intentionally absent from ``__all__`` because it is not part of the
# package's public surface.

_log = logging.getLogger(__name__)

_TERMINAL_STATUSES: frozenset[str] = frozenset({
    TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.DEAD_LETTER,
})


def _should_drop_lock(
    rec: TaskRecord | None,
    fresh_cutoff: datetime,
    heartbeat_cutoff: datetime,
) -> tuple[bool, str]:
    """Decide whether an arq:in-progress:* lock is reconciliable.

    Two staleness checks, most-specific first:
    1. If TaskRecord.heartbeat_at is set (engine is writing per-state
       heartbeats), a job is zombie if heartbeat_at < heartbeat_cutoff
       (default: now()-REAPER_HEARTBEAT_THRESHOLD_S = 24 hours).
    2. If heartbeat_at is None (pre-heartbeat code path or very first
       state not yet committed), fall back to started_at < fresh_cutoff
       (default: now()-REAPER_ZOMBIE_THRESHOLD_S = 55 minutes).
    """
    if rec is None:
        return True, "no_db_record"
    if rec.status in _TERMINAL_STATUSES:
        return True, f"db_status={rec.status}"
    if rec.status == TaskStatus.RUNNING:
        hb = rec.heartbeat_at
        if hb is not None:
            if hb.tzinfo is None:
                hb = hb.replace(tzinfo=UTC)
            if hb < heartbeat_cutoff:
                return True, "stale_heartbeat_at"
        else:
            started = rec.started_at
            if started is None:
                return True, "no_started_at"
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            if started < fresh_cutoff:
                return True, "stale_started_at"
    return False, ""


async def reaper(ctx: dict[str, object]) -> None:
    """ARQ cron — every minute. Reconciles orphan locks AND orphan TaskRecord rows.

    Two complementary sweeps:
      - ``_reconcile_orphan_arq_locks`` walks ``arq:in-progress:*`` keys and
        reaps tasks whose ARQ lock is still present but the owning worker
        is dead.
      - ``_sweep_orphan_running_tasks`` (also called at worker boot) does the
        reverse: walks DB rows in TaskStatus.RUNNING and reaps any whose
        ARQ lock has already been evicted. Without this in the periodic cron,
        phantom rows where the lock died but the DB row remained at RUNNING
        only got reaped at the next worker restart, blocking max_jobs
        until then.
    """
    try:
        await _reconcile_orphan_arq_locks()
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        _log.warning("reaper: arq lock reconciliation failed: %s", exc, exc_info=True)
    try:
        # Cron context: use a 10-minute grace so genuinely long-running
        # tool calls (audit_mcp cold-path index builds, multi-minute LLM
        # round-trips) don't get killed before their first heartbeat
        # lands. Firefox-scale fuzzing_targets cold path on audit_mcp
        # is ~5 minutes alone. Boot path keeps the 30s default.
        await _sweep_orphan_running_tasks(grace_seconds=600)
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        _log.warning("reaper: orphan running-task sweep failed: %s", exc, exc_info=True)


async def _reconcile_orphan_arq_locks() -> None:
    """Delete ``arq:in-progress:*`` keys whose TaskRecord is absent/terminal."""
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        return
    parsed = urlparse(redis_url)
    if parsed.scheme not in ("redis", "rediss"):
        return

    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    try:
        lock_keys: list[str] = []
        async for key in client.scan_iter(match=f"{ARQ_IN_PROGRESS_PREFIX}*", count=100):
            key_str = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
            # Exclude ARQ cron job locks (scheduler-managed, no TaskRecord backing).
            if key_str[len(ARQ_IN_PROGRESS_PREFIX):].startswith("cron:"):
                continue
            lock_keys.append(key_str)
        if not lock_keys:
            return
        now = datetime.now(tz=UTC)
        fresh_cutoff = now - timedelta(seconds=REAPER_ZOMBIE_THRESHOLD_S)
        heartbeat_cutoff = now - timedelta(seconds=REAPER_HEARTBEAT_THRESHOLD_S)
        lock_jobs = {k: k[len(ARQ_IN_PROGRESS_PREFIX):] for k in lock_keys}
        job_ids = list(lock_jobs.values())

        async with async_session_scope() as session:
            records = (await session.exec(
                select(TaskRecord).where(TaskRecord.id.in_(job_ids))  # type: ignore[attr-defined]
            )).all()
            by_id = {r.id: r for r in records}

        now = datetime.now(tz=UTC)
        tasks_to_fail: list[tuple[str, str]] = []  # (task_id, reason)

        for lock_key, job_id in lock_jobs.items():
            rec = by_id.get(job_id)
            drop, reason = _should_drop_lock(rec, fresh_cutoff, heartbeat_cutoff)
            if not drop:
                continue
            _log.warning("reaper.stale_in_progress_reconciled job_id=%s reason=%s", job_id, reason)
            for key in (lock_key, f"{ARQ_JOB_PREFIX}{job_id}", f"{ARQ_RETRY_PREFIX}{job_id}"):
                try:
                    await client.delete(key)
                except Exception as exc:
                    _log.debug("reaper: redis delete %s failed: %s", key, exc)
            if rec is not None:
                try:
                    await client.zrem(ARQ_QUEUE_KEY_TEMPLATE.format(track=rec.track), job_id)
                except Exception as exc:
                    _log.debug(
                        "reaper: redis zrem queue=%s job_id=%s failed: %s",
                        rec.track, job_id, exc,
                    )
                # Only flip non-terminal rows to FAILED. A TaskRecord already in a
                # terminal state (e.g. done, failed) means some earlier path
                # settled it; we just cleaned the Redis lock debris here.
                if rec.status not in _TERMINAL_STATUSES:
                    tasks_to_fail.append((rec.id, reason))
            TASK_ZOMBIES_REAPED_TOTAL.labels(reason="orphaned_arq_lock").inc()

        # Without this step the TaskRecord stays at ``running`` forever even
        # though Redis agrees the job is dead — the UI then shows investigations
        # / scans as "pending" or "running" indefinitely. Flip every reaped
        # task to FAILED in one commit so domain-layer reconcilers
        # (e.g. forensics_investigations pending → failed when task is failed)
        # can observe the change on the next GET.
        if tasks_to_fail:
            async with async_session_scope() as session:
                ids_to_update = [tid for tid, _ in tasks_to_fail]
                to_update = (await session.exec(
                    select(TaskRecord).where(TaskRecord.id.in_(ids_to_update))  # type: ignore[attr-defined]
                )).all()
                reason_by_id = dict(tasks_to_fail)
                for rec in to_update:
                    if rec.status in _TERMINAL_STATUSES:
                        continue
                    rec.status = TaskStatus.FAILED
                    rec.completed_at = now
                    rec.error = (
                        "Reaped by platform zombie-sweep — worker died mid-task "
                        f"(reason={reason_by_id.get(rec.id, 'unknown')})."
                    )
                    session.add(rec)
                    _log.warning(
                        "reaper.task_marked_failed task_id=%s reason=%s",
                        rec.id, reason_by_id.get(rec.id, "unknown"),
                    )
                await session.commit()
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            _log.debug("reaper: client.aclose() failed: %s", exc)


async def _persist_dead_letter(
    *,
    track: str,
    task_id: str,
    fn_path: str,
    fn_module: str,
    kwargs_json: str,
    user_id: str,
    error: str,
    attempts: int,
    exception_class: str,
) -> None:
    """Append a dead-letter entry to ``arq:dead-letter:{track}`` (bounded zset)."""
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        return

    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    try:
        now = datetime.now(tz=UTC)
        payload = json.dumps({
            "task_id": task_id, "track": track, "fn_path": fn_path,
            "fn_module": fn_module, "kwargs_json": kwargs_json,
            "user_id": user_id, "error": error[:2000], "attempts": attempts,
            "exception_class": exception_class,
            "dead_lettered_at": now.isoformat(),
        })
        key = ARQ_DEAD_LETTER_KEY_TEMPLATE.format(track=track)
        await client.zadd(key, {payload: now.timestamp()})
        await client.zremrangebyrank(key, 0, -1001)
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            _log.debug("dead_letter: client.aclose() failed: %s", exc)


# Registry bootstrap: scan all feature module packages and import their
# workflow/task.py so @platform_task decorators fire before WorkerSettings
# reads _REGISTRY.all_functions(). No module names are hard-coded here —
# the same pkgutil scan used by _discover_feature_module_factories() drives
# discovery so adding a new module never requires touching this file.
def _bootstrap_platform_tasks() -> None:
    import pkgutil

    try:
        import aila.modules as _modules_pkg
    except Exception:
        _log.warning("platform-task bootstrap: could not import aila.modules", exc_info=True)
        return

    for module_info in pkgutil.iter_modules(_modules_pkg.__path__, _modules_pkg.__name__ + "."):
        short_name = module_info.name.rsplit(".", 1)[-1]
        if not module_info.ispkg or short_name.startswith("_"):
            continue
        task_module = f"{module_info.name}.workflow.task"
        try:
            __import__(task_module)
        except ModuleNotFoundError:
            pass  # module has no workflow/task.py — fine
        except Exception:
            _log.warning("platform-task bootstrap: %s import failed", task_module, exc_info=True)


def _legacy_arq_functions() -> list[Any]:
    """Non-@platform_task ARQ callables (reports, discovery). Phase 182 migrates."""
    fns: list[Any] = []
    for mod_name, fn_name in (
        ("aila.platform.tasks.report_tasks", "generate_scheduled_report_job"),
        ("aila.platform.tasks.discovery", "network_discovery_job"),
        ("aila.platform.tasks.entrypoints", "run_platform_handle"),
    ):
        try:
            fns.append(getattr(__import__(mod_name, fromlist=[fn_name]), fn_name))
        except Exception:
            _log.warning("legacy import %s failed", mod_name, exc_info=True)
    return fns


_bootstrap_platform_tasks()


# --- ARQ WorkerSettings ----------------------------------------------------
_redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:6379")
_parsed = urlparse(_redis_url)
_db = int(_parsed.path.lstrip("/")) if _parsed.path and _parsed.path != "/" else 0


async def _on_startup(ctx: dict[str, Any]) -> None:
    """Dispose async engines created on the wrong event loop (Windows fix).

    On Windows, Python 3.12+ defaults to ProactorEventLoop. asyncpg connections
    created on that loop become unusable after we switch to SelectorEventLoop via
    WindowsSelectorEventLoopPolicy. Any engine in _ASYNC_ENGINES that was created
    during module import (ProactorEventLoop context) must be disposed INSIDE the
    worker's SelectorEventLoop so the pool drains cleanly and the next DB access
    creates fresh connections bound to the correct loop.
    """
    from aila.logging_config import configure_logging
    configure_logging()

    import sys

    if sys.platform != "win32":
        return

    from aila.storage import database as _db_module

    engines = list(_db_module._ASYNC_ENGINES.values())
    for eng in engines:
        try:
            await eng.dispose()
        except Exception as exc:
            # Connection may already be dead (ProactorEventLoop closed) — ignore.
            _log.debug("on_startup: stale engine dispose failed: %s", exc)
    _db_module._ASYNC_ENGINES.clear()
    _log.debug("ARQ on_startup: cleared %d stale async engine(s) (Windows loop migration)", len(engines))

    await _sweep_orphan_running_tasks()


async def _workflow_cursor_is_resumable(session: Any, task_id: str) -> bool:
    """Return True iff a workflow_state_cursor row exists for ``task_id``
    AND its ``current_state`` is not a reserved terminal state.

    Workflow tasks store their resumable position in workflow_state_cursor
    keyed by run_id == task_id. If the cursor exists and the state is
    non-terminal, the next worker pickup can resume the workflow from
    that state — reaping the TaskRecord would defeat the durability
    contract (D-86). Terminal states (__succeeded__/__failed__/
    __cancelled__/__crashed__) mean the workflow already completed
    one way or another; the TaskRecord SHOULD be reaped in that case.
    """
    from sqlalchemy import text as _sql_text

    row = (await session.exec(
        _sql_text(
            "SELECT current_state FROM workflow_state_cursor WHERE run_id = :rid"
        ).bindparams(rid=task_id),
    )).first()
    if row is None:
        return False
    current = str(row[0]) if row[0] is not None else ""
    return current not in (
        "__succeeded__", "__failed__", "__cancelled__", "__crashed__",
    )


async def _sweep_orphan_running_tasks(grace_seconds: int = 30) -> None:
    """Reap orphan tasks at startup using the same rules as the cron reaper,
    PLUS a reverse sweep that catches tasks whose ARQ lock was already
    evicted (the lock-iterator sweep misses those because there's no lock
    key left to see).

    Safety: this does **not** blanket-fail every RUNNING task — it only
    flips rows whose ARQ in-progress lock is missing. If a peer worker is
    genuinely running the job, its lock is alive and we leave it alone.
    """
    try:
        await _reconcile_orphan_arq_locks()
    except Exception:
        _log.warning("worker.startup_sweep reconciliation failed", exc_info=True)

    # Reverse sweep at startup: TaskRecord rows claiming RUNNING that cannot
    # possibly be owned by any live worker.
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        return
    parsed = urlparse(redis_url)
    if parsed.scheme not in ("redis", "rediss"):
        return

    import redis.asyncio as aioredis
    from sqlmodel import select as _select

    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    now = datetime.now(tz=UTC)
    try:
        async with async_session_scope() as session:
            running = (await session.exec(
                _select(TaskRecord).where(TaskRecord.status == TaskStatus.RUNNING)
            )).all()
            if not running:
                return
            reaped = 0
            # Healthy workers write a heartbeat every few seconds. Any task
            # whose heartbeat is older than (now - grace_seconds) is
            # considered orphan-evidence. ``grace_seconds`` is 30s at boot
            # (no live worker can have touched anything older than itself,
            # narrow window OK) and longer (300s) when called periodically
            # from the cron — a freshly-claimed task may sit at
            # status=RUNNING with heartbeat=NULL for several seconds before
            # the worker's first heartbeat lands, and a 30s window risks
            # killing it before it gets a chance to write one.
            stale_cutoff = now - timedelta(seconds=grace_seconds)
            for rec in running:
                hb = rec.heartbeat_at
                if hb is not None and hb.tzinfo is None:
                    hb = hb.replace(tzinfo=UTC)
                started = rec.started_at
                if started is not None and started.tzinfo is None:
                    started = started.replace(tzinfo=UTC)
                # Three orphan signals, most conservative first:
                #   (1) ARQ in-progress lock missing → no worker ever reclaimed
                #   (2) heartbeat older than startup cutoff → prior worker died
                #   (3) no heartbeat AND started_at older than the same cutoff
                lock_exists = await client.exists(f"{ARQ_IN_PROGRESS_PREFIX}{rec.id}")
                if lock_exists and hb is not None and hb > stale_cutoff:
                    # Lock present AND heartbeat is fresh — legit, peer owns it.
                    continue
                if hb is not None and hb > stale_cutoff:
                    # Lock missing but heartbeat is brand-new: very unlikely
                    # edge case, skip to avoid false positives.
                    continue
                # D-86: DurableStateMachine workflows persist via
                # workflow_state_cursor. Reaping such a task on stale
                # heartbeat is wrong — the cursor still carries the live
                # state and the next worker run can resume from it. Only
                # reap workflow tasks if the cursor itself reached a
                # terminal reserved state.
                if await _workflow_cursor_is_resumable(session, rec.id):
                    _log.info(
                        "worker.reverse_sweep: task_id=%s SKIPPED — workflow "
                        "cursor is resumable (D-86)", rec.id,
                    )
                    continue
                reason = (
                    "lock_missing_or_stale_heartbeat"
                    if lock_exists else "lock_missing"
                )
                if started is not None and hb is None and started > stale_cutoff:
                    # Task was submitted literally a second ago and hasn't
                    # had time to write its first heartbeat. Don't reap.
                    continue
                rec.status = TaskStatus.FAILED
                rec.completed_at = now
                rec.error = (
                    f"Reaped by sweep ({reason}) at {now.isoformat()} — "
                    f"task heartbeat ({hb.isoformat() if hb else 'never'}) "
                    f"and started_at ({started.isoformat() if started else 'never'}) "
                    f"both predate stale_cutoff ({stale_cutoff.isoformat()}, "
                    f"grace={grace_seconds}s)."
                )
                session.add(rec)
                reaped += 1
                _log.warning(
                    "worker.reverse_sweep: task_id=%s reason=%s — marking failed",
                    rec.id, reason,
                )
            if reaped:
                await session.commit()
                _log.warning("worker.reverse_sweep: reaped %d orphan running task(s)", reaped)
    except Exception:
        _log.warning("worker.reverse_sweep failed", exc_info=True)
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            _log.debug("worker.reverse_sweep: client.aclose() failed: %s", exc)


class WorkerSettings:
    """ARQ worker entry point (D-07..D-14)."""

    redis_settings = RedisSettings(
        host=_parsed.hostname or "127.0.0.1",
        port=_parsed.port or 6379,
        database=_db,
        password=_parsed.password,
    )
    queue_name = "arq:queue:vulnerability"
    # Legacy ARQ functions preserved for non-@platform_task callers
    # (scheduled reports + network discovery). Phase 182 re-homes them.
    functions: list[Any] = _REGISTRY.all_functions() + _legacy_arq_functions()
    cron_jobs = [cron(reaper, second=0)]
    max_tries = 3
    job_timeout = 3600
    keep_result = 3600
    retry_jobs = True
    allow_abort_jobs = True
    health_check_interval = 60
    on_startup = staticmethod(_on_startup)
    on_job_start = staticmethod(_on_job_start)
    on_job_end = staticmethod(_on_job_end)
