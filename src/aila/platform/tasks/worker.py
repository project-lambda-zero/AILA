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
from aila.platform.contracts._common import utc_now
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

# fix §62 — every datetime comparison in this module routes through
# ``utc_now()`` (timezone-aware) instead of ``datetime.now(tz=UTC)`` /
# ``datetime.utcnow()``. The pattern is enforced by importing ONLY
# ``timedelta`` and the platform's tz-aware ``utc_now`` from
# ``contracts._common``; bare ``datetime`` is intentionally absent
# at module scope, so any future re-introduction of tz-naive comparisons
# triggers an immediate import-time failure.

# fix §44 — grace seconds for the cron reaper are env-driven. The
# historical cron value (600s) is the default; boot path still
# hard-codes 30s for legitimate reasons (see `_on_startup`). Operators
# can override via PLATFORM_WORKER_HEARTBEAT_GRACE_S for the cron
# only.
try:
    _REAPER_CRON_GRACE_S: int = int(
        os.environ.get("PLATFORM_WORKER_HEARTBEAT_GRACE_S", "600"),
    )
except ValueError:
    _REAPER_CRON_GRACE_S = 600

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


async def _sweep_orphan_queued_tasks() -> None:
    """Reap TaskRecord rows marked QUEUED in DB but absent from the
    ARQ Redis queue.

    Observed live: after worker crashes, manual zombie kills, or ARQ
    job-record deletion (e.g. operator-driven queue purge), the DB
    keeps the TaskRecord at QUEUED but nothing in Redis will ever
    dequeue it. The UI shows "queued" forever; the operator has no
    visibility into the desync until they ask why a target isn't
    progressing.

    Strategy: for each non-cron QUEUED row in the DB, check if its
    job_id is present in any arq:queue:<track> zset. If absent across
    all tracks, flip to FAILED with reason orphan_not_in_arq_queue.
    Tasks queued within the last 60s are skipped — they may have been
    enqueued in DB but not yet pushed to Redis by an in-flight submit().
    """
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        return

    import redis.asyncio as aioredis  # noqa: PLC0415

    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    try:
        # fix §61 — collect job_ids per ARQ queue track instead of one
        # global set. UUID collisions are vanishingly rare, but the
        # legacy second-colon-filter (skips arq:queue:foo:dlq style
        # keys) is too permissive for any future ARQ extension that
        # adds a sub-key namespace. Keying by track makes the sweep's
        # "is this row present in ARQ?" check track-specific so the
        # TaskRecord.track column drives the lookup.
        present_by_track: dict[str, set[str]] = {}
        async for key in client.scan_iter(match="arq:queue:*", count=50):
            key_str = key.decode() if isinstance(key, bytes) else str(key)
            track_suffix = key_str.removeprefix("arq:queue:")
            # Skip cron / health-check keys (not real job queues).
            if ":" in track_suffix:
                continue
            members = await client.zrange(key_str, 0, -1)
            present_by_track.setdefault(track_suffix, set())
            for m in members:
                present_by_track[track_suffix].add(
                    m.decode() if isinstance(m, bytes) else str(m),
                )
        # Union for the path that still needs cross-queue presence
        # (e.g. the row's track was renamed). Kept as a SECONDARY check
        # so a renamed track doesn't false-reap a live job, but the
        # PRIMARY decision is the per-track membership above.
        present_in_arq: set[str] = set().union(*present_by_track.values()) if present_by_track else set()

        # Find candidate DB rows: QUEUED rows that are past the boot-time
        # grace window. fix §45 — at boot the api_router may have INSERTed
        # the row but not yet pushed to ARQ Redis (ZADD races the INSERT
        # commit). Skipping rows younger than 10s prevents the boot sweep
        # against reaping legitimate in-flight submissions.
        recency_cutoff = utc_now() - timedelta(seconds=60)
        boot_grace_cutoff = utc_now() - timedelta(seconds=10)
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(TaskRecord).where(
                    TaskRecord.status == TaskStatus.QUEUED,
                    TaskRecord.created_at < recency_cutoff,
                    TaskRecord.created_at < boot_grace_cutoff,
                )
            )).all()
            reaped = 0
            now = utc_now()
            # fix §70 — per-row UoW so a constraint failure on one
            # task doesn't roll back the others' commits. We still
            # bulk-commit by accumulating into the session, but if a
            # row violates a constraint we flush per-row and skip the
            # bad one.
            for rec in rows:
                if rec.id.startswith("cron:"):
                    continue
                # fix §61 — primary check: per-track membership. Only
                # fall back to the cross-track union when the row's
                # track isn't represented in the scan (renamed track,
                # new track ARQ hasn't bound a zset for yet).
                track_members = present_by_track.get(rec.track or "")
                if track_members is not None:
                    if rec.id in track_members:
                        continue
                elif rec.id in present_in_arq:
                    continue
                rec.status = TaskStatus.FAILED
                rec.completed_at = now
                rec.updated_at = now
                team_marker = (
                    f" team_id={rec.team_id}" if getattr(rec, "team_id", None) else ""
                )
                # fix §68 — team_id surfaced in the audit message so
                # multi-tenant deployments can grep reaped rows by
                # owning team. The filter itself stays cross-team
                # (operator confirmed acceptable per cutover spec).
                rec.error = (
                    "Reaped by orphan-queued sweep — DB row marked queued "
                    "but absent from arq:queue:* zsets. ARQ has no record "
                    "of this job; operator can resume via the owning "
                    f"domain's resume endpoint.{team_marker}"
                )
                try:
                    session.add(rec)
                    await session.flush()
                    reaped += 1
                    TASK_ZOMBIES_REAPED_TOTAL.labels(
                        reason="orphan_queued_not_in_arq",
                    ).inc()
                except Exception as exc:  # noqa: BLE001 — best-effort per-row
                    _log.warning(
                        "_sweep_orphan_queued_tasks: row %s flush failed "
                        "(%s); skipping", rec.id, exc,
                    )
                    await session.rollback()
            if reaped:
                await session.commit()
                _log.warning(
                    "_sweep_orphan_queued_tasks: reaped %d DB-queued rows "
                    "with no ARQ entry",
                    reaped,
                )
    finally:
        try:
            await client.aclose()
        except (OSError, RuntimeError):
            pass


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

    Step ordering — fix §57 — orphan_queued runs BEFORE cursor_reaper so a
    cursor whose TaskRecord just flipped to FAILED in this tick is cleared
    the SAME tick instead of lingering for ~60s.

    Exception filter — fix §56 — every sub-sweep catches the broad
    ``Exception`` instead of a tuple that misses SQLAlchemy errors. The
    cron's whole point is best-effort: a DB hiccup in one sub-sweep
    must NOT crash the remaining sub-sweeps in the chain.
    """
    try:
        await _reconcile_orphan_arq_locks()
    except Exception as exc:  # noqa: BLE001 — best-effort sub-sweep
        _log.warning("reaper: arq lock reconciliation failed: %s", exc, exc_info=True)
    try:
        # Cron context: env-driven grace (default 600s, override with
        # PLATFORM_WORKER_HEARTBEAT_GRACE_S — fix §44) AND skip
        # heartbeat=None tasks. ARQ doesn't auto-extend the in-progress
        # lock for tasks that don't call ctx.heartbeat() during a long await
        # — single-shot tool calls like run_function_ranking (one
        # ~5-min audit_mcp HTTP request) end up with lock_missing +
        # heartbeat=None mid-flight even though the worker is still
        # healthily awaiting the response. Killing them there destroyed
        # the firefox ranking task multiple times today. Boot path
        # still uses defaults (30s grace, reap_null_heartbeat=True)
        # because heartbeat=None before boot is unambiguous zombie
        # evidence.
        await _sweep_orphan_running_tasks(
            grace_seconds=_REAPER_CRON_GRACE_S,
            reap_null_heartbeat=False,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort sub-sweep
        _log.warning("reaper: orphan running-task sweep failed: %s", exc, exc_info=True)
    # fix §X-platform-layering — iterate the generic sweep registry instead
    # of hardcoding module-specific imports. Modules register their sweeps
    # at import time via aila.platform.tasks.sweeps.register_periodic_sweep.
    # The platform worker has zero awareness of which modules own which
    # sweeps; this restores the "platform never imports from modules"
    # invariant (CLAUDE.md non-negotiable rule #5).
    from .sweeps import all_periodic_sweeps  # noqa: PLC0415
    for sweep_name, sweep_fn in all_periodic_sweeps().items():
        try:
            result = await sweep_fn()
            if result:
                # Truthy result is logged at INFO. The sweep owns its
                # own structured-detail logging; the platform just
                # surfaces "this sweep produced work this tick" for
                # the operator-visible cron log.
                _log.info("reaper.%s: %s", sweep_name, result)
        except Exception as exc:  # noqa: BLE001 — best-effort sub-sweep
            _log.warning(
                "reaper.%s: failed: %s", sweep_name, exc, exc_info=True,
            )

    # fix §57 — orphan_queued runs BEFORE cursor_reaper. A QUEUED row
    # absent from ARQ gets flipped to FAILED first; the cursor cleanup
    # in the next step then sees the terminal status and clears the
    # cursor immediately rather than the next minute's tick.
    try:
        await _sweep_orphan_queued_tasks()
    except Exception as exc:  # noqa: BLE001 — best-effort sub-sweep
        _log.warning("reaper: orphan-queued sweep failed: %s", exc, exc_info=True)
    try:
        # fix §58 — sweep covers ALL FOUR reserved terminal cursor states,
        # not just __crashed__.
        from .cursor_reaper import sweep_orphan_crashed_cursors  # noqa: PLC0415
        cleared = await sweep_orphan_crashed_cursors()
        if cleared:
            _log.info("reaper: cleared %d orphan terminal cursors", cleared)
    except Exception as exc:  # noqa: BLE001 — best-effort sub-sweep
        _log.warning("reaper: cursor cleanup failed: %s", exc, exc_info=True)
    # fix §123 — idempotency-cache expired-row purge wired into the same
    # cron loop so the table doesn't accumulate stale rows forever. The
    # purge is best-effort and never crashes the cron tick.
    try:
        from aila.platform.llm.idempotency_cache import (  # noqa: PLC0415
            run_purge_expired_cron,
        )
        purged = await run_purge_expired_cron()
        if purged:
            _log.info(
                "reaper.idempotency_cache: purged %d expired rows", purged,
            )
    except Exception as exc:  # noqa: BLE001 — best-effort sub-sweep
        _log.warning(
            "reaper: idempotency cache purge failed: %s", exc, exc_info=True,
        )


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
        now = utc_now()
        fresh_cutoff = now - timedelta(seconds=REAPER_ZOMBIE_THRESHOLD_S)
        heartbeat_cutoff = now - timedelta(seconds=REAPER_HEARTBEAT_THRESHOLD_S)
        lock_jobs = {k: k[len(ARQ_IN_PROGRESS_PREFIX):] for k in lock_keys}
        job_ids = list(lock_jobs.values())

        async with async_session_scope() as session:
            records = (await session.exec(
                select(TaskRecord).where(TaskRecord.id.in_(job_ids))  # type: ignore[attr-defined]
            )).all()
            by_id = {r.id: r for r in records}

        now = utc_now()
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
        now = utc_now()
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

    # Trigger every builtin module's create_module() so module-owned
    # periodic sweeps (vr.stage_tracker, vr.branch_reaper,
    # vr.masvs_parent_reconciler, vr.finalize, vr.stall_recovery, etc.)
    # register themselves with the platform sweep registry. Without
    # this, the worker process only sees platform-level sweeps; module
    # sweeps never fire on the cron, even though the SAME registration
    # works in the backend (which calls register_builtin_modules via
    # build_platform_runtime).
    #
    # Diagnosed 2026-06-14: 15 Yanimda investigations stalled for 11+
    # hours because vr.stall_recovery never fired in any worker. Cron
    # reaper was iterating an EMPTY list of VR sweeps. Manual call to
    # the sweep function showed examined=15 / enqueued=90 would have
    # been ready — sweep was correct, just never triggered.
    try:
        from aila.platform.modules import load_builtin_modules  # noqa: PLC0415
        load_builtin_modules()
        _log.info("ARQ on_startup: registered builtin module sweeps")
    except Exception as exc:  # noqa: BLE001 — non-fatal, worker still runs
        _log.warning(
            "ARQ on_startup: builtin module registration failed: %s",
            exc, exc_info=True,
        )

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


async def _sweep_orphan_running_tasks(
    grace_seconds: int = 30,
    reap_null_heartbeat: bool = True,
) -> None:
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
    now = utc_now()
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
            # by the cron — a freshly-claimed task may sit at
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
                    # Three-state reconciliation:
                    #   (a) arq:in-progress:<id>  — delete to free the
                    #       worker slot (3-source-of-truth drift root
                    #       cause; throttles max_jobs by N for 1hr)
                    #   (b) TaskRecord.status      — transition to
                    #       CANCELLED so consumers asking 'is this
                    #       task active?' get a consistent NO. The
                    #       cursor (current_state) is the live source
                    #       of truth for resumption; TaskRecord is
                    #       just the audit log.
                    #   (c) workflow_state_cursor — untouched, owns
                    #       the next-resume position.
                    try:
                        await client.delete(f"{ARQ_IN_PROGRESS_PREFIX}{rec.id}")
                    except (OSError, TimeoutError, RuntimeError) as exc:
                        _log.warning(
                            "worker.reverse_sweep: failed to delete leaked "
                            "in-progress key for %s: %s", rec.id, exc,
                        )
                    rec.status = TaskStatus.CANCELLED.value
                    rec.completed_at = utc_now()
                    session.add(rec)
                    _log.info(
                        "worker.reverse_sweep: task_id=%s SKIPPED — workflow "
                        "cursor is resumable (D-86); status -> CANCELLED, "
                        "in-progress lock cleared",
                        rec.id,
                    )
                    # Re-enqueue a fresh ARQ job with the same fn+kwargs so
                    # the workflow engine actually picks the resumable cursor
                    # back up. Without this step the cursor sits resumable
                    # forever and the investigation visibly stalls: the
                    # sweep clears the in-progress lock, but no code path
                    # ever schedules the next turn.
                    try:
                        fn_short = (
                            rec.fn_path.rsplit(".", 1)[-1]
                            if rec.fn_path else None
                        )
                        try:
                            re_kwargs = (
                                json.loads(rec.kwargs_json)
                                if rec.kwargs_json else {}
                            )
                        except (TypeError, ValueError) as kw_exc:
                            _log.warning(
                                "worker.reverse_sweep: kwargs_json malformed "
                                "for %s (%s); re-enqueue skipped",
                                rec.id, kw_exc,
                            )
                            fn_short = None
                            re_kwargs = None
                        queue_key = (
                            ARQ_QUEUE_KEY_TEMPLATE.format(track=rec.track)
                            if rec.track else None
                        )
                        if fn_short and queue_key and re_kwargs is not None:
                            from uuid import uuid4 as _uuid4

                            from arq import create_pool as _create_pool
                            from arq.connections import RedisSettings as _RedisSettings
                            arq_pool = await _create_pool(
                                _RedisSettings.from_dsn(redis_url)
                            )
                            try:
                                new_job_id = str(_uuid4())
                                await arq_pool.enqueue_job(
                                    fn_short,
                                    _queue_name=queue_key,
                                    _job_id=new_job_id,
                                    **re_kwargs,
                                )
                                _log.info(
                                    "worker.reverse_sweep: re-enqueued "
                                    "resumable workflow %s as %s "
                                    "(fn=%s queue=%s)",
                                    rec.id, new_job_id, fn_short, queue_key,
                                )
                            finally:
                                try:
                                    await arq_pool.close()
                                except (OSError, TimeoutError, RuntimeError) as close_exc:
                                    _log.debug(
                                        "worker.reverse_sweep: arq pool close "
                                        "failed for %s: %s",
                                        rec.id, close_exc,
                                    )
                    except (OSError, TimeoutError, RuntimeError) as enq_exc:
                        _log.warning(
                            "worker.reverse_sweep: re-enqueue failed for %s: %s",
                            rec.id, enq_exc,
                        )
                    continue
                reason = (
                    "lock_missing_or_stale_heartbeat"
                    if lock_exists else "lock_missing"
                )
                if not reap_null_heartbeat and hb is None:
                    # Periodic mode: tasks with heartbeat=None cannot be
                    # safely judged as zombies WITHIN the ARQ job timeout
                    # window. ARQ's lock TTL can expire on legitimately
                    # long-running tasks that don't call ctx.heartbeat()
                    # (e.g. single-shot async tool calls like
                    # run_function_ranking that delegate to a 5-min
                    # audit_mcp.fuzzing_targets HTTP request). Lock-missing
                    # in that scenario is normal, not evidence of death.
                    #
                    # BUT: a task that started more than ARQ_JOB_TIMEOUT_S
                    # ago with no heartbeat is definitively dead. ARQ caps
                    # any single job run at ARQ_JOB_TIMEOUT_S (3600s); past
                    # that, ARQ has already killed and abandoned the
                    # execution. The DB row sitting at RUNNING forever is
                    # the bug this branch fixes (observed live: BIND9
                    # ingestion task stuck 199 min before manual kill).
                    if started is not None:
                        if started.tzinfo is None:
                            started_norm = started.replace(tzinfo=UTC)
                        else:
                            started_norm = started
                        from aila.platform.tasks.constants import ARQ_JOB_TIMEOUT_S  # noqa: PLC0415
                        arq_giveup_cutoff = now - timedelta(
                            seconds=ARQ_JOB_TIMEOUT_S + 120,
                        )
                        if started_norm < arq_giveup_cutoff:
                            # Fall through to the reap block below.
                            reason = "stale_no_heartbeat_past_arq_timeout"
                        else:
                            continue
                    else:
                        # No started_at AND no heartbeat → can't judge → safer to skip.
                        continue
                # Mirror of the null-heartbeat case: a task that DID write
                # at least one heartbeat but hasn't written one in past
                # ARQ_JOB_TIMEOUT_S is just as dead as one that never
                # wrote any. ARQ would have killed the execution at
                # timeout regardless. Observed live: task 7ca90d7d wrote
                # one heartbeat at T+30s, then the worker died; reaper
                # skipped it for 174 min because hb was not None.
                if hb is not None:
                    from aila.platform.tasks.constants import ARQ_JOB_TIMEOUT_S  # noqa: PLC0415
                    if hb.tzinfo is None:
                        hb_norm = hb.replace(tzinfo=UTC)
                    else:
                        hb_norm = hb
                    hb_giveup_cutoff = now - timedelta(seconds=ARQ_JOB_TIMEOUT_S + 120)
                    if hb_norm < hb_giveup_cutoff:
                        # Override reason with explicit stale-heartbeat tag
                        # so the failure record makes the diagnosis clear.
                        reason = "stale_heartbeat_past_arq_timeout"
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
            # Always commit — the D-86 resumable-workflow path also
            # mutates rec.status (-> CANCELLED) and re-enqueues, but
            # never increments `reaped`. Without an unconditional
            # commit those cancellations got rolled back at session
            # close, leaving the same task in RUNNING for the next
            # cron pass and the same D-86 cancel-then-rollback cycle.
            # Observed live: task 7ca90d7d survived 174 min of cron
            # passes before manual kill.
            await session.commit()
            if reaped:
                _log.warning(
                    "worker.reverse_sweep: reaped %d orphan running task(s)",
                    reaped,
                )
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
