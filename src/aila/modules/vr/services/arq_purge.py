"""Purge pending ARQ jobs that target a paused / completed / failed
investigation, so the worker does not later dequeue them, run
investigation_setup, log a STATUS_LOCKED exit, and consume a queue
slot for zero forward progress.

The reactive guard at ``investigation_setup.py`` (added in commit
``f4ae7f6``) is the safety net: it catches dequeued jobs whose
investigation has flipped state since enqueue. The proactive purge
here removes the jobs from the queue in the first place, so:
  * the worker is not woken up to immediately exit
  * ``arq:queue:vr`` reflects "actual pending work" rather than
    "actual pending work + bookkeeping"
  * the operator's pause feels like a stop, not a delayed soft-stop

Layout knowledge (ARQ + AILA platform/tasks/constants.py):
  * ``arq:queue:<track>`` is a zset, member=job_id, score=enqueue_ms
  * ``arq:job:<job_id>`` is a pickled dict with key ``k`` holding
    the kwargs (including ``investigation_id``)
  * ``arq:in-progress:<job_id>`` is the per-job worker lock; held
    only while a worker is executing the job

We never delete in-progress locks here (the worker handles those on
exit). We only purge queued jobs that have not yet been dequeued.

Called from three sites:
  1. ``POST /vr/investigations/{id}/pause`` (api_router)
  2. ``investigation_emit`` cap_exceeded sweep
  3. ``OutcomeDispatcher._update_outcome_status`` sibling halt
"""
from __future__ import annotations

import logging
import pickle
from typing import Any

from aila.platform.tasks.constants import (
    ARQ_JOB_PREFIX,
    ARQ_QUEUE_KEY_TEMPLATE,
)

__all__ = ["purge_arq_jobs_for_investigation"]

_log = logging.getLogger(__name__)


async def purge_arq_jobs_for_investigation(
    investigation_id: str,
    *,
    track: str = "vr",
    redis_url: str | None = None,
) -> dict[str, int]:
    """Drop queued ARQ jobs whose ``kwargs.investigation_id`` matches.

    Returns a count summary so callers can log how much was reclaimed.
    Best-effort: any Redis / unpickle error is logged and skipped — the
    investigation_setup STATUS_LOCKED guard still catches anything we
    miss here, so a partial purge is safe.
    """
    if redis_url is None:
        import os  # noqa: PLC0415
        redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
        if not redis_url:
            try:
                from aila.platform.services.config_registry import (  # noqa: PLC0415
                    ConfigRegistry,
                )
                from aila.platform.tasks.constants import (  # noqa: PLC0415
                    CONFIG_KEY_REDIS_URL,
                    CONFIG_NS_PLATFORM,
                )
                registry = ConfigRegistry()
                redis_url = await registry.get(
                    CONFIG_NS_PLATFORM, CONFIG_KEY_REDIS_URL,
                )
            except (ImportError, AttributeError, RuntimeError):
                redis_url = None
    if not redis_url:
        return {"scanned": 0, "matched": 0, "purged_jobs": 0}

    try:
        import redis.asyncio as _aredis  # noqa: PLC0415
    except ImportError:
        _log.warning("purge_arq_jobs_for_investigation: redis library missing")
        return {"scanned": 0, "matched": 0, "purged_jobs": 0}

    client = _aredis.from_url(redis_url, decode_responses=False)
    queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=track)

    scanned = 0
    matched = 0
    purged_jobs = 0
    try:
        # Snapshot the queue. ZRANGE with WITHSCORES isn't needed —
        # we only need member ids. Cap at 10k to bound work; in
        # practice the queue rarely exceeds a few hundred entries.
        job_ids: list[bytes] = await client.zrange(queue_key, 0, 9999)
        for raw in job_ids:
            scanned += 1
            job_id = raw.decode() if isinstance(raw, bytes) else str(raw)
            job_key = f"{ARQ_JOB_PREFIX}{job_id}"
            try:
                blob = await client.get(job_key)
                if blob is None:
                    continue
                obj: Any = pickle.loads(blob)  # noqa: S301 — ARQ-owned pickle
                kwargs = obj.get("k") or obj.get("kwargs") or {}
                if not isinstance(kwargs, dict):
                    continue
                if kwargs.get("investigation_id") != investigation_id:
                    continue
                matched += 1
                # Drop from queue first, then delete the job record.
                # Order matters: if zrem fails, the worker might still
                # try to fetch the (now-deleted) job_key and crash.
                removed = await client.zrem(queue_key, job_id)
                if removed:
                    await client.delete(job_key)
                    purged_jobs += 1
            except (pickle.UnpicklingError, KeyError, TypeError) as exc:
                _log.debug(
                    "purge_arq_jobs_for_investigation: skipping job_id=%s err=%s",
                    job_id, exc,
                )
                continue
    finally:
        try:
            await client.aclose()
        except (OSError, RuntimeError):
            pass

    if matched > 0:
        _log.info(
            "arq_purge investigation=%s track=%s scanned=%d matched=%d purged=%d",
            investigation_id, track, scanned, matched, purged_jobs,
        )
    return {"scanned": scanned, "matched": matched, "purged_jobs": purged_jobs}
