"""Centralised ARQ purge for investigations transitioning to a terminal
state (fix §27).

:func:`purge_arq_jobs_for_investigation` is the SINGLE platform entry
point for clearing queued ARQ jobs that target a specific investigation.
Four call sites historically existed:

  * ``POST /vr/investigations/{id}/pause`` (api_router -- Phase B owns)
  * ``investigation_emit`` cap-exceeded sweep (Phase C deletes the block)
  * ``OutcomeDispatcher._update_outcome_status`` sibling halt (W2 E1)
  * ``investigation_reaper`` cap sweep (Phase C deletes the file)

All four route through this function -- none re-implements the purge
primitive. :func:`purge_for_investigation` is a thin alias kept for
future-callers that prefer the shorter name.

Layout knowledge (ARQ + AILA platform/tasks/constants.py):
  * ``arq:queue:<track>`` is a zset, member=job_id, score=enqueue_ms
  * ``arq:job:<job_id>`` is a pickled dict with key ``k`` holding
    the kwargs (including ``investigation_id``)
  * ``arq:in-progress:<job_id>`` is the per-job worker lock; held
    only while a worker is executing the job

We never delete in-progress locks here (the worker handles those on
exit). We only purge queued jobs that have not yet been dequeued.

Race window: between the zrem and the delete of the job blob, a worker
that already dequeued the job (BEFORE the zrem fired) still has the
job_id in memory and will fetch the (not-yet-deleted) blob and run the
job. The ``investigation_setup`` STATUS_LOCKED guard catches that
execution and exits cleanly -- the dequeued worker's run becomes a
no-op. See §60 for the full race analysis; the comment at the
zrem/delete pair below is the canonical mitigation reference.
"""
from __future__ import annotations

import logging
import os
import pickle
from typing import Any

from aila.platform.tasks.constants import (
    ARQ_JOB_PREFIX,
    ARQ_QUEUE_KEY_TEMPLATE,
    CONFIG_KEY_REDIS_URL,
    CONFIG_NS_PLATFORM,
)

_log = logging.getLogger(__name__)

__all__ = [
    "purge_arq_jobs_for_investigation",
    "purge_for_investigation",
]


async def purge_arq_jobs_for_investigation(
    investigation_id: str,
    *,
    track: str = "vr",
    redis_url: str | None = None,
) -> dict[str, int]:
    """Drop queued ARQ jobs whose ``kwargs.investigation_id`` matches.

    Returns a count summary so callers can log how much was reclaimed.
    Best-effort: any Redis / unpickle error is logged and skipped -- the
    investigation_setup STATUS_LOCKED guard still catches anything we
    miss here, so a partial purge is safe.
    """
    if redis_url is None:
        redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
        if not redis_url:
            try:
                from aila.platform.services.config_registry import (
                    ConfigRegistry,
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
        import redis.asyncio as _aredis
    except ImportError:
        _log.warning("purge_arq_jobs_for_investigation: redis library missing")
        return {"scanned": 0, "matched": 0, "purged_jobs": 0}

    client = _aredis.from_url(redis_url, decode_responses=False)
    queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=track)

    scanned = 0
    matched = 0
    purged_jobs = 0
    try:
        # Snapshot the queue. ZRANGE with WITHSCORES isn't needed --
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
                obj: Any = pickle.loads(blob)
                kwargs = obj.get("k") or obj.get("kwargs") or {}
                if not isinstance(kwargs, dict):
                    continue
                if kwargs.get("investigation_id") != investigation_id:
                    continue
                matched += 1
                # fix §60 -- dequeue-then-delete window (worker that
                # already dequeued before zrem will still find the blob
                # and execute it) is mitigated by investigation_setup's
                # STATUS_LOCKED guard at the start of the workflow turn,
                # NOT by this code. The order below (zrem THEN delete)
                # is the correct one: a future worker zpop after zrem
                # returns nothing, so the blob deletion is unobservable
                # to anyone except a worker that already had the id in
                # memory.
                removed = await client.zrem(queue_key, job_id)
                if removed:
                    await client.delete(job_key)
                    purged_jobs += 1
            except (
                pickle.UnpicklingError,
                KeyError,
                TypeError,
                ImportError,
                EOFError,
                AttributeError,
                ValueError,
            ) as exc:
                # fix §59 -- broaden the pickle catch. Old ARQ versions
                # pickled classes that no longer exist (ImportError),
                # truncated blobs raise EOFError, AttributeError fires
                # when ``obj.get`` is missing because the unpickle
                # produced a non-dict, and ValueError covers malformed
                # length bytes. All of these are "skip this job, keep
                # iterating", never "crash the whole purge".
                _log.debug(
                    "purge_arq_jobs_for_investigation: skipping job_id=%s "
                    "err=%s (%s)",
                    job_id, exc, type(exc).__name__,
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


# fix §27 -- alias under the shorter name from the cutover spec so
# future callers can converge on a single shape. Both names point at
# the same primitive; the centralisation claim is that NO other module
# implements ARQ purge logic -- they all go through here.
purge_for_investigation = purge_arq_jobs_for_investigation
