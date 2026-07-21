"""Platform maintenance actions registered with AutomationRegistry.

These are platform-owned background jobs that run without team context
(team_id=None). They are submitted through the standard TaskQueue path
when their automation schedule fires.

AUTO-06: Platform maintenance jobs use module_id='platform'.

Finding 46-7 (see .run/designs/DESIGN_automation_events_reporting.md):
platform_health_check used to be a log-only no-op. It now probes the
platform's cheap in-process dependencies (async DB engine round-trip
and Redis PING when a pool is configured) and returns a structured
HealthReport. The call is best-effort: any probe failure records that
dependency as unhealthy and continues; nothing bubbles out of the
health check itself. Callsite audit: no reader consumes the return
value today (runner.py submits this action via TaskQueue and only
records last_run_result), so widening the return type from None to
HealthReport is additive and safe.
"""
from __future__ import annotations

__all__ = [
    "DependencyState",
    "DependencyStatus",
    "HealthReport",
    "platform_health_check",
    "register_maintenance_actions",
]

import asyncio
import logging
from datetime import UTC, datetime
from typing import Literal, TypedDict

import sqlalchemy.exc
from redis.exceptions import RedisError
from sqlalchemy import text

from aila.platform.automation.registry import AutomationRegistry
from aila.platform.services.redis_pool import get_redis, pool_available
from aila.storage.database import async_session_scope

_log = logging.getLogger(__name__)


# Redis PING wall-clock deadline. A wedged pool must not hang the whole
# health check; any timeout here is captured as an unhealthy Redis. Set
# generously (5s) so a briefly-loaded Redis on a slow host still passes.
_REDIS_PING_TIMEOUT_S: float = 5.0


# Named-exception isolation tuples. Each probe records its own failure
# and returns a status dict; nothing bubbles out of platform_health_check.
# Bare `except Exception` is banned by the honesty audit (rule 33), so
# every reachable failure class is enumerated. On Python 3.11+
# asyncio.TimeoutError aliases the built-in TimeoutError, so listing
# TimeoutError once covers both.
_DB_PROBE_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    ConnectionError,
)


_REDIS_PROBE_ERRORS: tuple[type[BaseException], ...] = (
    RedisError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    ConnectionError,
)


DependencyState = Literal["healthy", "unhealthy", "skipped"]


class DependencyStatus(TypedDict):
    """Status of a single platform dependency probed by the health check.

    status: healthy | unhealthy | skipped. "skipped" means the dependency
        was not exercised (e.g. no Redis pool initialized in a dev
        deployment). Skipped dependencies do not vote in the overall
        verdict.
    error: on unhealthy, the exception class name of the failure. Message
        bodies are omitted per the platform's redaction policy for
        structured summaries; the full traceback lives in the worker log.
    """

    status: DependencyState
    error: str | None


class HealthReport(TypedDict):
    """Structured result returned by platform_health_check.

    healthy: True iff every non-skipped dependency reports healthy. A
        dependency that self-skipped (not configured) does not by itself
        make the platform unhealthy.
    checked_at: ISO 8601 timestamp in UTC when the probe suite ran.
    dependencies: per-name status map. Current keys are 'database' and
        'redis'; the shape is stable so downstream consumers (dashboards,
        AppendJournal readers, later scheduling gates) can rely on it.
    """

    healthy: bool
    checked_at: str
    dependencies: dict[str, DependencyStatus]


async def _probe_database() -> DependencyStatus:
    """Run SELECT 1 through the pooled async engine.

    Any known upstream / connection / query failure is captured as
    unhealthy with the exception class name in ``error``. The full
    exception is logged with ``exc_info`` at WARN so the operator log
    keeps the traceback while callers receive only the redacted class
    name.
    """
    try:
        async with async_session_scope() as session:
            await session.execute(text("SELECT 1"))
    except _DB_PROBE_ERRORS as exc:
        _log.warning(
            "platform_health_check: database probe failed (%s)",
            type(exc).__name__,
            exc_info=exc,
        )
        return {"status": "unhealthy", "error": type(exc).__name__}
    return {"status": "healthy", "error": None}


async def _probe_redis() -> DependencyStatus:
    """PING the shared Redis pool if one is initialized.

    Returns status='skipped' when no pool is available (init_redis_pool
    was never called or the URL env var was empty). Redis is a soft
    dependency on single-node dev deployments; DESIGN section 3.2
    documents the pool_available fallback and this probe honours it.
    """
    if not pool_available():
        return {"status": "skipped", "error": None}
    try:
        async with get_redis() as client:
            await asyncio.wait_for(client.ping(), timeout=_REDIS_PING_TIMEOUT_S)
    except _REDIS_PROBE_ERRORS as exc:
        _log.warning(
            "platform_health_check: redis probe failed (%s)",
            type(exc).__name__,
            exc_info=exc,
        )
        return {"status": "unhealthy", "error": type(exc).__name__}
    return {"status": "healthy", "error": None}


async def platform_health_check(**kwargs: object) -> HealthReport:
    """Probe platform dependencies; return a structured HealthReport.

    Best-effort and non-crashing: a failed probe records that dependency
    as unhealthy but does not raise out of the call. Current probes:
    async DB engine (SELECT 1) and Redis (PING). No reader consumes the
    return value today; the runner submits this action via
    TaskQueue.submit and only records last_run_result. The structured
    shape is defined so later consumers (dashboards, AppendJournal
    readers, scheduling gates) can rely on it without a second migration.

    ``kwargs`` is retained so the runner's ``target_name`` /
    ``execution_context`` injection continues to work; only
    ``target_name`` is read here, and only for logging.

    Not decorated with ``@platform_task`` per DESIGN section 3.6: the
    runner-owned submit path already invokes bare callables, and the
    decorator would create the __name__ collision documented in
    CLAUDE.md common mistake 19.
    """
    target = kwargs.get("target_name", "platform")

    # The probes isolate their own expected failures, but the health check
    # must never raise even if a probe escapes its own guard (a bug, or an
    # unenumerated failure class). A probe that raises past its guard is
    # captured here as unhealthy so the report is always well-formed.
    try:
        db_status = await _probe_database()
    except _DB_PROBE_ERRORS as exc:
        _log.warning(
            "platform_health_check: database probe raised past its guard (%s)",
            type(exc).__name__,
            exc_info=exc,
        )
        db_status = {"status": "unhealthy", "error": type(exc).__name__}
    try:
        redis_status = await _probe_redis()
    except _REDIS_PROBE_ERRORS as exc:
        _log.warning(
            "platform_health_check: redis probe raised past its guard (%s)",
            type(exc).__name__,
            exc_info=exc,
        )
        redis_status = {"status": "unhealthy", "error": type(exc).__name__}

    dependencies: dict[str, DependencyStatus] = {
        "database": db_status,
        "redis": redis_status,
    }
    # A skipped probe never marks the platform unhealthy by itself; only
    # a positively-unhealthy dependency vetoes the overall verdict.
    healthy = all(
        dep["status"] != "unhealthy" for dep in dependencies.values()
    )

    report: HealthReport = {
        "healthy": healthy,
        "checked_at": datetime.now(UTC).isoformat(),
        "dependencies": dependencies,
    }
    _log.info(
        "Platform health check completed target=%s healthy=%s db=%s redis=%s",
        target,
        healthy,
        db_status["status"],
        redis_status["status"],
    )
    return report


def register_maintenance_actions(registry: AutomationRegistry) -> None:
    """Register all platform-owned maintenance actions.

    Called during app startup after the AutomationRegistry is created.
    Each action here runs with team_id=None (platform scope).
    """
    registry.register_action(
        action_id="platform.health_check",
        handler_fn=platform_health_check,
        description="Platform health check and cleanup",
        module_id="platform",
    )
    _log.info("Platform maintenance actions registered")
