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
    "run_calibration_sweep",
    "run_calibrator_trainer_sweep",
    "run_semantic_consolidation_sweep",
    "run_skill_library_sweep",
    "tool_storage_prune",
]

import asyncio
import logging
from datetime import UTC, datetime
from typing import Literal, TypedDict

import sqlalchemy.exc
from redis.exceptions import RedisError
from sqlalchemy import text

from aila.platform.automation.registry import AutomationRegistry
from aila.platform.eval.calibration_sweep import (
    run_calibration_sweep,
    run_calibrator_trainer_sweep,
)
from aila.platform.services.memory import (
    run_semantic_consolidation_sweep,
    run_skill_library_sweep,
)
from aila.platform.services.redis_pool import get_redis, pool_available
from aila.platform.tools.pruner import ToolStoragePruneReport, prune_tool_storage
from aila.storage.database import async_session_scope
from aila.storage.registry import ConfigRegistry

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


async def tool_storage_prune(**kwargs: object) -> ToolStoragePruneReport:
    """Prune platform-owned tool storage tables (#56).

    Thin wrapper around :func:`aila.platform.tools.pruner.prune_tool_storage`
    that constructs a fresh :class:`ConfigRegistry` per tick so operator
    overrides on the ``platform.tool_storage_*`` knobs are picked up
    without a worker restart. See the pruner module for the full
    per-half semantics; this callable exists only so the automation
    runner's ``bare-callable`` submit path can find it under a stable
    ``action_id`` (``platform.tool_storage_prune``).

    Not decorated with ``@platform_task`` for the same reason
    :func:`platform_health_check` isn't -- DESIGN section 3.6 documents
    the runner-owned bare-callable path, and the decorator would
    trigger the ``__name__`` collision documented in CLAUDE.md common
    mistake 19.
    """
    _ = kwargs
    return await prune_tool_storage(config_registry=ConfigRegistry())


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
    registry.register_action(
        action_id="platform.tool_storage_prune",
        handler_fn=tool_storage_prune,
        description=(
            "Prune expired and overflowing rows from platform tool storage "
            "(permanent memory + generic artifacts) per the "
            "tool_storage_* platform config knobs"
        ),
        module_id="platform",
    )
    # RFC-08 step 2 wiring: aggregate recent per-outcome_kind accept/reject
    # review history into versioned CalibrationProposalRecord rows. Advisory
    # only -- proposals are persisted; the module's live threshold is never
    # mutated by this action. Inert until an operator creates a schedule via
    # POST /automation/schedules; the register call alone does not run the
    # sweep. Mirrors the platform.tool_storage_prune registration model.
    registry.register_action(
        action_id="platform.calibration_proposer_sweep",
        handler_fn=run_calibration_sweep,
        description=(
            "Aggregate recent per-outcome_kind accept/reject review history "
            "across module-owned outcome + review tables into versioned "
            "CalibrationProposalRecord rows (RFC-08 step 2). Proposal only -- "
            "the live confidence threshold is never mutated by this action; "
            "promoting a proposal into the runtime config is a separate, "
            "gated admin step per the propose-and-gate contract."
        ),
        module_id="platform",
    )
    # RFC-08 Tier D fit path: complements the proposer sweep by fitting
    # per-task_type CalibratorVersionRecord candidates from the same
    # accept/reject review history the proposer aggregates. Candidate
    # only -- promotion to active is a separate quorum-gated admin step.
    registry.register_action(
        action_id="platform.calibrator_trainer_sweep",
        handler_fn=run_calibrator_trainer_sweep,
        description=(
            "Fit per-task_type confidence calibrator candidates from "
            "accept/reject review history"
        ),
        module_id="platform",
    )
    # Issue #150 semantic-tier memory consolidation. Reads recent
    # terminal-status investigations from the shared investigation
    # ledger, distills each into a few de-contextualized factual
    # statements via a cheap LLM route, and writes them to the module's
    # live-read semantic namespace in the pgvector knowledge store.
    # Inert until an :class:`AutomationScheduleRecord` targets this
    # action_id -- the seed_schedules module wires a nightly default so
    # a fresh install still runs the sweep without operator setup.
    registry.register_action(
        action_id="platform.semantic_consolidation_sweep",
        handler_fn=run_semantic_consolidation_sweep,
        description=(
            "Distill recent resolved-investigation ledger traces into "
            "de-contextualized semantic facts and store them in the "
            "existing pgvector knowledge index under each module's "
            "workspace-scoped semantic namespace"
        ),
        module_id="platform",
    )
    # Issue #150 procedural (skill-library) tier. Reads recently-resolved
    # investigations with a confirmed outcome (approved + dispatched
    # outcome row at STRONG/EXACT/MEDIUM confidence), extracts one
    # ``(problem_shape -> approach)`` skill per investigation, and writes
    # it to the team-scoped ``skill.team.<team_id>`` namespace (or the
    # ``skill.global`` fallback on single-tenant installs). Idempotent
    # per investigation via the dedup key ``skill:<inv_id>``, so a
    # repeat tick with nothing new is a bounded, LLM-free no-op.
    # Registered as its own action rather than folded into the semantic
    # sweep so operators can pin the two tiers to different cheap
    # models, cadences, or per-tick caps without dragging the other
    # tier along.
    registry.register_action(
        action_id="platform.skill_library_sweep",
        handler_fn=run_skill_library_sweep,
        description=(
            "Extract one (problem_shape -> approach) skill per "
            "recently-resolved confirmed-outcome investigation and store "
            "it in the existing pgvector knowledge index under the "
            "team-scoped skill.* namespace"
        ),
        module_id="platform",
    )
    _log.info("Platform maintenance actions registered")
