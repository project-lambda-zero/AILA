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
    "run_retrieval_eval_sweep",
    "run_semantic_consolidation_sweep",
    "run_shadow_report_sweep",
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

# Retrieval-eval sweep (#140) and shadow-report sweep (#141) live in
# ``maintenance.py`` so all bare-callable action handlers stay in one
# module (DESIGN section 3.6). Both are deferred-import from the
# specific action bodies below to keep API startup light: neither
# machinery is exercised unless the corresponding automation schedule
# is active.

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
    # RFC #140 activation: replay every registered retrieval benchmark
    # through the live routed retriever and record a
    # ``RetrievalRunRecord`` (verdict='baseline_only' report-mode --
    # never gates promotion). Inert until an operator schedules the
    # ``platform.retrieval_eval_sweep`` action_id.
    registry.register_action(
        action_id="platform.retrieval_eval_sweep",
        handler_fn=run_retrieval_eval_sweep,
        description=(
            "Replay registered retrieval benchmarks through the live "
            "KnowledgeService.retrieve_routed path and record scored "
            "RetrievalRunRecord rows. Report-mode -- verdicts are "
            "persisted for regression tracking but never gate promotion"
        ),
        module_id="platform",
    )
    # RFC #141 activation: run a ShadowReport for every ACTIVE shadow
    # assignment in the lifecycle_canary_assignments table. Default-off
    # in seed_schedules.py so existing operator-initiated behavior is
    # preserved; an operator enabling the schedule gets continuous
    # shadow-evidence accrual for every candidate the lifecycle
    # controller has shadowed.
    registry.register_action(
        action_id="platform.shadow_report_sweep",
        handler_fn=run_shadow_report_sweep,
        description=(
            "Run a shadow report for every ACTIVE lifecycle shadow "
            "assignment (kind='shadow', state='active'). Each report "
            "samples recent traffic, replays under the shadow candidate, "
            "and writes one ShadowReportRecord + one metrics-update "
            "LifecycleTransitionRecord per (key, version) pair"
        ),
        module_id="platform",
    )
    _log.info("Platform maintenance actions registered")


# ---------------------------------------------------------------------------
# RFC #140 -- retrieval eval sweep.
#
# Enumerates registered retrieval benchmarks (latest-per-key by default)
# and replays each through the live routed retriever, recording a
# scored ``RetrievalRunRecord`` per benchmark. Report-mode: no
# comparison baseline is supplied so ``verdict='baseline_only'`` for
# every run -- the RFC explicitly wants "report first, not a hard
# block" so the sweep never rejects a promotion.
#
# Operator-supplied ``action_kwargs_json`` on the schedule row MAY
# carry:
#
# * ``namespace_patterns_by_key``: ``{benchmark_key: [namespace_pattern, ...]}``.
#   REQUIRED per benchmark -- the platform does not know which
#   knowledge namespace an operator-authored benchmark targets. A
#   benchmark whose key is absent from this mapping is SKIPPED with a
#   ``missing_namespaces`` entry in ``errors``.
# * ``min_score``: relevance floor forwarded to ``retrieve_routed``
#   (float in [0, 1]); default 0.3.
# * ``route``: retrieval route forwarded to ``retrieve_routed``
#   (``simple`` | ``hybrid`` | ...); default ``simple``.
# * ``benchmark_limit``: max distinct benchmarks replayed per tick
#   (int > 0); default 50.
# * ``benchmark_keys``: optional list restricting the sweep to a
#   subset of registered keys.
#
# Each stage isolates its own failures: an unknown-benchmark read that
# fails does not stop later keys, a run that raises does not stop the
# next benchmark. The sweep NEVER raises; the returned report carries
# the error trail so the schedule's ``last_run_result`` snapshot is
# self-describing.
# ---------------------------------------------------------------------------


class RetrievalEvalSweepReport(TypedDict):
    """Structured result of one ``run_retrieval_eval_sweep`` invocation."""

    benchmarks_seen: int
    benchmarks_replayed: int
    benchmarks_skipped: int
    runs_persisted: int
    errors: list[str]


_RETRIEVAL_SWEEP_ACTOR: str = "platform.retrieval_eval_sweep"

# Isolation tuple for the retrieval sweep. Same posture as the
# calibration sweep's ``_SWEEP_ERRORS``: every realistic infra fault on
# the read / replay / persist path is captured so one benchmark's
# failure does not abort the whole tick. Bare ``except Exception`` is
# banned by honesty audit rule 33.
_RETRIEVAL_SWEEP_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    LookupError,
    ArithmeticError,
    ConnectionError,
)


def _retrieval_coerce_int(raw: object, default: int) -> int:
    """Best-effort int cast for schedule-supplied kwargs."""
    if raw is None:
        return default
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _retrieval_coerce_float(raw: object, default: float) -> float:
    """Best-effort float cast for schedule-supplied kwargs."""
    if raw is None:
        return default
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _retrieval_coerce_str_list(raw: object) -> list[str]:
    """Validate a ``list[str]`` schedule override; junk falls back to []."""
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for entry in raw:
        if isinstance(entry, str) and entry.strip():
            out.append(entry.strip())
    return out


def _retrieval_coerce_namespace_map(
    raw: object,
) -> dict[str, list[str]]:
    """Validate an operator-supplied ``namespace_patterns_by_key`` override.

    Expected shape ``{benchmark_key: [namespace_pattern, ...]}``. Any
    entry whose value is not a non-empty list of strings is dropped so
    a malformed override never crashes the sweep.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, patterns in raw.items():
        if not isinstance(key, str) or not key.strip():
            continue
        patterns_list = _retrieval_coerce_str_list(patterns)
        if patterns_list:
            out[key.strip()] = patterns_list
    return out


async def run_retrieval_eval_sweep(
    **kwargs: object,
) -> RetrievalEvalSweepReport:
    """Replay registered retrieval benchmarks; record scored runs.

    Called by :class:`AutomationRunner` when an operator has scheduled
    ``platform.retrieval_eval_sweep``. Runner-injected metadata
    (``target_name`` / ``execution_context``) is swallowed so the
    bare-callable ``**kwargs`` path doesn't reject unknown keys.

    Enumerates the latest-per-key :class:`RetrievalBenchmarkRecord`
    (bounded by ``benchmark_limit``, optionally restricted to
    ``benchmark_keys``), and for each key with a configured namespace
    mapping runs one :meth:`RetrievalEvalRunner.run` in report-mode
    (``first_eval_auto_passes=False`` -> ``verdict='baseline_only'``).

    The sweep NEVER raises; the returned report captures the error
    trail so the schedule's ``last_run_result`` snapshot is
    self-describing.
    """
    # Deferred import: keeping heavy retrieval modules out of API
    # startup, only paid when this sweep actually runs.
    from sqlalchemy import func as _sqlfunc
    from sqlmodel import select as _select

    from aila.platform.eval.retrieval_live import make_retrieve_fn
    from aila.platform.eval.retrieval_models import RetrievalBenchmarkRecord
    from aila.platform.eval.retrieval_runner import (
        EmptyRetrievalBenchmarkError,
        RetrievalBenchmarkNotFoundError,
        RetrievalEvalRunner,
    )

    _ = kwargs.pop("target_name", None)
    _ = kwargs.pop("execution_context", None)

    namespace_by_key = _retrieval_coerce_namespace_map(
        kwargs.get("namespace_patterns_by_key"),
    )
    min_score = max(
        0.0, min(1.0, _retrieval_coerce_float(kwargs.get("min_score"), 0.3)),
    )
    route_raw = kwargs.get("route")
    route = route_raw.strip() if isinstance(route_raw, str) and route_raw.strip() else "simple"
    benchmark_limit = _retrieval_coerce_int(
        kwargs.get("benchmark_limit"), 50,
    )
    benchmark_keys = _retrieval_coerce_str_list(kwargs.get("benchmark_keys"))

    report: RetrievalEvalSweepReport = {
        "benchmarks_seen": 0,
        "benchmarks_replayed": 0,
        "benchmarks_skipped": 0,
        "runs_persisted": 0,
        "errors": [],
    }

    # Latest-per-key: newest created_at wins so a re-registration of a
    # benchmark under the same key supersedes older revisions on the
    # sweep. Bounded by benchmark_limit to keep a large corpus from
    # exhausting the tick.
    try:
        async with async_session_scope() as session:
            latest_created = (
                _select(
                    RetrievalBenchmarkRecord.key,
                    _sqlfunc.max(RetrievalBenchmarkRecord.created_at).label(
                        "max_created_at",
                    ),
                )
                .group_by(RetrievalBenchmarkRecord.key)
                .subquery()
            )
            stmt = (
                _select(RetrievalBenchmarkRecord)
                .join(
                    latest_created,
                    (RetrievalBenchmarkRecord.key == latest_created.c.key)
                    & (
                        RetrievalBenchmarkRecord.created_at
                        == latest_created.c.max_created_at
                    ),
                )
                .order_by(RetrievalBenchmarkRecord.created_at.desc())
                .limit(int(benchmark_limit))
            )
            benchmarks = list((await session.exec(stmt)).all())
    except _RETRIEVAL_SWEEP_ERRORS as exc:
        _log.warning(
            "retrieval_eval_sweep: benchmark enumeration failed (%s)",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"enumerate:{type(exc).__name__}")
        return report

    report["benchmarks_seen"] = len(benchmarks)
    if not benchmarks:
        _log.info("retrieval_eval_sweep: no registered benchmarks; no-op")
        return report

    runner = RetrievalEvalRunner()
    allowed_keys = set(benchmark_keys) if benchmark_keys else None

    for benchmark in benchmarks:
        if allowed_keys is not None and benchmark.key not in allowed_keys:
            continue
        patterns = namespace_by_key.get(benchmark.key)
        if not patterns:
            report["benchmarks_skipped"] += 1
            report["errors"].append(
                f"missing_namespaces:{benchmark.key}",
            )
            continue
        retrieve_fn = make_retrieve_fn(
            namespace_patterns=list(patterns),
            min_score=min_score,
            route=route,
        )
        try:
            await runner.run(
                key=benchmark.key,
                benchmark_id=benchmark.id,
                candidate_label="scheduled_live",
                candidate_retrieve_fn=retrieve_fn,
                first_eval_auto_passes=False,
                actor=_RETRIEVAL_SWEEP_ACTOR,
            )
        except (
            RetrievalBenchmarkNotFoundError,
            EmptyRetrievalBenchmarkError,
        ) as exc:
            _log.info(
                "retrieval_eval_sweep skip benchmark_id=%s key=%s: %s",
                benchmark.id, benchmark.key, exc,
            )
            report["benchmarks_skipped"] += 1
            report["errors"].append(
                f"skip:{benchmark.key}:{type(exc).__name__}",
            )
            continue
        except _RETRIEVAL_SWEEP_ERRORS as exc:
            _log.warning(
                "retrieval_eval_sweep: run failed for benchmark_id=%s "
                "key=%s (%s)",
                benchmark.id, benchmark.key, type(exc).__name__,
                exc_info=exc,
            )
            report["errors"].append(
                f"run:{benchmark.key}:{type(exc).__name__}",
            )
            continue
        report["benchmarks_replayed"] += 1
        report["runs_persisted"] += 1

    _log.info(
        "retrieval_eval_sweep completed seen=%d replayed=%d skipped=%d "
        "persisted=%d errors=%d",
        report["benchmarks_seen"], report["benchmarks_replayed"],
        report["benchmarks_skipped"], report["runs_persisted"],
        len(report["errors"]),
    )
    return report


# ---------------------------------------------------------------------------
# RFC #141 -- shadow-report sweep.
#
# Runs a shadow report for every ACTIVE shadow assignment in the
# ``lifecycle_canary_assignments`` table. Default-off in
# ``seed_schedules.py`` so existing operator-initiated behavior is
# preserved unchanged; an operator enabling the schedule gets
# continuous shadow-evidence accrual across every candidate the
# lifecycle controller has shadowed.
#
# Operator-supplied ``action_kwargs_json`` on the schedule row MAY
# carry:
#
# * ``sample_n``: per-assignment replay-sample count (int > 0);
#   default 5, forwarded to :func:`run_shadow`.
# * ``faithfulness_floor``: replay-diff faithfulness floor
#   (float in [0, 1]); default forwarded to
#   :func:`DEFAULT_FAITHFULNESS_FLOOR` via the underlying call.
# * ``assignment_limit``: max active assignments processed per tick
#   (int > 0); default 100 -- an unbounded corpus of stale shadows
#   should not silently blow the tick budget.
# * ``keys``: optional ``list[str]`` restricting the sweep to a
#   subset of registered assignment keys.
#
# Each per-assignment call isolates its own failures: a raise from
# ``run_shadow`` on one (key, version) does not stop the next. The
# sweep NEVER raises; the returned report captures the error trail so
# the schedule's ``last_run_result`` snapshot is self-describing.
# ---------------------------------------------------------------------------


class ShadowReportSweepReport(TypedDict):
    """Structured result of one ``run_shadow_report_sweep`` invocation."""

    assignments_seen: int
    reports_persisted: int
    assignments_skipped: int
    errors: list[str]


_SHADOW_SWEEP_ACTOR: str = "platform.shadow_report_sweep"

# Same posture as ``_RETRIEVAL_SWEEP_ERRORS`` above. The shadow report
# path additionally emits DB rows through the transition journal, so
# every failure class the calibration + retrieval sweeps enumerate is
# reachable here too.
_SHADOW_SWEEP_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    LookupError,
    ArithmeticError,
    ConnectionError,
)


async def run_shadow_report_sweep(
    **kwargs: object,
) -> ShadowReportSweepReport:
    """Run one shadow report per ACTIVE shadow assignment.

    Called by :class:`AutomationRunner` when an operator has scheduled
    ``platform.shadow_report_sweep``. Runner-injected metadata
    (``target_name`` / ``execution_context``) is swallowed so the
    bare-callable ``**kwargs`` path doesn't reject unknown keys.

    Enumerates the ``lifecycle_canary_assignments`` table directly
    (state='active', kind='shadow'); the controller exposes only a
    per-key ``active_shadow`` lookup, which is insufficient for a
    sweep. Reading the table directly is fine here: this is
    platform-owned code reading a platform-owned table, exactly the
    same pattern the controller itself uses (see
    ``AgentLifecycleController._active_assignment``).

    Each per-assignment call delegates to :func:`run_shadow` which
    persists exactly one :class:`ShadowReportRecord` row and one
    metrics-update :class:`LifecycleTransitionRecord` row. The sweep
    NEVER raises.
    """
    # Deferred import: shadow / lifecycle modules pull the eval runner
    # and prompt-version store; keeping them out of API startup keeps
    # the cold-start light.
    from sqlmodel import select as _select

    from aila.platform.lifecycle.assignments import (
        AssignmentKind,
        AssignmentState,
        LifecycleCanaryAssignment,
    )
    from aila.platform.lifecycle.controller import (
        AgentLifecycleController,
        StageTransitionError,
    )
    from aila.platform.lifecycle.shadow import (
        DEFAULT_FAITHFULNESS_FLOOR,
        run_shadow,
    )

    _ = kwargs.pop("target_name", None)
    _ = kwargs.pop("execution_context", None)

    sample_n = _retrieval_coerce_int(kwargs.get("sample_n"), 5)
    faithfulness_floor_raw = _retrieval_coerce_float(
        kwargs.get("faithfulness_floor"), float(DEFAULT_FAITHFULNESS_FLOOR),
    )
    faithfulness_floor = max(0.0, min(1.0, faithfulness_floor_raw))
    assignment_limit = _retrieval_coerce_int(
        kwargs.get("assignment_limit"), 100,
    )
    key_filter = _retrieval_coerce_str_list(kwargs.get("keys"))

    report: ShadowReportSweepReport = {
        "assignments_seen": 0,
        "reports_persisted": 0,
        "assignments_skipped": 0,
        "errors": [],
    }

    try:
        async with async_session_scope() as session:
            stmt = (
                _select(LifecycleCanaryAssignment)
                .where(
                    LifecycleCanaryAssignment.kind
                    == AssignmentKind.SHADOW.value,
                    LifecycleCanaryAssignment.state
                    == AssignmentState.ACTIVE.value,
                )
                .order_by(LifecycleCanaryAssignment.created_at.desc())
                .limit(int(assignment_limit))
            )
            assignments = list((await session.exec(stmt)).all())
    except _SHADOW_SWEEP_ERRORS as exc:
        _log.warning(
            "shadow_report_sweep: assignment enumeration failed (%s)",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"enumerate:{type(exc).__name__}")
        return report

    report["assignments_seen"] = len(assignments)
    if not assignments:
        _log.info(
            "shadow_report_sweep: no ACTIVE shadow assignments; no-op",
        )
        return report

    allowed_keys = set(key_filter) if key_filter else None
    controller = AgentLifecycleController()

    for assignment in assignments:
        if allowed_keys is not None and assignment.key not in allowed_keys:
            continue
        try:
            await run_shadow(
                controller=controller,
                key=assignment.key,
                version=assignment.version,
                sample_n=sample_n,
                actor=_SHADOW_SWEEP_ACTOR,
                faithfulness_floor=faithfulness_floor,
            )
        except StageTransitionError as exc:
            # A race with a supersede between enumeration and replay:
            # the row is no longer the active shadow. Skip -- the next
            # tick will pick up whatever is active then.
            _log.info(
                "shadow_report_sweep skip key=%s version=%s: %s",
                assignment.key, assignment.version, exc,
            )
            report["assignments_skipped"] += 1
            continue
        except _SHADOW_SWEEP_ERRORS as exc:
            _log.warning(
                "shadow_report_sweep: run_shadow failed key=%s "
                "version=%s (%s)",
                assignment.key, assignment.version,
                type(exc).__name__, exc_info=exc,
            )
            report["errors"].append(
                f"shadow:{assignment.key}:{type(exc).__name__}",
            )
            continue
        report["reports_persisted"] += 1

    _log.info(
        "shadow_report_sweep completed seen=%d persisted=%d skipped=%d "
        "errors=%d",
        report["assignments_seen"], report["reports_persisted"],
        report["assignments_skipped"], len(report["errors"]),
    )
    return report
