"""Health and status endpoints for the AILA REST API.

GET /health  — DB + module checks, no auth required (D-15: never 503)
GET /status  — version + uptime, no auth required

These endpoints are intentionally on an unprotected router. Load balancers
and monitoring tools must be able to check health without an API key.
"""
from __future__ import annotations

import asyncio
import importlib.metadata as _importlib_metadata
import inspect
import logging
import time
from datetime import UTC
from typing import Any

import sqlalchemy.exc
from fastapi import APIRouter, Depends, Request

from aila.api.auth import ROLE_LEVELS, AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.deps import get_platform
from aila.api.metrics import SILENT_FAILURE_TOTAL
from aila.api.schemas.comprehensive_health import (
    ComprehensiveHealthResponse,
    SubsystemHealth,
)
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.health import HealthCheckResponse, HealthCheckResult, StatusResponse
from aila.platform.runtime import AILAPlatform
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)


def _module_registry_from(request: Request) -> Any | None:
    """Pull the platform's module registry off the FastAPI app state.

    The platform is created in the FastAPI lifespan (api/app.py) and
    exposes ``runtime.module_registry``. Returns None when the
    platform hasn't initialized yet (rare — early-request race during
    boot). Keeping the access tolerant means the probe degrades to
    "unknown" instead of 500.
    """
    platform = getattr(request.app.state, "platform", None)
    if platform is None:
        return None
    runtime = getattr(platform, "runtime", None)
    if runtime is None:
        return None
    return getattr(runtime, "module_registry", None)

_AILA_VERSION: str = _importlib_metadata.version("aila")

# Unprotected router — NO dependencies=[Depends(require_api_key)] here
router = APIRouter(tags=["health"])


async def _check_database() -> HealthCheckResult:
    """Perform an async DB ping via async_session_scope.

    Executes SELECT 1 to verify the database connection is responsive.

    Returns:
        HealthCheckResult with status 'up' and latency_ms, or 'down' with message.
    """
    start_time = time.monotonic()
    try:
        from sqlalchemy import text as _text

        async with async_session_scope() as session:
            await session.execute(_text("SELECT 1"))
        latency_ms = (time.monotonic() - start_time) * 1000
        return HealthCheckResult(status="up", latency_ms=round(latency_ms, 2))
    except sqlalchemy.exc.SQLAlchemyError as exc:
        _log.warning("Database health check failed: %s", exc)
        return HealthCheckResult(status="down", message=None)


async def _check_redis() -> HealthCheckResult:
    """Probe Redis / Memurai via PING and map result to HealthCheckResult.

    Maps SubsystemHealth status to HealthCheckResult:
      - healthy            -> up
      - timed_out/degraded -> degraded
      - all others         -> down
    """
    import redis.exceptions

    from aila.platform.services.health_probes import probe_redis

    start_time = time.monotonic()
    try:
        result = await probe_redis()
    except redis.exceptions.RedisError as exc:
        _log.warning("Redis health probe raised RedisError: %s", exc)
        return HealthCheckResult(status="down", message="redis error")
    latency_ms = round((time.monotonic() - start_time) * 1000, 2)
    if result.status == "healthy":
        return HealthCheckResult(status="up", latency_ms=latency_ms)
    if result.status in {"timed_out", "degraded"}:
        return HealthCheckResult(status="degraded", message=result.message)
    # unreachable, offline, error, unknown -> down
    return HealthCheckResult(status="down", message=result.message)


async def _check_workers() -> HealthCheckResult:
    """Probe ARQ worker liveness and map result to HealthCheckResult.

    Maps SubsystemHealth status to HealthCheckResult:
      - running            -> up
      - offline/unreachable -> down (zero workers = no scan capacity)
      - all others         -> degraded
    """
    import redis.exceptions

    from aila.platform.services.health_probes import probe_arq_worker

    try:
        result = await probe_arq_worker()
    except redis.exceptions.RedisError as exc:
        _log.warning("ARQ worker health probe raised RedisError: %s", exc)
        return HealthCheckResult(status="down", message="redis error")
    if result.status == "running":
        return HealthCheckResult(status="up")
    if result.status in {"offline", "unreachable", "unknown"}:
        return HealthCheckResult(status="down", message=result.message)
    return HealthCheckResult(status="degraded", message=result.message)


@router.get("/health", response_model=HealthCheckResponse)
async def get_health(
    platform: AILAPlatform = Depends(get_platform),
) -> HealthCheckResponse:
    """Return platform health status including DB, Redis, worker, and module checks.

    D-14: Checks database, Redis, and ARQ worker count as critical dependencies.
    D-15: Always returns HTTP 200. The body status field is truthful:
      - healthy   : all checks up
      - degraded  : some checks degraded
      - unhealthy : any critical check (DB, Redis, workers) is down
    D-13: Module health_checks() contributions are collected via hasattr check.

    Redis down -> unhealthy. Zero workers -> unhealthy. These are not overridable.

    Args:
        platform: AILAPlatform singleton from lifespan (injected by get_platform).

    Returns:
        HealthCheckResponse with status and per-check dict. HTTP 200 always.
    """
    checks: dict[str, HealthCheckResult] = {}

    # Core check: database (D-14)
    db_result = await _check_database()
    checks["database"] = db_result

    # Critical infrastructure checks: Redis and ARQ workers (Bug 12 fix)
    redis_result = await _check_redis()
    checks["redis"] = redis_result

    workers_result = await _check_workers()
    checks["workers"] = workers_result

    # D-13: Module health checks — optional, no error if module lacks the method
    module_checks_map = await _collect_module_health_checks(platform)
    checks.update(module_checks_map)

    # D-15: Aggregate status — HTTP 200 always; body is truthful
    # Critical checks: DB, Redis, workers — any down -> unhealthy
    critical_names = {"database", "redis", "workers"}
    critical_statuses = {k: c.status for k, c in checks.items() if k in critical_names}
    if any(s == "down" for s in critical_statuses.values()):
        top_status = "unhealthy"
    else:
        all_statuses = [c.status for c in checks.values()]
        if all(s == "up" for s in all_statuses):
            top_status = "healthy"
        else:
            top_status = "degraded"

    return HealthCheckResponse(status=top_status, checks=checks)


async def _collect_module_health_checks(platform: AILAPlatform) -> dict[str, HealthCheckResult]:
    """Gather health check results from all registered modules.

    Each module may expose a health_checks() method returning a dict of
    {check_name: check_fn}. Results are collected per-module and keyed as
    '{module_id}_{check_name}'. Failures are caught per-check to avoid one
    broken module preventing others from reporting.
    """
    results: dict[str, HealthCheckResult] = {}
    if platform is None:
        return results
    try:
        module_registry = platform.runtime.module_registry
    except AttributeError:
        # platform.runtime.module_registry not available in test doubles — skip
        return results

    for module in module_registry.modules:
        module_id = module.module_id
        if not hasattr(module, "health_checks"):
            continue
        try:
            module_checks: dict[str, object] = module.health_checks()
        except Exception as exc:
            _log.warning("Module %s health_checks() raised: %s", module_id, exc)
            SILENT_FAILURE_TOTAL.labels(component="module_health").inc()
            results[f"{module_id}_health"] = HealthCheckResult(
                status="down", message=None
            )
            continue

        for check_name, check_fn in module_checks.items():
            results[f"{module_id}_{check_name}"] = await _run_single_health_check(check_fn)

    return results


_HEALTH_CHECK_TIMEOUT_SECONDS: float = 5.0


async def _run_single_health_check(check_fn: object) -> HealthCheckResult:
    """Execute a single module health check function and return the result.

    T-138-11: Each check is bounded to _HEALTH_CHECK_TIMEOUT_SECONDS (5s) via
    asyncio.wait_for so one slow or hung module cannot block the health response.
    """
    if not callable(check_fn):
        return HealthCheckResult(status="down", message="Health check is not callable")
    try:
        if inspect.iscoroutinefunction(check_fn):
            coro = check_fn()
        else:
            coro = asyncio.to_thread(check_fn)
        result: object = await asyncio.wait_for(coro, timeout=_HEALTH_CHECK_TIMEOUT_SECONDS)
        if hasattr(result, "status"):
            return HealthCheckResult(
                status=result.status,
                latency_ms=getattr(result, "latency_ms", None),
                message=getattr(result, "message", None),
            )
        # dict-shaped result (as returned by SbD health check async callables)
        if isinstance(result, dict):
            return HealthCheckResult(
                status=str(result.get("status", "down")),
                message=None,  # T-138-12: never leak module error details to clients
            )
        return HealthCheckResult(status="up")
    except TimeoutError:
        return HealthCheckResult(status="down", message="timeout")
    except Exception as exc:
        _log.warning("Health check failed: %s", exc)
        SILENT_FAILURE_TOTAL.labels(component="module_health").inc()
        return HealthCheckResult(status="down", message=None)


# ---------------------------------------------------------------------------
# GET /health/comprehensive (Phase 176d -- admin only)
# ---------------------------------------------------------------------------


@router.get(
    "/health/comprehensive",
    response_model=DataEnvelope[ComprehensiveHealthResponse],
    summary="Admin-only deep health probe across all subsystems",
)
async def get_comprehensive_health(
    request: Request,
    auth_ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[ComprehensiveHealthResponse]:
    """Probe every subsystem concurrently and return per-subsystem status.

    Admin-only (enforced inline to keep the /health/* router public otherwise).
    Every probe runs under its own explicit timeout; gather(return_exceptions=True)
    guarantees a single bad probe cannot block the handler.

    Subsystems probed:
      - redis (Memurai on Windows)
      - omniroute (local LLM router)
      - arch_security (external HEAD)
      - nvd (external GET with lightweight CVE)
      - ssh_systems (per-managed-system TCP connect)
      - arq_worker (heartbeat key scan)
      - modules (per-module activity summary)

    Returns DataEnvelope wrapping ComprehensiveHealthResponse. The overall
    status aggregates all subsystems: healthy / degraded / unhealthy.
    """
    from fastapi import HTTPException, status

    required_level = ROLE_LEVELS.get(ROLE_ADMIN, 2)
    caller_level = ROLE_LEVELS.get(auth_ctx.role, -1)
    if caller_level < required_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Comprehensive health requires 'admin' role",
        )

    import time as _time
    from datetime import datetime as _datetime

    from aila.platform.services.health_probes import (
        probe_arch_security,
        probe_arq_worker,
        probe_modules,
        probe_nvd,
        probe_omniroute,
        probe_redis,
        probe_ssh_reachability,
    )

    started_at = _datetime.now(tz=UTC)
    probe_deadline = _time.monotonic() + 10.0  # hard upper bound for whole batch

    systems = await _load_team_systems_for_ssh_probe(auth_ctx.team_id)

    probe_coros = [
        probe_redis(),
        probe_omniroute(),
        probe_arch_security(),
        probe_nvd(),
        probe_ssh_reachability(systems),
        probe_arq_worker(),
        probe_modules(team_id=auth_ctx.team_id, module_registry=_module_registry_from(request)),
    ]

    try:
        raw_results = await asyncio.wait_for(
            asyncio.gather(*probe_coros, return_exceptions=True),
            timeout=max(0.5, probe_deadline - _time.monotonic()),
        )
    except TimeoutError:
        raw_results = [
            TimeoutError(f"probe batch exceeded {10.0}s deadline")
            for _ in probe_coros
        ]

    subsystems: list[SubsystemHealth] = []
    for raw in raw_results:
        if isinstance(raw, SubsystemHealth):
            subsystems.append(raw)
        elif isinstance(raw, BaseException):
            subsystems.append(
                SubsystemHealth(
                    name="unknown",
                    status="error",
                    last_checked_at=_datetime.now(tz=UTC),
                    message=f"probe raised: {type(raw).__name__}",
                )
            )

    overall = _aggregate_overall_status(subsystems)

    return DataEnvelope(
        data=ComprehensiveHealthResponse(
            overall_status=overall,
            checked_at=started_at,
            subsystems=subsystems,
        ),
    )


async def _load_team_systems_for_ssh_probe(
    team_id: str | None,
) -> list[dict[str, object]]:
    """Fetch managed systems (team-scoped) as lightweight dicts for SSH probing."""
    from sqlmodel import select

    from aila.storage.db_models import ManagedSystemRecord

    try:
        async with async_session_scope() as session:
            stmt = select(ManagedSystemRecord)
            if team_id is not None:
                stmt = stmt.where(ManagedSystemRecord.team_id == team_id)
            records = (await session.exec(stmt)).all()
        return [
            {"id": r.id, "name": r.name, "host": r.host, "port": r.port}
            for r in records
            if r.id is not None
        ]
    except sqlalchemy.exc.SQLAlchemyError as exc:
        _log.warning("managed systems lookup for ssh probe failed: %s", exc)
        return []


def _aggregate_overall_status(
    subsystems: list[SubsystemHealth],
) -> str:
    """Reduce per-subsystem statuses to an overall healthy/degraded/unhealthy.

    - any 'unreachable' or 'offline' or 'error'         -> unhealthy
    - any 'degraded' or 'timed_out' or 'stale' or 'rate_limited' -> degraded
    - everything healthy / running / unknown            -> healthy
    """
    # Phase 178: "unhealthy" is now a first-class subsystem status (worker
    # frozen -> subsystem unhealthy -> overall unhealthy). Previously the
    # probe could only return "stale" which was aggregated as "degraded",
    # hiding a dead worker from the summary.
    unhealthy_flags = {"unreachable", "offline", "error", "unhealthy"}
    degraded_flags = {"degraded", "timed_out", "stale", "rate_limited"}

    has_unhealthy = any(s.status in unhealthy_flags for s in subsystems)
    if has_unhealthy:
        return "unhealthy"
    has_degraded = any(s.status in degraded_flags for s in subsystems)
    if has_degraded:
        return "degraded"
    return "healthy"


@router.get("/status", response_model=StatusResponse)
async def get_status(request: Request) -> StatusResponse:
    """Return API version and uptime.

    No authentication required. Used for ops monitoring and deployment checks.
    Uptime is read from request.app.state.start_time (set by the lifespan in
    app.py) rather than a module-level variable to ensure the measurement
    reflects true server start time, not module import time.

    Args:
        request: FastAPI Request object — provides access to app.state.

    Returns:
        StatusResponse with version string and uptime_seconds integer.
    """
    start_time: float = getattr(request.app.state, "start_time", time.monotonic())
    return StatusResponse(
        version=_AILA_VERSION,
        uptime_seconds=int(time.monotonic() - start_time),
    )
