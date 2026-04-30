"""Subsystem health probes for the comprehensive health endpoint (Phase 176d).

Each probe is an async function returning a SubsystemHealth result. Probes are
deliberately defensive: all exceptions are caught and translated into a
status value. A broken probe must never raise into the request handler.

Every HTTP probe uses httpx.AsyncClient with an explicit timeout. Every TCP
probe uses asyncio.open_connection wrapped in asyncio.wait_for. Redis and DB
probes bound execution with asyncio.wait_for.

Timeouts (all seconds):
    HTTP probes: 3.0
    SSH TCP connect probes: 2.0
    Redis ping: 2.0

Per the 176d brief: timeouts must never block the request handler. The
comprehensive endpoint uses asyncio.gather(..., return_exceptions=True) to
run all probes concurrently; this module guarantees each probe resolves.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from aila.api.schemas.comprehensive_health import (
    ModuleHealthSummary,
    SshReachabilityResult,
    SubsystemHealth,
)

__all__ = [
    "HTTP_PROBE_TIMEOUT_S",
    "REDIS_PROBE_TIMEOUT_S",
    "SSH_PROBE_TIMEOUT_S",
    "probe_arch_security",
    "probe_arq_worker",
    "probe_modules",
    "probe_nvd",
    "probe_omniroute",
    "probe_redis",
    "probe_ssh_reachability",
]

_log = logging.getLogger(__name__)

HTTP_PROBE_TIMEOUT_S: float = 3.0
SSH_PROBE_TIMEOUT_S: float = 2.0
REDIS_PROBE_TIMEOUT_S: float = 2.0

# Arch Security endpoint is idempotent/cached; a HEAD to the root is cheap.
_ARCH_SECURITY_URL: str = "https://security.archlinux.org/"
# NVD lightweight probe: a single well-known CVE id returns a tiny JSON page.
_NVD_PROBE_URL: str = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
)
# OmniRoute local model catalog.
_OMNIROUTE_MODELS_URL_DEFAULT: str = "http://localhost:20128/v1/models"

# Phase 179: the legacy per-worker liveness key is DELETED. We now
# read ARQ's native arq:<queue>:health-check TTL only.


def _utcnow() -> datetime:
    """Return an aware UTC datetime for last_checked_at fields."""
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Redis / Memurai
# ---------------------------------------------------------------------------


async def probe_redis(redis_url: str | None = None) -> SubsystemHealth:
    """Probe the configured Redis / Memurai instance via PING.

    Reads AILA_PLATFORM_REDIS_URL when redis_url is None. Returns a
    SubsystemHealth with status:
      - healthy   : PING returned PONG
      - unreachable: connection refused or DNS failure
      - timed_out : probe exceeded REDIS_PROBE_TIMEOUT_S
      - error     : any other failure
    """
    url = redis_url if redis_url is not None else os.getenv("AILA_PLATFORM_REDIS_URL")
    if not url:
        return SubsystemHealth(
            name="redis",
            status="unknown",
            last_checked_at=_utcnow(),
            message="AILA_PLATFORM_REDIS_URL not configured",
        )

    # Local import so missing redis dep does not break module import.
    import redis.asyncio as aioredis

    started = time.monotonic()
    client = aioredis.Redis.from_url(url, socket_connect_timeout=REDIS_PROBE_TIMEOUT_S)
    try:
        result = await asyncio.wait_for(client.ping(), timeout=REDIS_PROBE_TIMEOUT_S)
        latency_ms = (time.monotonic() - started) * 1000.0
        if result is True:
            return SubsystemHealth(
                name="redis",
                status="healthy",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message="PING ok",
            )
        return SubsystemHealth(
            name="redis",
            status="degraded",
            latency_ms=round(latency_ms, 2),
            last_checked_at=_utcnow(),
            message="PING returned non-true value",
        )
    except TimeoutError:
        return SubsystemHealth(
            name="redis",
            status="timed_out",
            last_checked_at=_utcnow(),
            message=f"ping timed out after {REDIS_PROBE_TIMEOUT_S}s",
        )
    except Exception as exc:
        message = type(exc).__name__
        _log.debug("redis probe failed: %s", exc)
        return SubsystemHealth(
            name="redis",
            status="unreachable",
            last_checked_at=_utcnow(),
            message=f"connection failed: {message}",
        )
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            _log.debug("redis probe: client.aclose() failed: %s", exc)


# ---------------------------------------------------------------------------
# OmniRoute (local LLM router)
# ---------------------------------------------------------------------------


async def probe_omniroute(url: str | None = None) -> SubsystemHealth:
    """GET <omniroute>/v1/models and classify the result.

    Uses OMNIROUTE_BASE_URL env var when explicit URL not provided, otherwise
    the hardcoded local default. Status:
      - healthy    : 200 with non-empty models list
      - degraded   : 200 but models list missing or empty
      - unreachable: connection error
      - timed_out  : request exceeded HTTP_PROBE_TIMEOUT_S
      - error      : non-2xx response or unexpected failure
    """
    target = url or os.getenv("OMNIROUTE_BASE_URL") or _OMNIROUTE_MODELS_URL_DEFAULT
    # Accept either a bare base URL or the full /v1/models path.
    if "/v1/models" not in target:
        target = target.rstrip("/") + "/v1/models"

    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=HTTP_PROBE_TIMEOUT_S) as client:
            response = await client.get(target)
        latency_ms = (time.monotonic() - started) * 1000.0
        if response.status_code // 100 != 2:
            return SubsystemHealth(
                name="omniroute",
                status="error",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message=f"HTTP {response.status_code}",
            )
        body: Any
        try:
            body = response.json()
        except Exception as exc:
            _log.debug("omniroute probe: response.json() failed: %s", exc)
            body = None
        models = _extract_models_list(body)
        if not models:
            return SubsystemHealth(
                name="omniroute",
                status="degraded",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message="reachable but no models reported",
                details={"model_count": 0},
            )
        return SubsystemHealth(
            name="omniroute",
            status="healthy",
            latency_ms=round(latency_ms, 2),
            last_checked_at=_utcnow(),
            message=f"{len(models)} models available",
            details={"model_count": len(models)},
        )
    except httpx.TimeoutException:
        return SubsystemHealth(
            name="omniroute",
            status="timed_out",
            last_checked_at=_utcnow(),
            message=f"timed out after {HTTP_PROBE_TIMEOUT_S}s",
        )
    except httpx.HTTPError as exc:
        return SubsystemHealth(
            name="omniroute",
            status="unreachable",
            last_checked_at=_utcnow(),
            message=type(exc).__name__,
        )


def _extract_models_list(body: Any) -> list[Any]:
    """Safely extract a model-list from an OmniRoute/OpenAI-compat payload."""
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, list):
            return data
        models = body.get("models")
        if isinstance(models, list):
            return models
    if isinstance(body, list):
        return body
    return []


# ---------------------------------------------------------------------------
# External HTTP probes: Arch Security and NVD
# ---------------------------------------------------------------------------


async def probe_arch_security(url: str = _ARCH_SECURITY_URL) -> SubsystemHealth:
    """HEAD https://security.archlinux.org/ with a 3s timeout.

    Status:
      - healthy     : 2xx or 3xx response
      - rate_limited: 429
      - unreachable : connection error / DNS failure
      - timed_out   : request exceeded HTTP_PROBE_TIMEOUT_S
      - error       : 5xx or other HTTP failure
    """
    return await _probe_http_head("arch_security", url)


async def probe_nvd(url: str = _NVD_PROBE_URL) -> SubsystemHealth:
    """GET a lightweight known CVE from the NVD API.

    NVD does not respond to HEAD for the cves endpoint, so this issues a
    small GET. Uses the same status classification as probe_arch_security.
    """
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=HTTP_PROBE_TIMEOUT_S) as client:
            response = await client.get(url)
        latency_ms = (time.monotonic() - started) * 1000.0
        if response.status_code == 429:
            return SubsystemHealth(
                name="nvd",
                status="rate_limited",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message="HTTP 429 -- rate limited",
            )
        if response.status_code // 100 == 2:
            return SubsystemHealth(
                name="nvd",
                status="healthy",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message=f"HTTP {response.status_code}",
            )
        return SubsystemHealth(
            name="nvd",
            status="error",
            latency_ms=round(latency_ms, 2),
            last_checked_at=_utcnow(),
            message=f"HTTP {response.status_code}",
        )
    except httpx.TimeoutException:
        return SubsystemHealth(
            name="nvd",
            status="timed_out",
            last_checked_at=_utcnow(),
            message=f"timed out after {HTTP_PROBE_TIMEOUT_S}s",
        )
    except httpx.HTTPError as exc:
        return SubsystemHealth(
            name="nvd",
            status="unreachable",
            last_checked_at=_utcnow(),
            message=type(exc).__name__,
        )


async def _probe_http_head(name: str, url: str) -> SubsystemHealth:
    """Shared HEAD-probe helper used by external service probes."""
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=HTTP_PROBE_TIMEOUT_S, follow_redirects=True) as client:
            response = await client.head(url)
        latency_ms = (time.monotonic() - started) * 1000.0
        if response.status_code == 429:
            return SubsystemHealth(
                name=name,
                status="rate_limited",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message="HTTP 429 -- rate limited",
            )
        if response.status_code // 100 in (2, 3):
            return SubsystemHealth(
                name=name,
                status="healthy",
                latency_ms=round(latency_ms, 2),
                last_checked_at=_utcnow(),
                message=f"HTTP {response.status_code}",
            )
        return SubsystemHealth(
            name=name,
            status="error",
            latency_ms=round(latency_ms, 2),
            last_checked_at=_utcnow(),
            message=f"HTTP {response.status_code}",
        )
    except httpx.TimeoutException:
        return SubsystemHealth(
            name=name,
            status="timed_out",
            last_checked_at=_utcnow(),
            message=f"timed out after {HTTP_PROBE_TIMEOUT_S}s",
        )
    except httpx.HTTPError as exc:
        return SubsystemHealth(
            name=name,
            status="unreachable",
            last_checked_at=_utcnow(),
            message=type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# SSH per-system reachability (TCP connect only -- NO auth)
# ---------------------------------------------------------------------------


async def probe_ssh_reachability(
    systems: list[dict[str, Any]],
) -> SubsystemHealth:
    """TCP-connect to each managed system's SSH port with 2s timeout each.

    The probe is explicitly unauthenticated: it only verifies that the TCP
    port accepts a connection. Credential validation is out of scope for a
    health probe (and would be a security smell).

    Args:
        systems: list of {id, name, host, port} dicts. Callers pass the
            authenticated caller's team-scoped systems; this function does not
            query the database itself (keeps the probe decoupled from storage).

    Returns SubsystemHealth with details['systems'] containing per-system
    results for frontend rendering.
    """
    if not systems:
        return SubsystemHealth(
            name="ssh_systems",
            status="unknown",
            last_checked_at=_utcnow(),
            message="no managed systems registered",
            details={"systems": []},
        )

    results = await asyncio.gather(
        *(_probe_single_ssh(sys) for sys in systems),
        return_exceptions=True,
    )

    per_system: list[SshReachabilityResult] = []
    reachable = 0
    total = 0
    for raw, sys in zip(results, systems, strict=False):
        total += 1
        if isinstance(raw, SshReachabilityResult):
            per_system.append(raw)
            if raw.status == "reachable":
                reachable += 1
        else:
            # Defensive: _probe_single_ssh never raises, but keep guard.
            per_system.append(
                SshReachabilityResult(
                    system_id=int(sys.get("id", 0)),
                    system_name=str(sys.get("name", "")),
                    host=str(sys.get("host", "")),
                    port=int(sys.get("port", 22)),
                    status="error",
                    message=type(raw).__name__ if isinstance(raw, BaseException) else "unknown",
                )
            )

    if reachable == total:
        status: str = "healthy"
    elif reachable == 0:
        status = "unreachable"
    else:
        status = "degraded"

    return SubsystemHealth(
        name="ssh_systems",
        status=status,  # type: ignore[arg-type]
        last_checked_at=_utcnow(),
        message=f"{reachable}/{total} systems reachable",
        details={
            "reachable": reachable,
            "total": total,
            "systems": [r.model_dump(mode="json") for r in per_system],
        },
    )


async def _probe_single_ssh(system: dict[str, Any]) -> SshReachabilityResult:
    """TCP-connect to one system's SSH port. Never raises."""
    system_id = int(system.get("id", 0))
    name = str(system.get("name", ""))
    host = str(system.get("host", ""))
    port = int(system.get("port", 22))

    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port),
            timeout=SSH_PROBE_TIMEOUT_S,
        )
        latency_ms = (time.monotonic() - started) * 1000.0
        try:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as exc:
                _log.debug(
                    "ssh probe: writer.wait_closed() failed for %s:%d: %s",
                    host, port, exc,
                )
        finally:
            del reader
        return SshReachabilityResult(
            system_id=system_id,
            system_name=name,
            host=host,
            port=port,
            status="reachable",
            latency_ms=round(latency_ms, 2),
            message="TCP connect ok",
        )
    except TimeoutError:
        return SshReachabilityResult(
            system_id=system_id,
            system_name=name,
            host=host,
            port=port,
            status="timed_out",
            message=f"timed out after {SSH_PROBE_TIMEOUT_S}s",
        )
    except (OSError, socket.gaierror) as exc:
        return SshReachabilityResult(
            system_id=system_id,
            system_name=name,
            host=host,
            port=port,
            status="unreachable",
            message=type(exc).__name__,
        )
    except Exception as exc:
        return SshReachabilityResult(
            system_id=system_id,
            system_name=name,
            host=host,
            port=port,
            status="error",
            message=type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# ARQ worker heartbeat
# ---------------------------------------------------------------------------


async def probe_arq_worker(redis_url: str | None = None) -> SubsystemHealth:
    """Inspect ARQ worker liveness via its native health-check key (D-23).

    Phase 179 rewrite: we read ``arq:<queue>:health-check`` TTL and treat
    ``TTL > 0`` as running, ``TTL <= 0`` or missing as offline. The legacy
    per-worker liveness scan path is DELETED. ``queue_depth``,
    ``in_progress_count``, and ``dead_letter_count`` are still reported in
    ``details`` so the 176d grid keeps its operational summary.
    """
    url = redis_url if redis_url is not None else os.getenv("AILA_PLATFORM_REDIS_URL")
    if not url:
        return SubsystemHealth(
            name="arq_worker",
            status="unknown",
            last_checked_at=_utcnow(),
            message="AILA_PLATFORM_REDIS_URL not configured",
        )

    import redis.asyncio as aioredis

    from aila.platform.tasks.constants import (
        ARQ_DEAD_LETTER_KEY_TEMPLATE,
        ARQ_IN_PROGRESS_PREFIX,
        ARQ_QUEUE_KEY_TEMPLATE,
    )

    queue_name = "arq:queue:vulnerability"  # single track for Phase 179
    health_check_key = f"{queue_name}:health-check"

    client = aioredis.Redis.from_url(url, socket_connect_timeout=REDIS_PROBE_TIMEOUT_S)
    try:
        ttl_ms = await client.pttl(health_check_key)

        queue_depth = 0
        async for key in client.scan_iter(
            match=ARQ_QUEUE_KEY_TEMPLATE.format(track="*"), count=100,
        ):
            try:
                queue_depth += int(await client.zcard(key) or 0)
            except Exception:
                continue

        in_progress_count = 0
        async for _ in client.scan_iter(
            match=f"{ARQ_IN_PROGRESS_PREFIX}*", count=100,
        ):
            in_progress_count += 1

        dead_letter_count = 0
        async for key in client.scan_iter(
            match=ARQ_DEAD_LETTER_KEY_TEMPLATE.format(track="*"), count=100,
        ):
            try:
                dead_letter_count += int(await client.zcard(key) or 0)
            except Exception:
                continue

        details: dict[str, Any] = {
            "queue_depth": queue_depth,
            "in_progress_count": in_progress_count,
            "dead_letter_count": dead_letter_count,
        }

        if not isinstance(ttl_ms, int) or ttl_ms <= 0:
            return SubsystemHealth(
                name="arq_worker",
                status="offline",
                last_checked_at=_utcnow(),
                message="health-check key missing or expired",
                details=details,
            )

        age_s = max(0.0, 60.0 - (ttl_ms / 1000.0))
        details["last_heartbeat_age_s"] = round(age_s, 2)
        return SubsystemHealth(
            name="arq_worker",
            status="running",
            last_checked_at=_utcnow(),
            message=(
                f"healthy, last beat ~{int(age_s)}s ago, "
                f"queue={queue_depth}, in_progress={in_progress_count}, "
                f"dead_letter={dead_letter_count}"
            ),
            details=details,
        )
    except Exception as exc:
        _log.debug("arq worker probe failed: %s", exc)
        return SubsystemHealth(
            name="arq_worker",
            status="unreachable",
            last_checked_at=_utcnow(),
            message=f"redis error: {type(exc).__name__}",
        )
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            _log.debug("arq worker probe: client.aclose() failed: %s", exc)


# ---------------------------------------------------------------------------
# Module activity summaries
# ---------------------------------------------------------------------------


async def probe_modules(team_id: str | None = None) -> SubsystemHealth:
    """Summarize module-level activity for the authenticated team.

    Reports:
      - vulnerability: last inventory collection timestamp and run count
      - sbd_nfr: assessment count
      - scheduled_reports: last run timestamp

    A module is 'stale' when no activity is recorded in the last 24h.
    The overall subsystem status is the worst module status.
    """
    from sqlalchemy import func
    from sqlmodel import select

    from aila.storage.database import async_session_scope
    from aila.storage.db_models import WorkflowRunRecord

    summaries: list[ModuleHealthSummary] = []

    # Probes run via a single short-lived session. Exceptions are isolated
    # per-module so a broken table does not bring down the probe.
    try:
        async with async_session_scope() as session:
            summaries.append(await _module_summary_from_runs(session, team_id, "vulnerability"))
            summaries.append(await _module_summary_from_runs(session, team_id, "sbd_nfr"))
            summaries.append(await _scheduled_reports_summary(session, team_id))
            # Silence unused-import warning during the awaited statements above.
            _ = WorkflowRunRecord, select, func
    except Exception as exc:
        _log.warning("module probe DB session failed: %s", exc)
        return SubsystemHealth(
            name="modules",
            status="error",
            last_checked_at=_utcnow(),
            message=f"db error: {type(exc).__name__}",
            details={"modules": []},
        )

    worst = _worst_module_status([s.status for s in summaries])
    return SubsystemHealth(
        name="modules",
        status=worst,  # type: ignore[arg-type]
        last_checked_at=_utcnow(),
        message=_module_summary_message(summaries),
        details={"modules": [s.model_dump(mode="json") for s in summaries]},
    )


def _worst_module_status(statuses: list[str]) -> str:
    """Reduce per-module statuses into the worst aggregate."""
    priority = {"error": 3, "stale": 2, "healthy": 1, "unknown": 0}
    if not statuses:
        return "unknown"
    worst = max(statuses, key=lambda s: priority.get(s, 0))
    return "healthy" if worst == "healthy" else worst


def _module_summary_message(summaries: list[ModuleHealthSummary]) -> str:
    healthy = sum(1 for s in summaries if s.status == "healthy")
    return f"{healthy}/{len(summaries)} modules healthy"


async def _module_summary_from_runs(
    session: Any, team_id: str | None, module_id: str
) -> ModuleHealthSummary:
    """Summarize a module by its WorkflowRunRecord history."""
    from sqlalchemy import func
    from sqlmodel import select

    from aila.storage.db_models import WorkflowRunRecord

    try:
        count_stmt = select(func.count()).select_from(WorkflowRunRecord).where(
            WorkflowRunRecord.module_id == module_id,
        )
        last_stmt = select(func.max(WorkflowRunRecord.completed_at)).where(
            WorkflowRunRecord.module_id == module_id,
        )
        if team_id is not None:
            count_stmt = count_stmt.where(WorkflowRunRecord.team_id == team_id)
            last_stmt = last_stmt.where(WorkflowRunRecord.team_id == team_id)

        count_result = await session.exec(count_stmt)
        count_value = count_result.one()
        if isinstance(count_value, tuple):
            count_value = count_value[0]

        last_result = await session.exec(last_stmt)
        last_at = last_result.one()
        if isinstance(last_at, tuple):
            last_at = last_at[0]
    except Exception as exc:
        return ModuleHealthSummary(
            module_id=module_id,
            status="error",
            message=f"query failed: {type(exc).__name__}",
        )

    status = _activity_status(last_at)
    return ModuleHealthSummary(
        module_id=module_id,
        status=status,
        last_activity_at=last_at,
        activity_count=int(count_value or 0),
        message=None,
    )


async def _scheduled_reports_summary(
    session: Any, team_id: str | None
) -> ModuleHealthSummary:
    """Summarize the scheduled_reports module by last execution time."""
    from sqlalchemy import func
    from sqlmodel import select

    try:
        # ScheduledReportRecord may or may not exist depending on migrations.
        from aila.storage.db_models import ScheduledReportRecord
    except ImportError:
        return ModuleHealthSummary(
            module_id="scheduled_reports",
            status="unknown",
            message="module not installed",
        )

    try:
        count_stmt = select(func.count()).select_from(ScheduledReportRecord)
        last_stmt = select(func.max(ScheduledReportRecord.last_run_at))
        if team_id is not None and hasattr(ScheduledReportRecord, "team_id"):
            count_stmt = count_stmt.where(ScheduledReportRecord.team_id == team_id)
            last_stmt = last_stmt.where(ScheduledReportRecord.team_id == team_id)

        count_result = await session.exec(count_stmt)
        count_value = count_result.one()
        if isinstance(count_value, tuple):
            count_value = count_value[0]

        last_result = await session.exec(last_stmt)
        last_at = last_result.one()
        if isinstance(last_at, tuple):
            last_at = last_at[0]
    except Exception as exc:
        return ModuleHealthSummary(
            module_id="scheduled_reports",
            status="error",
            message=f"query failed: {type(exc).__name__}",
        )

    status = _activity_status(last_at) if count_value else "healthy"
    return ModuleHealthSummary(
        module_id="scheduled_reports",
        status=status,
        last_activity_at=last_at,
        activity_count=int(count_value or 0),
        message=None,
    )


def _activity_status(last_at: datetime | None) -> str:
    """Classify a last-activity timestamp into healthy/stale/unknown."""
    if last_at is None:
        # No activity yet is not 'stale' -- the module may simply be new.
        return "healthy"
    if last_at.tzinfo is None:
        # Treat naive timestamps as UTC to avoid TypeError on subtraction.
        last_at = last_at.replace(tzinfo=UTC)
    age = _utcnow() - last_at
    if age.total_seconds() > 24 * 3600:
        return "stale"
    return "healthy"
