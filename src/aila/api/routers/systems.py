"""Systems router for AILA REST API.

Platform-owned endpoint for managed systems (SSH targets).
System detail includes module-contributed dashboard data via system_summary().
List endpoint returns enriched items with connectivity, tags, scan status, and top severity.
"""
from __future__ import annotations

import asyncio
import logging
import math
import time as _time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import IntegrityError
from sqlmodel import func, select

from aila.api.auth import (
    AuthContext,
    TeamContext,
    require_role,
    require_user_or_api_key,
)
from aila.api.constants import (
    AUDIT_ACTION_SYSTEM_CREATE,
    AUDIT_ACTION_SYSTEM_DELETE,
    AUDIT_ACTION_SYSTEM_UPDATE,
    AUDIT_STAGE_SYSTEM,
    AUDIT_STATUS_COMPLETED,
    ROLE_OPERATOR,
)
from aila.api.limiter import limiter
from aila.api.schemas.findings import FindingResponse, FindingsListResponse
from aila.api.schemas.systems import (
    ConnectivityStatusResponse,
    ScanHistoryResponse,
    SystemCreateRequest,
    SystemCSVImportRequest,
    SystemCSVImportResponse,
    SystemDetailResponse,
    SystemEnrichedResponse,
    SystemListResponse,
    SystemResponse,
    SystemUpdateRequest,
)
from aila.platform.contracts._common import utc_now
from aila.platform.services.audit import record_audit_event
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord, SystemPortRecord, WorkflowRunRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

class HeartbeatResponse(BaseModel):
    """Live SSH reachability result returned by /systems/{id}/heartbeat."""

    model_config = ConfigDict(extra="forbid")

    system_id: int
    reachable: bool
    latency_ms: float | None
    checked_at: str
    error: str | None


class HeartbeatEnvelope(BaseModel):
    """Wrapper used by /systems/{id}/heartbeat to mirror DataEnvelope shape."""

    model_config = ConfigDict(extra="forbid")

    data: HeartbeatResponse



router = APIRouter(
    prefix="/systems",
    tags=["systems"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _system_to_response(record: ManagedSystemRecord) -> SystemResponse:
    return SystemResponse(
        id=record.id,  # type: ignore[arg-type]
        name=record.name,
        host=record.host,
        username=record.username,
        port=record.port,
        distro=record.distro,
        description=record.description,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


async def _build_connectivity_map(session: object, system_ids: list[int]) -> dict[int, str]:
    """Return connectivity status for each system_id.

    Queries SystemPortRecord grouped by system_id. Logic per D-03:
    - At least one non-stale row: reachable
    - All rows stale: unreachable
    - No rows at all: unknown
    """
    if not system_ids:
        return {}

    stmt = (
        select(
            SystemPortRecord.system_id,
            func.bool_or(~SystemPortRecord.is_stale).label("has_live"),
            func.count(SystemPortRecord.id).label("total"),
        )
        .where(SystemPortRecord.system_id.in_(system_ids))  # type: ignore[attr-defined]
        .group_by(SystemPortRecord.system_id)
    )
    try:
        rows = (await session.exec(stmt)).all()  # type: ignore[union-attr]
    except Exception:
        _log.debug("connectivity_map query failed", exc_info=True)
        return {}

    result: dict[int, str] = {}
    for row in rows:
        sid = int(row.system_id)
        if row.has_live:
            result[sid] = "reachable"
        else:
            result[sid] = "unreachable"

    # Systems with no port records stay "unknown" (absent from result dict)
    return result


async def _build_tags_map(session: object, system_ids: list[int], platform: object) -> dict[int, list[dict[str, str]]]:
    """Return tag lists for each system_id through the vulnerability module surface."""
    if platform is None or not system_ids:
        return {}
    try:
        module = platform.runtime.module_registry.require("vulnerability")  # type: ignore[attr-defined]
        return await module.system_tags_map(system_ids, session)
    except Exception:
        _log.debug("tags_map query failed", exc_info=True)
        return {}


async def _build_scan_map(session: object, system_names: list[str]) -> dict[str, tuple[object, str | None]]:
    """Return (last_scan_at, last_scan_status) keyed by system name.

    Uses the route_json string-contains pattern established in get_system() (D-12).
    Returns the most recent completed_at per system name.
    """
    if not system_names:
        return {}

    try:
        all_runs = (await session.exec(select(WorkflowRunRecord))).all()  # type: ignore[union-attr]
    except Exception:
        _log.debug("scan_map query failed", exc_info=True)
        return {}

    # Group by system name match (string-contains, same trade-off as get_system)
    result: dict[str, tuple[object, str | None]] = {}
    for run in all_runs:
        route = run.route_json or ""
        for name in system_names:
            if name in route:
                existing = result.get(name)
                if existing is None or (run.completed_at and (existing[0] is None or run.completed_at > existing[0])):
                    result[name] = (run.completed_at, run.status)
    return result


async def _build_fleet_severity_map(platform: object, system_ids: list[int], session: object) -> dict[int, str]:
    """Collect top severity per system_id from all registered modules.

    Calls optional fleet_severity_summary(system_ids, session) on each module.
    Modules that do not implement this method are silently skipped (D-20).
    """
    if platform is None or not system_ids:
        return {}

    try:
        modules = platform.runtime.module_registry.modules  # type: ignore[attr-defined]
    except AttributeError:
        _log.debug("Platform runtime missing module_registry for fleet severity", exc_info=True)
        return {}

    merged: dict[int, str] = {}
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for module in modules:
        if not hasattr(module, "fleet_severity_summary"):
            continue
        try:
            module_result: dict[int, str] = await module.fleet_severity_summary(system_ids, session)
            for sid, sev in module_result.items():
                existing = merged.get(sid)
                if existing is None or severity_order.get(sev, 0) > severity_order.get(existing, 0):
                    merged[sid] = sev
        except Exception:
            _log.debug("Module %s fleet_severity_summary failed", getattr(module, "module_id", "?"), exc_info=True)

    return merged


@router.get("", response_model=SystemListResponse, summary="List registered systems")
@limiter.limit("120/minute")
async def list_systems(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> SystemListResponse:
    """Return a paginated list of all registered SSH systems with enrichment data.

    Each item includes connectivity_status, tags, last_scan_at, last_scan_status,
    and top_severity. Enrichment uses aggregated queries -- not N+1 per system (D-03/D-11/D-12/D-20).
    """

    async def _query() -> tuple[list[ManagedSystemRecord], int, dict, dict, dict, dict]:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            count_stmt = select(func.count(ManagedSystemRecord.id))
            if auth.team_id is not None:
                count_stmt = count_stmt.where(ManagedSystemRecord.team_id == auth.team_id)
            total = (await session.exec(count_stmt)).one()

            offset = (page - 1) * page_size
            stmt = (
                select(ManagedSystemRecord)
                .order_by(ManagedSystemRecord.name)
                .offset(offset)
                .limit(page_size)
            )
            rows = list((await session.exec(stmt)).all())
            system_ids = [r.id for r in rows if r.id is not None]
            system_names = [r.name for r in rows]

            connectivity_map = await _build_connectivity_map(session, system_ids)
            platform = getattr(request.app.state, "platform", None)
            tags_map = await _build_tags_map(session, system_ids, platform)
            scan_map = await _build_scan_map(session, system_names)
            severity_map = await _build_fleet_severity_map(platform, system_ids, session)

            return rows, int(total), connectivity_map, tags_map, scan_map, severity_map

    rows, total, connectivity_map, tags_map, scan_map, severity_map = await _query()

    items: list[SystemEnrichedResponse] = []
    for r in rows:
        sid = r.id
        scan_entry = scan_map.get(r.name)
        items.append(
            SystemEnrichedResponse(
                id=sid,  # type: ignore[arg-type]
                name=r.name,
                host=r.host,
                username=r.username,
                port=r.port,
                distro=r.distro,
                description=r.description,
                created_at=r.created_at,
                updated_at=r.updated_at,
                connectivity_status=connectivity_map.get(sid) if sid is not None else None,  # type: ignore[arg-type]
                tags=tags_map.get(sid, []) if sid is not None else [],  # type: ignore[arg-type]
                last_scan_at=scan_entry[0] if scan_entry else None,  # type: ignore[arg-type]
                last_scan_status=scan_entry[1] if scan_entry else None,
                top_severity=severity_map.get(sid) if sid is not None else None,  # type: ignore[arg-type]
            )
        )

    return SystemListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
        items=items,
    )


async def _collect_module_summaries(platform: object, system_id: int, session: object) -> dict[str, dict[str, object]]:
    """Gather system_summary() contributions from all registered modules.

    Each module may expose an optional system_summary(system_id, session) method.
    Failures are caught per-module so one broken module does not block the rest.
    """
    if platform is None:
        return {}
    try:
        modules = platform.runtime.module_registry.modules  # type: ignore[attr-defined]  # AILAPlatform duck-typed
    except AttributeError:
        _log.debug("Platform runtime missing module_registry", exc_info=True)
        return {}

    summaries: dict[str, dict[str, object]] = {}
    for module in modules:
        if not hasattr(module, "system_summary"):
            continue
        try:
            result = await module.system_summary(system_id, session)
            if result:
                summaries[module.module_id] = result
        except Exception:
            _log.debug("Module %s system_summary failed", module.module_id, exc_info=True)
    return summaries


@router.get("/{system_id}/connectivity", response_model=ConnectivityStatusResponse, summary="Get SSH connectivity status")
@limiter.limit("120/minute")
async def get_system_connectivity(
    system_id: int,
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> ConnectivityStatusResponse:
    """Return SSH connectivity status for a system based on the last network discovery probe.

    Logic per D-03:
    - At least one non-stale port record: reachable
    - All port records stale: unreachable
    - No port records at all: unknown

    last_checked is the MAX(last_collected) across all port records for this system.
    """

    async def _query() -> ConnectivityStatusResponse | None:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            # Verify the system exists and belongs to the caller's team
            sys_record = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if sys_record is None:
                return None

            live_stmt = select(func.count(SystemPortRecord.id)).where(
                SystemPortRecord.system_id == system_id,
                ~SystemPortRecord.is_stale,
            )
            live_count = (await session.exec(live_stmt)).one()

            stale_stmt = select(func.count(SystemPortRecord.id)).where(
                SystemPortRecord.system_id == system_id,
                SystemPortRecord.is_stale,
            )
            stale_count = (await session.exec(stale_stmt)).one()

            last_checked_stmt = select(func.max(SystemPortRecord.last_collected)).where(
                SystemPortRecord.system_id == system_id,
            )
            last_checked = (await session.exec(last_checked_stmt)).one()

            total = int(live_count) + int(stale_count)
            if total == 0:
                conn_status = "unknown"
            elif int(live_count) > 0:
                conn_status = "reachable"
            else:
                conn_status = "unreachable"

            return ConnectivityStatusResponse(status=conn_status, last_checked=last_checked)

    result = await _query()
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found -- verify the ID via GET /systems",
        )
    return result



_HEARTBEAT_CACHE_TTL_S = 30.0
_heartbeat_cache: dict[int, tuple[float, dict]] = {}
_heartbeat_locks: dict[int, asyncio.Lock] = {}


def _heartbeat_lock(system_id: int) -> asyncio.Lock:
    lock = _heartbeat_locks.get(system_id)
    if lock is None:
        lock = asyncio.Lock()
        _heartbeat_locks[system_id] = lock
    return lock


@router.get(
    "/{system_id}/heartbeat",
    response_model=HeartbeatEnvelope,
    summary=(
        "Live SSH reachability probe (echo ok, 3 s timeout). Cached "
        "30 s server-side."
    ),
)
@limiter.limit("60/minute")
async def get_system_heartbeat(
    system_id: int,
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> HeartbeatEnvelope:
    """Live SSH heartbeat -- opens a fresh paramiko connect with a 3 s
    timeout, runs ``echo ok``, measures latency, and returns the
    result. Cached for 30 s to avoid hammering the workstation when
    the frontend polls every 30 s anyway.
    """
    del request
    from aila.config import get_settings
    from aila.platform.config import build_platform_settings
    from aila.platform.services.ssh import SSHService

    # Enforce team ownership before consulting the shared cache so a
    # cross-team caller cannot read another team's cached probe result.
    async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
        owned = (await session.exec(
            select(ManagedSystemRecord.id).where(ManagedSystemRecord.id == system_id)
        )).first()
    if owned is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )

    now = _time.monotonic()
    cached = _heartbeat_cache.get(system_id)
    if cached is not None and (now - cached[0]) < _HEARTBEAT_CACHE_TTL_S:
        return HeartbeatEnvelope(data=HeartbeatResponse(**cached[1]))

    async with _heartbeat_lock(system_id):
        cached = _heartbeat_cache.get(system_id)
        if cached is not None and (_time.monotonic() - cached[0]) < _HEARTBEAT_CACHE_TTL_S:
            return HeartbeatEnvelope(data=HeartbeatResponse(**cached[1]))

        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            sys_record = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if sys_record is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"System {system_id} not found",
                )
            integration = {
                "name": sys_record.name,
                "host": sys_record.host,
                "username": sys_record.username,
                "port": sys_record.port,
                "private_key_path": sys_record.private_key_path,
                "password_secret_id": sys_record.password_secret_id,
                "known_hosts_path": sys_record.known_hosts_path,
                "host_key_fingerprint": sys_record.host_key_fingerprint,
            }

        ssh = SSHService(build_platform_settings(get_settings()))
        checked_at = datetime.now(UTC).isoformat()
        started = _time.monotonic()
        reachable = False
        latency_ms: float | None = None
        error: str | None = None
        try:
            await ssh.run_command(
                integration, "echo ok",
                timeout_seconds=3.0, connect_timeout=3.0,
            )
            reachable = True
            latency_ms = round((_time.monotonic() - started) * 1000.0, 1)
        except (OSError, TimeoutError) as exc:
            error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # paramiko-specific errors
            error = f"{type(exc).__name__}: {exc}"

        payload = {
            "system_id": system_id,
            "reachable": reachable,
            "latency_ms": latency_ms,
            "checked_at": checked_at,
            "error": error,
        }
        _heartbeat_cache[system_id] = (_time.monotonic(), payload)
        return HeartbeatEnvelope(data=HeartbeatResponse(**payload))


@router.get("/{system_id}", response_model=SystemDetailResponse, summary="Get system detail")
async def get_system(
    system_id: int,
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> SystemDetailResponse:
    """Return full system detail with module-contributed dashboard data.

    Module summaries come from calling system_summary(system_id, session)
    on each registered module that implements the optional method.
    """

    async def _fetch() -> tuple[ManagedSystemRecord | None, int, dict[str, dict[str, object]]]:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            record = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if record is None:
                return None, 0, {}

            stmt = select(WorkflowRunRecord).where(
                WorkflowRunRecord.route_json.contains(record.name)  # type: ignore[attr-defined]  # SQLModel column expression
            )
            scan_count = len((await session.exec(stmt)).all())

            platform = request.app.state.platform
            module_summaries = await _collect_module_summaries(platform, system_id, session)

            return record, scan_count, module_summaries

    record, scan_count, module_summaries = await _fetch()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found -- verify the ID via GET /systems",
        )

    base = _system_to_response(record)
    return SystemDetailResponse(
        id=base.id,
        name=base.name,
        host=base.host,
        username=base.username,
        port=base.port,
        distro=base.distro,
        description=base.description,
        created_at=base.created_at,
        updated_at=base.updated_at,
        module_summaries=module_summaries,
        scan_count=scan_count,
    )


@router.get("/{system_id}/findings", response_model=FindingsListResponse, summary="Get findings for system")
async def get_system_findings(
    system_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> FindingsListResponse:
    """Return findings scoped to one system via module protocol delegation.

    Delegates to each registered module's system_findings() method so the
    platform router never imports module-internal models (MOD-STD-07).
    """
    platform = getattr(request.app.state, "platform", None)

    async def _query() -> dict[str, object]:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            sys_record = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if sys_record is None:
                return {"items": [], "total": 0}

            all_items: list[dict[str, object]] = []
            total = 0
            if platform is not None:
                try:
                    for module in platform.runtime.module_registry.modules:
                        if hasattr(module, "system_findings"):
                            result = await module.system_findings(
                                system_id=system_id,
                                system_name=sys_record.name,
                                session=session,
                                page=page,
                                page_size=page_size,
                            )
                            all_items.extend(result.get("items", []))
                            total += result.get("total", 0)
                except Exception:
                    _log.debug("system_findings delegation failed for system %s", system_id, exc_info=True)

            return {"items": all_items, "total": total}

    result = await _query()
    items_raw = result.get("items", [])
    total = int(result.get("total", 0))

    items = [
        FindingResponse(
            run_id=str(r.get("run_id", "")),
            cve_id=str(r.get("cve_id")) if r.get("cve_id") is not None else None,
            package=str(r.get("package")) if r.get("package") is not None else None,
            host=str(r.get("host")) if r.get("host") is not None else None,
            severity=str(r.get("severity")) if r.get("severity") is not None else None,
            kev=bool(r.get("kev", False)),
            score=float(str(r.get("score"))) if r.get("score") is not None else None,
            status=str(r.get("status")) if r.get("status") is not None else None,
        )
        for r in items_raw
    ]
    return FindingsListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
        items=items,
    )


@router.get("/{system_id}/scans", response_model=ScanHistoryResponse, summary="Get scan history for system")
async def get_system_scans(
    system_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> ScanHistoryResponse:
    """Return scan history for a system (workflow runs linked to this system)."""
    from aila.api.schemas.reports import ReportSummaryResponse

    async def _query() -> tuple[ManagedSystemRecord | None, list[WorkflowRunRecord]]:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            sys_record = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if sys_record is None:
                return None, []
            stmt = select(WorkflowRunRecord).order_by(WorkflowRunRecord.created_at.desc())  # type: ignore[attr-defined]  # SQLModel column expression
            all_runs = list((await session.exec(stmt)).all())
            matching = [r for r in all_runs if sys_record.name in (r.route_json or "")]
            return sys_record, matching

    sys_record, runs = await _query()
    if sys_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found -- verify the ID via GET /systems",
        )

    total = len(runs)
    offset = (page - 1) * page_size
    page_runs = runs[offset : offset + page_size]
    items = [
        ReportSummaryResponse(
            run_id=r.id,
            query_text=r.query_text,
            module_id=r.module_id,
            status=r.status,
            created_at=r.created_at,
            completed_at=r.completed_at,
        )
        for r in page_runs
    ]
    return ScanHistoryResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
        items=[i.model_dump() for i in items],
    )


@router.post(
    "/import-csv",
    response_model=SystemCSVImportResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch import systems from CSV data",
)
@limiter.limit("60/minute")
async def import_systems_csv(
    request: Request,
    req: SystemCSVImportRequest,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> SystemCSVImportResponse:
    """Batch create systems from a parsed CSV payload (D-09, T-142-01, T-142-05).

    Accepts up to 500 system definitions. Processes each row individually:
    - Success: appended to created[]
    - Duplicate name or validation error: appended to errors[] with {row_index, name, reason}

    Always returns HTTP 200 (partial success is valid for batch operations).
    Rate limited at 60/minute. Requires operator+ role (T-142-01).
    Audit event records total created and error counts (T-142-03).
    """
    created: list[SystemResponse] = []
    errors: list[dict[str, object]] = []

    for idx, system_req in enumerate(req.systems):
        async def _create_one(item: SystemCreateRequest) -> ManagedSystemRecord:
            async with async_session_scope() as session:
                from aila.storage.secrets import SecretStore
                secret_store = SecretStore()

                private_key_secret_id: str | None = None
                if item.private_key:
                    secret_rec = await secret_store.store(
                        session, scope="ssh",
                        secret_key=f"system.{item.name}.private_key",
                        plaintext=item.private_key,
                    )
                    private_key_secret_id = secret_rec.id

                password_secret_id: str | None = None
                if item.password:
                    secret_rec = await secret_store.store(
                        session, scope="ssh",
                        secret_key=f"system.{item.name}.password",
                        plaintext=item.password,
                    )
                    password_secret_id = secret_rec.id

                record = ManagedSystemRecord(
                    team_id=auth.team_id,
                    name=item.name,
                    host=item.host,
                    username=item.username,
                    port=item.port,
                    distro=item.distro,
                    description=item.description,
                    private_key_secret_id=private_key_secret_id,
                    password_secret_id=password_secret_id,
                )
                session.add(record)
                await session.commit()
                await session.refresh(record)
                return record

        try:
            record = await _create_one(system_req)
            created.append(_system_to_response(record))
        except IntegrityError:
            errors.append(
                {
                    "row_index": idx,
                    "name": system_req.name,
                    "reason": f"System name '{system_req.name}' already exists",
                }
            )
        except Exception as exc:
            errors.append(
                {
                    "row_index": idx,
                    "name": system_req.name,
                    "reason": str(exc),
                }
            )

    # Audit the import event (T-142-03: repudiation mitigation)
    try:
        async with async_session_scope() as audit_session:
            record_audit_event(
                audit_session,
                run_id=f"csv-import-{auth.user_id}",
                stage=AUDIT_STAGE_SYSTEM,
                action=AUDIT_ACTION_SYSTEM_CREATE,
                status=AUDIT_STATUS_COMPLETED,
                target="csv-batch-import",
                user_id=auth.user_id,
                details={
                    "created_count": len(created),
                    "error_count": len(errors),
                    "total_submitted": len(req.systems),
                },
            )
            await audit_session.commit()
    except Exception:
        _log.debug("Audit event for CSV import failed", exc_info=True)

    return SystemCSVImportResponse(created=created, errors=errors)


@limiter.limit("60/minute")
@router.post("", response_model=SystemResponse, status_code=status.HTTP_201_CREATED, summary="Register a system")
async def create_system(
    request: Request,
    req: SystemCreateRequest,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),  # D-07: operator+ per D-21
) -> SystemResponse:
    """Create a new managed system (SSH target). Requires operator+ role (D-07).

    Returns 409 Conflict if name is already taken (D-08 unique constraint).
    """

    async def _create() -> ManagedSystemRecord:
        async with async_session_scope() as session:
            from aila.storage.secrets import SecretStore
            secret_store = SecretStore()

            # Encrypt private key content if provided
            private_key_secret_id: str | None = None
            if req.private_key:
                secret_rec = await secret_store.upsert_secret(
                    session,
                    scope="ssh",
                    secret_key=f"system.{req.name}.private_key",
                    plaintext=req.private_key,
                )
                private_key_secret_id = secret_rec.id

            # Encrypt password if provided
            password_secret_id: str | None = None
            if req.password:
                secret_rec = await secret_store.upsert_secret(
                    session,
                    scope="ssh",
                    secret_key=f"system.{req.name}.password",
                    plaintext=req.password,
                )
                password_secret_id = secret_rec.id

            record = ManagedSystemRecord(
                team_id=auth.team_id,
                name=req.name,
                host=req.host,
                username=req.username,
                port=req.port,
                distro=req.distro,
                description=req.description,
                private_key_secret_id=private_key_secret_id,
                password_secret_id=password_secret_id,
            )
            session.add(record)
            # #52-3.2: flush to populate the DB-generated PK and surface
            # the unique-name constraint here, then stage the audit row
            # and commit both in a single transaction. The previous flow
            # (`commit(); refresh; audit; commit()`) opened a crash
            # window where the system row was persisted but the audit
            # trail row was lost. A duplicate-name 409 short-circuits
            # before any audit row is staged -- no change, no audit.
            try:
                await session.flush()
            except IntegrityError:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"System name '{req.name}' already exists -- choose a different name or update the existing system via PUT /systems/{{id}}",
                )
            record_audit_event(
                session,
                run_id=str(record.id),
                stage=AUDIT_STAGE_SYSTEM,
                action=AUDIT_ACTION_SYSTEM_CREATE,
                status=AUDIT_STATUS_COMPLETED,
                target=record.name,
                user_id=auth.user_id,
                details={"host": record.host, "name": record.name},
            )
            await session.commit()
            await session.refresh(record)
            return record

    record = await _create()
    return _system_to_response(record)


@limiter.limit("60/minute")
@router.put("/{system_id}", response_model=SystemResponse, summary="Update a system")
async def update_system(
    request: Request,
    system_id: int,
    req: SystemUpdateRequest,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),  # D-07: operator+ per D-21
) -> SystemResponse:
    """Update mutable fields on a registered system. Requires operator+ role (D-07).

    Only non-None fields in the request body are applied; absent fields are unchanged.
    Returns 404 if the system does not exist.
    Returns 409 if the new name conflicts with an existing system.
    """

    async def _update() -> ManagedSystemRecord:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            record: ManagedSystemRecord | None = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if record is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"System {system_id} not found -- verify the ID via GET /systems",
                )
            update_data = req.model_dump(exclude_none=True)

            from aila.storage.secrets import SecretStore
            secret_store = SecretStore()

            # Handle private key content -- encrypt and store as secret
            if "private_key" in update_data:
                plaintext = update_data.pop("private_key")
                secret_rec = await secret_store.store(
                    session, scope="ssh",
                    secret_key=f"system.{record.name}.private_key",
                    plaintext=plaintext,
                    secret_id=record.private_key_secret_id,
                )
                record.private_key_secret_id = secret_rec.id

            # Handle password encryption
            if "password" in update_data:
                plaintext = update_data.pop("password")
                secret_rec = await secret_store.store(
                    session, scope="ssh",
                    secret_key=f"system.{record.name}.password",
                    plaintext=plaintext,
                    secret_id=record.password_secret_id,
                )
                record.password_secret_id = secret_rec.id

            # Handle passphrase -- not a direct DB field, pop to avoid setattr
            if "private_key_passphrase" in update_data:
                update_data.pop("private_key_passphrase")

            for field, value in update_data.items():
                setattr(record, field, value)
            record.updated_at = utc_now()
            session.add(record)
            # #52-3.2: stage the audit row inside the SAME transaction as
            # the row update. Previously the update committed first and
            # the audit row was written in a second transaction, so a
            # crash between the two lost the audit trail. record_audit_event
            # only stages an INSERT on the session; the single commit
            # below persists both or neither. An IntegrityError from the
            # unique-name constraint rolls the audit row back with the
            # attempted rename -- correct: no change, no audit.
            audited_fields = list(update_data.keys())
            record_audit_event(
                session,
                run_id=str(system_id),
                stage=AUDIT_STAGE_SYSTEM,
                action=AUDIT_ACTION_SYSTEM_UPDATE,
                status=AUDIT_STATUS_COMPLETED,
                target=record.name,
                user_id=auth.user_id,
                details={"fields": audited_fields},
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"System name '{req.name}' already exists -- choose a different name or update the existing system via PUT /systems/{{id}}",
                )
            await session.refresh(record)
            return record

    record = await _update()
    return _system_to_response(record)


@limiter.limit("60/minute")
@router.delete("/{system_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a system")
async def delete_system(
    request: Request,
    system_id: int,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),  # D-07: operator+ per D-21
) -> None:
    """Remove a registered system. Requires operator+ role (D-07).

    Returns 404 if the system does not exist.
    """

    async def _delete() -> None:
        async with async_session_scope(team_context=TeamContext.from_auth(auth)) as session:
            record = (await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
            if record is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"System {system_id} not found -- verify the ID via GET /systems",
                )
            system_name = record.name
            await session.delete(record)
            # #52-3.2: audit row shares the same transaction as the row
            # delete. Previously a crash between the two commits lost the
            # audit trail while the system row was already gone.
            record_audit_event(
                session,
                run_id=str(system_id),
                stage=AUDIT_STAGE_SYSTEM,
                action=AUDIT_ACTION_SYSTEM_DELETE,
                status=AUDIT_STATUS_COMPLETED,
                target=system_name,
                user_id=auth.user_id,
                details={"system_id": system_id},
            )
            await session.commit()

    await _delete()
