"""Admin sandbox exec router (issue #147).

Operator surface for on-demand :class:`SandboxService` runs. Every
endpoint requires god-tier admin (``team_id=None``): the sandbox host
is a shared platform resource and a per-team admin has no reason to
drive it directly -- normal module callers reach the sandbox through
the ``sandbox_exec`` tool inside their agent turn.

Endpoints:

    POST /platform/sandbox/exec
        Body: :class:`SandboxExecRequest` -- argv + optional overrides.
        Returns the full :class:`SandboxResult` payload. When no backend
        is provisioned for the deployment the endpoint returns 503 with
        an actionable message.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.deps import get_config_registry
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.config import get_settings
from aila.platform.config import build_platform_settings
from aila.platform.services.sandbox import (
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
)
from aila.platform.services.sandbox.service import SandboxProbe, SandboxService
from aila.storage.database import async_session_scope
from aila.storage.db_models import SandboxExecHistoryRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Sandbox exec drives a shared platform resource; god-tier only.

    A team-scoped admin has no business submitting arbitrary commands
    to the sandbox host on behalf of another team's workload. Callers
    who need scoped access go through their module's normal
    ``sandbox_exec`` tool, which carries the team context automatically
    inside the agent turn.
    """
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Platform sandbox exec is restricted to god-tier "
                "administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/platform/sandbox",
    tags=["platform-sandbox"],
    dependencies=[Depends(_require_admin)],
)


class SandboxExecRequest(BaseModel):
    """HTTP body for ``POST /platform/sandbox/exec``.

    Kept intentionally close to :class:`SandboxSpec` -- every field
    maps 1:1 -- so the router body is a thin projection of the service
    contract and there is exactly one policy surface (the service
    itself).
    """

    model_config = ConfigDict(extra="forbid")

    argv: list[str] = Field(min_length=1, description="Command + arguments to execute inside the sandbox.")
    stdin: str | None = None
    input_files: dict[str, str] = Field(default_factory=dict)
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: float = Field(default=30.0, gt=0.0)
    network: bool = False
    vcpu: int = Field(default=1, ge=1)
    mem_mb: int = Field(default=512, ge=1)
    workdir: str = "/work"
    output_globs: list[str] = Field(default_factory=list)


class SandboxResultResponse(BaseModel):
    """Response projection of :class:`SandboxResult` for the admin surface."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    exit_code: int | None
    stdout: str
    stderr: str
    output_files: dict[str, str]
    duration_s: float
    timed_out: bool
    oom: bool
    truncated: bool


class SandboxCheck(BaseModel):
    """A single readiness check for the sandbox governance panel."""

    model_config = ConfigDict(extra="forbid")

    name: str
    ok: bool
    detail: str


class SandboxStatus(BaseModel):
    """Config-derived readiness snapshot for ``GET /platform/sandbox/status``."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    provisioned: bool
    ssh_host: str
    ssh_reachable: bool | None
    host_os: str
    checks: list[SandboxCheck]


class SandboxProbeResponse(BaseModel):
    """Response body for ``POST /platform/sandbox/probe``."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    detail: str
    duration_ms: int
    tool_installed: bool = True
    tool_missing: bool = False
    installed_path: str | None = None


class SandboxBootstrapRequest(BaseModel):
    """Request body for ``POST /platform/sandbox/install``."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(default="nsjail", description="Sandbox tool to install: 'nsjail' or 'firecracker'.")


class SandboxBootstrapResponse(BaseModel):
    """Response body for ``POST /platform/sandbox/install``."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    detail: str
    output: str
    duration_ms: int


class SandboxTargetRequest(BaseModel):
    """Request body for ``POST /platform/sandbox/target``."""

    model_config = ConfigDict(extra="forbid")

    system_id: str | None = Field(default=None, description="Registered system ID from Systems Registry.")
    system_name: str | None = Field(default=None, description="System name.")
    host: str = Field(..., description="SSH host IP or hostname.")
    username: str = Field(default="root", description="SSH username.")
    port: int = Field(default=22, description="SSH port.")
    backend: str | None = Field(default=None, description="Target backend: 'nsjail' or 'firecracker'.")


class SandboxHistoryRow(BaseModel):
    """Response row for ``GET /platform/sandbox/history``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    actor_user_id: str | None
    argv: list[str]
    exit_code: int | None
    duration_s: float
    timed_out: bool
    oom: bool
    truncated: bool
    created_at: str


def _to_response(result: SandboxResult) -> SandboxResultResponse:
    return SandboxResultResponse(
        backend=result.backend,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        output_files=dict(result.output_files),
        duration_s=result.duration_s,
        timed_out=result.timed_out,
        oom=result.oom,
        truncated=result.truncated,
    )


@router.post("/exec", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def exec_sandbox(
    request: Request,
    body: SandboxExecRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[SandboxResultResponse]:
    """Dispatch one command through the platform sandbox.

    Returns 503 (Service Unavailable) with a clear message when the
    operator has not provisioned a sandbox backend for the deployment;
    the caller MUST treat that as a config gap and NEVER retry with a
    request that would need an un-isolated fallback.
    """
    del request  # rate limiter reads it; body handler does not
    _log.info(
        "platform.sandbox.exec argv0=%s timeout_s=%.1f network=%s actor=%s",
        body.argv[0], body.timeout_s, body.network, ctx.user_id or "unknown",
    )

    spec = SandboxSpec(
        argv=list(body.argv),
        stdin=body.stdin,
        input_files=dict(body.input_files),
        env=dict(body.env),
        timeout_s=body.timeout_s,
        network=body.network,
        vcpu=body.vcpu,
        mem_mb=body.mem_mb,
        workdir=body.workdir,
        output_globs=list(body.output_globs),
    )

    # Fresh service instance so the config is re-resolved per request --
    # a PUT /config/platform/sandbox_* takes effect on the next dispatch
    # without a worker restart.
    platform_settings = build_platform_settings(get_settings())
    service = SandboxService(platform_settings)

    try:
        result = await service.run(spec)
    except SandboxUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except SandboxExecutionError as exc:
        _log.warning("platform.sandbox.exec backend failure: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"sandbox backend failed: {exc}",
        ) from exc

    try:
        async with async_session_scope() as session:
            session.add(SandboxExecHistoryRecord(
                actor_user_id=ctx.user_id,
                argv=list(spec.argv),
                exit_code=result.exit_code,
                duration_s=result.duration_s,
                timed_out=result.timed_out,
                oom=result.oom,
                truncated=result.truncated,
            ))
            await session.commit()
    except SQLAlchemyError as exc:
        _log.warning("platform.sandbox.exec history insert failed: %s", exc)

    return DataEnvelope(data=_to_response(result))


@router.get("/status", status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def sandbox_status(
    request: Request,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[SandboxStatus]:
    """Config-derived readiness for the sandbox governance panel.

    Reads the live ConfigRegistry snapshot (same values ``exec`` resolves)
    and reports per-knob checks. It NEVER runs a job and NEVER 500s on an
    unprovisioned or misconfigured backend -- an un-provisioned deployment
    honestly returns ``provisioned=false`` with the failing checks named.
    ``ssh_reachable`` is left ``null`` (config-only probe); a live round-trip
    happens on demand via ``POST /exec``.
    """
    del request, ctx
    service = SandboxService(build_platform_settings(get_settings()))
    cfg = await service.describe()

    backend = (cfg.backend or "none").strip().lower()
    ssh_host = (cfg.ssh_host or "").strip()
    checks: list[SandboxCheck] = []

    backend_ok = backend in ("nsjail", "firecracker")
    checks.append(SandboxCheck(
        name="backend selected",
        ok=backend_ok,
        detail=(f"sandbox_backend={backend}" if backend_ok
                else "sandbox_backend is 'none' -- set it to 'nsjail' or 'firecracker' to provision"),
    ))
    host_ok = bool(ssh_host)
    checks.append(SandboxCheck(
        name="ssh host configured",
        ok=host_ok,
        detail=(f"sandbox_ssh_host={ssh_host}" if host_ok else "sandbox_ssh_host is empty"),
    ))

    if backend == "nsjail":
        checks.append(SandboxCheck(
            name="nsjail binary configured",
            ok=bool(cfg.nsjail_bin.strip()),
            detail=f"sandbox_nsjail_bin={cfg.nsjail_bin or '(unset)'}",
        ))
    elif backend == "firecracker":
        checks.append(SandboxCheck(name="firecracker binary configured", ok=bool(cfg.firecracker_bin.strip()), detail=f"sandbox_firecracker_bin={cfg.firecracker_bin or '(unset)'}"))
        checks.append(SandboxCheck(name="jailer binary configured", ok=bool(cfg.jailer_bin.strip()), detail=f"sandbox_jailer_bin={cfg.jailer_bin or '(unset)'}"))
        checks.append(SandboxCheck(name="rootfs path configured", ok=bool(cfg.rootfs_path.strip()), detail=f"sandbox_rootfs_path={cfg.rootfs_path or '(unset)'}"))
        checks.append(SandboxCheck(name="kernel path configured", ok=bool(cfg.kernel_path.strip()), detail=f"sandbox_kernel_path={cfg.kernel_path or '(unset)'}"))

    provisioned = backend_ok and host_ok and all(c.ok for c in checks)
    return DataEnvelope(data=SandboxStatus(
        backend=backend or "none",
        provisioned=provisioned,
        ssh_host=ssh_host,
        ssh_reachable=None,
        host_os=os.name,
        checks=checks,
    ))


def _history_row(record: SandboxExecHistoryRecord) -> SandboxHistoryRow:
    return SandboxHistoryRow(
        id=record.id,
        actor_user_id=record.actor_user_id,
        argv=list(record.argv),
        exit_code=record.exit_code,
        duration_s=record.duration_s,
        timed_out=record.timed_out,
        oom=record.oom,
        truncated=record.truncated,
        created_at=record.created_at.isoformat(),
    )


@router.post("/probe", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def probe_sandbox(
    request: Request,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[SandboxProbeResponse]:
    """Run a bounded live SSH round-trip to the configured sandbox host.

    Never raises on a failed probe; the response body carries ``ok=False``
    plus an actionable ``detail`` so the governance panel can flip
    ``ssh_reachable`` and surface the reason inline.
    """
    del ctx
    registry = get_config_registry(request)
    service = SandboxService(build_platform_settings(get_settings()), config_registry=registry)
    probe: SandboxProbe = await service.probe()
    return DataEnvelope(data=SandboxProbeResponse(
        ok=probe.ok,
        detail=probe.detail,
        duration_ms=probe.duration_ms,
        tool_installed=probe.tool_installed,
        tool_missing=probe.tool_missing,
        installed_path=probe.installed_path,
    ))


@router.post("/target", status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def set_sandbox_target(
    request: Request,
    body: SandboxTargetRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[SandboxProbeResponse]:
    """Atomically configure the sandbox host target and run an immediate probe."""
    del ctx
    registry = get_config_registry(request)
    if body.backend:
        await registry.set("platform", "sandbox_backend", body.backend)
    if body.system_id is not None:
        await registry.set("platform", "sandbox_system_id", str(body.system_id))
    if body.system_name is not None:
        await registry.set("platform", "sandbox_system_name", body.system_name)
    await registry.set("platform", "sandbox_ssh_host", body.host.strip())
    await registry.set("platform", "sandbox_ssh_user", body.username.strip())
    await registry.set("platform", "sandbox_ssh_port", body.port)

    service = SandboxService(build_platform_settings(get_settings()), config_registry=registry)
    probe: SandboxProbe = await service.probe()
    return DataEnvelope(data=SandboxProbeResponse(
        ok=probe.ok,
        detail=probe.detail,
        duration_ms=probe.duration_ms,
        tool_installed=probe.tool_installed,
        tool_missing=probe.tool_missing,
        installed_path=probe.installed_path,
    ))


@router.post("/install", status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
async def install_sandbox_tooling(
    request: Request,
    body: SandboxBootstrapRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[SandboxBootstrapResponse]:
    """Automated installation of sandbox binaries on the configured remote host."""
    del request, ctx
    service = SandboxService(build_platform_settings(get_settings()))
    result = await service.bootstrap_tooling(tool=body.tool)
    return DataEnvelope(data=SandboxBootstrapResponse(
        ok=result.ok,
        detail=result.detail,
        output=result.output,
        duration_ms=result.duration_ms,
    ))


@router.get("/history", status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def sandbox_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[SandboxHistoryRow]]:
    """Return recent admin sandbox exec dispatches, newest first.

    Reads the shape-only history table populated by successful POSTs to
    ``/platform/sandbox/exec``. NEVER exposes stdin, stdout, or stderr --
    those are not stored.
    """
    del request, ctx
    async with async_session_scope() as session:
        stmt = (
            select(SandboxExecHistoryRecord)
            .order_by(SandboxExecHistoryRecord.created_at.desc())  # type: ignore[attr-defined]
            .offset(offset)
            .limit(limit)
        )
        rows = (await session.exec(stmt)).all()
    return DataEnvelope(data=[_history_row(r) for r in rows])
