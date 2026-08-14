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

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
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
from aila.platform.services.sandbox.service import SandboxService

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
    return DataEnvelope(data=_to_response(result))
