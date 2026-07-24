"""Admin prompt-version router (RFC-09).

Operator surface for the prompt version store: register an immutable,
content-hashed prompt body under a key, then flip a release alias
(candidate / staging / production) to deploy or roll back a prompt change
without a code release. The researchers resolve the ``production`` alias on
every turn (see each module's ``_load_prompt``), so setting that alias is
the deploy action.

All endpoints require god-tier admin (team_id=None): prompt versions are
platform-wide, not team-scoped. Every request is rate-limited.

Endpoints:
    POST /admin/prompts/versions          register a new immutable version
    GET  /admin/prompts/versions?key=     list registered versions for a key
    PUT  /admin/prompts/aliases           point an alias at a version (deploy)
    GET  /admin/prompts/aliases?key=      list alias pointers for a key
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.contracts import utc_now
from aila.platform.prompts.version_store import (
    PromptVersionNotFoundError,
    PromptVersionStore,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

_STORE = PromptVersionStore()


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Prompt versioning is platform-wide, so a team-scoped admin is refused;
    only a god-tier admin (team_id=None) may register versions or flip a
    release alias that every team's investigations resolve."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Prompt-version administration is restricted to god-tier administrators.",
        )
    return ctx


router = APIRouter(
    prefix="/admin/prompts",
    tags=["admin-prompts"],
    dependencies=[Depends(_require_admin)],
)


class RegisterVersionRequest(BaseModel):
    key: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1)
    author: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)


class VersionInfo(BaseModel):
    key: str
    version: str
    content_hash: str
    author: str
    notes: str
    created_at: datetime


class SetAliasRequest(BaseModel):
    key: str = Field(min_length=1, max_length=256)
    alias: str = Field(min_length=1, max_length=32)
    version: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=4096)


class AliasInfo(BaseModel):
    key: str
    alias: str
    version: str
    updated_at: datetime


@router.post("/versions", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def register_version(
    request: Request,
    body: RegisterVersionRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[VersionInfo]:
    """Register an immutable version. An identical body returns the existing
    version (content-hash deduplicated) rather than creating a duplicate."""
    del request
    version = await _STORE.register(
        body.key, body.body, author=body.author or ctx.user_id, notes=body.notes,
    )
    row = await _STORE.resolve(body.key, version=version)
    if row is None:  # pragma: no cover - register just wrote it
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="version vanished after register",
        )
    return DataEnvelope(data=VersionInfo(
        key=row.key, version=row.version, content_hash=row.content_hash,
        author=row.author, notes=row.notes, created_at=row.created_at,
    ))


@router.get("/versions")
@limiter.limit("60/minute")
async def list_versions(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[VersionInfo]]:
    """List every registered version for a key, oldest first."""
    del request, ctx
    rows = await _STORE.list_versions(key)
    return DataEnvelope(data=[
        VersionInfo(
            key=r.key, version=r.version, content_hash=r.content_hash,
            author=r.author, notes=r.notes, created_at=r.created_at,
        )
        for r in rows
    ])


@router.put("/aliases")
@limiter.limit("30/minute")
async def set_alias(
    request: Request,
    body: SetAliasRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[AliasInfo]:
    """Point an alias at a version (deploy / rollback). 404 if the version is
    not registered for the key."""
    del request
    try:
        await _STORE.set_alias(
            body.key, body.alias, body.version,
            actor=ctx.user_id, reason=body.reason,
        )
    except PromptVersionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc),
        ) from exc
    return DataEnvelope(data=AliasInfo(
        key=body.key, alias=body.alias, version=body.version,
        updated_at=utc_now(),
    ))


@router.get("/aliases")
@limiter.limit("60/minute")
async def list_aliases(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[AliasInfo]]:
    """List every alias pointer for a key."""
    del request, ctx
    rows = await _STORE.list_aliases(key)
    return DataEnvelope(data=[
        AliasInfo(
            key=r.key, alias=r.alias, version=r.version, updated_at=r.updated_at,
        )
        for r in rows
    ])
