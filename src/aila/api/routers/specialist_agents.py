"""Specialist-agent registry router -- user-extensible optional panel members.

    GET    /agents/specialists?module_id=vr        -- list a module's specialists
    POST   /agents/specialists                     -- create or update one
    POST   /agents/specialists/{module_id}/seed    -- seed built-in defaults
    DELETE /agents/specialists/{module_id}/{name}  -- delete one

A specialist is data: a capability (matching a dispatch phase so the hub
routes it), an optional prompt family, and a description. Any authenticated
caller can list; operator+ role is required to create/seed/delete. Every
row carries a ``team_id`` -- NULL means a platform-global built-in visible
to every team, a concrete value means an owned row visible only to that
team (and to god-tier admins). Cross-team modify/delete returns 404 so the
router does not become an existence oracle for other teams' specialists.
All responses use DataEnvelope.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from aila.api.auth import AuthContext, require_role, require_user_or_api_key
from aila.api.constants import ROLE_OPERATOR
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.services.specialist_registry import (
    CrossTeamSpecialistError,
    SpecialistAgentCreate,
    SpecialistAgentRegistry,
    SpecialistAgentSummary,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/agents/specialists", tags=["specialist-agents"])


def _registry() -> SpecialistAgentRegistry:
    return SpecialistAgentRegistry()


def _team_view(auth: AuthContext) -> tuple[str | None, bool]:
    """Return (team_id, is_admin) suitable for the registry API.

    ``is_admin`` is True when the caller's ``team_id`` is NULL (TEAM-06
    god tier); every other principal is treated as team-scoped even if
    its role happens to be ``admin`` inside a specific team.
    """
    return auth.team_id, auth.team_id is None


@router.get(
    "",
    response_model=DataEnvelope[list[SpecialistAgentSummary]],
    summary="List a module's specialist agents",
)
@limiter.limit("120/minute")
async def list_specialists(
    request: Request,
    module_id: str = Query(..., min_length=1, max_length=64),
    enabled_only: bool = Query(default=False),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[SpecialistAgentSummary]]:
    team_id, is_admin = _team_view(auth)
    rows = await _registry().list_by_module(
        module_id,
        enabled_only=enabled_only,
        team_id=team_id,
        is_admin=is_admin,
    )
    return DataEnvelope(data=rows)


@router.post(
    "",
    response_model=DataEnvelope[SpecialistAgentSummary],
    summary="Create or update a specialist agent",
)
@limiter.limit("30/minute")
async def upsert_specialist(
    request: Request,
    body: SpecialistAgentCreate,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> DataEnvelope[SpecialistAgentSummary]:
    team_id, is_admin = _team_view(auth)
    try:
        summary = await _registry().upsert(body, team_id=team_id, is_admin=is_admin)
    except CrossTeamSpecialistError as exc:
        # Return 404 rather than 403 so the caller cannot use the
        # response code to probe another team's specialist names.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Specialist not found",
        ) from exc
    _log.info(
        "specialist_agent upsert module=%s name=%s capability=%s team=%s",
        summary.module_id, summary.name, summary.capability, summary.team_id,
    )
    return DataEnvelope(data=summary)


@router.post(
    "/{module_id}/seed",
    response_model=DataEnvelope[dict[str, int]],
    summary="Seed a module's built-in default specialists",
)
@limiter.limit("10/minute")
async def seed_specialists(
    request: Request,
    module_id: str,
    _auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> DataEnvelope[dict[str, int]]:
    inserted = await _registry().seed_defaults(module_id)
    return DataEnvelope(data={"inserted": inserted})


@router.delete(
    "/{module_id}/{name}",
    response_model=DataEnvelope[dict[str, bool]],
    summary="Delete a specialist agent",
)
@limiter.limit("30/minute")
async def delete_specialist(
    request: Request,
    module_id: str,
    name: str,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> DataEnvelope[dict[str, bool]]:
    team_id, is_admin = _team_view(auth)
    deleted = await _registry().delete(
        module_id, name, team_id=team_id, is_admin=is_admin,
    )
    return DataEnvelope(data={"deleted": deleted})
