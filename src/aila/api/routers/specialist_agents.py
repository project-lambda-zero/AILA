"""Specialist-agent registry router -- user-extensible optional panel members.

    GET    /agents/specialists?module_id=vr        -- list a module's specialists
    POST   /agents/specialists                     -- create or update one
    POST   /agents/specialists/{module_id}/seed    -- seed built-in defaults
    DELETE /agents/specialists/{module_id}/{name}  -- delete one

A specialist is data: a capability (matching a dispatch phase so the hub
routes it), an optional prompt family, and a description. Any authenticated
caller can define specialists for a module, so an operator adds a new expert
perspective without a code change. All responses use DataEnvelope.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.services.specialist_registry import (
    SpecialistAgentCreate,
    SpecialistAgentRegistry,
    SpecialistAgentSummary,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/agents/specialists", tags=["specialist-agents"])


def _registry() -> SpecialistAgentRegistry:
    return SpecialistAgentRegistry()


@router.get(
    "",
    response_model=DataEnvelope[list[SpecialistAgentSummary]],
    summary="List a module's specialist agents",
)
async def list_specialists(
    module_id: str = Query(..., min_length=1, max_length=64),
    enabled_only: bool = Query(default=False),
    _ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[SpecialistAgentSummary]]:
    rows = await _registry().list_by_module(module_id, enabled_only=enabled_only)
    return DataEnvelope(data=rows)


@router.post(
    "",
    response_model=DataEnvelope[SpecialistAgentSummary],
    summary="Create or update a specialist agent",
)
async def upsert_specialist(
    body: SpecialistAgentCreate,
    _ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[SpecialistAgentSummary]:
    summary = await _registry().upsert(body)
    _log.info(
        "specialist_agent upsert module=%s name=%s capability=%s",
        summary.module_id, summary.name, summary.capability,
    )
    return DataEnvelope(data=summary)


@router.post(
    "/{module_id}/seed",
    response_model=DataEnvelope[dict[str, int]],
    summary="Seed a module's built-in default specialists",
)
async def seed_specialists(
    module_id: str,
    _ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[dict[str, int]]:
    inserted = await _registry().seed_defaults(module_id)
    return DataEnvelope(data={"inserted": inserted})


@router.delete(
    "/{module_id}/{name}",
    response_model=DataEnvelope[dict[str, bool]],
    summary="Delete a specialist agent",
)
async def delete_specialist(
    module_id: str,
    name: str,
    _ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[dict[str, bool]]:
    deleted = await _registry().delete(module_id, name)
    return DataEnvelope(data={"deleted": deleted})
