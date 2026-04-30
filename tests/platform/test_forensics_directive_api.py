from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from starlette.requests import Request

from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.contracts.directive import AnalystDirectiveCreate
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.storage.database import async_session_scope


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _make_auth_context(team_id: str = "team-1") -> object:
    ctx = MagicMock()
    ctx.user_id = "user-001"
    ctx.role = "operator"
    ctx.team_id = team_id
    return ctx


@pytest.mark.asyncio
async def test_create_and_list_directive_preserve_structured_controls(test_db) -> None:
    project_id = f"proj-{uuid4().hex[:8]}"
    async with async_session_scope() as session:
        session.add(
            ForensicsProjectRecord(
                id=project_id,
                name="Directive Project",
                system_id=1,
                evidence_directory="/evidence",
                analyzer_os="linux",
                project_kind="disk_evidence",
                status="ready",
                team_id="team-1",
                created_at=_utc_now(),
                updated_at=_utc_now(),
            )
        )
        await session.commit()

    router = create_forensics_router()
    create_handler = next(route.endpoint for route in router.routes if getattr(route, "path", "") == "/projects/{project_id}/directives" and "POST" in getattr(route, "methods", set()))
    list_handler = next(route.endpoint for route in router.routes if getattr(route, "path", "") == "/projects/{project_id}/directives" and "GET" in getattr(route, "methods", set()))
    request = Request({"type": "http", "method": "POST", "path": "/forensics"})

    created = await create_handler(
        request=request,
        project_id=project_id,
        body=AnalystDirectiveCreate(
            text="Focus on APK manifest and signing chain first.",
            strategy_family="mobile_reverse",
            required_artifact="artifact-42",
        ),
        auth=_make_auth_context(),
    )

    assert created.data.strategy_family == "mobile_reverse"
    assert created.data.required_artifact == "artifact-42"

    listed = await list_handler(
        request=Request({"type": "http", "method": "GET", "path": "/forensics"}),
        project_id=project_id,
        auth=_make_auth_context(),
        investigation_id=None,
        include_inactive=False,
    )

    assert len(listed.data) == 1
    assert listed.data[0].strategy_family == "mobile_reverse"
    assert listed.data[0].required_artifact == "artifact-42"
