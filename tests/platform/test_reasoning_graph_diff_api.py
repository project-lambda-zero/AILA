from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from starlette.requests import Request

from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.contracts import ReasoningGraphDiffResult
from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
from aila.platform.services.reasoning_graphs import ReasoningGraphService
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
async def test_diff_reasoning_graphs_returns_added_nodes(test_db) -> None:
    project_id = f"proj-{uuid4().hex[:8]}"
    investigation_id = f"inv-{uuid4().hex[:8]}"

    async with async_session_scope() as session:
        session.add(
            ForensicsProjectRecord(
                id=project_id,
                name="Graph Diff Project",
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
        session.add(
            InvestigationRunRecord(
                id=investigation_id,
                project_id=project_id,
                question="What launched the payload?",
                status="completed",
                created_at=_utc_now(),
            )
        )
        await session.commit()

    service = ReasoningGraphService()
    await service.save_snapshot(
        run_id="run-graph-diff",
        module_id="forensics",
        subject_kind="investigation",
        subject_id=investigation_id,
        step_number=1,
        strategy_family="filesystem_triage",
        graph={"nodes": [{"id": "contract", "kind": "contract", "label": "filename"}], "edges": []},
    )
    await service.save_snapshot(
        run_id="run-graph-diff",
        module_id="forensics",
        subject_kind="investigation",
        subject_id=investigation_id,
        step_number=2,
        strategy_family="filesystem_triage",
        graph={
            "nodes": [
                {"id": "contract", "kind": "contract", "label": "filename"},
                {"id": "answer", "kind": "answer", "label": "payload.lnk"},
            ],
            "edges": [{"source": "contract", "target": "answer", "kind": "answered_by"}],
        },
    )

    router = create_forensics_router()
    handler = next(route.endpoint for route in router.routes if getattr(route, "path", "") == "/projects/{project_id}/investigations/{investigation_id}/reasoning-graphs/diff")
    request = Request({"type": "http", "method": "GET", "path": "/forensics"})

    result = await handler(
        request=request,
        project_id=project_id,
        investigation_id=investigation_id,
        from_step=1,
        to_step=2,
        auth=_make_auth_context(),
    )

    assert isinstance(result.data, ReasoningGraphDiffResult)
    assert result.data.investigation_id == investigation_id
    assert result.data.diff.to_step == 2
    assert any(node.id == "answer" for node in result.data.diff.added_nodes)
    assert any(edge.kind == "answered_by" for edge in result.data.diff.added_edges)
