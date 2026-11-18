"""Regression coverage for the ``target_id`` filter on ``GET /platform/mcp/calls``.

The malware X-ray MCP panel asks the server for one target's rows. This pins
that the filter returns only that target's rows and that ``meta.total`` counts
only the filtered set, so the client's offset walk ends at the target boundary.
"""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from httpx import AsyncClient

from aila.platform.mcp.call_log_record import McpCallLogRecord
from aila.storage.database import async_session_scope

__all__: list[str] = []


def _row(scope: str, target_id: str | None, action: str) -> McpCallLogRecord:
    return McpCallLogRecord(
        id=uuid4().hex,
        module_scope=scope,
        server_id="rea",
        base_url="http://localhost:0",
        action=action,
        status="ok",
        target_id=target_id,
        called_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_target_id_filter_returns_only_that_target(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """Rows for other targets in the same scope are excluded and total is scoped."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = f"mcpfilter-{uuid4().hex[:8]}"
    target_a = f"target-a-{uuid4().hex[:8]}"
    target_b = f"target-b-{uuid4().hex[:8]}"

    async with async_session_scope() as session:
        session.add(_row(scope, target_a, "search"))
        session.add(_row(scope, target_a, "read"))
        session.add(_row(scope, target_b, "search"))
        await session.commit()

    response = await async_client.get(
        "/platform/mcp/calls",
        params={"module_scope": scope, "target_id": target_a},
        headers=hdr,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["meta"]["total"] == 2
    assert len(body["data"]) == 2
    assert {row["target_id"] for row in body["data"]} == {target_a}


@pytest.mark.asyncio
async def test_without_target_id_returns_all_scope_rows(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """Omitting target_id keeps the existing scope-wide behaviour."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = f"mcpfilter-{uuid4().hex[:8]}"

    async with async_session_scope() as session:
        session.add(_row(scope, "target-x", "search"))
        session.add(_row(scope, "target-y", "search"))
        await session.commit()

    response = await async_client.get(
        "/platform/mcp/calls",
        params={"module_scope": scope},
        headers=hdr,
    )
    assert response.status_code == 200, response.text
    assert response.json()["meta"]["total"] == 2
