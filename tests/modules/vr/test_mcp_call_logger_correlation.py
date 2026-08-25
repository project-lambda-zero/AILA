"""#39: a VR MCP call log carries the investigation/branch/turn that requested it.

After req 10/40, the VR partial writes into the consolidated platform
``mcp_call_log`` table stamped with ``module_scope='vr'``; the correlation
join-keys still land on the row from the ambient ContextVar.
"""
from __future__ import annotations

import pytest
from sqlmodel import select

from aila.modules.vr.services.mcp_call_logger import record_call
from aila.platform.llm.correlation import correlation_scope
from aila.platform.mcp.call_log_record import McpCallLogRecord
from aila.platform.uow import UnitOfWork


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_mcp_call_log_carries_correlation() -> None:
    with correlation_scope(investigation_id="inv-m", branch_id="br-m", turn_number=9):
        async with record_call(
            server_id="audit_mcp", base_url="http://x", action="corr_search",
        ) as ctx:
            ctx["status"] = "ready"
            ctx["http_status"] = 200

    async with UnitOfWork() as uow:
        rows = (
            await uow.session.exec(
                select(McpCallLogRecord).where(
                    McpCallLogRecord.action == "corr_search",
                    McpCallLogRecord.module_scope == "vr",
                ),
            )
        ).all()
    assert rows
    row = rows[-1]
    assert (row.investigation_id, row.branch_id, row.turn_number) == ("inv-m", "br-m", 9)
    assert row.module_scope == "vr"
