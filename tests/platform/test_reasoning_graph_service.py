from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.services.reasoning_graphs import ReasoningGraphService
from aila.storage.database import async_session_scope
from aila.storage.db_models import ReasoningGraphSnapshotRecord


@pytest.mark.asyncio
async def test_save_snapshot_upserts_same_subject_step(test_db) -> None:
    service = ReasoningGraphService()
    subject_id = f"inv-{uuid4().hex[:8]}"

    first = await service.save_snapshot(
        run_id="run-1",
        module_id="forensics",
        subject_kind="investigation",
        subject_id=subject_id,
        step_number=1,
        strategy_family="filesystem_triage",
        graph={"nodes": [{"id": "contract"}], "edges": []},
    )
    second = await service.save_snapshot(
        run_id="run-1",
        module_id="forensics",
        subject_kind="investigation",
        subject_id=subject_id,
        step_number=1,
        strategy_family="malware_static",
        graph={"nodes": [{"id": "answer"}], "edges": []},
    )

    rows = await service.list_snapshots(
        module_id="forensics",
        subject_kind="investigation",
        subject_id=subject_id,
    )

    assert first.id == second.id
    assert len(rows) == 1
    assert rows[0].strategy_family == "malware_static"
    assert rows[0].graph_json["nodes"][0]["id"] == "answer"


@pytest.mark.asyncio
async def test_list_snapshots_orders_by_step_number(test_db) -> None:
    service = ReasoningGraphService()
    subject_id = f"inv-{uuid4().hex[:8]}"

    await service.save_snapshot(
        run_id="run-2",
        module_id="forensics",
        subject_kind="investigation",
        subject_id=subject_id,
        step_number=2,
        strategy_family="network_forensics",
        graph={"nodes": [{"id": "step-2"}], "edges": []},
    )
    await service.save_snapshot(
        run_id="run-2",
        module_id="forensics",
        subject_kind="investigation",
        subject_id=subject_id,
        step_number=1,
        strategy_family="filesystem_triage",
        graph={"nodes": [{"id": "step-1"}], "edges": []},
    )

    rows = await service.list_snapshots(
        module_id="forensics",
        subject_kind="investigation",
        subject_id=subject_id,
    )

    assert [row.step_number for row in rows] == [1, 2]

    async with async_session_scope() as session:
        persisted = (await session.exec(
            select(ReasoningGraphSnapshotRecord).where(
                ReasoningGraphSnapshotRecord.subject_id == subject_id
            )
        )).all()
    assert len(persisted) == 2
