from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from ...platform.contracts.reasoning import ReasoningGraphDiff, ReasoningGraphEdge, ReasoningGraphNode
from ...storage.database import async_session_scope
from ...storage.db_models import ReasoningGraphSnapshotRecord

__all__ = ["ReasoningGraphService"]

@asynccontextmanager
async def _session_or_new(session: AsyncSession | None) -> AsyncGenerator[tuple[AsyncSession, bool], None]:
    if session is not None:
        yield session, False
    else:
        async with async_session_scope() as new_session:
            yield new_session, True


class ReasoningGraphService:
    """Platform query/write surface for durable reasoning graph snapshots."""

    async def save_snapshot(
        self,
        *,
        module_id: str,
        subject_kind: str,
        subject_id: str,
        step_number: int,
        strategy_family: str,
        graph: dict[str, Any],
        run_id: str | None = None,
        session: AsyncSession | None = None,
    ) -> ReasoningGraphSnapshotRecord:
        async with _session_or_new(session) as (sess, owns):
            stmt = select(ReasoningGraphSnapshotRecord).where(
                ReasoningGraphSnapshotRecord.module_id == module_id,
                ReasoningGraphSnapshotRecord.subject_kind == subject_kind,
                ReasoningGraphSnapshotRecord.subject_id == subject_id,
                ReasoningGraphSnapshotRecord.step_number == step_number,
            )
            record = (await sess.exec(stmt)).first()
            if record is None:
                record = ReasoningGraphSnapshotRecord(
                    run_id=run_id,
                    module_id=module_id,
                    subject_kind=subject_kind,
                    subject_id=subject_id,
                    step_number=step_number,
                    strategy_family=strategy_family,
                    graph_json=graph,
                )
                sess.add(record)
            else:
                record.run_id = run_id
                record.strategy_family = strategy_family
                record.graph_json = graph
                sess.add(record)
            if owns:
                await sess.commit()
                await sess.refresh(record)
            return record

    async def list_snapshots(
        self,
        *,
        module_id: str,
        subject_kind: str,
        subject_id: str,
        session: AsyncSession | None = None,
    ) -> list[ReasoningGraphSnapshotRecord]:
        async with _session_or_new(session) as (sess, _owns):
            stmt = (
                select(ReasoningGraphSnapshotRecord)
                .where(
                    ReasoningGraphSnapshotRecord.module_id == module_id,
                    ReasoningGraphSnapshotRecord.subject_kind == subject_kind,
                    ReasoningGraphSnapshotRecord.subject_id == subject_id,
                )
                .order_by(ReasoningGraphSnapshotRecord.step_number)
            )
            return list((await sess.exec(stmt)).all())


    async def latest_snapshot(
        self,
        *,
        module_id: str,
        subject_kind: str,
        subject_id: str,
        session: AsyncSession | None = None,
    ) -> ReasoningGraphSnapshotRecord | None:
        rows = await self.list_snapshots(
            module_id=module_id,
            subject_kind=subject_kind,
            subject_id=subject_id,
            session=session,
        )
        return rows[-1] if rows else None

    async def diff_snapshots(
        self,
        *,
        module_id: str,
        subject_kind: str,
        subject_id: str,
        from_step: int,
        to_step: int,
        session: AsyncSession | None = None,
    ) -> ReasoningGraphDiff:
        async with _session_or_new(session) as (sess, _owns):
            stmt = select(ReasoningGraphSnapshotRecord).where(
                ReasoningGraphSnapshotRecord.module_id == module_id,
                ReasoningGraphSnapshotRecord.subject_kind == subject_kind,
                ReasoningGraphSnapshotRecord.subject_id == subject_id,
                ReasoningGraphSnapshotRecord.step_number.in_([from_step, to_step]),
            )
            rows = list((await sess.exec(stmt)).all())

        by_step = {row.step_number: row for row in rows}
        from_graph = dict(by_step[from_step].graph_json) if from_step in by_step else {"nodes": [], "edges": []}
        to_graph = dict(by_step[to_step].graph_json) if to_step in by_step else {"nodes": [], "edges": []}

        from_nodes = {str(node.get("id")): node for node in from_graph.get("nodes", []) if isinstance(node, dict)}
        to_nodes = {str(node.get("id")): node for node in to_graph.get("nodes", []) if isinstance(node, dict)}
        from_edges = {
            (str(edge.get("source")), str(edge.get("target")), str(edge.get("kind"))): edge
            for edge in from_graph.get("edges", [])
            if isinstance(edge, dict)
        }
        to_edges = {
            (str(edge.get("source")), str(edge.get("target")), str(edge.get("kind"))): edge
            for edge in to_graph.get("edges", [])
            if isinstance(edge, dict)
        }

        return ReasoningGraphDiff(
            from_step=from_step,
            to_step=to_step,
            added_nodes=[ReasoningGraphNode.model_validate(node) for key, node in to_nodes.items() if key not in from_nodes],
            removed_nodes=[ReasoningGraphNode.model_validate(node) for key, node in from_nodes.items() if key not in to_nodes],
            added_edges=[ReasoningGraphEdge.model_validate(edge) for key, edge in to_edges.items() if key not in from_edges],
            removed_edges=[ReasoningGraphEdge.model_validate(edge) for key, edge in from_edges.items() if key not in to_edges],
        )
