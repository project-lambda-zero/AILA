"""RFC-12 Phase 6: backfill historical VR findings into the knowledge base.

The knowledge base started empty because every write was rejected by the
384-vs-1024 embedding dimension desync (#37), so findings recorded before the
fix never reached the vector store. This re-embeds each stored VR finding into
its workspace-scoped finding namespace through the canonical KnowledgeService,
so cross-investigation retrieval reflects work already done (including negative
results, which spare a later investigation from repeating a dead end).

Idempotent: the store upserts on ``(namespace, dedup_key)`` and every row
carries ``model_id``, so a re-run updates in place and a future embedding-model
swap re-embeds rather than silently duplicating. ``dry_run`` reports eligibility
without writing.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr.db_models import VRFindingRecord, VRTargetRecord
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.uow import UnitOfWork

__all__ = ["backfill_vr_knowledge"]

_log = logging.getLogger(__name__)


def _safe_refs(evidence_refs_json: str | None) -> list[Any]:
    try:
        refs = json.loads(evidence_refs_json or "[]")
    except (ValueError, TypeError) as exc:
        _log.warning("backfill: unparseable evidence_refs_json (%s); using []", exc)
        return []
    return refs if isinstance(refs, list) else []


async def backfill_vr_knowledge(*, dry_run: bool = False) -> dict[str, Any]:
    """Re-embed stored VR findings into the workspace-scoped finding namespace.

    Returns a summary dict of counts. A finding is eligible when it has a
    non-empty ``root_cause`` and its target resolves to a workspace id; the
    rest are reported as skipped. Never raises per finding: a store failure is
    logged and counted so one bad row does not abort the sweep.
    """
    scanned = 0
    skipped_no_workspace = 0
    skipped_empty = 0
    async with UnitOfWork() as uow:
        rows = list((await uow.session.exec(_select(VRFindingRecord))).all())
        target_ids = {r.target_id for r in rows if r.target_id}
        ws_by_target: dict[str, str] = {}
        if target_ids:
            targets = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id.in_(target_ids)),
            )).all()
            ws_by_target = {
                t.id: str(t.workspace_id) for t in targets if t.workspace_id
            }

    plan: list[tuple[VRFindingRecord, str, str]] = []
    for r in rows:
        scanned += 1
        content = (r.root_cause or "").strip()
        if not content:
            skipped_empty += 1
            continue
        ws_id = ws_by_target.get(r.target_id or "")
        if not ws_id:
            skipped_no_workspace += 1
            continue
        plan.append((r, ws_id, content))

    if dry_run:
        return {
            "dry_run": True,
            "scanned": scanned,
            "eligible": len(plan),
            "skipped_no_workspace": skipped_no_workspace,
            "skipped_empty": skipped_empty,
            "sample": [
                {"finding_id": r.id, "workspace_id": ws, "chars": len(c)}
                for r, ws, c in plan[:5]
            ],
        }

    knowledge = KnowledgeService()
    embedded = 0
    errors = 0
    for r, ws_id, content in plan:
        try:
            await knowledge.store(
                namespace=f"vr.finding.workspace.{ws_id}",
                content=content,
                metadata={
                    "finding_id": r.id,
                    "target_id": r.target_id,
                    "workspace_id": ws_id,
                    "crash_type": r.crash_type,
                    "vulnerable_function": r.vulnerable_function,
                    "evidence_refs": _safe_refs(r.evidence_refs_json),
                    "source": "backfill",
                },
                dedup_key=f"finding:{r.id}",
                team_id=r.team_id,
                extract_entities=True,
                link_neighbors=True,
            )
            embedded += 1
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            errors += 1
            _log.warning(
                "backfill: VR finding %s failed to embed: %s",
                r.id, exc, exc_info=True,
            )

    return {
        "dry_run": False,
        "scanned": scanned,
        "embedded": embedded,
        "skipped_no_workspace": skipped_no_workspace,
        "skipped_empty": skipped_empty,
        "errors": errors,
    }
