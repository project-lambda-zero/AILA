"""RFC-12 Phase 6: build a retrieval-recall benchmark from stored VR findings.

Each benchmark case pairs the question a VR investigation was asked with the
knowledge entry of the finding that answered it: query = the originating
investigation's ``initial_question``, relevant id = the finding's
``knowledgeentryrecord`` id. Replaying this through the live retriever measures
whether a future investigation asking the same question would surface the prior
finding (recall@k), which is exactly the cross-investigation memory RFC-12
promises. The benchmark grows as investigations accumulate.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.db_models import VRInvestigationRecord
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import KnowledgeEntryRecord

__all__ = [
    "VR_FINDING_NAMESPACE_GLOB",
    "VR_FINDING_NAMESPACE_PREFIX",
    "build_vr_finding_benchmark_cases",
]

_log = logging.getLogger(__name__)

VR_FINDING_NAMESPACE_PREFIX = "vr.finding.workspace."
# retrieve_routed treats a trailing '*' as a prefix match (glob); the SQL-LIKE
# query below needs the '%' form. Derive both from one prefix so they cannot
# drift.
VR_FINDING_NAMESPACE_GLOB = f"{VR_FINDING_NAMESPACE_PREFIX}*"
_FINDING_NAMESPACE_LIKE = f"{VR_FINDING_NAMESPACE_PREFIX}%"


async def build_vr_finding_benchmark_cases() -> list[dict[str, Any]]:
    """Return recall cases from backfilled/live VR finding knowledge entries.

    Skips a finding entry with no resolvable originating question (a finding
    whose investigation link or ``initial_question`` is absent) rather than
    inventing a query, so the benchmark stays honest.
    """
    cases: list[dict[str, Any]] = []
    async with UnitOfWork() as uow:
        session = uow.session
        rows = list((await session.exec(
            _select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.namespace.like(_FINDING_NAMESPACE_LIKE),
                KnowledgeEntryRecord.model_id.is_not(None),
            ),
        )).all())
        for row in rows:
            try:
                meta = json.loads(row.entry_metadata or "{}")
            except (ValueError, TypeError):
                _log.warning(
                    "retrieval benchmark: entry %s has unparseable metadata; skip",
                    row.id,
                )
                continue
            finding_id = meta.get("finding_id")
            if not finding_id:
                continue
            inv = (await session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.linked_finding_ids_json.like(
                        f"%{finding_id}%",
                    ),
                ),
            )).first()
            query = ""
            if inv is not None:
                query = (inv.initial_question or inv.title or "").strip()
            if not query:
                continue
            cases.append({
                "query_id": str(finding_id),
                "query": query,
                "relevant_ids": [str(row.id)],
            })
    return cases
