"""Pattern catalog storage + retrieval service (Knowledge Transfer plan).

Writes pairs of rows: the structured ``VRPatternRecord`` and a mirrored
``KnowledgeEntryRecord`` (pgvector + FTS) so the pattern is retrievable
by both structured filters (kind / applicability / scope) and semantic
search.

v1 ships:
  - create()      — insert pattern + mirror entry in one transaction
  - get()         — fetch single pattern
  - list()        — paginated + filterable
  - patch()       — operator review + scope promotion
  - applicable()  — structured-filter + semantic search retrieval

Deferred to v1.1 (per GA-45/46):
  - vr_pattern_usages success-rate tracking
  - vr_pattern_chains cross-investigation links
  - automatic re-rank by success_rate + recency
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.modules.vr.contracts.pattern import (
    PatternConfidence,
    PatternKind,
    PatternScope,
    PatternStatus,
    VRPatternCreate,
    VRPatternPatch,
    VRPatternSummary,
)
from aila.modules.vr.db_models import VRPatternRecord
from aila.platform.contracts._common import utc_now
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.uow import UnitOfWork

__all__ = [
    "PatternRetrievalResult",
    "PatternStore",
    "PatternStoreError",
]

_log = logging.getLogger(__name__)


class PatternStoreError(Exception):
    """Raised on fatal pattern operations (missing FK, invalid promotion)."""


@dataclass(slots=True)
class PatternRetrievalResult:
    """One pattern returned by ``applicable()`` with a relevance score."""

    pattern: VRPatternSummary
    score: float
    matched_by: str  # "structured" | "semantic" | "both"


def _scope_namespace(workspace_id: str, team_id: str | None, scope: PatternScope) -> str:
    """Build the KnowledgeEntryRecord namespace per scope.

    Local + Workspace patterns scope by workspace_id; Team patterns scope
    by team_id; Global is shared cross-team.
    """
    if scope == PatternScope.GLOBAL:
        return "vr.pattern.global"
    if scope == PatternScope.TEAM and team_id:
        return f"vr.pattern.team.{team_id}"
    return f"vr.pattern.workspace.{workspace_id}"


def _scope_widens(old: PatternScope, new: PatternScope) -> bool:
    """Scope promotion is one-way; demotion goes through status=archived."""
    order = {
        PatternScope.LOCAL: 0,
        PatternScope.WORKSPACE: 1,
        PatternScope.TEAM: 2,
        PatternScope.GLOBAL: 3,
    }
    return order[new] >= order[old]


def _record_to_summary(row: VRPatternRecord) -> VRPatternSummary:
    return VRPatternSummary(
        id=row.id,
        workspace_id=row.workspace_id,
        investigation_id=row.investigation_id,
        kind=PatternKind(row.kind),
        summary=row.summary,
        body=row.body or "",
        applicability=json.loads(row.applicability_json or "{}"),
        confidence=PatternConfidence(row.confidence),
        evidence_refs=json.loads(row.evidence_refs_json or "[]"),
        status=PatternStatus(row.status),
        scope=PatternScope(row.scope),
        superseded_by=row.superseded_by,
        knowledge_entry_id=row.knowledge_entry_id,
        times_retrieved=row.times_retrieved,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class PatternStore:
    """Pair-write storage: vr_patterns + KnowledgeEntryRecord mirror."""

    def __init__(self, knowledge: KnowledgeService | Any) -> None:
        self._knowledge = knowledge

    async def create(
        self,
        body: VRPatternCreate,
        team_id: str | None,
    ) -> VRPatternSummary:
        """Insert a new pattern + its KnowledgeEntryRecord mirror.

        The mirror's content is ``summary + body`` so both surface in
        semantic search. dedup_key derived from (workspace, kind,
        summary-hash) so re-inserting an identical pattern updates
        instead of proliferating.

        fix §204 — all three writes (pattern INSERT, knowledge mirror
        INSERT, knowledge_entry_id back-link UPDATE) now happen in ONE
        UnitOfWork. Previously a crash between writes left orphaned
        rows (pattern without mirror, or mirror without back-link).
        Requires KnowledgeService.store to flush so ``entry_id`` is
        populated before we read it back for the link UPDATE — handled
        by the matching §204 flush in
        ``aila/platform/services/knowledge.py``.
        """
        scope = body.scope
        namespace = _scope_namespace(body.workspace_id, team_id, scope)
        content = (
            f"# {body.summary}\n\n{body.body}"
            if body.body and body.body.strip()
            else body.summary
        )
        # fix §205 — body-hash dedup_key. Two patterns whose summaries
        # share the first 200 characters but have different bodies
        # used to collide under the legacy ``summary[:200]`` truncation
        # — KnowledgeService treated them as the same entry, dropping
        # the second. SHA-256 over the full content is collision-
        # resistant; the leading 16 hex chars are ample for the
        # namespace-scoped (workspace_id|kind|hash) key space.
        body_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        dedup_key = f"{body.workspace_id}|{body.kind.value}|{body_hash}"

        async with UnitOfWork() as uow:
            row = VRPatternRecord(
                team_id=team_id,
                workspace_id=body.workspace_id,
                investigation_id=body.investigation_id,
                kind=body.kind.value,
                summary=body.summary,
                body=body.body,
                applicability_json=json.dumps(body.applicability),
                confidence=body.confidence.value,
                evidence_refs_json=json.dumps(body.evidence_refs),
                status=PatternStatus.DRAFT.value,
                scope=scope.value,
            )
            uow.session.add(row)
            # Flush so row.id is populated for the metadata payload and
            # the back-link UPDATE below — but no commit yet.
            await uow.session.flush()
            pattern_id = row.id

            # Mirror through KnowledgeService on the SAME session so the
            # whole create is one atomic transaction. KnowledgeService
            # internally flushes (§204) so entry_id is populated even
            # though we own the session.
            store_result = await self._knowledge.store(
                namespace=namespace,
                content=content,
                metadata={
                    "pattern_id": pattern_id,
                    "workspace_id": body.workspace_id,
                    "investigation_id": body.investigation_id,
                    "kind": body.kind.value,
                    "scope": scope.value,
                    "confidence": body.confidence.value,
                    "applicability": body.applicability,
                },
                dedup_key=dedup_key,
                session=uow.session,
            )
            entry_id = store_result.get("entry_id")

            # fix §206 — refuse to ship a pattern whose mirror isn't
            # persisted. Previously this silently left
            # ``knowledge_entry_id=NULL`` and the caller treated the
            # pattern as stored — invisible to semantic search. The
            # whole point of the pair-write is that the back-link
            # exists; if KnowledgeService.store didn't surface an
            # entry_id it failed to persist and we MUST roll back the
            # pattern INSERT (the surrounding UoW does this on raise).
            if not isinstance(entry_id, int):
                raise PatternStoreError(
                    "mirror not persisted: KnowledgeService.store returned "
                    f"no entry_id (got {entry_id!r}, operation={store_result.get('operation')!r}). "
                    "Pattern INSERT rolled back via UoW exception path.",
                )
            row.knowledge_entry_id = entry_id
            uow.session.add(row)

            await uow.commit()
            await uow.session.refresh(row)
            return _record_to_summary(row)

    async def get(
        self,
        pattern_id: str,
        *,
        team_id: str | None = None,
    ) -> VRPatternSummary | None:
        async with UnitOfWork() as uow:
            stmt = _select(VRPatternRecord).where(VRPatternRecord.id == pattern_id)
            if team_id is not None:
                stmt = stmt.where(VRPatternRecord.team_id == team_id)
            row = (await uow.session.exec(stmt)).first()
            if row is None:
                return None
            return _record_to_summary(row)

    async def list(
        self,
        *,
        workspace_id: str | None = None,
        kind: PatternKind | None = None,
        status: PatternStatus | None = None,
        scope: PatternScope | None = None,
        team_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[VRPatternSummary], int]:
        async with UnitOfWork() as uow:
            stmt = _select(VRPatternRecord)
            count_stmt = _select(sa_func.count()).select_from(VRPatternRecord)
            if team_id is not None:
                stmt = stmt.where(VRPatternRecord.team_id == team_id)
                count_stmt = count_stmt.where(VRPatternRecord.team_id == team_id)
            if workspace_id:
                stmt = stmt.where(VRPatternRecord.workspace_id == workspace_id)
                count_stmt = count_stmt.where(VRPatternRecord.workspace_id == workspace_id)
            if kind:
                stmt = stmt.where(VRPatternRecord.kind == kind.value)
                count_stmt = count_stmt.where(VRPatternRecord.kind == kind.value)
            if status:
                stmt = stmt.where(VRPatternRecord.status == status.value)
                count_stmt = count_stmt.where(VRPatternRecord.status == status.value)
            if scope:
                stmt = stmt.where(VRPatternRecord.scope == scope.value)
                count_stmt = count_stmt.where(VRPatternRecord.scope == scope.value)

            total = (await uow.session.exec(count_stmt)).one()
            stmt = (
                stmt.order_by(VRPatternRecord.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = (await uow.session.exec(stmt)).all()
            return [_record_to_summary(r) for r in rows], int(total)

    async def patch(
        self,
        pattern_id: str,
        body: VRPatternPatch,
        team_id: str | None,
    ) -> VRPatternSummary:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRPatternRecord).where(VRPatternRecord.id == pattern_id),
            )).first()
            if row is None:
                raise PatternStoreError(f"pattern {pattern_id} not found")

            mutated = False
            scope_changed_to: PatternScope | None = None
            if body.summary is not None and body.summary != row.summary:
                row.summary = body.summary
                mutated = True
            if body.body is not None and body.body != row.body:
                row.body = body.body
                mutated = True
            if body.applicability is not None:
                new_app = json.dumps(body.applicability)
                if new_app != (row.applicability_json or "{}"):
                    row.applicability_json = new_app
                    mutated = True
            if body.confidence is not None and body.confidence.value != row.confidence:
                row.confidence = body.confidence.value
                mutated = True
            if body.status is not None and body.status.value != row.status:
                row.status = body.status.value
                mutated = True
            if body.scope is not None and body.scope.value != row.scope:
                old_scope = PatternScope(row.scope)
                if not _scope_widens(old_scope, body.scope):
                    raise PatternStoreError(
                        f"scope demotion forbidden — old={old_scope.value}, "
                        f"new={body.scope.value}. Archive instead.",
                    )
                row.scope = body.scope.value
                scope_changed_to = body.scope
                mutated = True
            if body.superseded_by is not None and body.superseded_by != row.superseded_by:
                row.superseded_by = body.superseded_by
                mutated = True

            if mutated:
                row.updated_at = utc_now()
                uow.session.add(row)
                await uow.session.commit()
                await uow.session.refresh(row)

            # Re-store mirror entry if scope widened OR content changed:
            # the namespace key depends on scope.
            if scope_changed_to is not None or (
                mutated and body.body is not None
            ):
                namespace = _scope_namespace(
                    row.workspace_id, team_id, PatternScope(row.scope),
                )
                content = (
                    f"# {row.summary}\n\n{row.body}"
                    if row.body and row.body.strip()
                    else row.summary
                )
                dedup_key = (
                    f"{row.workspace_id}|{row.kind}|{row.summary[:200]}"
                )
                store_result = await self._knowledge.store(
                    namespace=namespace,
                    content=content,
                    metadata={
                        "pattern_id": row.id,
                        "workspace_id": row.workspace_id,
                        "investigation_id": row.investigation_id,
                        "kind": row.kind,
                        "scope": row.scope,
                        "confidence": row.confidence,
                        "applicability": json.loads(row.applicability_json or "{}"),
                    },
                    dedup_key=dedup_key,
                )
                entry_id = store_result.get("entry_id")
                if isinstance(entry_id, int) and entry_id != row.knowledge_entry_id:
                    async with UnitOfWork() as uow2:
                        row2 = (await uow2.session.exec(
                            _select(VRPatternRecord).where(
                                VRPatternRecord.id == pattern_id,
                            ),
                        )).first()
                        if row2 is not None:
                            row2.knowledge_entry_id = entry_id
                            uow2.session.add(row2)
                            await uow2.session.commit()
                            await uow2.session.refresh(row2)
                            return _record_to_summary(row2)
            return _record_to_summary(row)

    async def applicable(
        self,
        *,
        workspace_id: str,
        team_id: str | None,
        query: str,
        target_kind: str | None = None,
        primary_language: str | None = None,
        k: int = 5,
    ) -> list[PatternRetrievalResult]:
        """Two-stage retrieval: applicability filter → semantic search.

        Stage 1: structured filter on vr_patterns (active status,
        widening scope chain, applicability intersection).
        Stage 2: semantic search across the scope chain namespaces,
        intersected with stage 1 candidates.

        Increments ``times_retrieved`` + ``last_used_at`` for hits so
        the v1.1 success-rate tracker has the base counters ready.
        """
        # Stage 1 — structured candidate pool
        async with UnitOfWork() as uow:
            stmt = _select(VRPatternRecord).where(
                VRPatternRecord.status == PatternStatus.ACTIVE.value,
            )
            scope_chain = [
                PatternScope.WORKSPACE.value,
                PatternScope.TEAM.value,
                PatternScope.GLOBAL.value,
            ]
            stmt = stmt.where(VRPatternRecord.scope.in_(scope_chain))
            stmt = stmt.where(
                (VRPatternRecord.scope != PatternScope.WORKSPACE.value)
                | (VRPatternRecord.workspace_id == workspace_id),
            )
            if team_id:
                stmt = stmt.where(
                    (VRPatternRecord.scope != PatternScope.TEAM.value)
                    | (VRPatternRecord.team_id == team_id),
                )
            rows = (await uow.session.exec(stmt)).all()

        candidates: dict[str, VRPatternRecord] = {}
        for row in rows:
            applicability = json.loads(row.applicability_json or "{}")
            if target_kind and "target_kinds" in applicability:
                tk_list = applicability.get("target_kinds") or []
                if isinstance(tk_list, list) and tk_list and target_kind not in tk_list:
                    continue
            if primary_language and "languages" in applicability:
                lang_list = applicability.get("languages") or []
                if (
                    isinstance(lang_list, list)
                    and lang_list
                    and primary_language not in lang_list
                ):
                    continue
            candidates[row.id] = row

        if not candidates:
            return []

        # Stage 2 — semantic search across scope-chain namespaces.
        namespaces: list[str] = [f"vr.pattern.workspace.{workspace_id}"]
        if team_id:
            namespaces.append(f"vr.pattern.team.{team_id}")
        namespaces.append("vr.pattern.global")

        hits = await self._knowledge.retrieve(
            query=query,
            namespaces=namespaces,
            limit=k * 4,
        )

        results: list[PatternRetrievalResult] = []
        seen: set[str] = set()
        for hit in hits:
            meta = hit.get("metadata") or {}
            pid = meta.get("pattern_id") if isinstance(meta, dict) else None
            if pid is None or pid not in candidates or pid in seen:
                continue
            score = float(hit.get("score") or 0.0)
            results.append(
                PatternRetrievalResult(
                    pattern=_record_to_summary(candidates[pid]),
                    score=score,
                    matched_by="both",
                ),
            )
            seen.add(pid)
            if len(results) >= k:
                break

        # Backfill from structured candidates not matched by search so
        # the engine still sees relevant patterns even when semantic
        # signal is weak.
        if len(results) < k:
            for pid, row in candidates.items():
                if pid in seen:
                    continue
                results.append(
                    PatternRetrievalResult(
                        pattern=_record_to_summary(row),
                        score=0.0,
                        matched_by="structured",
                    ),
                )
                seen.add(pid)
                if len(results) >= k:
                    break

        # Update usage counters for retrieved patterns (single-shot UoW).
        if results:
            now = utc_now()
            ids = [r.pattern.id for r in results]
            async with UnitOfWork() as uow:
                update_rows = (await uow.session.exec(
                    _select(VRPatternRecord).where(VRPatternRecord.id.in_(ids)),
                )).all()
                for ur in update_rows:
                    ur.times_retrieved = (ur.times_retrieved or 0) + 1
                    ur.last_used_at = now
                    uow.session.add(ur)
                await uow.session.commit()

        return results
