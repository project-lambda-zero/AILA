"""Pattern catalog storage + retrieval service (Knowledge Transfer plan).

Writes pairs of rows: the structured pattern record and a mirrored
``KnowledgeEntryRecord`` (pgvector + FTS) so the pattern is retrievable
by both structured filters (kind / applicability / scope) and semantic
search.

Generic over the module: a concrete subclass binds the pattern record
model, the module summary contract, and the ``KnowledgeEntryRecord``
namespace prefix as class variables. The platform base owns the
create / get / list / patch / applicable logic and never names a module.

v1 ships:
  - create()      -- insert pattern + mirror entry in one transaction
  - get()         -- fetch single pattern
  - list()        -- paginated + filterable
  - patch()       -- operator review + scope promotion
  - applicable()  -- structured-filter + semantic search retrieval

Deferred to v1.1 (per GA-45/46):
  - <module>_pattern_usages success-rate tracking
  - <module>_pattern_chains cross-investigation links
  - automatic re-rank by success_rate + recency
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any, ClassVar

from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import (
    PatternConfidence,
    PatternScope,
    PatternStatus,
    PatternTrustTier,
)
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_router import Route
from aila.platform.uow import UnitOfWork
from aila.storage.registry import ConfigRegistry

# RFC-12 relevance floor default for pattern retrieval. Below this combined
# score (0.6*vec + 0.4*fts) a retrieval hit is considered noise and stripped
# before it can reach a researcher prompt. Kept as a module constant so the
# lookup below has a final safety fallback if ConfigRegistry itself fails
# (bad DB row, transient OSError). Mirrors the PlatformConfigSchema field
# ``knowledge_pattern_relevance_floor`` -- both must move together.
PATTERN_RELEVANCE_FLOOR_DEFAULT: float = 0.3

# ConfigRegistry namespace + key for the operator-tunable floor. Resolution
# order (via ConfigRegistry.get): env AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR
# -> cache -> DB row -> PlatformConfigSchema.knowledge_pattern_relevance_floor
# schema default. PATTERN_RELEVANCE_FLOOR_DEFAULT is the last-resort fallback
# used only when the registry lookup itself raises or returns a bad value.
_RELEVANCE_FLOOR_CONFIG_NS: str = "platform"
_RELEVANCE_FLOOR_CONFIG_KEY: str = "knowledge_pattern_relevance_floor"

# RFC-08 memory-poisoning negative-prior penalty. When a returned positive
# overlaps with a filtered-out NEGATIVE pattern, its score is multiplied by
# this factor per overlap. Positives whose own trust_tier is UNREVIEWED get
# one additional multiplication. Same resolution chain as the relevance
# floor: env AILA_PLATFORM_KNOWLEDGE_NEGATIVE_PRIOR_PENALTY -> cache -> DB
# row -> ``PlatformConfigSchema.knowledge_negative_prior_penalty`` default.
# NEGATIVE_PRIOR_PENALTY_DEFAULT is the last-resort fallback when the
# registry lookup itself fails; the schema default is 0.5.
NEGATIVE_PRIOR_PENALTY_DEFAULT: float = 0.5
_NEGATIVE_PRIOR_PENALTY_CONFIG_NS: str = "platform"
_NEGATIVE_PRIOR_PENALTY_CONFIG_KEY: str = "knowledge_negative_prior_penalty"

__all__ = [
    "NEGATIVE_PRIOR_PENALTY_DEFAULT",
    "PATTERN_RELEVANCE_FLOOR_DEFAULT",
    "PatternRetrievalResult",
    "PatternStoreBase",
    "PatternStoreError",
]

_log = logging.getLogger(__name__)


class PatternStoreError(Exception):
    """Raised on fatal pattern operations (missing FK, invalid promotion)."""


@dataclass(slots=True)
class PatternRetrievalResult:
    """One pattern returned by ``applicable()`` with a relevance score."""

    pattern: Any
    score: float
    matched_by: str  # "structured" | "semantic" | "both"


def _scope_widens(old: PatternScope, new: PatternScope) -> bool:
    """Scope promotion is one-way; demotion goes through status=archived."""
    order = {
        PatternScope.LOCAL: 0,
        PatternScope.WORKSPACE: 1,
        PatternScope.TEAM: 2,
        PatternScope.GLOBAL: 3,
    }
    return order[new] >= order[old]


def _applicability_overlaps(
    neg_app: dict[str, Any], pos_app: dict[str, Any],
) -> bool:
    """True when a NEGATIVE pattern's scope could apply to a positive's.

    RFC-08 says a NEGATIVE lowers a prior when it applies to the same
    context as the positive it's near. Determinism: only compare
    list-valued applicability keys (``target_kinds``, ``languages``,
    ``bug_classes``, ``families``, ``capabilities``, ...); a scalar key
    like the ExperienceWriter-stamped ``polarity`` is ignored because
    the two patterns naturally disagree on it by construction.

    Two dicts overlap unless there exists at least one list-valued key
    they both restrict on with zero intersection -- in that single case
    the negative provably does not apply to the positive's context and
    the score is left alone. Absence of a key on either side is treated
    as ``matches all`` (the standard applicability-filter semantics used
    at Stage 1 above).
    """
    for key, neg_val in neg_app.items():
        if not isinstance(neg_val, list) or not neg_val:
            continue
        pos_val = pos_app.get(key)
        if not isinstance(pos_val, list) or not pos_val:
            # positive doesn't restrict on this key -> overlaps
            continue
        if not set(neg_val) & set(pos_val):
            return False
    return True


class PatternStoreBase:
    """Pair-write storage: <module>_patterns + KnowledgeEntryRecord mirror.

    A concrete subclass MUST set ``_record_model``, ``_summary_cls``, and
    ``_namespace_prefix``.
    """

    _record_model: ClassVar[type]
    _summary_cls: ClassVar[type]
    _namespace_prefix: ClassVar[str]

    def __init__(self, knowledge: KnowledgeService | Any) -> None:
        self._knowledge = knowledge

    def _scope_namespace(
        self,
        workspace_id: str,
        team_id: str | None,
        scope: PatternScope,
    ) -> str:
        """Build the KnowledgeEntryRecord namespace per scope.

        Local + Workspace patterns scope by workspace_id; Team patterns scope
        by team_id; Global is shared cross-team.
        """
        if scope == PatternScope.GLOBAL:
            return f"{self._namespace_prefix}.global"
        if scope == PatternScope.TEAM and team_id:
            return f"{self._namespace_prefix}.team.{team_id}"
        return f"{self._namespace_prefix}.workspace.{workspace_id}"

    def _to_summary(self, row: Any) -> Any:
        # RFC-08 memory-poisoning fields. ``trust_tier`` defaults to
        # UNREVIEWED for rows that pre-date the tier column (a live
        # DB where migration 113 has run and rows carry ``'unreviewed'``
        # server-default already matches this fallback). ``provenance``
        # decodes to an empty envelope for rows without one.
        try:
            trust_tier = PatternTrustTier(row.trust_tier or PatternTrustTier.UNREVIEWED.value)
        except (TypeError, ValueError):
            trust_tier = PatternTrustTier.UNREVIEWED
        try:
            provenance = json.loads(row.provenance_json or "{}")
        except (TypeError, ValueError):
            provenance = {}
        if not isinstance(provenance, dict):
            provenance = {}
        return self._summary_cls(
            id=row.id,
            workspace_id=row.workspace_id,
            investigation_id=row.investigation_id,
            kind=row.kind,
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
            trust_tier=trust_tier,
            provenance=provenance,
        )

    async def create(
        self,
        body: Any,
        team_id: str | None,
    ) -> Any:
        """Insert a new pattern + its KnowledgeEntryRecord mirror.

        The mirror's content is ``summary + body`` so both surface in
        semantic search. dedup_key derived from (workspace, kind,
        summary-hash) so re-inserting an identical pattern updates
        instead of proliferating.

        fix §204 -- all three writes (pattern INSERT, knowledge mirror
        INSERT, knowledge_entry_id back-link UPDATE) now happen in ONE
        UnitOfWork. Previously a crash between writes left orphaned
        rows (pattern without mirror, or mirror without back-link).
        Requires KnowledgeService.store to flush so ``entry_id`` is
        populated before we read it back for the link UPDATE -- handled
        by the matching §204 flush in
        ``aila/platform/services/knowledge.py``.
        """
        scope = body.scope
        namespace = self._scope_namespace(body.workspace_id, team_id, scope)
        content = (
            f"# {body.summary}\n\n{body.body}"
            if body.body and body.body.strip()
            else body.summary
        )
        # fix §205 -- body-hash dedup_key. Two patterns whose summaries
        # share the first 200 characters but have different bodies
        # used to collide under the legacy ``summary[:200]`` truncation
        # -- KnowledgeService treated them as the same entry, dropping
        # the second. SHA-256 over the full content is collision-
        # resistant; the leading 16 hex chars are ample for the
        # namespace-scoped (workspace_id|kind|hash) key space.
        body_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        dedup_key = f"{body.workspace_id}|{body.kind.value}|{body_hash}"

        # RFC-08 memory-poisoning stamp. Callers that route through
        # :class:`ExperienceWriter` supply VERIFIED / NEGATIVE from a
        # signed quorum verdict; sanctioned DRAFT proposers stamp
        # UNREVIEWED. Fallbacks keep back-compat with any legacy
        # caller that constructs the create body without the fields.
        trust_tier = getattr(body, "trust_tier", PatternTrustTier.UNREVIEWED)
        if not isinstance(trust_tier, PatternTrustTier):
            trust_tier = PatternTrustTier(str(trust_tier))
        provenance = getattr(body, "provenance", {}) or {}
        if not isinstance(provenance, dict):
            provenance = {}
        async with UnitOfWork() as uow:
            row = self._record_model(
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
                trust_tier=trust_tier.value,
                provenance_json=json.dumps(provenance),
            )
            uow.session.add(row)
            # Flush so row.id is populated for the metadata payload and
            # the back-link UPDATE below -- but no commit yet.
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
                extract_entities=True,
                link_neighbors=True,
            )
            entry_id = store_result.get("entry_id")

            # fix §206 -- refuse to ship a pattern whose mirror isn't
            # persisted. Previously this silently left
            # ``knowledge_entry_id=NULL`` and the caller treated the
            # pattern as stored -- invisible to semantic search. The
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
            return self._to_summary(row)

    async def get(
        self,
        pattern_id: str,
        *,
        team_id: str | None = None,
    ) -> Any | None:
        model = self._record_model
        async with UnitOfWork() as uow:
            stmt = _select(model).where(model.id == pattern_id)
            if team_id is not None:
                stmt = stmt.where(model.team_id == team_id)
            row = (await uow.session.exec(stmt)).first()
            if row is None:
                return None
            return self._to_summary(row)

    async def list(
        self,
        *,
        workspace_id: str | None = None,
        kind: Any | None = None,
        status: PatternStatus | None = None,
        scope: PatternScope | None = None,
        team_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Any], int]:
        model = self._record_model
        async with UnitOfWork() as uow:
            stmt = _select(model)
            count_stmt = _select(sa_func.count()).select_from(model)
            if team_id is not None:
                stmt = stmt.where(model.team_id == team_id)
                count_stmt = count_stmt.where(model.team_id == team_id)
            if workspace_id:
                stmt = stmt.where(model.workspace_id == workspace_id)
                count_stmt = count_stmt.where(model.workspace_id == workspace_id)
            if kind:
                stmt = stmt.where(model.kind == kind.value)
                count_stmt = count_stmt.where(model.kind == kind.value)
            if status:
                stmt = stmt.where(model.status == status.value)
                count_stmt = count_stmt.where(model.status == status.value)
            if scope:
                stmt = stmt.where(model.scope == scope.value)
                count_stmt = count_stmt.where(model.scope == scope.value)

            total = (await uow.session.exec(count_stmt)).one()
            stmt = (
                stmt.order_by(model.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = (await uow.session.exec(stmt)).all()
            return [self._to_summary(r) for r in rows], int(total)

    async def patch(
        self,
        pattern_id: str,
        body: Any,
        team_id: str | None,
    ) -> Any:
        model = self._record_model
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(model).where(model.id == pattern_id),
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
                        f"scope demotion forbidden -- old={old_scope.value}, "
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
                namespace = self._scope_namespace(
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
                    extract_entities=True,
                    link_neighbors=True,
                )
                entry_id = store_result.get("entry_id")
                if isinstance(entry_id, int) and entry_id != row.knowledge_entry_id:
                    async with UnitOfWork() as uow2:
                        row2 = (await uow2.session.exec(
                            _select(model).where(
                                model.id == pattern_id,
                            ),
                        )).first()
                        if row2 is not None:
                            row2.knowledge_entry_id = entry_id
                            uow2.session.add(row2)
                            await uow2.session.commit()
                            await uow2.session.refresh(row2)
                            return self._to_summary(row2)
            return self._to_summary(row)

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

        Stage 1: structured filter on the module pattern table (active
        status, widening scope chain, applicability intersection).
        Stage 2: semantic search across the scope chain namespaces,
        intersected with stage 1 candidates.

        Increments ``times_retrieved`` + ``last_used_at`` for hits so
        the v1.1 success-rate tracker has the base counters ready.
        """
        model = self._record_model
        # Stage 1 -- structured candidate pool
        async with UnitOfWork() as uow:
            stmt = _select(model).where(
                model.status == PatternStatus.ACTIVE.value,
            )
            scope_chain = [
                PatternScope.WORKSPACE.value,
                PatternScope.TEAM.value,
                PatternScope.GLOBAL.value,
            ]
            stmt = stmt.where(model.scope.in_(scope_chain))
            stmt = stmt.where(
                (model.scope != PatternScope.WORKSPACE.value)
                | (model.workspace_id == workspace_id),
            )
            if team_id:
                stmt = stmt.where(
                    (model.scope != PatternScope.TEAM.value)
                    | (model.team_id == team_id),
                )
            rows = (await uow.session.exec(stmt)).all()

        # Split into positive + negative candidate pools by trust_tier.
        # NEGATIVE patterns are RFC-08 poisoning-defense priors: they
        # never enter the actionable results list; they only lower a
        # colliding positive's score. UNREVIEWED + VERIFIED can be
        # returned, but UNREVIEWED positives eat one additional penalty.
        positive_candidates: dict[str, Any] = {}
        negative_candidates: dict[str, Any] = {}
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
            tier_raw = getattr(row, "trust_tier", None) or PatternTrustTier.UNREVIEWED.value
            try:
                tier = PatternTrustTier(tier_raw)
            except (TypeError, ValueError):
                tier = PatternTrustTier.UNREVIEWED
            if tier == PatternTrustTier.NEGATIVE:
                negative_candidates[row.id] = row
            else:
                positive_candidates[row.id] = row

        if not positive_candidates:
            # No positives to return, and NEGATIVEs alone never surface
            # as standalone actionable hits. Nothing to send upstream.
            return []

        # Stage 2 -- semantic search across scope-chain namespaces.
        namespaces: list[str] = [
            f"{self._namespace_prefix}.workspace.{workspace_id}",
        ]
        if team_id:
            namespaces.append(f"{self._namespace_prefix}.team.{team_id}")
        namespaces.append(f"{self._namespace_prefix}.global")

        # RFC-12 relevance floor. Passed to retrieve_routed() as the
        # ``min_score`` gate for the graph route's seed hybrid stage
        # (SEED-time cosine-relevance cut). It is NOT re-applied to the
        # returned hits below: RFC-14 routes this call through the PPR
        # graph path, whose per-hit ``score`` is stationary PPR mass, not
        # the 0.6vec+0.4fts hybrid figure the floor was calibrated on.
        # Dropping graph-reached patterns by that floor would silently
        # suppress the connected patterns the graph route exists to
        # surface. The stage-1 structured filter above stays the
        # authoritative pattern-layer gate; the seed stage inside
        # retrieve_routed still honours the floor at its own layer.
        floor = await self._resolve_relevance_floor()

        # RFC-14: force the graph route. PPR with no edges degenerates to
        # the hybrid seed ranking, so a sparse workspace behaves exactly
        # like the pre-RFC-14 flat path; a linked workspace surfaces
        # edge-connected patterns that a flat retrieve would miss.
        routed = await self._knowledge.retrieve_routed(
            query=query,
            namespaces=namespaces,
            route=Route.GRAPH,
            limit=k * 4,
            min_score=floor,
            session=None,
        )
        hits = routed.get("results", [])

        # Build the positives-only result list preserving retrieve_routed()
        # order. Hits whose pattern_id resolves to a NEGATIVE candidate
        # are dropped silently -- the KB mirror still returns them (the
        # mirror has no trust_tier column) but the pattern layer strips
        # them here so they never reach a researcher prompt.
        results: list[PatternRetrievalResult] = []
        seen: set[str] = set()
        for hit in hits:
            meta = hit.get("metadata") or {}
            pid = meta.get("pattern_id") if isinstance(meta, dict) else None
            if pid is None or pid in seen:
                continue
            if pid in negative_candidates:
                seen.add(pid)
                continue
            if pid not in positive_candidates:
                continue
            score = float(hit.get("score") or 0.0)
            # A hop > 0 hit was reached via an edge traversal from a
            # seed; label it accordingly so downstream telemetry can
            # separate graph-reached from seed-matched patterns.
            hop = int(hit.get("hop") or 0)
            matched_by = "graph" if hop > 0 else "both"
            results.append(
                PatternRetrievalResult(
                    pattern=self._to_summary(positive_candidates[pid]),
                    score=score,
                    matched_by=matched_by,
                ),
            )
            seen.add(pid)
            if len(results) >= k:
                break

        # Backfill from structured positive candidates not matched by
        # search so the engine still sees relevant patterns even when
        # semantic signal is weak. Negatives never backfill.
        if len(results) < k:
            for pid, row in positive_candidates.items():
                if pid in seen:
                    continue
                results.append(
                    PatternRetrievalResult(
                        pattern=self._to_summary(row),
                        score=0.0,
                        matched_by="structured",
                    ),
                )
                seen.add(pid)
                if len(results) >= k:
                    break

        # RFC-08 memory-poisoning down-weight. For every returned positive:
        #   * multiply score by ``penalty`` per NEGATIVE candidate whose
        #     applicability overlaps it (a NEGATIVE lowering a prior on
        #     a colliding positive) -- never a hard-block.
        #   * multiply once more when the positive itself is UNREVIEWED
        #     (an unreviewed positive that reached ACTIVE retrieves at
        #     reduced weight until an operator promotes it to VERIFIED).
        # Both multiplications are order-stable and deterministic; the
        # ordering of the ``results`` list is not re-sorted so a caller
        # that relies on the retrieve() ranking still sees it.
        if results:
            penalty = await self._resolve_negative_prior_penalty()
            if penalty < 1.0:
                penalised: list[PatternRetrievalResult] = []
                neg_apps = [
                    json.loads(r.applicability_json or "{}")
                    for r in negative_candidates.values()
                ]
                for r in results:
                    factor = 1.0
                    pos_app = r.pattern.applicability or {}
                    for neg_app in neg_apps:
                        if _applicability_overlaps(neg_app, pos_app):
                            factor *= penalty
                    if r.pattern.trust_tier == PatternTrustTier.UNREVIEWED:
                        factor *= penalty
                    penalised.append(
                        PatternRetrievalResult(
                            pattern=r.pattern,
                            score=r.score * factor,
                            matched_by=r.matched_by,
                        ),
                    )
                results = penalised

        # Update usage counters for retrieved patterns (single-shot UoW).
        if results:
            now = utc_now()
            ids = [r.pattern.id for r in results]
            async with UnitOfWork() as uow:
                update_rows = (await uow.session.exec(
                    _select(model).where(model.id.in_(ids)),
                )).all()
                for ur in update_rows:
                    ur.times_retrieved = (ur.times_retrieved or 0) + 1
                    ur.last_used_at = now
                    uow.session.add(ur)
                await uow.session.commit()

        return results

    @staticmethod
    async def _resolve_relevance_floor() -> float:
        """Resolve the pattern retrieval relevance floor via ConfigRegistry.

        Env -> cache -> DB -> PlatformConfigSchema default (via
        :class:`ConfigRegistry`). The schema field is
        ``knowledge_pattern_relevance_floor`` so a fresh install returns
        0.3 without any DB seeding. :data:`PATTERN_RELEVANCE_FLOOR_DEFAULT`
        is the last-resort fallback used only when the registry lookup
        itself raises or returns a non-numeric value -- a bad DB row must
        never silently disable the floor.
        """
        try:
            raw = await ConfigRegistry().get(
                _RELEVANCE_FLOOR_CONFIG_NS,
                _RELEVANCE_FLOOR_CONFIG_KEY,
            )
        except (OSError, RuntimeError, ValueError, TypeError):
            return PATTERN_RELEVANCE_FLOOR_DEFAULT
        if raw is None:
            return PATTERN_RELEVANCE_FLOOR_DEFAULT
        try:
            return float(raw)
        except (TypeError, ValueError):
            return PATTERN_RELEVANCE_FLOOR_DEFAULT

    @staticmethod
    async def _resolve_negative_prior_penalty() -> float:
        """Resolve the RFC-08 memory-poisoning penalty via ConfigRegistry.

        Env -> cache -> DB -> ``PlatformConfigSchema.knowledge_negative_prior_penalty``
        (default 0.5). :data:`NEGATIVE_PRIOR_PENALTY_DEFAULT` is the
        last-resort fallback when the registry lookup itself raises or
        returns a non-numeric value -- a bad DB row must never silently
        disable the down-weight defense.

        Values are clamped to ``[0.0, 1.0]``. Above 1.0 would amplify a
        prior instead of lowering it (breaks the RFC-08 contract);
        below 0.0 would flip the sign of a positive's score.
        """
        try:
            raw = await ConfigRegistry().get(
                _NEGATIVE_PRIOR_PENALTY_CONFIG_NS,
                _NEGATIVE_PRIOR_PENALTY_CONFIG_KEY,
            )
        except (OSError, RuntimeError, ValueError, TypeError):
            return NEGATIVE_PRIOR_PENALTY_DEFAULT
        if raw is None:
            return NEGATIVE_PRIOR_PENALTY_DEFAULT
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return NEGATIVE_PRIOR_PENALTY_DEFAULT
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value
