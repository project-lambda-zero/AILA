"""CVE record ingest + audit memo invalidation (v0.4 GA-51).

Two responsibilities:

1. **ingest_cve(body)** -- upsert a single CVE record (idempotent on
   cve_id). On insert, embed the description via KnowledgeService and
   search for similar audit memos. Each match above the similarity
   threshold gets an invalidation_event recorded on the memo's
   metadata.

2. **list_invalidations_for_memo(entry_id)** -- read all invalidation
   events that have been recorded for one memo entry. Used by the
   operator UI to surface "this memo may be outdated".

The actual NVD / GHSA poller is deferred to the operator-run cron task
``poll_cve_feeds`` -- out of scope for the service layer. v1 ships the
ingest endpoint; operators can manually POST CVEs via API.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.modules.vr.contracts.cve import (
    CVEFeedSource,
    CVERecordSummary,
    MemoInvalidationEvent,
    VRCVERecordCreate,
)
from aila.modules.vr.db_models.cve import VRCVERecord
from aila.platform.contracts import utc_now
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.uow import UnitOfWork

__all__ = [
    "CVEServiceError",
    "CVEService",
    "DEFAULT_SIMILARITY_THRESHOLD",
]

_log = logging.getLogger(__name__)


# Default cosine-similarity threshold above which an audit memo is
# flagged as potentially invalidated by a CVE. Tunable per
# investigation in v1.1; v1 ships a single global threshold.
DEFAULT_SIMILARITY_THRESHOLD = 0.85

# Max audit memos a single CVE can invalidate per ingest call. Higher
# than typical match count (~3-5) but bounded so a vague CVE
# description doesn't flag every memo in the workspace.
_MAX_INVALIDATIONS_PER_CVE = 25


class CVEServiceError(Exception):
    """User-facing CVE service errors."""


def _record_to_summary(record: VRCVERecord) -> CVERecordSummary:
    return CVERecordSummary(
        id=record.id,
        cve_id=record.cve_id,
        source=CVEFeedSource(record.source),
        title=record.title or "",
        description=record.description or "",
        published_at=record.published_at,
        last_modified_at=record.last_modified_at,
        cvss_score=record.cvss_score,
        cwe_ids=json.loads(record.cwe_ids_json or "[]"),
        references=json.loads(record.references_json or "[]"),
        affected_components=json.loads(record.affected_components_json or "[]"),
        invalidations_triggered=record.invalidations_triggered or 0,
        ingested_at=record.ingested_at,
    )


@dataclass(slots=True)
class CVEIngestResult:
    """Result of one ingest call."""

    cve: CVERecordSummary
    inserted: bool
    invalidation_events: list[MemoInvalidationEvent]


class CVEService:
    """Ingest CVE records + invalidate matching audit memos."""

    def __init__(
        self,
        knowledge: KnowledgeService | Any,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ) -> None:
        self._knowledge = knowledge
        self._threshold = similarity_threshold

    async def ingest_cve(self, body: VRCVERecordCreate) -> CVEIngestResult:
        """Upsert a CVE record + flag matching audit memos.

        Idempotent on ``cve_id``. When the row already exists, this
        method updates the description / cvss / references / affected
        components but does NOT re-run the invalidation scan (memos
        already flagged stay flagged; new flags would duplicate).
        """
        async with UnitOfWork() as uow:
            existing = (await uow.session.exec(
                _select(VRCVERecord).where(
                    VRCVERecord.cve_id == body.cve_id,
                ),
            )).first()

            if existing is not None:
                existing.source = body.source.value
                existing.title = body.title or existing.title
                existing.description = body.description or existing.description
                existing.cvss_score = body.cvss_score or existing.cvss_score
                existing.last_modified_at = body.last_modified_at or existing.last_modified_at
                if body.cwe_ids:
                    existing.cwe_ids_json = json.dumps(body.cwe_ids)
                if body.references:
                    existing.references_json = json.dumps(body.references)
                if body.affected_components:
                    existing.affected_components_json = json.dumps(
                        body.affected_components,
                    )
                if body.raw_payload:
                    existing.raw_payload_json = json.dumps(body.raw_payload)
                uow.session.add(existing)
                await uow.session.commit()
                await uow.session.refresh(existing)
                return CVEIngestResult(
                    cve=_record_to_summary(existing),
                    inserted=False,
                    invalidation_events=[],
                )

            record = VRCVERecord(
                cve_id=body.cve_id,
                source=body.source.value,
                title=body.title or "",
                description=body.description or "",
                published_at=body.published_at,
                last_modified_at=body.last_modified_at,
                cvss_score=body.cvss_score,
                cwe_ids_json=json.dumps(body.cwe_ids),
                references_json=json.dumps(body.references),
                affected_components_json=json.dumps(body.affected_components),
                raw_payload_json=json.dumps(body.raw_payload),
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)
            record_id = record.id

        # Now run invalidation scan in its own UoW (the embedding +
        # similarity scan can be slow; we don't want the insert
        # transaction holding locks). Use the description as the query
        # text since that's the CVE's semantic signature.
        if not body.description.strip():
            _log.info(
                "cve_service: %s has no description; skipping invalidation scan",
                body.cve_id,
            )
            return CVEIngestResult(
                cve=await self._reload(record_id),
                inserted=True,
                invalidation_events=[],
            )

        events = await self._invalidate_matching_memos(
            cve_id=body.cve_id,
            cve_description=body.description,
            published_at=body.published_at or utc_now(),
        )

        # Record the count back on the CVE row
        if events:
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    _select(VRCVERecord).where(VRCVERecord.id == record_id),
                )).first()
                if row is not None:
                    row.invalidations_triggered = len(events)
                    uow.session.add(row)
                    await uow.session.commit()

        return CVEIngestResult(
            cve=await self._reload(record_id),
            inserted=True,
            invalidation_events=events,
        )

    async def _reload(self, record_id: str) -> CVERecordSummary:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRCVERecord).where(VRCVERecord.id == record_id),
            )).first()
            if row is None:
                raise CVEServiceError(
                    f"cve record {record_id} vanished after insert",
                )
            return _record_to_summary(row)

    async def _invalidate_matching_memos(
        self,
        *,
        cve_id: str,
        cve_description: str,
        published_at: datetime,
    ) -> list[MemoInvalidationEvent]:
        """Semantic search audit memos and flag matches above threshold.

        Audit memos live under ``vr.audit_memo.*`` namespaces in
        KnowledgeEntryRecord. We search across all such namespaces
        (workspace + team + global). Each match above the threshold
        gets an invalidation_event appended to its metadata.
        """
        # KnowledgeService.retrieve handles namespace_patterns
        try:
            hits = await self._knowledge.retrieve(
                query=cve_description,
                namespace_patterns=["vr.audit_memo.*"],
                limit=_MAX_INVALIDATIONS_PER_CVE,
            )
        except (OSError, RuntimeError) as exc:
            _log.warning(
                "cve_service: knowledge.retrieve failed for %s: %s",
                cve_id, exc,
            )
            return []

        events: list[MemoInvalidationEvent] = []
        for hit in hits or []:
            score = float(hit.get("score") or 0.0)
            if score < self._threshold:
                continue
            entry_id = hit.get("id")
            namespace = hit.get("namespace") or ""
            if not isinstance(entry_id, int):
                continue
            event = MemoInvalidationEvent(
                memo_entry_id=entry_id,
                cve_id=cve_id,
                similarity_score=score,
                flagged_at=published_at,
                namespace=str(namespace),
            )
            # Append to the memo's metadata. KnowledgeService doesn't
            # currently expose a metadata-merge API so we go through
            # store() with the existing content + merged metadata.
            try:
                await self._append_invalidation_to_memo(hit, event)
                events.append(event)
            except (OSError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "cve_service: failed to append invalidation to memo %s: %s",
                    entry_id, exc,
                )
        return events

    async def _append_invalidation_to_memo(
        self,
        hit: dict[str, Any],
        event: MemoInvalidationEvent,
    ) -> None:
        """Re-store the memo with the invalidation event appended.

        Reuses dedup_key (sha256 of memo content) so we update the same
        KnowledgeEntryRecord row in place.
        """
        existing_metadata: dict[str, Any] = hit.get("metadata") or {}
        if not isinstance(existing_metadata, dict):
            existing_metadata = {}
        invalidations: list[dict[str, Any]] = list(
            existing_metadata.get("cve_invalidations") or [],
        )
        if any(
            inv.get("cve_id") == event.cve_id
            for inv in invalidations
        ):
            return  # already flagged; idempotent
        invalidations.append(event.model_dump(mode="json"))

        merged_metadata = {
            **existing_metadata,
            "cve_invalidations": invalidations,
        }
        await self._knowledge.store(
            namespace=event.namespace,
            content=hit.get("content") or "",
            metadata=merged_metadata,
            dedup_key=existing_metadata.get("target_signature")
            or existing_metadata.get("dedup_key"),
        )

    async def get(self, cve_id: str) -> CVERecordSummary | None:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRCVERecord).where(VRCVERecord.cve_id == cve_id),
            )).first()
            if row is None:
                return None
            return _record_to_summary(row)

    async def list_cves(
        self,
        *,
        source: CVEFeedSource | None = None,
        min_cvss: float | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[CVERecordSummary], int]:
        async with UnitOfWork() as uow:
            stmt = _select(VRCVERecord)
            count_stmt = _select(sa_func.count()).select_from(VRCVERecord)
            if source:
                stmt = stmt.where(VRCVERecord.source == source.value)
                count_stmt = count_stmt.where(VRCVERecord.source == source.value)
            if min_cvss is not None:
                stmt = stmt.where(VRCVERecord.cvss_score >= min_cvss)
                count_stmt = count_stmt.where(VRCVERecord.cvss_score >= min_cvss)

            total = (await uow.session.exec(count_stmt)).one()
            stmt = (
                stmt.order_by(VRCVERecord.published_at.desc().nullslast())
                .offset(offset)
                .limit(limit)
            )
            rows = (await uow.session.exec(stmt)).all()
            return [_record_to_summary(r) for r in rows], int(total)
