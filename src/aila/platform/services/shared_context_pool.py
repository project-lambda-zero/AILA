"""RFC-24 step-4 shared cross-branch observation pool.

Sibling reasoning branches inside one investigation historically
re-derived the same understanding of the same code independently:
tool calls were deduplicated (RFC-05), but the DOWNSTREAM readings
and per-branch conclusions never crossed the branch boundary. RFC-24
closes that gap with a per-investigation pool of distilled
observations every branch may contribute to and read from through
the RETRIEVED tier.

Backed by the existing knowledge store -- NO new table. Each pool
entry is one :class:`KnowledgeEntryRecord` under the reserved
platform namespace
``platform.shared_pool.investigation.<investigation_id>``. Reads are
served by the same :class:`KnowledgeRetrievalProvider` that hydrates
the RETRIEVED tier from module-owned observation namespaces, so a
sibling's contribution shows up on the reader branch by way of the
same routed retrieval + BGE-M3 embedding + hybrid pgvector + tsvector
path.

Eviction is relevance-weighted with temporal decay. Every contribution
carries a ``relevance_at_write`` metadata float (the contributing
branch's own live-hypothesis relevance score at write time) and a
``contributed_at`` UTC timestamp. When the per-investigation row
count exceeds :attr:`SharedContextPool.max_entries`, the trimmer
computes
``score = relevance_at_write * 0.5 ** (age_hours / half_life)`` for
every row in the namespace and deletes rows in ascending score order
until the count is at or below the cap. Recent + high-relevance
contributions survive; stale or weakly-relevant ones age out.

The pool is intentionally best-effort: any store or trim failure
logs at DEBUG and returns rather than raising into the turn. RFC-24
treats the pool as an augmentation, not a precondition -- an
unreachable knowledge store degrades a turn to the pre-flag path.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.platform.contracts._common import utc_now
from aila.platform.services.knowledge import KnowledgeService
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

__all__ = [
    "SHARED_POOL_NAMESPACE_PREFIX",
    "SharedContextPool",
    "shared_pool_namespace",
]

_log = logging.getLogger(__name__)

# Reserved knowledge-namespace prefix for the pool. The
# ``platform.shared_pool.`` prefix keeps the pool out of the
# per-module ``<module>.observation.workspace.<id>`` bucket the
# RFC-137 observation collectors write into -- retrieval scopes with
# a wildcard on either segment (``platform.shared_pool.investigation.*``
# or ``vr.observation.workspace.*``) never collide, and the
# ``trust_tier_from_namespace`` mapping treats the pool as
# ``verified`` (no ``.observation.`` segment) so pool contributions
# are NOT down-weighted as target-derived at the RFC-12 Phase-5
# post-rank stage.
SHARED_POOL_NAMESPACE_PREFIX = "platform.shared_pool.investigation."


def shared_pool_namespace(investigation_id: str) -> str:
    """Return the per-investigation namespace pool entries land in.

    Single source of truth for the naming so contributors and the
    retrieval-side namespace-pattern builder cannot drift. Empty
    ``investigation_id`` is refused (Silent empty-suffix writes would
    dump every contribution into one shared bucket).
    """
    if not investigation_id:
        raise ValueError("investigation_id must be non-empty")
    return f"{SHARED_POOL_NAMESPACE_PREFIX}{investigation_id}"


def _pool_dedup_key(branch_id: str, subject: str) -> str:
    """Stable per-(branch, subject) idempotent-upsert key.

    A branch that re-contributes the same subject over successive
    turns UPDATES the existing row (fresh content + timestamp) rather
    than accumulating duplicates. The hash keeps the key length
    bounded and hides raw branch ids from the metadata surface
    (parity with :func:`aila.platform.agents.observation.observation_dedup_key`).
    """
    digest = hashlib.sha256(
        f"pool\x00{branch_id}\x00{subject}".encode(),
    ).hexdigest()
    return f"pool:{digest[:32]}"


def _row_eviction_score(
    entry_metadata: dict[str, Any] | None,
    updated_at: datetime | None,
    *,
    now: datetime,
    half_life_hours: float,
) -> float:
    """Compute the eviction-time score used to rank pool rows.

    ``relevance_at_write`` in the row's metadata carries the
    contributing branch's own confidence-in-relevance stamp; missing
    or malformed values fall back to 0.5 (neutral) rather than
    penalising an under-annotated writer.  Age is measured from
    ``updated_at`` so a re-contribution resets the clock (matches
    ``KnowledgeService.store`` upsert semantics).  A non-positive
    ``half_life_hours`` disables the temporal decay half -- score
    collapses to ``relevance_at_write`` alone.
    """
    meta = entry_metadata or {}
    try:
        base = float(meta.get("relevance_at_write", 0.5))
    except (TypeError, ValueError):
        base = 0.5
    if half_life_hours <= 0 or updated_at is None:
        return base
    ts = updated_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=now.tzinfo)
    delta = (now - ts).total_seconds()
    if delta <= 0:
        return base
    age_hours = delta / 3600.0
    return base * (0.5 ** (age_hours / half_life_hours))


@dataclass(slots=True)
class SharedContextPool:
    """Cap-bounded pool of cross-branch observations, one namespace per
    investigation.

    ``knowledge_service`` may be injected for tests; the default None
    lets the pool construct its own :class:`KnowledgeService` on
    first use so callers reach the pool without wiring dependencies.
    ``max_entries`` and ``decay_half_life_hours`` are resolved from
    :class:`ConfigRegistry` at the turn runner boundary (see
    ``AgentTurnRunnerBase._rfc24_shared_pool_contribute``); the
    dataclass defaults match ``PlatformConfigSchema`` so a direct
    construction in a test is a coherent baseline.
    """

    knowledge_service: KnowledgeService | None = None
    max_entries: int = 200
    decay_half_life_hours: float = 24.0

    async def contribute(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        subject: str,
        content: str,
        relevance_at_write: float = 0.5,
        turn_number: int = 0,
        extra_metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Upsert one pool entry, then trim overflow. Best-effort.

        Returns the resulting entry id as a string (matches
        :func:`record_observation`), or ``None`` when the write or
        the trim failed. A missing ``investigation_id`` / empty
        ``content`` returns ``None`` without a store round-trip.
        """
        if not investigation_id or not content.strip():
            return None
        namespace = shared_pool_namespace(investigation_id)
        dedup_key = _pool_dedup_key(branch_id, subject)
        metadata: dict[str, Any] = dict(extra_metadata or {})
        metadata.update({
            "pool": "rfc24_shared",
            "investigation_id": investigation_id,
            "branch_id": branch_id,
            "subject": subject,
            "turn_number": int(turn_number),
            "relevance_at_write": max(0.0, min(1.0, float(relevance_at_write))),
            "contributed_at": utc_now().isoformat(),
        })
        service = self.knowledge_service or KnowledgeService()
        try:
            result = await service.store(
                namespace=namespace,
                content=content,
                metadata=metadata,
                dedup_key=dedup_key,
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.debug(
                "rfc24 shared pool: contribute failed inv=%s branch=%s "
                "subject=%s (%s: %s); pool skip",
                investigation_id, branch_id, subject,
                type(exc).__name__, exc,
            )
            return None
        entry_id = result.get("entry_id")
        # Trim after every write. Trimmer is idempotent (a namespace
        # already under cap is a no-op) so an extra call adds one
        # cheap COUNT + short LIMIT scan and nothing else.
        try:
            await self.trim_overflow(investigation_id)
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.debug(
                "rfc24 shared pool: trim after contribute failed "
                "inv=%s (%s: %s); leaving pool above cap until next tick",
                investigation_id, type(exc).__name__, exc,
            )
        return str(entry_id) if entry_id is not None else None

    async def trim_overflow(self, investigation_id: str) -> int:
        """Delete lowest-scoring rows in the namespace until under cap.

        Returns the number of rows deleted. ``max_entries <= 0``
        disables the cap (unbounded pool -- tests only) and returns
        0. When the current row count is already at or below the
        cap, returns 0 without touching the store.
        """
        if self.max_entries <= 0:
            return 0
        namespace = shared_pool_namespace(investigation_id)
        service = self.knowledge_service or KnowledgeService()
        now = utc_now()
        # Sort in Python (not SQL): the eviction score depends on the
        # entry_metadata JSON which is not indexed and the pool is
        # bounded to ~a few hundred rows per investigation, so a
        # single SELECT of every namespace row is inexpensive and
        # keeps the score formula in one place. Uses the ambient
        # ``async_session_scope`` -- the pool is platform-scoped
        # (namespace prefix ``platform.shared_pool.``) and the trim
        # is best-effort, so a per-service TeamContext override adds
        # no value here.
        async with async_session_scope() as session:
            rows = (
                await session.exec(
                    select(
                        KnowledgeEntryRecord.id,
                        KnowledgeEntryRecord.entry_metadata,
                        KnowledgeEntryRecord.updated_at,
                    ).where(KnowledgeEntryRecord.namespace == namespace),
                )
            ).all()
        if len(rows) <= self.max_entries:
            return 0
        scored: list[tuple[int, float]] = []
        for row in rows:
            meta_raw = row.entry_metadata
            if isinstance(meta_raw, str):
                # KnowledgeService.store persists metadata as
                # ``json.dumps(meta)``; ORM hydration returns the
                # string. Best-effort parse; a malformed JSON blob
                # falls back to a neutral score so trimming never
                # crashes on a corrupt row.
                try:
                    meta = json.loads(meta_raw)
                except (TypeError, ValueError):
                    meta = {}
            elif isinstance(meta_raw, dict):
                meta = meta_raw
            else:
                meta = {}
            scored.append(
                (
                    int(row.id),
                    _row_eviction_score(
                        meta,
                        row.updated_at,
                        now=now,
                        half_life_hours=self.decay_half_life_hours,
                    ),
                ),
            )
        scored.sort(key=lambda item: item[1])
        overflow = len(scored) - self.max_entries
        victims = [entry_id for entry_id, _score in scored[:overflow]]
        deleted = 0
        for entry_id in victims:
            try:
                deleted += await service.delete(
                    namespace=namespace, entry_id=entry_id,
                )
            except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
                _log.debug(
                    "rfc24 shared pool: delete of victim entry_id=%d "
                    "failed (%s: %s)",
                    entry_id, type(exc).__name__, exc,
                )
        return deleted
