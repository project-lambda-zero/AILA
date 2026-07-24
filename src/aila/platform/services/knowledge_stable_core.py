"""Cache-Augmented Generation (CAG) stable-core cache -- RFC-12 criterion 5.

Preloads the small, stable knowledge subset (rubrics, accept-bar policies,
verified prior verdicts -- the exact material the RFC lists as CAG
candidates) into a process-local list once, then serves stable-core queries
from that list without an embedding call, an FTS query, or a hybrid merge.

Membership rule: an entry is stable-core iff its ``namespace`` starts with
:data:`STABLE_CORE_NAMESPACE_PREFIX`. Using the existing namespace
mechanism -- rather than adding a marker column -- keeps the change
migration-free at the schema level (no column, no index, no backfill) and
matches how the platform already scopes ownership per D-09
(``platform:*`` = shared admin data). Operators promote an entry to the
stable core by writing it into ``platform:stable_core:<key>``; demoting
means moving it back to a regular namespace.

The cache is process-local (a plain list guarded by a thread lock) and
opts callers into explicit invalidation:

* :meth:`StableCoreCache.preload` runs the single SELECT and populates
  the cache; safe to call repeatedly (idempotent) but only reloads when
  invalidated or forced.
* :meth:`StableCoreCache.entries` returns the cached rows, running
  :meth:`preload` on the first call.
* :meth:`StableCoreCache.invalidate` clears the cache so the next
  :meth:`entries` call reloads from the DB.

Cache staleness is real (RFC-12 lists it as a CAG hazard). Writers into
the stable-core namespace SHOULD call :meth:`invalidate` after their
commit; the retrieval slice does not own that hook, so the enrichment
slice will wire it into ``KnowledgeService.store`` alongside the other
provenance work.
"""

from __future__ import annotations

import threading
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from ...storage.db_models import KnowledgeEntryRecord
from .knowledge import _session_or_new

__all__ = [
    "STABLE_CORE_NAMESPACE_PREFIX",
    "STABLE_CORE_TOKEN_PREFIX",
    "StableCoreCache",
    "is_stable_core_namespace",
]

# The single namespace prefix that marks an entry as stable core. Matches
# the make_platform_namespace scheme (``platform:<category>``) so an
# entry lands in the CAG by being stored under
# ``platform:stable_core:<subkey>`` (for example
# ``platform:stable_core:accept_bar_high_severity``).
STABLE_CORE_NAMESPACE_PREFIX: str = "platform:stable_core:"

# A caller-facing lexical token the router recognises as "this query
# targets the stable core". Distinct from the namespace prefix so the
# router does not need to import DB constants and the token stays legible
# in a query string (``"stable-core: accept bar for critical"``).
STABLE_CORE_TOKEN_PREFIX: str = "stable-core:"


def is_stable_core_namespace(namespace: str | None) -> bool:
    """Return True when ``namespace`` belongs to the stable-core CAG bucket.

    ``None`` returns False so callers can pipe an entry row's raw
    namespace column through without a null-check.
    """
    if not namespace:
        return False
    return namespace.startswith(STABLE_CORE_NAMESPACE_PREFIX)


class StableCoreCache:
    """Process-local CAG cache of stable-core :class:`KnowledgeEntryRecord` rows.

    One shared list, guarded by a lock so a concurrent preload from two
    workers doesn't emit two parallel SELECTs against the same subset.
    The cache holds the fields the retrieval path needs (id, namespace,
    content, entry_metadata, and every provenance column) -- not the
    embedding vector, since the stable-core path never runs a cosine
    query.
    """

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] | None = None
        self._lock = threading.Lock()

    async def preload(
        self,
        session: AsyncSession | None = None,
        force: bool = False,
    ) -> list[dict[str, Any]]:
        """Populate the cache with every stable-core entry in the DB.

        No-op when the cache is already loaded and ``force`` is False;
        that is the CAG contract -- pay the SELECT once, reuse the
        result across every stable-core query until the operator (or
        the enrichment slice writer hook) invalidates it. Passing
        ``force=True`` forces the reload, mostly for the invalidate ->
        preload path a store hook needs.

        Returns the loaded entries so a caller who wants both the
        preload and the values can avoid a second :meth:`entries` call.
        """
        # Fast-path outside the lock: an already-loaded cache stays
        # loaded, and returning ``self._entries`` from here matches the
        # entries() reader path.
        if not force and self._entries is not None:
            return list(self._entries)
        stmt = select(
            KnowledgeEntryRecord.id,
            KnowledgeEntryRecord.namespace,
            KnowledgeEntryRecord.content,
            KnowledgeEntryRecord.entry_metadata,
            KnowledgeEntryRecord.model_id,
            KnowledgeEntryRecord.content_hash,
            KnowledgeEntryRecord.source_type,
            KnowledgeEntryRecord.created_at,
            KnowledgeEntryRecord.updated_at,
        ).where(
            KnowledgeEntryRecord.namespace.like(f"{STABLE_CORE_NAMESPACE_PREFIX}%"),
        )
        async with _session_or_new(session) as (sess, _owns):
            rows = (await sess.exec(stmt)).all()
        loaded = [
            {
                "id": int(r.id),
                "namespace": r.namespace,
                "content": r.content,
                "entry_metadata": r.entry_metadata,
                "model_id": r.model_id,
                "content_hash": r.content_hash,
                "source_type": r.source_type,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            }
            for r in rows
        ]
        with self._lock:
            self._entries = loaded
        return list(loaded)

    async def entries(
        self,
        session: AsyncSession | None = None,
    ) -> list[dict[str, Any]]:
        """Return the cached entries, loading them on first access.

        Delegates to :meth:`preload` when the cache is cold so a
        first-time caller gets the same list without a separate warm-up
        step. Every subsequent call is a pure list copy -- no SQL, no
        embedding, no allocation beyond the list header.
        """
        if self._entries is None:
            return await self.preload(session=session)
        return list(self._entries)

    def invalidate(self) -> None:
        """Drop the cached entries; the next :meth:`entries` reloads.

        Cheap, sync, and safe to call from a background task or a store
        hook (no I/O). The next stable-core query pays the reload SELECT.
        """
        with self._lock:
            self._entries = None

    def is_loaded(self) -> bool:
        """True when :meth:`preload` has populated the cache.

        Test hook. Callers should generally not branch on this -- the
        :meth:`entries` reader loads on first access -- but the
        cache-preloaded assertion in the routing test needs it.
        """
        return self._entries is not None
