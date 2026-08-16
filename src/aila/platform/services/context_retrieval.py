"""RFC-24 RETRIEVED-tier producer backed by ``KnowledgeService.retrieve_routed``.

Wires the RFC-24 step-3 RETRIEVED tier onto the platform's existing
adaptive retrieval path: ``KnowledgeService.retrieve_routed`` (BGE-M3
1024-dim embeddings, hybrid pgvector + tsvector, adaptive route
selection, RFC-12 sanitize/classify gate, RFC-12 Phase-5 trust +
temporal decay ranker). No new embedding model, no new storage table
-- the same knowledge entries the modules already write for
observations (RFC-137 ``<module>.observation.workspace.<id>``) and the
shared cross-branch pool (``platform.shared_pool.investigation.<id>``,
see :mod:`aila.platform.services.shared_context_pool`) are queried
here and folded into ONE synthesized :class:`ContextSection` tagged
:data:`ContextTier.RETRIEVED`. The section body preserves the routed
retrieval's score ordering (highest first), stamps every hit with
its namespace + score for auditability, and copies the hit content
verbatim -- the assembler's SUMMARY producer (:mod:`context_assembler`)
already guarantees ``path:line`` anchors survive eviction, so the
audit chain is preserved end-to-end.

Failure-mode contract: the provider NEVER raises out of ``fetch``.
An unreachable knowledge store (Postgres down, embedding provider
mismatched, empty result set) returns ``[]`` and logs at DEBUG so a
transient store outage degrades a turn to the pre-flag path
instead of crashing it. This matches the ``_refresh_retrieved_knowledge``
best-effort contract that VR + malware already follow for their
private RETRIEVED-tier fetches.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.services.context_assembler import (
    ContextSection,
    ContextTier,
    RetrievalRequest,
    estimate_tokens,
)
from aila.platform.services.knowledge import KnowledgeService

__all__ = [
    "KnowledgeRetrievalProvider",
    "format_retrieved_body",
]

_log = logging.getLogger(__name__)


def format_retrieved_body(
    hits: list[dict[str, Any]],
    *,
    heading: str = "# Retrieved observations (relevance-ranked)",
) -> str:
    """Render a routed-retrieval hit list into a single RETRIEVED section body.

    One bullet per hit, highest-score first, carrying:

    * ``namespace`` -- so the reader knows which store the hit came
      from (a VR observation, a malware observation, the shared pool).
    * ``score`` -- the routed retrieval's post-decay score, formatted
      to two decimals so the operator can compare hits at a glance
      without reading the numbers in full precision.
    * ``content`` -- copied VERBATIM. The RFC-24 guardrail requires
      that ``path:line`` anchors are never paraphrased; passing the
      content through unchanged satisfies that guarantee (the
      assembler's SUMMARY producer re-applies the same rule if the
      section is folded).
    """
    bullets = [heading]
    for hit in hits:
        namespace = str(hit.get("namespace") or "unknown")
        score = float(hit.get("score") or 0.0)
        content = str(hit.get("content") or "").strip()
        if not content:
            continue
        bullets.append(
            f"- [{namespace}] score={score:.2f} :: {content}",
        )
    return "\n".join(bullets)


def _truncate_hits_to_budget(
    hits: list[dict[str, Any]], *, max_tokens: int,
) -> list[dict[str, Any]]:
    """Drop lowest-score hits until the rendered body fits ``max_tokens``.

    The routed retrieval returns hits sorted highest-score first, so
    trimming from the tail preserves the most relevant content. An
    empty ``hits`` short-circuits to ``[]``. A ``max_tokens <= 0``
    disables the trim (returns the input unchanged) -- callers use
    this to inspect the full set for tests.
    """
    if not hits or max_tokens <= 0:
        return list(hits)
    accepted: list[dict[str, Any]] = []
    for hit in hits:
        candidate = accepted + [hit]
        if estimate_tokens(format_retrieved_body(candidate)) > max_tokens:
            break
        accepted.append(hit)
    return accepted


@dataclass(slots=True)
class KnowledgeRetrievalProvider:
    """Concrete :class:`RetrievalProvider` over
    :meth:`KnowledgeService.retrieve_routed`.

    The provider owns the ``KnowledgeService`` instance so a caller
    can share one across turns (embedding-provider instantiation is
    the expensive part; reusing avoids the cold-start on every fetch).
    An external service can be injected (tests, alternate embedding
    provider) via ``knowledge_service``.
    """

    knowledge_service: KnowledgeService | None = None

    async def fetch(
        self, request: RetrievalRequest,
    ) -> list[ContextSection]:
        """Return zero or one RETRIEVED-tier :class:`ContextSection`.

        Called by the turn runner (see
        :meth:`AgentTurnRunnerBase._rfc24_populate_retrieved_tier`)
        exactly once per turn when
        ``platform.context_retrieved_enabled`` is True. Returns an
        empty list when the query is empty (no signal to search on),
        no namespaces were provided (no scope to search in), or the
        routed retrieval turned up nothing above the relevance floor.

        The provider folds ALL surviving hits into a SINGLE
        :class:`ContextSection` -- one bullet per hit -- so the
        assembler either keeps the whole retrieved block or drops it
        wholesale. This matches how the platform already renders
        recalled knowledge (one block per pivot) and keeps the
        assembler's eviction ledger from spraying dozens of tiny
        RETRIEVED entries into the drop log on a budget-pressured turn.
        """
        query = (request.query or "").strip()
        if not query:
            return []
        if not request.namespaces and not request.namespace_patterns:
            return []
        service = self.knowledge_service or KnowledgeService()
        try:
            routed = await service.retrieve_routed(
                query=query,
                namespaces=list(request.namespaces) or None,
                namespace_patterns=list(request.namespace_patterns) or None,
                limit=max(1, int(request.limit)),
                min_score=float(request.min_score),
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.debug(
                "rfc24 retrieval: retrieve_routed failed (%s: %s); "
                "returning empty RETRIEVED tier for this turn",
                type(exc).__name__, exc,
            )
            return []
        # ``retrieve_routed`` returns ``{status, route, query, count,
        # results, hop_bound}``; the ranked hit rows live under
        # ``results`` (each carries ``id``, ``content``, ``namespace``,
        # ``score``, ``metadata``, ``provenance``, ``sanitized_content``,
        # ``classification``).
        hits = list(routed.get("results") or [])
        if not hits:
            return []
        hits = _truncate_hits_to_budget(hits, max_tokens=request.max_tokens)
        if not hits:
            return []
        body = format_retrieved_body(hits)
        return [
            ContextSection(
                tier=ContextTier.RETRIEVED,
                label=request.label,
                body=body,
            ),
        ]
