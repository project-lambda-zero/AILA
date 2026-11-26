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
its namespace + score for auditability, and copies only the gated
sanitized content verbatim -- the assembler's SUMMARY producer
(:mod:`context_assembler`) already guarantees ``path:line`` anchors
survive eviction, so the audit chain is preserved end-to-end.

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

_SOURCE_ID_KEYS = (
    "observation_id",
    "trace_id",
    "action_id",
    "asset_id",
    "raw_artifact_id",
    "raw_sha256",
)
_MAX_EVIDENCE_REFS = 8
_MAX_SOURCE_IDS = 12
_MAX_NAMESPACE_CHARS = 128
_MAX_ID_CHARS = 96
_MAX_PREFIX_CHARS = 1024


def _inline_metadata(value: Any, *, limit: int = _MAX_ID_CHARS) -> str:
    """Return bounded single-line text for an allowlisted metadata value."""
    text = str(value)[:limit]
    escaped = "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )
    return escaped[:limit]


def _source_identifiers(hit: dict[str, Any]) -> list[str]:
    """Extract only known source-id fields, never arbitrary metadata values."""
    metadata = hit.get("metadata")
    mappings: list[dict[str, Any]] = [hit]
    if isinstance(metadata, dict):
        mappings.append(metadata)

    # ``source`` and mapping-shaped evidence refs can carry exact source
    # identifiers. String refs and unrelated metadata remain private to the
    # knowledge record instead of being copied into an autonomous prompt.
    for container in tuple(mappings):
        provenance = container.get("provenance")
        if isinstance(provenance, dict):
            mappings.append(provenance)
        source = container.get("source")
        if isinstance(source, dict):
            mappings.append(source)
        refs = container.get("evidence_refs")
        if isinstance(refs, dict):
            refs = [refs]
        if isinstance(refs, (list, tuple)):
            mappings.extend(
                ref for ref in refs[:_MAX_EVIDENCE_REFS] if isinstance(ref, dict)
            )

    identifiers: list[str] = []
    seen: set[tuple[str, str]] = set()
    for mapping in mappings:
        for key in _SOURCE_ID_KEYS:
            value = mapping.get(key)
            if (
                value is None
                or isinstance(value, bool)
                or not isinstance(value, (str, int))
            ):
                continue
            rendered = _inline_metadata(value)
            if not rendered or (key, rendered) in seen:
                continue
            seen.add((key, rendered))
            identifiers.append(f"{key}={rendered}")
            if len(identifiers) >= _MAX_SOURCE_IDS:
                return identifiers
    return identifiers


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
    * ``entry_id`` and allowlisted source identifiers -- stable handles
      for exact follow-up reads. Inline metadata is escaped and bounded;
      arbitrary metadata and string evidence refs are never rendered.
    * ``sanitized_content`` -- copied VERBATIM after the RFC-12 gate.
      Raw ``content`` is never a fallback: a hit whose sanitized body is
      empty is omitted so sanitization cannot be bypassed. The RFC-24
      guardrail requires that ``path:line`` anchors are never
      paraphrased; the assembler's SUMMARY producer re-applies the same
      rule if the section is folded.
    """
    bullets = [heading]
    for hit in hits:
        namespace = _inline_metadata(
            hit.get("namespace") or "unknown", limit=_MAX_NAMESPACE_CHARS,
        )
        score = float(hit.get("score") or 0.0)
        raw_entry_id = hit.get("id")
        if raw_entry_id is None:
            raw_entry_id = hit.get("entry_id")
        entry_id = _inline_metadata(
            raw_entry_id if raw_entry_id is not None else "unknown",
        )
        content = str(hit.get("sanitized_content") or "")
        if not content.strip():
            continue
        prefix = f"[{namespace}] score={score:.2f} entry_id={entry_id}"
        for identifier in _source_identifiers(hit):
            candidate = f"{prefix} {identifier}"
            if len(candidate) > _MAX_PREFIX_CHARS:
                break
            prefix = candidate
        bullets.append(f"- {prefix} :: {content}")
    return "\n".join(bullets)


def _truncate_hits_to_budget(
    hits: list[dict[str, Any]], *, max_tokens: int,
) -> list[dict[str, Any]]:
    """Skip hits that do not fit while preserving lower-score fitting hits.

    The routed retrieval returns hits sorted highest-score first. Each
    non-fitting hit is omitted without starving later candidates; accepted
    hits retain their original relative order. An empty ``hits``
    short-circuits to ``[]``. A ``max_tokens <= 0`` disables the trim
    (returns the input unchanged) -- callers use this to inspect the full
    set for tests.
    """
    if not hits or max_tokens <= 0:
        return list(hits)
    accepted: list[dict[str, Any]] = []
    for hit in hits:
        candidate = accepted + [hit]
        if estimate_tokens(format_retrieved_body(candidate)) > max_tokens:
            continue
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
        try:
            service = self.knowledge_service or KnowledgeService()
            routed = await service.retrieve_routed(
                query=query,
                namespaces=list(request.namespaces) or None,
                namespace_patterns=list(request.namespace_patterns) or None,
                limit=max(1, int(request.limit)),
                min_score=float(request.min_score),
            )
        except (
            SQLAlchemyError, ImportError, OSError, RuntimeError, ValueError, TypeError,
        ) as exc:
            _log.debug(
                "rfc24 retrieval: knowledge construction/retrieval failed "
                "(%s: %s); returning empty RETRIEVED tier for this turn",
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
