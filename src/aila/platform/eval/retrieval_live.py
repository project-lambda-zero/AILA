"""RFC-12 Phase 6: wire the retrieval eval harness to the live KnowledgeService.

:class:`RetrievalEvalRunner` scores a benchmark by replaying it through an
injected ``RetrieveFn`` (``(query, k) -> ranked entry ids``). This module
supplies the live adapter: it turns the adaptive ``retrieve_routed`` path into
that RetrieveFn, returning the entry ids in rank order. A module supplies the
namespace scope to search (findings, patterns, ...); this stays platform-generic
and imports no module.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence

from aila.platform.services.knowledge import KnowledgeService

__all__ = ["make_retrieve_fn"]

_log = logging.getLogger(__name__)


def make_retrieve_fn(
    *,
    namespace_patterns: list[str],
    min_score: float = 0.3,
    route: str = "simple",
) -> Callable[[str, int], Awaitable[Sequence[str]]]:
    """Build a ``RetrieveFn`` over ``retrieve_routed`` for the eval runner.

    The returned coroutine runs one adaptive retrieval per benchmark query,
    scoped to ``namespace_patterns``, and returns the knowledge entry ids in
    descending relevance order (the ranking the recall/MRR/nDCG metrics score).
    Relevance-floored + gate-sanitized like every other routed call.
    """

    async def _retrieve(query: str, k: int) -> Sequence[str]:
        routed = await KnowledgeService().retrieve_routed(
            query=query,
            route=route,
            limit=k,
            min_score=min_score,
            namespace_patterns=list(namespace_patterns),
        )
        return [
            str(hit["id"])
            for hit in routed.get("results", [])
            if hit.get("id") is not None
        ]

    return _retrieve
