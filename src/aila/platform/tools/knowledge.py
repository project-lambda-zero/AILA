from __future__ import annotations

import threading

from ..config import PlatformSettings
from ._common import Tool, normalize_limit, require_text

__all__ = [
    "KnowledgeRetrieveTool",
    "KnowledgeStoreTool",
]

# Module-level lazy singleton (per D-08): constructed only when a knowledge
# tool is first used. #37: the store/retrieve tools MUST embed with the same
# provider as KnowledgeService (the service store/retrieve path), or vectors
# written by one path and queried by the other land in incompatible embedding
# spaces and retrieval returns garbage. Both paths now go through
# KnowledgeService.embed (canonical resolve_provider selection + the shared
# 1024-dim BGE-M3 space), so a single cached service is reused here.
_KNOWLEDGE_SERVICE = None
_SERVICE_LOCK = threading.Lock()


def _knowledge_service() -> object:
    """Return the cached KnowledgeService, constructing it on first call."""
    global _KNOWLEDGE_SERVICE
    if _KNOWLEDGE_SERVICE is None:
        with _SERVICE_LOCK:
            if _KNOWLEDGE_SERVICE is None:
                from ..services.knowledge import KnowledgeService
                _KNOWLEDGE_SERVICE = KnowledgeService()
    return _KNOWLEDGE_SERVICE


class KnowledgeStoreTool(Tool):
    """Platform tool for storing text with semantic embeddings in a namespace-scoped knowledge store.

    The namespace isolates each agent's knowledge from others at the SQL level
    (WHERE namespace = ?). The embedding is computed outside the write transaction
    to keep lock hold time short. Deduplication via _dedup_key prevents
    re-storing identical content across multiple runs.

    The SentenceTransformer model is loaded lazily on first use to avoid import
    overhead when the knowledge store is not needed.
    """

    name = "knowledge_store"
    description = "Store text content with a semantic embedding in the agent's knowledge namespace."
    inputs = {
        "content": {
            "type": "string",
            "description": "Text to embed and store.",
        },
        "metadata": {
            "type": "object",
            "description": "Optional JSON metadata (e.g. source, tags).",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, namespace: str, settings: PlatformSettings):
        # namespace = agent.__class__.__name__ per D-04; validated at construction, not per call
        self.namespace = require_text(namespace, tool_name="KnowledgeStoreTool", field_name="namespace")
        self.settings = settings

    async def forward(self, content: str, metadata: dict | None = None) -> dict:
        content = require_text(content, tool_name="KnowledgeStoreTool", field_name="content")
        meta = dict(metadata or {})
        # Extract dedup sentinel before storing -- do not persist _dedup_key inside entry_metadata (per D-06)
        dedup_key: str | None = meta.pop("_dedup_key", None)

        # #37/RFC-12: delegate to KnowledgeService.store so this tool shares the
        # one embedding path, stamps provenance (model_id / content_hash /
        # source_type / updated_at) on every vector, upserts under the
        # advisory-lock dedup, and links semantic neighbours -- instead of
        # running a second, provenance-less INSERT path that wrote vectors the
        # #37 guardrails now forbid. extract_entities tags CVE / CWE / technique
        # ids so retrieval can scope through metadata_filter.
        return await _knowledge_service().store(
            namespace=self.namespace,
            content=content,
            metadata=meta,
            dedup_key=dedup_key,
            extract_entities=True,
            link_neighbors=True,
        )


class KnowledgeRetrieveTool(Tool):
    """Platform tool for adaptive namespace-scoped retrieval from the knowledge store.

    Consults the RFC-12 :class:`KnowledgeRouter` on every call so the
    query is served by the cheapest adequate path -- stable-core CAG,
    the hybrid pgvector + tsvector path, or the multi-hop graph
    traversal. The router pick propagates back to the caller as the
    ``route`` key on the return dict; per-hit provenance and the
    sanitize/classify gate are guaranteed regardless of the path.

    Namespace scoping still applies -- the tool passes its bound
    ``namespace`` to :meth:`KnowledgeService.retrieve_routed` so
    hybrid and graph seeds stay inside the agent's own store; the
    stable-core path is deliberately cross-namespace (the CAG core is
    platform-scoped by design).
    """

    name = "knowledge_retrieve"
    description = "Retrieve knowledge entries with adaptive routing (stable-core / hybrid / graph), scoped to the agent's namespace."
    inputs = {
        "query": {
            "type": "string",
            "description": "Query text -- the router classifies its shape and picks the retrieval path.",
        },
        "limit": {
            "type": "integer",
            "description": "Maximum results to return (default: 10, max: 50).",
            "nullable": True,
        },
        "route": {
            "type": "string",
            "description": "Optional retrieval route override: 'stable_core' | 'simple' | 'graph'. Omit to let the router classify.",
            "nullable": True,
        },
        "max_hops": {
            "type": "integer",
            "description": "Graph-path hop bound (default 2). Ignored on stable-core and simple.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, namespace: str, settings: PlatformSettings):
        self.namespace = require_text(namespace, tool_name="KnowledgeRetrieveTool", field_name="namespace")
        self.settings = settings

    async def forward(
        self,
        query: str,
        limit: int | None = None,
        route: str | None = None,
        max_hops: int | None = None,
    ) -> dict:
        query = require_text(query, tool_name="KnowledgeRetrieveTool", field_name="query")
        limit = normalize_limit(limit, default=10, maximum=50)

        service = _knowledge_service()
        # Cross-namespace stable-core (platform:stable_core:*) is served
        # cache-only, so we scope hybrid + graph seeds to the tool's
        # namespace and leave the stable-core path unrestricted -- the
        # CAG membership is namespace-driven at the retrieval layer.
        routed = await service.retrieve_routed(
            query=query,
            route=route,
            limit=limit,
            namespaces=[self.namespace],
            max_hops=max_hops,
        )

        return {
            "status": "retrieved",
            "namespace": self.namespace,
            "query": routed.get("query", query),
            "route": routed.get("route"),
            "hop_bound": routed.get("hop_bound"),
            "count": routed.get("count", 0),
            "hybrid": routed.get("route") == "simple",
            "results": routed.get("results", []),
        }
