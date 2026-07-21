"""#37 -- knowledge store/retrieve tools embed with the SAME provider as
KnowledgeService.

The prior bug: KnowledgeStoreTool / KnowledgeRetrieveTool hardcoded
all-MiniLM-L6-v2 (384-dim) while KnowledgeService used the canonical
resolve_provider() (BGE-M3, 1024-dim). Both wrote the same column, but in
different embedding spaces, so a vector stored via the tool and queried via the
service (or vice versa) had meaningless cosine distances and retrieval returned
garbage. Both paths now embed through KnowledgeService, so they share one
provider and one 1024-dim space.

Provider construction is lazy (the SentenceTransformer model loads only on the
first encode), so these assertions are cheap and need no model download.
"""
from __future__ import annotations

from aila.platform.services.embedding import MiniLMProvider
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.tools import knowledge as tool_mod


def test_tool_and_service_share_embedding_provider() -> None:
    tool_provider = type(tool_mod._knowledge_service().provider)
    service_provider = type(KnowledgeService().provider)
    assert tool_provider is service_provider


def test_tool_no_longer_hardcodes_minilm() -> None:
    # Regression guard: the tool must resolve the canonical provider, never the
    # MiniLM fallback it previously hardcoded.
    assert not isinstance(tool_mod._knowledge_service().provider, MiniLMProvider)
