"""Contextual chunk enrichment for knowledge ingestion (RFC-12 criterion 2).

The chunker in :mod:`aila.platform.services.ingestor` produces
boundary-aligned chunks; this module adds the situating half of the RFC-12
criterion. For each chunk we ask the LLM to write a 50 to 100 token blurb
saying WHERE the chunk sits inside its parent document. The blurb is
prepended to the chunk BEFORE embedding, so the stored vector carries
document-level terms the chunk itself may not repeat. The original,
unenriched chunk stays recoverable via ``entry_metadata["chunk_original"]``
and the generated blurb is captured under ``entry_metadata["context_blurb"]``.

Cost note: enrichment is one LLM call per chunk. Ingesting a 10-chunk
document with enrichment enabled pays for 10 chat completions on top of
the embedding calls. For that reason enrichment is opt-in on every call
(``store(..., enrich=True)``); the default path is byte-identical to the
unenriched baseline.

The prompt lives in ``src/aila/platform/prompts/system_knowledge_enrichment.md``
via the file :class:`aila.platform.prompts.PromptRegistry` (RFC-09 criterion 1:
no inline literal system prompts in code). The LLM call goes through
:func:`aila.platform.agents.idempotent_llm.idempotent_llm_call` so a retried
worker replays the cached blurb instead of paying for a second completion.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..agents.idempotent_llm import idempotent_llm_call
from ..prompts import PromptRegistry

if TYPE_CHECKING:
    from ..llm.client import AilaLLMClient

__all__ = [
    "ENRICHMENT_TASK_TYPE",
    "MAX_DOCUMENT_CHARS",
    "enrich_chunk",
]

_log = logging.getLogger(__name__)

# Task-type key used for routing + cost attribution. The platform LLM
# config resolves unknown task_types via ``llm_default_model``, so no
# schema change is required to enable enrichment; operators MAY still
# override with ``llm_model_knowledge_enrichment`` to route enrichment
# to a cheaper model than the default researcher model.
ENRICHMENT_TASK_TYPE: str = "knowledge_enrichment"

# Upper bound on the parent-document text delivered to the enrichment
# prompt. A parent doc many times the chunk size dominates the prompt
# tokens without proportionally improving the blurb (the LLM only needs
# enough surrounding context to name the section the chunk is part of).
# 8000 chars keeps a typical enrichment call under ~2k prompt tokens.
MAX_DOCUMENT_CHARS: int = 8000

# Enrichment system prompt lives at
# ``src/aila/platform/prompts/system_knowledge_enrichment.md`` and is loaded
# through :class:`PromptRegistry` so an operator may drop in a strategy-specific
# variant later without editing this module. The registry is process-cached
# (:func:`functools.lru_cache`) so repeated per-chunk lookups during an ingest
# never re-read the file (RFC-09 criterion 1: no inline literal prompts).
_PROMPT_DIR = Path(__file__).resolve().parents[1] / "prompts"
_PROMPT_REGISTRY = PromptRegistry(
    _PROMPT_DIR, fallback_base="system_knowledge_enrichment.md",
)


def _clip_document(document: str, chunk: str) -> str:
    """Return ``document`` bounded to :data:`MAX_DOCUMENT_CHARS`.

    When the document already fits under the ceiling it is returned
    unchanged. When it does not, we try to keep the window that
    surrounds ``chunk`` because the point of the parent-document context
    is to describe where the chunk sits; a window around the chunk
    itself carries the most useful section names. On failure to locate
    the chunk (verbatim match), fall back to the head of the document.
    """
    if len(document) <= MAX_DOCUMENT_CHARS:
        return document
    idx = document.find(chunk)
    if idx < 0:
        return document[:MAX_DOCUMENT_CHARS]
    half = MAX_DOCUMENT_CHARS // 2
    start = max(0, idx - half)
    end = min(len(document), start + MAX_DOCUMENT_CHARS)
    return document[start:end]


def _build_user_message(document: str, chunk: str) -> str:
    """Render the enrichment user turn.

    Plain JSON body so the model sees the two fields explicitly labelled;
    parsing on the model side is not required (the response is plain
    text) but the labels help the model distinguish the parent document
    from the chunk when both are prose.
    """
    return json.dumps(
        {
            "document": _clip_document(document, chunk),
            "chunk": chunk,
        },
        ensure_ascii=False,
    )


async def enrich_chunk(
    llm_client: AilaLLMClient,
    *,
    document: str,
    chunk: str,
    namespace: str,
    team_id: str | None = None,
) -> str:
    """Return a 50-100 token situating blurb for ``chunk`` inside ``document``.

    On LLM disabled (kill switch) or an empty response, returns ``""`` and
    logs a WARNING. The caller degrades gracefully: an empty blurb means
    the chunk is embedded verbatim (byte-identical to the non-enriched
    path for that one chunk).

    The idempotent wrapper caches responses keyed on
    (namespace-derived id, method, task_type, messages), so a retried
    ingest replays the same blurb instead of paying the model again.
    """
    system_prompt = _PROMPT_REGISTRY.load(ENRICHMENT_TASK_TYPE)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _build_user_message(document, chunk)},
    ]
    # No investigation context on ingest -- use a namespace-derived stable
    # id so the idempotency cache key is deterministic across retries of
    # the same ingest; the messages payload already differentiates every
    # (document, chunk) pair inside that namespace.
    investigation_id = f"knowledge-enrich:{namespace}"
    resp, _cache_hit = await idempotent_llm_call(
        llm_client,
        method="chat",
        task_type=ENRICHMENT_TASK_TYPE,
        messages=messages,
        investigation_id=investigation_id,
        team_id=team_id,
    )
    if resp.disabled:
        _log.warning(
            "knowledge_enrichment: LLM kill-switch active -- returning empty "
            "blurb for namespace=%s",
            namespace,
        )
        return ""
    text = (resp.content or "").strip()
    if not text:
        _log.warning(
            "knowledge_enrichment: empty LLM response for namespace=%s",
            namespace,
        )
    return text
