"""RFC-12 criterion 2 -- contextual enrichment on ingestion.

The chunker in :mod:`aila.platform.services.ingestor` already ships the
"code/doc boundary" half of criterion 2. This suite covers the
enrichment half: when :func:`KnowledgeService.store` is called with
``chunked=True, enrich=True`` and the service was built with an
``llm_client``, each chunk gets an LLM-written blurb prepended before
embedding, and the original chunk text is recoverable from
``entry_metadata``.

Two hard guarantees under test:

  1. Enrichment ON path -- the embedded ``content`` includes the
     generated blurb; ``entry_metadata`` records ``context_blurb`` and
     ``chunk_original`` separately; the LLM (mocked at the idempotent
     seam) is called exactly once per chunk.

  2. Enrichment OFF path (default) -- ``store()`` is byte-identical to
     the pre-enrichment behaviour: no LLM call, no new metadata keys, no
     blurb prepended.

The LLM is mocked at the idempotent seam
(:func:`aila.platform.services.knowledge_enrichment.enrich_chunk`
patches the idempotent wrapper) so no model / provider / cache setup is
needed. The embedding provider is stubbed to a zero vector so the real
BGE-M3 model is never downloaded.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from sqlmodel import select

from aila.platform.llm.client import LLMResponse
from aila.platform.services.knowledge import KnowledgeService
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

pytestmark = pytest.mark.usefixtures("test_db")


class _StubProvider:
    """Minimal EmbeddingProvider satisfying the runtime-checkable Protocol.

    ``encode`` records every text it saw so the test can assert what was
    embedded (byte-identical to the stored ``content`` -- the enriched
    text on the enrichment path, the raw chunk on the off path).
    """

    def __init__(self, model_name: str = "stub-provider/vX", dim: int = 1024) -> None:
        self._name = model_name
        self._dim = dim
        self.calls: list[str] = []

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def model_name(self) -> str:
        return self._name

    def encode(self, text: str) -> list[float]:
        self.calls.append(text)
        return [0.0] * self._dim

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


class _StubLLMClient:
    """Placeholder passed to :class:`KnowledgeService`.

    The enrichment path patches ``idempotent_llm_call`` before ever
    dispatching, so this object's methods are never invoked. It exists
    only to satisfy the ``self._llm_client is not None`` gate.
    """


def _make_llm_response(text: str) -> LLMResponse:
    """Build an :class:`LLMResponse` shaped like a real chat completion."""
    return LLMResponse(
        content=text,
        model="stub-enrichment-model",
        usage={"prompt_tokens": 12, "completion_tokens": 6},
        disabled=False,
        finish_reason="stop",
    )


_DOC = (
    "# Alpha\nAlpha section body describing the alpha subsystem.\n\n"
    "# Beta\nBeta section body describing the beta subsystem.\n\n"
    "# Gamma\nGamma section body describing the gamma subsystem.\n"
)


async def _read_entries(entry_ids: list[int]) -> list[KnowledgeEntryRecord]:
    """Fetch rows in insertion order for stable per-chunk assertions."""
    async with async_session_scope() as sess:
        rows = (
            await sess.exec(
                select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.id.in_(entry_ids),
                )
            )
        ).all()
    by_id = {row.id: row for row in rows}
    return [by_id[eid] for eid in entry_ids]


# ---------------------------------------------------------------------------
# Enrichment ON -- LLM is called once per chunk, blurb prepended, metadata
# records original chunk text separately.
# ---------------------------------------------------------------------------


async def test_enrich_on_prepends_blurb_and_records_metadata() -> None:
    """With enrich=True and an llm_client, every chunk carries a blurb.

    * Embedded ``content`` on each row is ``"<blurb>\\n\\n<chunk>"``.
    * ``entry_metadata['context_blurb']`` holds the blurb verbatim.
    * ``entry_metadata['chunk_original']`` holds the pre-enrichment chunk.
    * ``entry_metadata['enriched']`` is True.
    * The idempotent wrapper is called exactly once per chunk.
    * ``embed()`` sees the enriched text (not the raw chunk).
    """
    provider = _StubProvider()
    svc = KnowledgeService(provider=provider, llm_client=_StubLLMClient())

    call_counter = {"n": 0}

    async def fake_idempotent(*args, **kwargs) -> tuple[LLMResponse, bool]:
        call_counter["n"] += 1
        # Chunk text is JSON-encoded into the user message; parse it back
        # so the blurb references the chunk that triggered this call --
        # per-chunk uniqueness proves per-chunk enrichment (not a single
        # cached blurb shared across all chunks).
        user_content = kwargs["messages"][-1]["content"]
        chunk = json.loads(user_content)["chunk"]
        head = chunk.strip().splitlines()[0][:40]
        blurb = f"CTX[{call_counter['n']}]: situates chunk starting {head!r}."
        return _make_llm_response(blurb), False

    with patch(
        "aila.platform.services.knowledge_enrichment.idempotent_llm_call",
        new=AsyncMock(side_effect=fake_idempotent),
    ):
        result = await svc.store(
            namespace="agent:TestEnrich",
            content=_DOC,
            metadata={"tag": "enrich-on"},
            chunked=True,
            kind="document",
            enrich=True,
        )

    assert result["operation"] == "chunked"
    chunk_count = result["chunk_count"]
    assert chunk_count >= 2, (
        "the heading-split doc must produce at least two chunks so the "
        "one-blurb-per-chunk contract is exercised"
    )
    assert call_counter["n"] == chunk_count, (
        f"one idempotent LLM call per chunk expected; "
        f"got {call_counter['n']} for {chunk_count} chunks"
    )

    entry_ids = [rec["entry_id"] for rec in result["chunks"]]
    entries = await _read_entries(entry_ids)

    for index, row in enumerate(entries):
        meta = json.loads(row.entry_metadata)
        assert meta.get("enriched") is True, (
            f"chunk {index} metadata must declare enriched=True"
        )
        blurb = meta.get("context_blurb")
        original = meta.get("chunk_original")
        assert blurb, f"chunk {index} must record its context_blurb"
        assert original, f"chunk {index} must record its chunk_original"
        # Round-trip: stored content is exactly blurb + separator + original.
        assert row.content == f"{blurb}\n\n{original}", (
            f"chunk {index} stored content must be the prepended enrichment "
            f"of the original chunk; got {row.content!r}"
        )
        assert original not in blurb, (
            f"chunk {index} blurb must not re-embed the chunk body verbatim"
        )
        # The pre-enrichment metadata that the chunker set must survive.
        assert meta["chunk_index"] == index
        assert meta["chunk_count"] == chunk_count
        assert meta["chunk_kind"] == "document"
        assert meta["tag"] == "enrich-on"

    # embed() saw the enriched text on every chunk (byte-identical to
    # what got stored). The zero-vector provider records every call.
    stored_texts = [row.content for row in entries]
    assert provider.calls == stored_texts, (
        "embed() must be invoked with the enriched text (the same string "
        "that was written to KnowledgeEntryRecord.content); a mismatch "
        "means the vector and the stored content disagree"
    )


# ---------------------------------------------------------------------------
# Enrichment OFF -- byte-identical to the pre-enrichment chunked path.
# ---------------------------------------------------------------------------


async def test_enrich_off_is_byte_identical_no_llm() -> None:
    """Without enrich=True the store path is byte-identical to today.

    * No idempotent_llm_call is issued (patched to fail on any call).
    * ``entry_metadata`` contains only chunk_index / chunk_count /
      chunk_kind (+ caller-supplied keys). No ``enriched``,
      ``context_blurb``, or ``chunk_original``.
    * ``content`` on each row is the raw chunk from the ingestor.
    * ``embed()`` sees the raw chunk (no prepended blurb).
    """
    provider = _StubProvider()
    svc = KnowledgeService(provider=provider, llm_client=_StubLLMClient())

    async def _fail_if_called(*_a, **_kw) -> tuple[LLMResponse, bool]:
        raise AssertionError(
            "enrichment path must not call the idempotent LLM wrapper "
            "when enrich=False; the OFF path must be byte-identical to the "
            "pre-enrichment chunked path"
        )

    with patch(
        "aila.platform.services.knowledge_enrichment.idempotent_llm_call",
        new=AsyncMock(side_effect=_fail_if_called),
    ):
        result = await svc.store(
            namespace="agent:TestEnrich",
            content=_DOC,
            metadata={"tag": "enrich-off"},
            chunked=True,
            kind="document",
            # enrich defaults to False -- do not pass it, so the test
            # doubles as a default-off regression guard.
        )

    assert result["operation"] == "chunked"
    entry_ids = [rec["entry_id"] for rec in result["chunks"]]
    entries = await _read_entries(entry_ids)

    for row in entries:
        meta = json.loads(row.entry_metadata)
        assert "enriched" not in meta, (
            "OFF path must not stamp the enriched flag"
        )
        assert "context_blurb" not in meta, (
            "OFF path must not stamp a context_blurb"
        )
        assert "chunk_original" not in meta, (
            "OFF path must not stamp chunk_original"
        )
        # The stored content is the raw chunk emitted by the ingestor
        # (no blurb, no separator). We do not know the exact chunk text
        # boundaries here, but we do know it must originate from the doc
        # body verbatim.
        assert row.content.strip() in _DOC, (
            "OFF path content must be a verbatim slice of the source doc"
        )

    stored_texts = [row.content for row in entries]
    assert provider.calls == stored_texts, (
        "embed() must be called with the raw chunk on the OFF path"
    )


async def test_enrich_true_without_llm_client_is_noop() -> None:
    """``enrich=True`` without an ``llm_client`` degrades to the OFF path.

    Guards the constructor contract: a caller that opts into enrichment
    on a service built without an LLM client must not crash. The store
    call is byte-identical to the OFF path -- no metadata keys added,
    no per-chunk failure, and no attempt to reach the enrichment helper.
    """
    provider = _StubProvider()
    svc = KnowledgeService(provider=provider)  # NO llm_client

    async def _fail_if_called(*_a, **_kw) -> tuple[LLMResponse, bool]:
        raise AssertionError(
            "enrichment path must not fire when llm_client is None"
        )

    with patch(
        "aila.platform.services.knowledge_enrichment.idempotent_llm_call",
        new=AsyncMock(side_effect=_fail_if_called),
    ):
        result = await svc.store(
            namespace="agent:TestEnrich",
            content=_DOC,
            chunked=True,
            kind="document",
            enrich=True,
        )

    assert result["operation"] == "chunked"
    entries = await _read_entries([r["entry_id"] for r in result["chunks"]])
    for row in entries:
        meta = json.loads(row.entry_metadata)
        assert "enriched" not in meta
        assert "context_blurb" not in meta
        assert "chunk_original" not in meta


async def test_enrich_on_with_disabled_llm_stores_raw_chunk() -> None:
    """An LLM kill-switch response leaves the chunk stored verbatim.

    ``enrich_chunk`` returns ``""`` when the LLM is disabled; the store
    path must fall back to writing the raw chunk (byte-identical to the
    OFF path for that chunk) and record ``enriched=False``. No crash,
    no blocking write, no missing row.
    """
    provider = _StubProvider()
    svc = KnowledgeService(provider=provider, llm_client=_StubLLMClient())

    async def fake_disabled(*_a, **_kw) -> tuple[LLMResponse, bool]:
        return LLMResponse(content="", disabled=True), False

    with patch(
        "aila.platform.services.knowledge_enrichment.idempotent_llm_call",
        new=AsyncMock(side_effect=fake_disabled),
    ):
        result = await svc.store(
            namespace="agent:TestEnrich",
            content=_DOC,
            chunked=True,
            kind="document",
            enrich=True,
        )

    assert result["operation"] == "chunked"
    entries = await _read_entries([r["entry_id"] for r in result["chunks"]])
    for row in entries:
        meta = json.loads(row.entry_metadata)
        assert meta.get("enriched") is False, (
            "an empty blurb must be recorded as enriched=False, not omitted"
        )
        assert "context_blurb" not in meta
        assert "chunk_original" not in meta
        assert row.content.strip() in _DOC, (
            "on empty blurb the raw chunk must be stored verbatim"
        )
