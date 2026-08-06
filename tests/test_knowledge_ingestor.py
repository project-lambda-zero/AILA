"""Unit tests for KnowledgeIngestor -- pure boundary-aware chunking (RFC-12).

Most tests are pure (no fixtures, no DB, no embedding model) and exercise
chunk_code / chunk_document / chunk directly. One end-to-end test drives
``KnowledgeService.store(chunked=True)`` against the shared ``test_db``
fixture so the wired ingestion path is covered too -- the pure tests still
pass even if the DB is contended.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from aila.platform.services.ingestor import (
    DEFAULT_MAX_CHARS,
    KnowledgeIngestor,
)
from aila.platform.services.knowledge import (
    KnowledgeService,
    make_platform_namespace,
)


def test_chunk_code_splits_on_def_boundary() -> None:
    text = (
        "def foo():\n"
        "    return 1\n"
        "\n"
        "def bar():\n"
        "    return 2\n"
    )
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 2
    assert chunks[0].startswith("def foo")
    assert chunks[1].startswith("def bar")
    assert "return 1" in chunks[0]
    assert "return 2" in chunks[1]


def test_chunk_code_splits_on_class_boundary() -> None:
    text = (
        "class Alpha:\n"
        "    x = 1\n"
        "\n"
        "class Beta:\n"
        "    y = 2\n"
    )
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 2
    assert chunks[0].startswith("class Alpha")
    assert chunks[1].startswith("class Beta")


def test_chunk_code_async_def_boundary() -> None:
    text = (
        "async def handler_a():\n"
        "    return 1\n"
        "\n"
        "async def handler_b():\n"
        "    return 2\n"
    )
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 2
    assert chunks[0].startswith("async def handler_a")
    assert chunks[1].startswith("async def handler_b")


def test_chunk_code_multi_language_boundaries() -> None:
    text = (
        "func Alpha() int {\n"
        "    return 1\n"
        "}\n"
        "\n"
        "fn beta() -> i32 {\n"
        "    return 2\n"
        "}\n"
        "\n"
        "function gamma() {\n"
        "    return 3;\n"
        "}\n"
    )
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 3
    assert chunks[0].startswith("func Alpha")
    assert chunks[1].startswith("fn beta")
    assert chunks[2].startswith("function gamma")


def test_chunk_code_hard_splits_oversize_unit() -> None:
    body = "x" * 5000
    text = f"def big():\n    payload = '{body}'\n    return payload\n"
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=1024)
    assert len(chunks) >= 5, chunks
    assert max(len(c) for c in chunks) <= 1024
    joined = "".join(chunks)
    assert body in joined
    assert joined.startswith("def big")


def test_chunk_code_empty_input_returns_empty_list() -> None:
    ing = KnowledgeIngestor()
    assert ing.chunk_code("", max_chars=1024) == []
    assert ing.chunk_code("   \n\t\n", max_chars=1024) == []


def test_chunk_code_no_boundary_returns_single_chunk() -> None:
    text = "some prose with no leading declaration keyword"
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert chunks == [text]


def test_chunk_code_content_before_first_boundary_kept_as_unit() -> None:
    text = (
        "# module header comment\n"
        "import os\n"
        "\n"
        "def entry():\n"
        "    return os.getcwd()\n"
    )
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 2
    assert "module header comment" in chunks[0]
    assert "import os" in chunks[0]
    assert chunks[1].startswith("def entry")


def test_chunk_document_splits_on_headings() -> None:
    text = (
        "# Intro\n"
        "opening paragraph\n"
        "\n"
        "## Section\n"
        "middle paragraph\n"
        "\n"
        "### Sub\n"
        "closing paragraph\n"
    )
    chunks = KnowledgeIngestor().chunk_document(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 3
    assert chunks[0].startswith("# Intro")
    assert chunks[1].startswith("## Section")
    assert chunks[2].startswith("### Sub")


def test_chunk_document_empty_input_returns_empty_list() -> None:
    assert KnowledgeIngestor().chunk_document("", max_chars=1024) == []
    assert KnowledgeIngestor().chunk_document("   ", max_chars=1024) == []


def test_chunk_document_content_before_first_heading_is_own_chunk() -> None:
    text = (
        "lead paragraph with no heading\n"
        "\n"
        "# First heading\n"
        "body under heading\n"
    )
    chunks = KnowledgeIngestor().chunk_document(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 2
    assert chunks[0].startswith("lead paragraph")
    assert chunks[1].startswith("# First heading")


def test_chunk_document_hard_splits_oversize_section() -> None:
    heading = "# Overview\n"
    body = "y" * 4096
    text = f"{heading}{body}\n"
    chunks = KnowledgeIngestor().chunk_document(text, max_chars=1024)
    assert len(chunks) >= 4
    assert max(len(c) for c in chunks) <= 1024


def test_chunk_document_no_heading_returns_single_chunk() -> None:
    text = "plain paragraph with no markdown heading rows here."
    chunks = KnowledgeIngestor().chunk_document(text, max_chars=DEFAULT_MAX_CHARS)
    assert chunks == [text]


def test_chunk_dispatch_selects_code_or_document() -> None:
    ing = KnowledgeIngestor()
    code_text = (
        "def a():\n"
        "    pass\n"
        "def b():\n"
        "    pass\n"
    )
    doc_text = (
        "# h1\n"
        "body\n"
        "## h2\n"
        "body2\n"
    )
    assert len(ing.chunk(code_text, kind="code")) == 2
    assert len(ing.chunk(doc_text, kind="document")) == 2


def test_chunk_dispatch_forwards_max_chars() -> None:
    ing = KnowledgeIngestor()
    text = "def big():\n" + ("x" * 3000) + "\n"
    chunks = ing.chunk(text, kind="code", max_chars=512)
    assert len(chunks) >= 5
    assert max(len(c) for c in chunks) <= 512


def test_chunk_dispatch_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown kind"):
        KnowledgeIngestor().chunk("x", kind="html")  # type: ignore[arg-type]


def test_chunk_code_rejects_nonpositive_max_chars() -> None:
    with pytest.raises(ValueError, match="max_chars must be positive"):
        KnowledgeIngestor().chunk_code("def a():\n    pass", max_chars=0)
    with pytest.raises(ValueError, match="max_chars must be positive"):
        KnowledgeIngestor().chunk_code("def a():\n    pass", max_chars=-10)


def test_chunk_document_rejects_nonpositive_max_chars() -> None:
    with pytest.raises(ValueError, match="max_chars must be positive"):
        KnowledgeIngestor().chunk_document("# H\nbody", max_chars=0)


async def test_store_chunked_path_writes_one_row_per_chunk(test_db) -> None:
    """chunked=True stores each ingestor chunk as its own KnowledgeEntry row.

    Uses a stubbed embedding provider so the test does not depend on any
    real embedding model download or GPU. The chunked ingestion path is
    the operator-facing wiring for the RFC-12 chunker; a single end-to-end
    round-trip against the real KnowledgeEntryRecord table proves the
    wire-up delivers boundary-aligned rows with per-chunk dedup keys.
    """
    stub_provider = type(
        "StubProvider",
        (),
        {
            "encode": staticmethod(lambda _text: [0.1] * 1024),
            "dimension": 1024,
            # RFC-12 provenance stamping reads provider.model_name on every
            # store; the stub must satisfy the full EmbeddingProvider Protocol.
            "model_name": "stub/rfc12",
        },
    )()
    with patch(
        "aila.platform.services.knowledge.resolve_provider",
        return_value=stub_provider,
    ):
        service = KnowledgeService()

    long_code = (
        "def alpha():\n    return 1\n\n"
        "def beta():\n    return 2\n\n"
        "def gamma():\n    return 3\n"
    )
    namespace = make_platform_namespace("ingestor_test")
    dedup_key = "rfc12-store-chunked-smoke"

    result = await service.store(
        namespace=namespace,
        content=long_code,
        metadata={"origin": "ingestor_test"},
        dedup_key=dedup_key,
        chunked=True,
        kind="code",
        chunk_max_chars=DEFAULT_MAX_CHARS,
    )

    assert result["operation"] == "chunked"
    assert result["chunk_count"] == 3
    chunk_results = result["chunks"]
    assert len(chunk_results) == 3
    seen_entry_ids = {r["entry_id"] for r in chunk_results}
    assert len(seen_entry_ids) == 3, "each chunk gets its own row id"
    for r in chunk_results:
        assert r["operation"] == "inserted"
        assert r["namespace"] == namespace

    # Second call with the same dedup_key updates each chunk in place.
    result2 = await service.store(
        namespace=namespace,
        content=long_code,
        metadata={"origin": "ingestor_test"},
        dedup_key=dedup_key,
        chunked=True,
        kind="code",
        chunk_max_chars=DEFAULT_MAX_CHARS,
    )
    assert result2["chunk_count"] == 3
    for r in result2["chunks"]:
        assert r["operation"] == "updated"


async def test_store_chunked_empty_input_is_noop(test_db) -> None:
    """chunked=True with empty content returns a noop and writes no rows."""
    stub_provider = type(
        "StubProvider",
        (),
        {
            "encode": staticmethod(lambda _text: [0.1] * 1024),
            "dimension": 1024,
            # RFC-12 provenance stamping reads provider.model_name on every
            # store; the stub must satisfy the full EmbeddingProvider Protocol.
            "model_name": "stub/rfc12",
        },
    )()
    with patch(
        "aila.platform.services.knowledge.resolve_provider",
        return_value=stub_provider,
    ):
        service = KnowledgeService()

    result = await service.store(
        namespace=make_platform_namespace("ingestor_test"),
        content="   \n\t  \n",
        dedup_key="rfc12-empty-smoke",
        chunked=True,
        kind="document",
    )
    assert result["operation"] == "noop"
    assert result["chunk_count"] == 0
    assert result["chunks"] == []


def test_chunk_code_preserves_all_content_across_chunks() -> None:
    text = (
        "class One:\n"
        "    field_one = 1\n"
        "\n"
        "class Two:\n"
        "    field_two = 2\n"
        "\n"
        "def helper():\n"
        "    return field_two + field_one\n"
    )
    chunks = KnowledgeIngestor().chunk_code(text, max_chars=DEFAULT_MAX_CHARS)
    assert len(chunks) == 3
    joined_lines = "\n".join(chunks)
    for token in ("field_one", "field_two", "class One", "class Two", "def helper"):
        assert token in joined_lines
