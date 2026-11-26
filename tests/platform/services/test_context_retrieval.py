"""Deterministic regression tests for the platform RETRIEVED-tier producer."""

from __future__ import annotations

from typing import Any

import pytest

from aila.platform.services import context_retrieval
from aila.platform.services.context_assembler import RetrievalRequest, estimate_tokens
from aila.platform.services.context_retrieval import (
    KnowledgeRetrievalProvider,
    _truncate_hits_to_budget,
    format_retrieved_body,
)


def _hit(entry_id: int, sanitized_content: str) -> dict[str, Any]:
    return {
        "id": entry_id,
        "namespace": "vr.observation.workspace.workspace-1",
        "score": 0.9,
        "content": f"raw-content-{entry_id}",
        "sanitized_content": sanitized_content,
    }


def _request() -> RetrievalRequest:
    return RetrievalRequest(
        query="memory corruption in parser",
        namespaces=("vr.observation.workspace.workspace-1",),
        max_tokens=1000,
    )


def test_format_retrieved_body_uses_sanitized_content() -> None:
    hits = [
        {
            **_hit(41, "sanitized src/parser.c:42"),
            "content": "RAW-INJECTION-MUST-NOT-RENDER",
        },
        {
            **_hit(42, ""),
            "content": "EMPTY-SANITIZED-RAW-MUST-NOT-RENDER",
        },
        {
            **_hit(43, "   "),
            "content": "WHITESPACE-SANITIZED-RAW-MUST-NOT-RENDER",
        },
        {"id": 44, "namespace": "shared", "score": 0.2, "content": "UNgated-RAW"},
    ]

    body = format_retrieved_body(hits)

    assert "sanitized src/parser.c:42" in body
    assert "entry_id=41" in body
    assert "RAW-INJECTION-MUST-NOT-RENDER" not in body
    assert "EMPTY-SANITIZED-RAW-MUST-NOT-RENDER" not in body
    assert "WHITESPACE-SANITIZED-RAW-MUST-NOT-RENDER" not in body
    assert "UNgated-RAW" not in body
    assert body.count("- [") == 1


def test_format_retrieved_body_preserves_sanitized_content_verbatim() -> None:
    sanitized = "  leading and trailing space\npath/to/file.c:17  "

    body = format_retrieved_body([_hit(51, sanitized)])

    assert body.endswith(f"entry_id=51 :: {sanitized}")
    assert "raw-content-51" not in body


def test_truncate_hits_to_budget_skips_oversized_hit_and_keeps_later_fit() -> None:
    oversized = _hit(61, "X" * 4096)
    fitting = _hit(62, "small.txt:9 sanitized")
    budget = estimate_tokens(format_retrieved_body([fitting]))

    accepted = _truncate_hits_to_budget(
        [oversized, fitting], max_tokens=budget,
    )

    assert accepted == [fitting]
    assert "small.txt:9 sanitized" in format_retrieved_body(accepted)
    assert "X" * 32 not in format_retrieved_body(accepted)


def test_truncate_hits_to_budget_omits_lone_oversized_hit() -> None:
    oversized = _hit(63, "X" * 4096)

    assert _truncate_hits_to_budget([oversized], max_tokens=8) == []


def test_truncate_hits_to_budget_nonpositive_budget_is_unlimited() -> None:
    hits = [_hit(64, "first"), _hit(65, "second")]

    assert _truncate_hits_to_budget(hits, max_tokens=0) == hits
    assert _truncate_hits_to_budget(hits, max_tokens=-1) == hits


def test_format_retrieved_body_includes_entry_id_and_allowlisted_source_refs() -> None:
    hit = {
        **_hit(71, "sanitized observation"),
        "metadata": {
            "observation_id": "obs-1",
            "trace_id": "trace-1",
            "action_id": "action-1",
            "asset_id": "asset-1",
            "raw_artifact_id": "artifact-1",
            "raw_sha256": "a" * 64,
            "source": {"action_id": "source-action-1"},
            "evidence_refs": [
                {"observation_id": "obs-ref-1"},
                {"trace_id": "trace-ref-1", "private": "REF-SECRET"},
                "raw-string-ref-must-not-render",
            ],
            "secret": "METADATA-SECRET-MUST-NOT-RENDER",
            "workspace_id": "private-workspace-id",
        },
        "provenance": {"asset_id": "provenance-asset-1", "model_id": "private-model"},
    }

    body = format_retrieved_body([hit])

    assert "entry_id=71" in body
    for expected in (
        "observation_id=obs-1",
        "trace_id=trace-1",
        "action_id=action-1",
        "asset_id=asset-1",
        "raw_artifact_id=artifact-1",
        f"raw_sha256={'a' * 64}",
        "action_id=source-action-1",
        "observation_id=obs-ref-1",
        "trace_id=trace-ref-1",
        "asset_id=provenance-asset-1",
    ):
        assert expected in body
    assert "METADATA-SECRET-MUST-NOT-RENDER" not in body
    assert "REF-SECRET" not in body
    assert "raw-string-ref-must-not-render" not in body
    assert "private-workspace-id" not in body
    assert "private-model" not in body


def test_format_retrieved_body_escapes_and_bounds_inline_metadata() -> None:
    hit = {
        **_hit(72, "safe sanitized body"),
        "namespace": "namespace\n[forged-heading]",
        "metadata": {
            "observation_id": "obs\x00\nentry_id=forged",
            "evidence_refs": [
                {"trace_id": f"trace-{index}-" + "x" * 5000}
                for index in range(20)
            ],
        },
    }

    body = format_retrieved_body([hit])
    bullet = body.splitlines()[1]
    prefix = bullet.split(" :: ", 1)[0]

    assert len(body.splitlines()) == 2
    assert "namespace\\n[forged-heading]" in prefix
    assert "obs\\x00\\nentry_id=forged" in prefix
    assert "entry_id=72" in prefix
    assert len(prefix) <= 1026  # ``- `` plus the formatter's 1024-char cap.


class _ImportFailingService:
    async def retrieve_routed(self, **kwargs: object) -> dict[str, object]:
        del kwargs
        raise ImportError("sentence_transformers is unavailable")


async def test_fetch_returns_empty_when_embedding_dependency_is_missing() -> None:
    provider = KnowledgeRetrievalProvider(
        knowledge_service=_ImportFailingService(),  # type: ignore[arg-type]
    )

    assert await provider.fetch(_request()) == []


async def test_fetch_contains_service_construction_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_construction() -> object:
        raise ImportError("sentence_transformers is unavailable")

    monkeypatch.setattr(context_retrieval, "KnowledgeService", fail_construction)
    provider = KnowledgeRetrievalProvider()

    assert await provider.fetch(_request()) == []
