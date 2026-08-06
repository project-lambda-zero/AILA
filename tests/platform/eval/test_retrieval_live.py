"""RFC-12 Phase 6: the live retrieve_routed -> RetrieveFn adapter.

Locks the two things the adapter owns: it scopes the routed call to the given
namespace patterns, and it returns the entry ids in rank order (dropping hits
with no id) as the strings the eval runner scores.
"""
from __future__ import annotations

import aila.platform.eval.retrieval_live as rl


async def test_make_retrieve_fn_returns_ranked_ids(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class _FakeKnowledge:
        async def retrieve_routed(self, **kwargs):
            seen.update(kwargs)
            return {
                "results": [
                    {"id": 5, "score": 0.9},
                    {"id": 7, "score": 0.6},
                    {"id": None, "score": 0.5},   # dropped: no id
                    {"score": 0.4},                # dropped: no id key
                ],
            }

    monkeypatch.setattr(rl, "KnowledgeService", _FakeKnowledge)
    fn = rl.make_retrieve_fn(
        namespace_patterns=["vr.finding.workspace.*"], min_score=0.3,
    )
    ids = await fn("some query", 5)

    assert ids == ["5", "7"]  # rank order preserved, id-less hits filtered
    assert seen["namespace_patterns"] == ["vr.finding.workspace.*"]
    assert seen["limit"] == 5
    assert seen["min_score"] == 0.3
    assert seen["route"] == "simple"


async def test_make_retrieve_fn_empty_results(monkeypatch) -> None:
    class _FakeKnowledge:
        async def retrieve_routed(self, **kwargs):
            return {"results": []}

    monkeypatch.setattr(rl, "KnowledgeService", _FakeKnowledge)
    fn = rl.make_retrieve_fn(namespace_patterns=["vr.finding.workspace.*"])
    assert await fn("q", 3) == []
