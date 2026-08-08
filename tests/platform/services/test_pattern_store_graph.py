"""RFC-14 tests for pattern-store PPR graph retrieval.

Applies to the platform pattern-store wiring only: ``applicable()`` now
routes through :meth:`KnowledgeService.retrieve_routed` with
``route=Route.GRAPH`` so a linked workspace surfaces edge-connected
patterns that a flat retrieve would miss, and a sparse workspace still
returns the seed-ranked pool (PPR with no edges degenerates to seed
ranking).

The three observable behaviours the RFC promises:

  (a) A seed-matching pattern PLUS a graph-connected pattern both
      reach the caller, tagged ``matched_by="both"`` and
      ``matched_by="graph"`` respectively.

  (b) The stage-1 structured gate (scope chain, ACTIVE status,
      trust-tier partition) still strips DRAFT / NEGATIVE-tier /
      out-of-scope patterns even when the routed layer forwards them
      as edge-reachable.

  (c) A workspace with no edges yields sensible results without
      crashing: PPR degenerates to the hybrid seed ranking, so a
      routed reply containing only hop-0 rows produces the same
      surface the pre-RFC-14 flat path would have produced.

The retrieve_routed dependency is stubbed with :class:`AsyncMock` so
these assertions target the pattern-store wiring in isolation. The
end-to-end graph + PPR stack is covered by the KnowledgeGraphPPR /
KnowledgeService wiring tests.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

from aila.modules.vr.db_models import (
    VRPatternRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.contracts.enums import (
    PatternConfidence,
    PatternScope,
    PatternStatus,
    PatternTrustTier,
)
from aila.platform.uow import UnitOfWork


async def _seed_workspace(workspace_id: str, slug_hint: str) -> None:
    """Insert a VR workspace row so pattern FKs resolve."""
    async with UnitOfWork() as uow:
        uow.session.add(
            VRWorkspaceRecord(
                id=workspace_id,
                name=f"graph test {slug_hint}",
                slug=f"graph-test-{slug_hint}-{workspace_id[:8]}",
                description="",
                theme="custom",
                status="active",
            ),
        )
        await uow.commit()


async def _add_pattern(  # noqa: PLR0913 -- test factory; every arg maps to one column.
    *,
    pattern_id: str,
    workspace_id: str,
    status: PatternStatus = PatternStatus.ACTIVE,
    scope: PatternScope = PatternScope.WORKSPACE,
    tier: PatternTrustTier = PatternTrustTier.UNREVIEWED,
    kind: str = "exploitation_technique",
) -> None:
    """Insert one pattern row with the requested status/scope/tier."""
    async with UnitOfWork() as uow:
        uow.session.add(
            VRPatternRecord(
                id=pattern_id,
                workspace_id=workspace_id,
                investigation_id=None,
                kind=kind,
                summary=f"Test pattern {pattern_id[:8]}",
                body="Sample body",
                applicability_json="{}",
                confidence=PatternConfidence.MEDIUM.value,
                evidence_refs_json="[]",
                status=status.value,
                scope=scope.value,
                trust_tier=tier.value,
                knowledge_entry_id=None,
            ),
        )
        await uow.commit()


def _hit(pattern_id: str, score: float, *, hop: int = 0) -> dict[str, Any]:
    """Fake routed hit; ``hop`` drives the RFC-14 ``matched_by`` branch."""
    return {
        "id": 0,
        "content": "irrelevant",
        "metadata": {"pattern_id": pattern_id},
        "score": score,
        "vec_score": 0.0,
        "fts_score": 0.0,
        "source": "graph",
        "namespace": "vr.pattern.workspace.dummy",
        "hop": hop,
        "path": [],
        "incoming_relation": "related" if hop > 0 else None,
        "incoming_weight": 0.7 if hop > 0 else None,
    }


def _routed(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap hits in the ``retrieve_routed`` envelope."""
    return {
        "status": "retrieved",
        "route": "graph",
        "query": "anything",
        "count": len(hits),
        "results": hits,
        "hop_bound": 2,
    }


async def test_applicable_returns_seed_plus_graph_reached_pattern(
    test_db,
) -> None:
    """A graph-connected pattern reaches the caller alongside the seed match.

    The flat pre-RFC-14 retrieve would have returned only the seed hit
    because a naive hybrid can only match one row per hop. The routed
    graph reply carries both -- seed at hop 0 (``matched_by="both"``)
    plus its neighbour at hop 1 (``matched_by="graph"``).
    """
    workspace_id = str(uuid4())
    await _seed_workspace(workspace_id, "connected")
    seed_id = str(uuid4())
    neighbour_id = str(uuid4())
    await _add_pattern(pattern_id=seed_id, workspace_id=workspace_id)
    await _add_pattern(pattern_id=neighbour_id, workspace_id=workspace_id)

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([
            _hit(seed_id, 0.80, hop=0),
            _hit(neighbour_id, 0.35, hop=1),
        ]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="anything",
    )

    by_id = {r.pattern.id: r for r in results}
    assert seed_id in by_id, "seed-matching pattern must be returned"
    assert neighbour_id in by_id, (
        "graph-connected pattern must be returned -- this is the RFC-14 win "
        "over the flat retrieve path"
    )
    assert by_id[seed_id].matched_by == "both", (
        "hop-0 hit is a semantic seed match tagged 'both' (structured + semantic)"
    )
    assert by_id[neighbour_id].matched_by == "graph", (
        "hop>0 hit is edge-reached and must be tagged 'graph'"
    )


async def test_applicable_stage1_gate_excludes_edge_reachable_but_ineligible(
    test_db,
) -> None:
    """Stage-1 structured filter stays authoritative even for edge-reachable rows.

    Every ineligible pattern class (DRAFT status, NEGATIVE trust tier,
    wrong workspace scope) is stripped by the pre-retrieval structured
    filter regardless of how convincingly the routed layer would surface
    it. This is the RFC-08 poisoning guarantee restated for the RFC-14
    graph route: reachability does not equal eligibility.
    """
    ws_ok = str(uuid4())
    ws_other = str(uuid4())
    await _seed_workspace(ws_ok, "ok")
    await _seed_workspace(ws_other, "other")

    ok_id = str(uuid4())
    draft_id = str(uuid4())
    negative_id = str(uuid4())
    other_ws_id = str(uuid4())

    await _add_pattern(pattern_id=ok_id, workspace_id=ws_ok)
    await _add_pattern(
        pattern_id=draft_id,
        workspace_id=ws_ok,
        status=PatternStatus.DRAFT,
    )
    await _add_pattern(
        pattern_id=negative_id,
        workspace_id=ws_ok,
        tier=PatternTrustTier.NEGATIVE,
    )
    await _add_pattern(pattern_id=other_ws_id, workspace_id=ws_other)

    knowledge = AsyncMock()
    # Routed layer "reaches" every id, including the ones stage 1 should
    # reject. This forces the assertion to hit the structured gate, not
    # the retrieval ranking.
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([
            _hit(ok_id, 0.80, hop=0),
            _hit(draft_id, 0.75, hop=1),
            _hit(negative_id, 0.70, hop=1),
            _hit(other_ws_id, 0.65, hop=1),
        ]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=ws_ok,
        team_id=None,
        query="anything",
    )

    returned = {r.pattern.id for r in results}
    assert returned == {ok_id}, (
        f"stage-1 gate MUST strip DRAFT + NEGATIVE + out-of-scope patterns "
        f"even when edge-reachable; got {returned}"
    )


async def test_applicable_sparse_workspace_no_edges_returns_seed_ranking(
    test_db,
) -> None:
    """A workspace with no edges yields the seed-ranked pool without crashing.

    PPR with an empty edge set degenerates to the personalization
    vector (seed weights normalized), so retrieve_routed returns the
    seed rows unchanged. The pattern store must accept that reply and
    surface the seed pattern; hop-0 hits keep the pre-RFC-14
    ``matched_by="both"`` label so a caller inspecting the mode sees
    the sparse-workspace shape it expects.
    """
    workspace_id = str(uuid4())
    await _seed_workspace(workspace_id, "sparse")
    pattern_id = str(uuid4())
    await _add_pattern(pattern_id=pattern_id, workspace_id=workspace_id)

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([_hit(pattern_id, 0.55, hop=0)]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="anything",
    )

    assert len(results) == 1, (
        "sparse workspace with one active pattern must return exactly one "
        "result -- PPR degenerating to seed ranking must not crash or drop it"
    )
    assert results[0].pattern.id == pattern_id
    assert results[0].matched_by == "both", (
        "hop-0 seed hit keeps the semantic+structured label in the sparse case"
    )
