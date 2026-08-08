"""RFC-12 tests for the pattern-store relevance floor (RFC-14 wiring).

Covers the observable behaviours of the floor wiring after RFC-14
routed pattern retrieval through the PPR graph path:

  1. ``_resolve_relevance_floor`` returns the module constant when the
     ConfigRegistry lookup yields None, and returns the env-override
     value when set. Pure; no DB required.

  2. ``applicable()`` passes the resolved floor as ``min_score`` to
     :meth:`KnowledgeService.retrieve_routed` so the SEED-time hybrid
     stage inside the graph route still honours the operator floor.
     Requires ``test_db`` to seed one active VR pattern for stage 1.

RFC-14 removed the second-layer floor re-check inside the pattern
service (PPR scores are stationary mass, not the 0.6vec+0.4fts figure
the floor was calibrated on). The floor is still enforced at the
knowledge layer for seed selection; the pattern layer no longer drops
returned hits by that floor. That inversion is asserted here directly.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from aila.modules.vr.db_models import (
    VRPatternRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.contracts.enums import (
    PatternConfidence,
    PatternScope,
    PatternStatus,
)
from aila.platform.services import pattern_store as ps_mod
from aila.platform.services.pattern_store import (
    PATTERN_RELEVANCE_FLOOR_DEFAULT,
    PatternStoreBase,
)
from aila.platform.uow import UnitOfWork


async def test_resolve_relevance_floor_defaults_to_module_constant(monkeypatch) -> None:
    """When ConfigRegistry.get returns None the helper falls back to the constant."""
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )
    fake_registry = type(
        "FakeRegistry",
        (),
        {"get": AsyncMock(return_value=None)},
    )
    with patch.object(ps_mod, "ConfigRegistry", fake_registry):
        floor = await PatternStoreBase._resolve_relevance_floor()
    assert floor == PATTERN_RELEVANCE_FLOOR_DEFAULT
    assert floor > 0.0, "the module default must be non-zero -- a zero floor is off"


async def test_resolve_relevance_floor_reads_config_registry_value(monkeypatch) -> None:
    """A stored/env-provided value flows through the ConfigRegistry lookup."""
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )
    fake_registry = type(
        "FakeRegistry",
        (),
        {"get": AsyncMock(return_value=0.55)},
    )
    with patch.object(ps_mod, "ConfigRegistry", fake_registry):
        floor = await PatternStoreBase._resolve_relevance_floor()
    assert floor == pytest.approx(0.55)


async def test_resolve_relevance_floor_env_override(monkeypatch) -> None:
    """The env var route (real ConfigRegistry) yields the parsed float."""
    monkeypatch.setenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        "0.42",
    )
    floor = await PatternStoreBase._resolve_relevance_floor()
    assert floor == pytest.approx(0.42)


async def test_resolve_relevance_floor_bad_value_falls_back(monkeypatch) -> None:
    """A non-numeric stored value cannot silently disable the floor."""
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )
    fake_registry = type(
        "FakeRegistry",
        (),
        {"get": AsyncMock(return_value="not-a-number")},
    )
    with patch.object(ps_mod, "ConfigRegistry", fake_registry):
        floor = await PatternStoreBase._resolve_relevance_floor()
    assert floor == PATTERN_RELEVANCE_FLOOR_DEFAULT


async def _seed_workspace_and_patterns(
    workspace_id: str,
    pattern_ids: list[str],
) -> None:
    """Insert one VR workspace + one active workspace-scoped pattern per id.

    Workspace + patterns commit in separate transactions so the FK from
    vr_patterns.workspace_id to vr_workspaces.id is satisfied at insert
    time regardless of the ORM flush order for two unrelated mappers.
    """
    async with UnitOfWork() as uow:
        uow.session.add(
            VRWorkspaceRecord(
                id=workspace_id,
                name="floor test",
                slug=f"floor-test-{workspace_id[:8]}",
                description="",
                theme="custom",
                status="active",
            ),
        )
        await uow.commit()

    async with UnitOfWork() as uow:
        for pid in pattern_ids:
            uow.session.add(
                VRPatternRecord(
                    id=pid,
                    workspace_id=workspace_id,
                    investigation_id=None,
                    kind="exploitation_technique",
                    summary=f"Test pattern {pid[:8]}",
                    body="Sample body",
                    applicability_json="{}",
                    confidence=PatternConfidence.MEDIUM.value,
                    evidence_refs_json="[]",
                    status=PatternStatus.ACTIVE.value,
                    scope=PatternScope.WORKSPACE.value,
                    knowledge_entry_id=None,
                ),
            )
        await uow.commit()


def _fake_routed_hit(
    pattern_id: str,
    score: float,
    *,
    hop: int = 0,
) -> dict[str, Any]:
    """Shape a fake ``retrieve_routed`` result row.

    Mirrors the fields ``PatternStoreBase.applicable`` reads: ``score``
    for ranking, ``metadata.pattern_id`` for the join back to the
    structured pool, and ``hop`` for the RFC-14 ``matched_by`` branch
    (graph-reached vs. seed-matched).
    """
    return {
        "id": 0,
        "content": "irrelevant",
        "metadata": {"pattern_id": pattern_id},
        "score": score,
        "vec_score": score,
        "fts_score": 0.0,
        "source": "graph",
        "namespace": "vr.pattern.workspace.dummy",
        "hop": hop,
        "path": [],
        "incoming_relation": None,
        "incoming_weight": None,
    }


def _routed(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap hits in the ``retrieve_routed`` return envelope."""
    return {
        "status": "retrieved",
        "route": "graph",
        "query": "anything",
        "count": len(hits),
        "results": hits,
        "hop_bound": 2,
    }


async def test_applicable_passes_resolved_floor_to_retrieve_routed(
    test_db, monkeypatch,
) -> None:
    """The ``min_score`` kwarg passed to retrieve_routed matches the resolved floor."""
    monkeypatch.setenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        "0.5",
    )
    workspace_id = str(uuid4())
    pattern_id = str(uuid4())
    await _seed_workspace_and_patterns(workspace_id, [pattern_id])

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([_fake_routed_hit(pattern_id, 0.9)]),
    )
    store = PatternStore(knowledge)

    await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="anything",
    )

    knowledge.retrieve_routed.assert_awaited_once()
    call = knowledge.retrieve_routed.await_args
    assert call.kwargs["min_score"] == pytest.approx(0.5)
    assert call.kwargs["namespaces"][0] == f"vr.pattern.workspace.{workspace_id}"
    assert call.kwargs["namespaces"][-1] == "vr.pattern.global"
    # RFC-14: the graph route is the day-1 mechanism, always.
    assert str(call.kwargs["route"]) == "graph" or getattr(
        call.kwargs["route"], "value", None,
    ) == "graph"


async def test_applicable_does_not_reapply_floor_to_graph_hits(
    test_db, monkeypatch,
) -> None:
    """RFC-14: PPR-scored graph hits are not dropped by the cosine floor.

    The floor still gates the seed hybrid stage INSIDE retrieve_routed
    (min_score kwarg above), but a hit that made it through the routed
    envelope carries a stationary PPR score, not a hybrid cosine score,
    and MUST NOT be re-dropped by the same cosine-calibrated floor.
    """
    monkeypatch.setenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        "0.5",
    )
    workspace_id = str(uuid4())
    high_id = str(uuid4())
    low_id = str(uuid4())
    await _seed_workspace_and_patterns(workspace_id, [high_id, low_id])

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([
            _fake_routed_hit(high_id, 0.85, hop=0),
            _fake_routed_hit(low_id, 0.20, hop=1),
        ]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="anything",
    )

    ids = {r.pattern.id for r in results}
    assert high_id in ids, "seed-matched pattern must reach the researcher prompt"
    assert low_id in ids, (
        "graph-reached pattern with a low PPR mass MUST NOT be dropped by "
        "the cosine-calibrated relevance floor (RFC-14)"
    )


async def test_applicable_default_floor_when_env_unset(
    test_db, monkeypatch,
) -> None:
    """With no env override the passed floor equals the module default."""
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )
    workspace_id = str(uuid4())
    pattern_id = str(uuid4())
    await _seed_workspace_and_patterns(workspace_id, [pattern_id])

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([_fake_routed_hit(pattern_id, 0.9)]),
    )
    store = PatternStore(knowledge)

    await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="anything",
    )

    knowledge.retrieve_routed.assert_awaited_once()
    passed = knowledge.retrieve_routed.await_args.kwargs["min_score"]
    # The passed floor must resolve to the module default when no override
    # is present; both come from PATTERN_RELEVANCE_FLOOR_DEFAULT so a
    # future schema-field addition keeps this invariant.
    assert passed == pytest.approx(PATTERN_RELEVANCE_FLOOR_DEFAULT)
    assert passed > 0.0
