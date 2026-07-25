"""vr.investigate.v2 phase graph: structure + kind router + tool regimes.

The router reads the investigation kind via the real Postgres test db.
The per-phase tool allowlist is asserted on the declared graph spec.
"""
from __future__ import annotations

from uuid import uuid4

import pytest_asyncio

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.workflow.definitions_v2 import (
    _GRAPH,
    VR_INVESTIGATE_V2,
    _classify_kind,
)
from aila.platform.workflows.phase_graph import EMIT_STATE, SETUP_STATE
from aila.storage.database import async_session_scope


@pytest_asyncio.fixture(autouse=True)
async def _bind_db(test_db):
    """Point the engine cache at aila_test (fresh schema) for every test."""
    yield


async def _seed(kind: str) -> str:
    """Seed workspace + target + investigation; return the investigation id."""
    suffix = uuid4().hex[:8]
    team = f"team-{suffix}"
    async with async_session_scope() as session:  # no team_context => unfiltered
        ws = VRWorkspaceRecord(
            name=f"w-{suffix}", slug=f"w-{suffix}", description="",
            theme="custom", team_id=team,
        )
        session.add(ws)
        await session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id=team, display_name="t",
            kind="native_binary",
        )
        session.add(tgt)
        await session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id=team, title="inv", kind=kind,
            strategy_family="vulnerability_research.discovery_research",
        )
        session.add(inv)
        await session.commit()
        return inv.id


async def test_v2_graph_structure() -> None:
    d = VR_INVESTIGATE_V2
    assert d.definition_id == "vr.investigate.v2"
    assert d.start_state == SETUP_STATE
    assert {
        "recon",
        "recon__route",
        "source_audit",
        "variant_hunt",
        "binary_audit",
        "mobile_audit",
        EMIT_STATE,
    } <= set(d.states)


async def test_router_discovery_to_source_audit() -> None:
    inv_id = await _seed("discovery")
    assert await _classify_kind({"investigation_id": inv_id}) == "source_audit"


async def test_router_audit_to_source_audit() -> None:
    inv_id = await _seed("audit")
    assert await _classify_kind({"investigation_id": inv_id}) == "source_audit"


async def test_router_variant_hunt() -> None:
    inv_id = await _seed("variant_hunt")
    assert await _classify_kind({"investigation_id": inv_id}) == "variant_hunt"


async def test_router_nday_to_binary_audit() -> None:
    inv_id = await _seed("n_day")
    assert await _classify_kind({"investigation_id": inv_id}) == "binary_audit"


async def test_router_masvs_to_mobile_audit() -> None:
    inv_id = await _seed("masvs_audit")
    assert await _classify_kind({"investigation_id": inv_id}) == "mobile_audit"


async def test_router_triage_routes_to_emit() -> None:
    inv_id = await _seed("triage")
    assert await _classify_kind({"investigation_id": inv_id}) == EMIT_STATE


async def test_router_missing_id_defaults_source_audit() -> None:
    assert await _classify_kind({}) == "source_audit"


def _phase(name: str):
    return next(p for p in _GRAPH.phases if p.name == name)


async def test_phase_tool_regimes() -> None:
    assert _phase("source_audit").allowed_servers == ("audit_mcp",)
    assert _phase("binary_audit").allowed_servers == ("ida_headless",)
    assert _phase("mobile_audit").allowed_servers == ("android_mcp", "audit_mcp")
    assert _phase("variant_hunt").allowed_servers == ("audit_mcp", "ida_headless")
    assert _phase("recon").allowed_servers == ("audit_mcp", "ida_headless")
