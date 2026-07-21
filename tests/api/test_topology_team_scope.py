"""#36 -- topology queries are team-scoped.

ManagedSystemRecord is team-scoped, but GET /topology and GET /topology/subnets
ran select(ManagedSystemRecord) with no team predicate, so any authenticated
operator+ could read every team's network graph -- system names, hosts,
distros, subnet groupings, and derived port / service / connection detail.
Both endpoints now filter by the caller's team; a god-tier admin (team_id=None,
TEAM-06) still sees all.

The child records (SystemPortRecord, SystemServiceRecord, SystemConnectionRecord,
SystemMetadataRecord) are not team-scoped. They are only reachable through
the already-filtered system_ids set, so a team-a caller cannot see a
team-b system's ports or edges either.

Handlers are invoked directly with an explicit AuthContext (the router-level
require_user_or_api_key + _require_operator dependencies are not resolved on
direct invocation). The request stub carries a bare platform=None so the
severity + group-tag overlays short-circuit without hitting the vulnerability
module.
"""
from __future__ import annotations

import types
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aila.api.auth import AuthContext
from aila.api.routers.topology import router as topology_router
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    ManagedSystemRecord,
    SystemConnectionRecord,
    SystemPortRecord,
    SystemServiceRecord,
)


def _req() -> object:
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


def _endpoint(router: object, path: str, method: str):
    for route in router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str | None) -> AuthContext:
    return AuthContext(
        user_id="u-" + (team_id or "god"),
        role="admin" if team_id is None else "operator",
        auth_type="user",
        team_id=team_id,
    )


async def _seed_two_teams() -> tuple[str, str, int, int, int]:
    """Seed team-a with two systems (two subnets) and team-b with one system.

    The team-a systems get a port, a service, and an inter-system TCP edge so
    the response exercises the ports_by_system / services_by_system /
    edge_rows branches, not just the empty envelope path.
    """
    suffix = uuid4().hex[:8]
    team_a = f"team-a-{suffix}"
    team_b = f"team-b-{suffix}"
    now = datetime.now(UTC)
    async with async_session_scope() as session:  # no team_context => unfiltered insert
        a1 = ManagedSystemRecord(
            team_id=team_a, name=f"a1-{suffix}", host="10.20.1.1", username="u"
        )
        a2 = ManagedSystemRecord(
            team_id=team_a, name=f"a2-{suffix}", host="10.20.2.1", username="u"
        )
        b1 = ManagedSystemRecord(
            team_id=team_b, name=f"b1-{suffix}", host="10.20.3.1", username="u"
        )
        session.add(a1)
        session.add(a2)
        session.add(b1)
        await session.commit()
        await session.refresh(a1)
        await session.refresh(a2)
        await session.refresh(b1)
        session.add(
            SystemPortRecord(
                system_id=a1.id,
                port=22,
                protocol="tcp",
                local_address="0.0.0.0",
                process_name="sshd",
                last_collected=now,
                is_stale=False,
            )
        )
        session.add(
            SystemServiceRecord(
                system_id=a1.id,
                service_name="sshd",
                state="active",
                sub_state="running",
                last_collected=now,
                is_stale=False,
            )
        )
        session.add(
            SystemConnectionRecord(
                source_system_id=a1.id,
                dest_system_id=a2.id,
                dest_port=22,
                protocol="tcp",
                state="ESTAB",
                last_collected=now,
                is_stale=False,
            )
        )
        # Cross-team port + edge on the team-b system. A team-a caller must
        # NOT see these; a god-tier admin must.
        session.add(
            SystemPortRecord(
                system_id=b1.id,
                port=443,
                protocol="tcp",
                local_address="0.0.0.0",
                process_name="nginx",
                last_collected=now,
                is_stale=False,
            )
        )
        await session.commit()
        return team_a, team_b, a1.id, a2.id, b1.id


async def _get_topology(auth: AuthContext):
    ep = _endpoint(topology_router, "/topology", "GET")
    return await ep(request=_req(), auth=auth)


async def _get_subnets(auth: AuthContext):
    ep = _endpoint(topology_router, "/topology/subnets", "GET")
    return await ep(request=_req(), auth=auth)


@pytest.mark.usefixtures("test_db")
async def test_get_topology_team_scoped() -> None:
    team_a, _tb, a1_id, a2_id, b1_id = await _seed_two_teams()

    env = await _get_topology(_auth(team_a))
    node_ids = {n.id for n in env.data.nodes}
    assert node_ids == {a1_id, a2_id}
    # Subnet groupings must also drop the team-b /24.
    subnet_prefixes = {g.subnet_prefix for g in env.data.subnets}
    assert "10.20.1" in subnet_prefixes
    assert "10.20.2" in subnet_prefixes
    assert "10.20.3" not in subnet_prefixes
    # Edge from a1 to a2 survives; no edges reference b1.
    edge_pairs = {(e.source_system_id, e.dest_system_id) for e in env.data.edges}
    assert (a1_id, a2_id) in edge_pairs
    assert all(b1_id not in pair for pair in edge_pairs)
    # a1 keeps its port + service; b1's nginx port is unreachable.
    a1_node = next(n for n in env.data.nodes if n.id == a1_id)
    assert {p.port for p in a1_node.ports} == {22}
    assert {s.service_name for s in a1_node.services} == {"sshd"}
    assert env.meta["system_count"] == 2


@pytest.mark.usefixtures("test_db")
async def test_get_topology_god_tier_sees_all_teams() -> None:
    _ta, _tb, a1_id, a2_id, b1_id = await _seed_two_teams()

    env = await _get_topology(_auth(None))
    node_ids = {n.id for n in env.data.nodes}
    assert node_ids == {a1_id, a2_id, b1_id}
    subnet_prefixes = {g.subnet_prefix for g in env.data.subnets}
    assert subnet_prefixes == {"10.20.1", "10.20.2", "10.20.3"}
    b1_node = next(n for n in env.data.nodes if n.id == b1_id)
    assert {p.port for p in b1_node.ports} == {443}
    assert env.meta["system_count"] == 3


@pytest.mark.usefixtures("test_db")
async def test_get_topology_empty_for_isolated_team() -> None:
    _ta, _tb, _a1, _a2, _b1 = await _seed_two_teams()

    env = await _get_topology(_auth(f"team-c-{uuid4().hex[:6]}"))
    assert env.data.nodes == []
    assert env.data.edges == []
    assert env.data.subnets == []
    assert env.meta == {"system_count": 0}


@pytest.mark.usefixtures("test_db")
async def test_get_topology_subnets_team_scoped() -> None:
    team_a, _tb, a1_id, a2_id, b1_id = await _seed_two_teams()

    env = await _get_subnets(_auth(team_a))
    prefixes = {g.subnet_prefix for g in env.data}
    assert prefixes == {"10.20.1", "10.20.2"}
    all_ids = {sid for g in env.data for sid in g.system_ids}
    assert all_ids == {a1_id, a2_id}
    assert b1_id not in all_ids
    assert env.meta == {"subnet_count": 2}


@pytest.mark.usefixtures("test_db")
async def test_get_topology_subnets_god_tier_sees_all_teams() -> None:
    _ta, _tb, a1_id, a2_id, b1_id = await _seed_two_teams()

    env = await _get_subnets(_auth(None))
    prefixes = {g.subnet_prefix for g in env.data}
    assert prefixes == {"10.20.1", "10.20.2", "10.20.3"}
    all_ids = {sid for g in env.data for sid in g.system_ids}
    assert all_ids == {a1_id, a2_id, b1_id}
    assert env.meta == {"subnet_count": 3}
