"""#36 -- GET /search results are team-scoped.

global_search opened a bare async_session_scope (no TeamContext) and
matched ManagedSystemRecord via ILIKE across every team, then called
``vulnerability.search_entities`` which itself opened another bare
UnitOfWork and returned LatestFindingRecord rows unfiltered. Any
authenticated principal therefore enumerated other teams' systems and
findings by picking a search term that would hit them. The router now
binds the caller's TeamContext to the session, carries an explicit
god-tier-aware team predicate on the ManagedSystemRecord select, and
routes findings search through the module's team-scoped
``latest_findings`` surface. SessionRecord is already user-scoped and is
left alone (the query already restricts to auth.user_id).

The handler is invoked directly with an explicit AuthContext because the
router-level dependency is not resolved on direct invocation, and every
Query()-default param is passed explicitly (bare defaults are FieldInfo
sentinels).
"""
from __future__ import annotations

import types
from uuid import uuid4

import pytest

from aila.api.auth import AuthContext
from aila.api.routers.search import global_search
from aila.modules.vulnerability.db_models import LatestFindingRecord
from aila.modules.vulnerability.module import VulnerabilityModule
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


def _auth(team_id: str | None) -> AuthContext:
    return AuthContext(
        user_id="u-" + (team_id or "god"),
        role="admin" if team_id is None else "operator",
        auth_type="user",
        team_id=team_id,
    )


class _Registry:
    def __init__(self, module: object) -> None:
        self._module = module
        self.modules: list[object] = [module]

    def require(self, name: str) -> object:
        if name != "vulnerability":
            raise KeyError(name)
        return self._module


def _req(module: object) -> object:
    platform = types.SimpleNamespace(
        runtime=types.SimpleNamespace(module_registry=_Registry(module))
    )
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=platform))
    )


async def _seed_system(team_id: str, name: str) -> int:
    async with async_session_scope() as session:
        rec = ManagedSystemRecord(
            team_id=team_id, name=name, host=f"h-{name}", username="u"
        )
        session.add(rec)
        await session.commit()
        await session.refresh(rec)
        return rec.id


async def _seed_finding(team_id: str, cve: str, system_id: int) -> int:
    async with async_session_scope() as session:
        rec = LatestFindingRecord(
            system_id=system_id,
            system_name=f"sys-{team_id}",
            host=f"h-{team_id}",
            cve_id=cve,
            package_name="pkg",
            criticality="High",
            score=7.0,
            is_kev=False,
            current_workflow_state="new",
            nvd_url="https://nvd.example/x",
            last_scanned_at=utc_now(),
            created_at=utc_now(),
            team_id=team_id,
        )
        session.add(rec)
        await session.commit()
        await session.refresh(rec)
        return rec.id


async def _search(auth: AuthContext, module: object, q: str):
    return await global_search(
        request=_req(module),
        q=q,
        entity_types=None,
        limit=100,
        offset=0,
        auth=auth,
    )


@pytest.mark.usefixtures("test_db")
async def test_search_systems_scoped_to_team() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    name_a = f"needle-{suffix}-a"
    name_b = f"needle-{suffix}-b"
    await _seed_system("team-a", name_a)
    await _seed_system("team-b", name_b)

    envelope = await _search(_auth("team-a"), module, f"needle-{suffix}")
    systems = [r for r in envelope.data if r.entity_type == "system"]
    titles = {r.title for r in systems}
    assert name_a in titles
    assert name_b not in titles


@pytest.mark.usefixtures("test_db")
async def test_search_systems_god_tier_sees_all_teams() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    name_a = f"needle-{suffix}-a"
    name_b = f"needle-{suffix}-b"
    await _seed_system("team-a", name_a)
    await _seed_system("team-b", name_b)

    envelope = await _search(_auth(None), module, f"needle-{suffix}")
    systems = [r for r in envelope.data if r.entity_type == "system"]
    titles = {r.title for r in systems}
    assert name_a in titles
    assert name_b in titles


@pytest.mark.usefixtures("test_db")
async def test_search_findings_scoped_to_team() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", f"sysA-{suffix}")
    sb = await _seed_system("team-b", f"sysB-{suffix}")
    cve_a = f"CVE-A-{suffix}"
    cve_b = f"CVE-B-{suffix}"
    await _seed_finding("team-a", cve_a, sa)
    await _seed_finding("team-b", cve_b, sb)

    # A search term that matches both teams' CVEs by shared suffix.
    envelope = await _search(_auth("team-a"), module, suffix)
    findings = [r for r in envelope.data if r.entity_type == "finding"]
    titles = {r.title for r in findings}
    assert cve_a in titles
    assert cve_b not in titles


@pytest.mark.usefixtures("test_db")
async def test_search_findings_god_tier_sees_all_teams() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", f"sysA-{suffix}")
    sb = await _seed_system("team-b", f"sysB-{suffix}")
    cve_a = f"CVE-A-{suffix}"
    cve_b = f"CVE-B-{suffix}"
    await _seed_finding("team-a", cve_a, sa)
    await _seed_finding("team-b", cve_b, sb)

    envelope = await _search(_auth(None), module, suffix)
    findings = [r for r in envelope.data if r.entity_type == "finding"]
    titles = {r.title for r in findings}
    assert cve_a in titles
    assert cve_b in titles


@pytest.mark.usefixtures("test_db")
async def test_search_returns_empty_when_only_other_team_matches() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    name_b = f"needle-{suffix}-b"
    sb = await _seed_system("team-b", name_b)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    envelope = await _search(_auth("team-a"), module, f"needle-{suffix}")
    systems = [r for r in envelope.data if r.entity_type == "system"]
    findings = [r for r in envelope.data if r.entity_type == "finding"]
    assert systems == []
    assert findings == []
