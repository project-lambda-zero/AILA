"""#36, #367 -- GET /search results are team-scoped.

Systems, findings, malware targets, and VR investigations are matched on the
router's team-scoped session, so a team caller sees only its own team's rows
and a god-tier caller (team_id=None) sees every team's rows. Findings come
from the module ``latest_findings`` capability; malware targets and VR
investigations come from each module ``search_entities`` hook, which applies
its own team predicate. Each finding is returned once. SessionRecord is
already user-scoped and is left alone (the query already restricts to
auth.user_id).

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
from aila.modules.malware.db_models import MalwareTargetRecord, MalwareWorkspaceRecord
from aila.modules.malware.module import MalwareModule
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.module import VRModule
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
    def __init__(self, *modules: object) -> None:
        self._modules = modules

    def all_with(self, capability: str) -> list[object]:
        return [m for m in self._modules if callable(getattr(m, capability, None))]


def _req(*modules: object) -> object:
    platform = types.SimpleNamespace(
        runtime=types.SimpleNamespace(module_registry=_Registry(*modules))
    )
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=platform))
    )


def _platform_modules() -> tuple[object, ...]:
    return (VulnerabilityModule(), MalwareModule(), VRModule())


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


async def _seed_malware_target(team_id: str, display_name: str) -> str:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        workspace = MalwareWorkspaceRecord(
            team_id=team_id, name=f"ws-{suffix}", slug=f"ws-{suffix}"
        )
        session.add(workspace)
        await session.flush()
        target = MalwareTargetRecord(
            team_id=team_id,
            workspace_id=workspace.id,
            display_name=display_name,
            kind="elf_sample",
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)
        return target.id


async def _seed_vr_investigation(team_id: str, title: str) -> str:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        workspace = VRWorkspaceRecord(
            team_id=team_id, name=f"ws-{suffix}", slug=f"ws-{suffix}"
        )
        session.add(workspace)
        await session.flush()
        target = VRTargetRecord(
            team_id=team_id,
            workspace_id=workspace.id,
            display_name=f"tgt-{suffix}",
            kind="native_binary",
        )
        session.add(target)
        await session.flush()
        investigation = VRInvestigationRecord(
            team_id=team_id, target_id=target.id, title=title
        )
        session.add(investigation)
        await session.commit()
        await session.refresh(investigation)
        return investigation.id


async def _search(
    auth: AuthContext,
    q: str,
    *modules: object,
    entity_types: str | None = None,
):
    return await global_search(
        request=_req(*modules),
        q=q,
        entity_types=entity_types,
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

    envelope = await _search(_auth("team-a"), f"needle-{suffix}", module)
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

    envelope = await _search(_auth(None), f"needle-{suffix}", module)
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
    envelope = await _search(_auth("team-a"), suffix, module)
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

    envelope = await _search(_auth(None), suffix, module)
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

    envelope = await _search(_auth("team-a"), f"needle-{suffix}", module)
    systems = [r for r in envelope.data if r.entity_type == "system"]
    findings = [r for r in envelope.data if r.entity_type == "finding"]
    assert systems == []
    assert findings == []


@pytest.mark.usefixtures("test_db")
async def test_search_matches_malware_target_by_display_name() -> None:
    suffix = uuid4().hex[:6]
    target_id = await _seed_malware_target("team-a", f"Dropper-{suffix}-x64")

    envelope = await _search(_auth("team-a"), f"Dropper-{suffix}", *_platform_modules())
    hits = [
        (r.entity_type, r.entity_id, r.title, r.module_id)
        for r in envelope.data
        if r.entity_type == "target"
    ]
    assert hits == [("target", target_id, f"Dropper-{suffix}-x64", "malware")]


@pytest.mark.usefixtures("test_db")
async def test_search_matches_vr_investigation_by_title() -> None:
    suffix = uuid4().hex[:6]
    title = f"Heap overflow triage {suffix}"
    investigation_id = await _seed_vr_investigation("team-a", title)

    envelope = await _search(
        _auth("team-a"), f"overflow triage {suffix}", *_platform_modules()
    )
    hits = [
        (r.entity_type, r.entity_id, r.title, r.module_id)
        for r in envelope.data
        if r.entity_type == "investigation"
    ]
    assert hits == [("investigation", investigation_id, title, "vr")]


@pytest.mark.usefixtures("test_db")
async def test_search_module_entities_scoped_to_team() -> None:
    suffix = uuid4().hex[:6]
    needle = f"needle-{suffix}"
    own_target = await _seed_malware_target("team-a", f"{needle}-a")
    other_target = await _seed_malware_target("team-b", f"{needle}-b")
    own_investigation = await _seed_vr_investigation("team-a", f"{needle}-a")
    other_investigation = await _seed_vr_investigation("team-b", f"{needle}-b")

    envelope = await _search(_auth("team-a"), needle, *_platform_modules())
    ids = {r.entity_id for r in envelope.data}
    assert own_target in ids
    assert own_investigation in ids
    assert other_target not in ids
    assert other_investigation not in ids


@pytest.mark.usefixtures("test_db")
async def test_search_module_entities_god_tier_sees_all_teams() -> None:
    suffix = uuid4().hex[:6]
    needle = f"needle-{suffix}"
    target_a = await _seed_malware_target("team-a", f"{needle}-a")
    target_b = await _seed_malware_target("team-b", f"{needle}-b")
    investigation_a = await _seed_vr_investigation("team-a", f"{needle}-a")
    investigation_b = await _seed_vr_investigation("team-b", f"{needle}-b")

    envelope = await _search(_auth(None), needle, *_platform_modules())
    ids = {r.entity_id for r in envelope.data}
    assert {target_a, target_b, investigation_a, investigation_b} <= ids


@pytest.mark.usefixtures("test_db")
async def test_search_module_entities_empty_when_nothing_matches() -> None:
    suffix = uuid4().hex[:6]
    await _seed_malware_target("team-a", f"plain-{suffix}")
    await _seed_vr_investigation("team-a", f"plain-{suffix}")

    envelope = await _search(_auth("team-a"), f"absent-{suffix}", *_platform_modules())
    assert envelope.data == []


@pytest.mark.usefixtures("test_db")
async def test_search_treats_query_wildcards_literally() -> None:
    suffix = uuid4().hex[:6]
    literal = await _seed_malware_target("team-a", f"100%-{suffix}")
    plain = await _seed_malware_target("team-a", f"plain-{suffix}")

    envelope = await _search(
        _auth("team-a"), "%", *_platform_modules(), entity_types="target"
    )
    ids = {r.entity_id for r in envelope.data}
    assert literal in ids
    assert plain not in ids


@pytest.mark.usefixtures("test_db")
async def test_search_entity_types_filter_applies_to_module_hits() -> None:
    suffix = uuid4().hex[:6]
    needle = f"needle-{suffix}"
    await _seed_malware_target("team-a", f"{needle}-target")
    investigation_id = await _seed_vr_investigation("team-a", f"{needle}-investigation")

    envelope = await _search(
        _auth("team-a"), needle, *_platform_modules(), entity_types="investigation"
    )
    assert [(r.entity_type, r.entity_id) for r in envelope.data] == [
        ("investigation", investigation_id)
    ]


@pytest.mark.usefixtures("test_db")
async def test_search_returns_each_finding_once() -> None:
    suffix = uuid4().hex[:6]
    system_id = await _seed_system("team-a", f"sysOnce-{suffix}")
    cve = f"CVE-ONCE-{suffix}"
    await _seed_finding("team-a", cve, system_id)

    envelope = await _search(_auth("team-a"), suffix, *_platform_modules())
    findings = [r.title for r in envelope.data if r.entity_type == "finding"]
    assert findings == [cve]
