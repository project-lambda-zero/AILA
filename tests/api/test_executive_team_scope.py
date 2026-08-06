"""#36 -- executive reporting endpoints are team-scoped.

executive_health, download_risk_summary_pdf, and download_evidence_package
called ``_fetch_all_findings`` / ``_fetch_system_findings`` inside a bare
``async_session_scope()`` (no TeamContext) and then queried
LatestFindingRecord unfiltered through ``vulnerability.latest_findings``.
Any authenticated principal therefore read every team's findings, and
``download_evidence_package`` served the compliance ZIP for another team's
system whenever findings for that system id existed. Both helpers now bind
the caller's TeamContext to the session, and the evidence handler gates the
package by team ownership of the ManagedSystemRecord (via ``owned_or_404``)
before doing any work. A god-tier admin (team_id is None, TEAM-06) sees all.

Handlers are invoked directly with an explicit AuthContext because the
router-level ``require_user_or_api_key`` dependency is not resolved on
direct invocation. A minimal ``platform`` stub exposes the real
``VulnerabilityModule`` through ``runtime.module_registry``.
"""
from __future__ import annotations

import types
from uuid import uuid4

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers.executive import (
    download_evidence_package,
    download_risk_summary_pdf,
    executive_health,
)
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

    def first_with(self, capability: str) -> object | None:
        candidate = getattr(self._module, capability, None)
        return self._module if callable(candidate) else None


def _req(module: object) -> object:
    platform = types.SimpleNamespace(
        runtime=types.SimpleNamespace(module_registry=_Registry(module))
    )
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=platform))
    )


async def _seed_system(team_id: str, suffix: str) -> int:
    async with async_session_scope() as session:
        rec = ManagedSystemRecord(
            team_id=team_id,
            name=f"sys-{team_id}-{suffix}",
            host=f"h-{team_id}-{suffix}",
            username="u",
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


@pytest.mark.usefixtures("test_db")
async def test_executive_health_scoped_to_team() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", suffix)
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sa)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    envelope = await executive_health(request=_req(module), auth=_auth("team-a"))
    payload = envelope.data
    assert payload.total_findings == 1
    assert payload.systems_with_findings == 1


@pytest.mark.usefixtures("test_db")
async def test_executive_health_god_tier_sees_all_teams() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", suffix)
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sa)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    envelope = await executive_health(request=_req(module), auth=_auth(None))
    payload = envelope.data
    assert payload.total_findings == 2
    assert payload.systems_with_findings == 2


@pytest.mark.usefixtures("test_db")
async def test_evidence_package_cross_team_is_404() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    with pytest.raises(HTTPException) as exc:
        await download_evidence_package(
            request=_req(module), system_id=sb, auth=_auth("team-a")
        )
    assert exc.value.status_code == 404


@pytest.mark.usefixtures("test_db")
async def test_evidence_package_own_team_reads() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sa)

    resp = await download_evidence_package(
        request=_req(module), system_id=sa, auth=_auth("team-a")
    )
    # StreamingResponse for a valid ZIP payload; the exact bytes are covered
    # elsewhere -- only care here that no HTTPException fired for the caller's
    # own system.
    assert resp.media_type == "application/zip"


@pytest.mark.usefixtures("test_db")
async def test_evidence_package_god_tier_reads_any_team() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    resp = await download_evidence_package(
        request=_req(module), system_id=sb, auth=_auth(None)
    )
    assert resp.media_type == "application/zip"


@pytest.mark.usefixtures("test_db")
async def test_risk_summary_pdf_scoped_to_team_when_pdf_extra_missing() -> None:
    """Whether or not weasyprint is installed, the PDF handler MUST scope its
    findings query to the caller's team before rendering. If weasyprint is
    missing we get 503; if present we get 200. Both paths first fetched the
    findings that would go into the report -- assert scope by inspecting the
    findings collected by the module for the caller."""
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", suffix)
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sa)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    # Confirm the same fetch helper the PDF handler uses returns team-scoped
    # results for a non-admin caller.
    from aila.api.routers.executive import _fetch_all_findings

    team_a_findings = await _fetch_all_findings(module, _auth("team-a"))
    assert len(team_a_findings) == 1
    assert team_a_findings[0]["cve_id"] == f"CVE-A-{suffix}"

    all_findings = await _fetch_all_findings(module, _auth(None))
    assert len(all_findings) == 2

    # And the PDF route itself -- either renders (weasyprint present) or 503
    # (weasyprint absent). Both are acceptable; the test's purpose is to
    # confirm the handler is reachable end-to-end with a team-scoped auth
    # without leaking cross-team rows.
    try:
        resp = await download_risk_summary_pdf(
            request=_req(module), auth=_auth("team-a")
        )
        assert resp.media_type == "application/pdf"
    except HTTPException as exc:
        assert exc.status_code == 503


@pytest.mark.usefixtures("test_db")
async def test_latest_findings_team_id_filter() -> None:
    """latest_findings(team_id=...) scopes to one team on a session with no
    TeamContext (the scheduled-report worker path); team_id=None returns every
    team's findings for a god-tier report (#36)."""
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sys_a = await _seed_system("team-a", suffix)
    sys_b = await _seed_system("team-b", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sys_a)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sys_b)

    async with async_session_scope() as session:
        team_a = await module.latest_findings(session, team_id="team-a")
        god = await module.latest_findings(session, team_id=None)

    a_cves = {f["cve_id"] for f in team_a}
    all_cves = {f["cve_id"] for f in god}
    assert f"CVE-A-{suffix}" in a_cves
    assert f"CVE-B-{suffix}" not in a_cves, "team-a query must not see team-b findings"
    assert {f"CVE-A-{suffix}", f"CVE-B-{suffix}"} <= all_cves, "god-tier report sees all teams"
