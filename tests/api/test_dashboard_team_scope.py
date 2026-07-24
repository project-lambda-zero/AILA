"""#36 -- GET /dashboard aggregations are team-scoped.

The dashboard router counted ManagedSystemRecord rows over a bare session
(no TeamContext) and delegated the finding severity breakdown to
``vulnerability.report_count`` which itself queried LatestFindingRecord with
no team predicate. Any authenticated principal therefore saw fleet-wide
totals across every team. Both counts now scope to the caller's team; a
god-tier admin (team_id is None, TEAM-06) still sees every team's rows.

The handler is invoked directly with an explicit AuthContext because the
router-level ``require_operator`` dependency is not resolved on direct
invocation. A minimal ``platform`` stub exposes the real
``VulnerabilityModule`` through ``runtime.module_registry`` so ``report_count``
runs its actual DB query rather than a mock.
"""
from __future__ import annotations

import types
from uuid import uuid4

import pytest

from aila.api.auth import AuthContext
from aila.api.routers.dashboard import get_dashboard
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
    """Stub module_registry returning a single vulnerability module."""

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
    async with async_session_scope() as session:  # admin => unfiltered insert
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
async def test_dashboard_totals_scoped_to_team() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", suffix)
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sa)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    envelope = await get_dashboard(request=_req(module), auth=_auth("team-a"))
    fleet = envelope.data.fleet_stats
    assert fleet.total_systems == 1
    assert fleet.total_findings == 1


@pytest.mark.usefixtures("test_db")
async def test_dashboard_god_tier_sees_all_teams() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sa = await _seed_system("team-a", suffix)
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-a", f"CVE-A-{suffix}", sa)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    envelope = await get_dashboard(request=_req(module), auth=_auth(None))
    fleet = envelope.data.fleet_stats
    assert fleet.total_systems == 2
    assert fleet.total_findings == 2


@pytest.mark.usefixtures("test_db")
async def test_dashboard_reports_zero_when_only_other_team_has_data() -> None:
    module = VulnerabilityModule()
    suffix = uuid4().hex[:6]
    sb = await _seed_system("team-b", suffix)
    await _seed_finding("team-b", f"CVE-B-{suffix}", sb)

    envelope = await get_dashboard(request=_req(module), auth=_auth("team-a"))
    fleet = envelope.data.fleet_stats
    assert fleet.total_systems == 0
    assert fleet.total_findings == 0
