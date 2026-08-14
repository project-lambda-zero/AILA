"""#36, #103 -- god-tier-only admin router gates.

A team-scoped admin (team_id set) must not list/create/modify other teams,
read/requeue other teams' failed tasks, or (#103) inspect other teams'
workflow-run cursors and transition audit logs. Every router gates every
endpoint through a router-level _require_admin dependency; it refuses a
non-None team_id even when the role is admin. God-tier admins carry
team_id=None.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers import admin_dead_letter, admin_teams, admin_workflows

_GATED = [admin_teams, admin_dead_letter, admin_workflows]


def _auth(team_id: str | None, role: str = "admin") -> AuthContext:
    return AuthContext(user_id="u1", role=role, auth_type="user", team_id=team_id)


@pytest.mark.parametrize("mod", _GATED)
async def test_god_tier_admin_allowed(mod) -> None:
    ctx = _auth(team_id=None)
    assert await mod._require_admin(ctx=ctx) is ctx


@pytest.mark.parametrize("mod", _GATED)
async def test_team_scoped_admin_refused(mod) -> None:
    with pytest.raises(HTTPException) as excinfo:
        await mod._require_admin(ctx=_auth(team_id="team-a"))
    assert excinfo.value.status_code == 403


@pytest.mark.parametrize("mod", _GATED)
async def test_non_admin_refused(mod) -> None:
    with pytest.raises(HTTPException) as excinfo:
        await mod._require_admin(ctx=_auth(team_id=None, role="operator"))
    assert excinfo.value.status_code == 403
