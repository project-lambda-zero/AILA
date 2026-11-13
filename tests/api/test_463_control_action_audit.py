"""#463: investigation control actions write exactly one audit row.

Pausing, resuming, or cancelling an investigation or branch, resuming a
target analysis, and deleting an investigation, project, or workspace in
the vr, malware, and forensics modules each write one ``AuditEventRecord``
naming the actor, the action, and the target, committed with the state
change. A refused request (another team's id, a state conflict) or a
no-op writes none.

Handlers are invoked directly with an explicit ``AuthContext`` while the
caller's ``TeamContext`` is bound, as the request middleware binds it.
Task submission is replaced by a recording queue so nothing runs.
"""
from __future__ import annotations

import types
from uuid import uuid4

import pytest
from fastapi import APIRouter, HTTPException
from sqlmodel import select

from aila.api.auth import AuthContext, TeamContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
from aila.modules.malware.api_router import create_malware_router
from aila.modules.malware.db_models.branch import MalwareInvestigationBranchRecord
from aila.modules.malware.db_models.investigation import MalwareInvestigationRecord
from aila.modules.malware.db_models.project import MalwareProjectRecord
from aila.modules.malware.db_models.target import MalwareTargetRecord
from aila.modules.malware.db_models.workspace import MalwareWorkspaceRecord

# The resume handlers import their module's investigate task, whose agents load
# prompts through the sync engine at import time. Importing here, at collection,
# keeps that load off a pooled sync connection the per-test database reset closes.
from aila.modules.malware.workflow import task as _malware_task  # noqa: F401
from aila.modules.vr.api_router import _BranchOpBody, create_vr_router
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRProjectRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.workflow import task as _vr_task  # noqa: F401
from aila.platform.contracts.enums import InvestigationPauseReason
from aila.platform.services.team_scope import team_context_scope
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditEventRecord

_REQ = types.SimpleNamespace(app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None)))


class _RecordingQueue:
    """Task queue double: records each submit and runs nothing."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []

    async def submit(self, **kwargs):
        self.submitted.append(kwargs)
        return types.SimpleNamespace(task_id=f"task-{uuid4().hex}")


@pytest.fixture(autouse=True)
def _disable_forensics_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """The forensics router owns a module-local limiter the shared fixture leaves on."""
    monkeypatch.setattr(_forensics_limiter, "enabled", False)


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> _RecordingQueue:
    """Route every handler's task submission and ARQ purge to inert doubles."""
    recording = _RecordingQueue()

    async def _no_purge(*_args, **_kwargs) -> int:
        return 0

    async def _record_target_enqueue(target_id: str, _auth: AuthContext) -> None:
        recording.submitted.append({"target_id": target_id})

    monkeypatch.setattr("aila.api.deps.get_task_queue", lambda _module_id, _request: recording)
    monkeypatch.setattr(
        "aila.platform.services.investigation_lifecycle.purge_arq_jobs_for_investigation", _no_purge,
    )
    monkeypatch.setattr(
        "aila.modules.malware.api_router._enqueue_target_analysis", _record_target_enqueue,
    )
    return recording


def _endpoint(router: APIRouter, path: str, method: str):
    for route in router.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str) -> AuthContext:
    return AuthContext(user_id=f"u-{uuid4().hex[:8]}", role="operator", auth_type="user", team_id=team_id)


def _team() -> str:
    return f"team-{uuid4().hex[:12]}"


async def _call(endpoint, auth: AuthContext, **kwargs):
    with team_context_scope(TeamContext.from_auth(auth)):
        return await endpoint(request=_REQ, auth=auth, **kwargs)


async def _rows(run_id: str) -> list[AuditEventRecord]:
    async with async_session_scope() as session:
        return list((await session.exec(
            select(AuditEventRecord).where(AuditEventRecord.run_id == run_id),
        )).all())


async def _assert_one(run_id: str, *, stage: str, action: str, target: str, auth: AuthContext) -> None:
    rows = await _rows(run_id)
    assert [(r.stage, r.action, r.target, r.user_id, r.team_id, r.status) for r in rows] == [
        (stage, action, target, auth.user_id, auth.team_id, "completed"),
    ]


# ---------------------------------------------------------------------------
# vr
# ---------------------------------------------------------------------------


async def _seed_vr(team: str, *, inv_status: str = "running") -> types.SimpleNamespace:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        ws = VRWorkspaceRecord(team_id=team, name="W", slug=f"w-{suffix}")
        session.add(ws)
        await session.flush()
        target = VRTargetRecord(team_id=team, workspace_id=ws.id, display_name="t", kind="native_binary")
        session.add(target)
        await session.flush()
        inv = VRInvestigationRecord(team_id=team, target_id=target.id, title="inv-463", status=inv_status)
        session.add(inv)
        await session.flush()
        branch = VRInvestigationBranchRecord(investigation_id=inv.id)
        project = VRProjectRecord(team_id=team, target_id=target.id, name=f"p-{suffix}")
        session.add_all([branch, project])
        await session.commit()
        return types.SimpleNamespace(
            target_id=target.id, inv_id=inv.id, branch_id=branch.id, project_id=project.id,
        )


@pytest.mark.usefixtures("test_db")
async def test_vr_investigation_pause_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_vr(team)
    pause = _endpoint(create_vr_router(), "/investigations/{investigation_id}/pause", "POST")
    auth = _auth(team)
    await _call(pause, auth, investigation_id=seed.inv_id)
    await _assert_one(
        seed.inv_id, stage="vr", action="investigation_paused",
        target=f"investigation:{seed.inv_id}", auth=auth,
    )
    # Pausing an already paused investigation changes nothing and records nothing.
    await _call(pause, auth, investigation_id=seed.inv_id)
    assert len(await _rows(seed.inv_id)) == 1


@pytest.mark.usefixtures("test_db")
async def test_vr_investigation_pause_other_team_writes_nothing(queue: _RecordingQueue) -> None:
    seed = await _seed_vr(_team())
    pause = _endpoint(create_vr_router(), "/investigations/{investigation_id}/pause", "POST")
    with pytest.raises(HTTPException) as exc:
        await _call(pause, _auth(_team()), investigation_id=seed.inv_id)
    assert exc.value.status_code == 404
    assert await _rows(seed.inv_id) == []


@pytest.mark.usefixtures("test_db")
async def test_vr_investigation_resume_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_vr(team, inv_status="paused")
    resume = _endpoint(create_vr_router(), "/investigations/{investigation_id}/resume", "POST")
    auth = _auth(team)
    await _call(resume, auth, investigation_id=seed.inv_id)
    assert queue.submitted, "resume must dispatch the paused investigation's work"
    await _assert_one(
        seed.inv_id, stage="vr", action="investigation_resumed",
        target=f"investigation:{seed.inv_id}", auth=auth,
    )


@pytest.mark.usefixtures("test_db")
async def test_vr_investigation_resume_conflict_writes_nothing(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_vr(team, inv_status="running")
    resume = _endpoint(create_vr_router(), "/investigations/{investigation_id}/resume", "POST")
    with pytest.raises(HTTPException) as exc:
        await _call(resume, _auth(team), investigation_id=seed.inv_id)
    assert exc.value.status_code == 409
    assert await _rows(seed.inv_id) == []


@pytest.mark.usefixtures("test_db")
async def test_vr_branch_pause_and_resume_write_one_row_each(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_vr(team)
    router = create_vr_router()
    pause = _endpoint(router, "/investigations/{investigation_id}/branches/{branch_id}/pause", "POST")
    resume = _endpoint(router, "/investigations/{investigation_id}/branches/{branch_id}/resume", "POST")
    auth = _auth(team)
    ids = {"investigation_id": seed.inv_id, "branch_id": seed.branch_id}

    await _call(pause, auth, body=_BranchOpBody(reason="hold"), **ids)
    await _assert_one(
        seed.inv_id, stage="vr", action="branch_paused", target=f"branch:{seed.branch_id}", auth=auth,
    )
    await _call(resume, auth, body=_BranchOpBody(reason="go"), **ids)
    rows = await _rows(seed.inv_id)
    assert sorted(r.action for r in rows) == ["branch_paused", "branch_resumed"]
    # Resuming an already active branch is refused and records nothing.
    with pytest.raises(HTTPException) as exc:
        await _call(resume, auth, body=_BranchOpBody(reason="again"), **ids)
    assert exc.value.status_code == 409
    assert len(await _rows(seed.inv_id)) == 2


@pytest.mark.usefixtures("test_db")
async def test_vr_target_resume_analysis_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_vr(team)
    resume = _endpoint(create_vr_router(), "/targets/{target_id}/resume-analysis", "POST")
    with pytest.raises(HTTPException) as exc:
        await _call(resume, _auth(_team()), target_id=seed.target_id)
    assert exc.value.status_code == 404
    assert await _rows(seed.target_id) == []

    auth = _auth(team)
    await _call(resume, auth, target_id=seed.target_id)
    await _assert_one(
        seed.target_id, stage="vr", action="target_analysis_resumed",
        target=f"target:{seed.target_id}", auth=auth,
    )


@pytest.mark.usefixtures("test_db")
async def test_vr_project_delete_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_vr(team)
    delete = _endpoint(create_vr_router(), "/projects/{project_id}", "DELETE")
    with pytest.raises(HTTPException) as exc:
        await _call(delete, _auth(_team()), project_id=seed.project_id)
    assert exc.value.status_code in (403, 404)
    assert await _rows(seed.project_id) == []

    auth = _auth(team)
    await _call(delete, auth, project_id=seed.project_id)
    await _assert_one(
        seed.project_id, stage="vr", action="project_deleted",
        target=f"project:{seed.project_id}", auth=auth,
    )


# ---------------------------------------------------------------------------
# malware
# ---------------------------------------------------------------------------


async def _seed_malware(team: str, *, inv_status: str = "running") -> types.SimpleNamespace:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        ws = MalwareWorkspaceRecord(team_id=team, name="W", slug=f"w-{suffix}")
        session.add(ws)
        await session.flush()
        target = MalwareTargetRecord(team_id=team, workspace_id=ws.id, display_name="t", kind="elf_sample")
        session.add(target)
        await session.flush()
        inv = MalwareInvestigationRecord(
            team_id=team, target_id=target.id, title="inv-463", strategy_family="default", status=inv_status,
        )
        project = MalwareProjectRecord(team_id=team, target_id=target.id, name=f"p-{suffix}")
        session.add_all([inv, project])
        await session.flush()
        session.add(MalwareInvestigationBranchRecord(investigation_id=inv.id))
        await session.commit()
        return types.SimpleNamespace(
            workspace_id=ws.id, target_id=target.id, inv_id=inv.id, project_id=project.id,
        )


_MALWARE_ARCHIVES = [
    ("/workspaces/{workspace_id}", "workspace_id", "workspace_deleted", "workspace"),
    ("/projects/{project_id}", "project_id", "project_deleted", "project"),
    ("/investigations/{investigation_id}", "investigation_id", "investigation_deleted", "investigation"),
]
_SEED_FIELD = {"workspace_id": "workspace_id", "project_id": "project_id", "investigation_id": "inv_id"}


@pytest.mark.parametrize(("path", "param", "action", "kind"), _MALWARE_ARCHIVES)
@pytest.mark.usefixtures("test_db")
async def test_malware_delete_writes_one_row(
    queue: _RecordingQueue, path: str, param: str, action: str, kind: str,
) -> None:
    team = _team()
    seed = await _seed_malware(team)
    entity_id = getattr(seed, _SEED_FIELD[param])
    delete = _endpoint(create_malware_router(), path, "DELETE")
    with pytest.raises(HTTPException) as exc:
        await _call(delete, _auth(_team()), **{param: entity_id})
    assert exc.value.status_code == 404
    assert await _rows(entity_id) == []

    auth = _auth(team)
    await _call(delete, auth, **{param: entity_id})
    await _assert_one(entity_id, stage="malware", action=action, target=f"{kind}:{entity_id}", auth=auth)
    # Deleting an already archived row changes nothing and records nothing.
    await _call(delete, auth, **{param: entity_id})
    assert len(await _rows(entity_id)) == 1


@pytest.mark.usefixtures("test_db")
async def test_malware_investigation_pause_and_resume_write_one_row_each(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_malware(team)
    router = create_malware_router()
    pause = _endpoint(router, "/investigations/{investigation_id}/pause", "POST")
    resume = _endpoint(router, "/investigations/{investigation_id}/resume", "POST")

    with pytest.raises(HTTPException) as exc:
        await _call(pause, _auth(_team()), investigation_id=seed.inv_id, reason=InvestigationPauseReason.OPERATOR)
    assert exc.value.status_code == 404
    assert await _rows(seed.inv_id) == []

    auth = _auth(team)
    await _call(pause, auth, investigation_id=seed.inv_id, reason=InvestigationPauseReason.OPERATOR)
    await _assert_one(
        seed.inv_id, stage="malware", action="investigation_paused",
        target=f"investigation:{seed.inv_id}", auth=auth,
    )
    await _call(resume, auth, investigation_id=seed.inv_id)
    assert queue.submitted, "resume must dispatch the paused investigation's work"
    rows = await _rows(seed.inv_id)
    assert sorted(r.action for r in rows) == ["investigation_paused", "investigation_resumed"]
    assert {(r.target, r.user_id, r.team_id) for r in rows} == {
        (f"investigation:{seed.inv_id}", auth.user_id, auth.team_id),
    }


@pytest.mark.usefixtures("test_db")
async def test_malware_target_resume_analysis_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_malware(team)
    resume = _endpoint(create_malware_router(), "/targets/{target_id}/resume-analysis", "POST")
    with pytest.raises(HTTPException) as exc:
        await _call(resume, _auth(_team()), target_id=seed.target_id)
    assert exc.value.status_code == 404
    assert await _rows(seed.target_id) == []

    auth = _auth(team)
    await _call(resume, auth, target_id=seed.target_id)
    assert queue.submitted == [{"target_id": seed.target_id}]
    await _assert_one(
        seed.target_id, stage="malware", action="target_analysis_resumed",
        target=f"target:{seed.target_id}", auth=auth,
    )


# ---------------------------------------------------------------------------
# forensics
# ---------------------------------------------------------------------------


async def _seed_forensics(team: str) -> types.SimpleNamespace:
    project_id = f"proj-{uuid4().hex}"
    inv_id = f"inv-{uuid4().hex}"
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id, name=project_id, system_id=0, evidence_directory="/evidence", team_id=team,
        ))
        await session.flush()
        session.add(InvestigationRunRecord(
            id=inv_id, project_id=project_id, question="q", status="running", team_id=team,
        ))
        await session.commit()
    return types.SimpleNamespace(project_id=project_id, inv_id=inv_id)


@pytest.mark.usefixtures("test_db")
async def test_forensics_cancel_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_forensics(team)
    cancel = _endpoint(
        create_forensics_router(), "/projects/{project_id}/investigations/{investigation_id}/cancel", "POST",
    )
    ids = {"project_id": seed.project_id, "investigation_id": seed.inv_id}
    with pytest.raises(HTTPException) as exc:
        await _call(cancel, _auth(_team()), **ids)
    assert exc.value.status_code in (403, 404)
    assert await _rows(seed.inv_id) == []

    auth = _auth(team)
    await _call(cancel, auth, **ids)
    await _assert_one(
        seed.inv_id, stage="forensics", action="investigation_cancelled",
        target=f"investigation:{seed.inv_id}", auth=auth,
    )
    # Cancelling a terminal investigation is a no-op and records nothing.
    env = await _call(cancel, auth, **ids)
    assert env.data["already_terminal"] is True
    assert len(await _rows(seed.inv_id)) == 1


@pytest.mark.usefixtures("test_db")
async def test_forensics_project_delete_writes_one_row(queue: _RecordingQueue) -> None:
    team = _team()
    seed = await _seed_forensics(team)
    delete = _endpoint(create_forensics_router(), "/projects/{project_id}", "DELETE")
    with pytest.raises(HTTPException) as exc:
        await _call(delete, _auth(_team()), project_id=seed.project_id)
    assert exc.value.status_code in (403, 404)
    assert await _rows(seed.project_id) == []

    auth = _auth(team)
    await _call(delete, auth, project_id=seed.project_id)
    await _assert_one(
        seed.project_id, stage="forensics", action="project_deleted",
        target=f"project:{seed.project_id}", auth=auth,
    )
