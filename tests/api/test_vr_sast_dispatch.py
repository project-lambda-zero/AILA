from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.api.auth import issue_jwt_token
from aila.modules.vr.contracts import InvestigationKind, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.sast import SAST_DETECTION_SKILLS, SAST_SKILLS, load_sast_skill
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ApiKeyRecord


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _source_target(slug: str, ready: bool = True) -> str:
    async with UnitOfWork() as uow:
        workspace = VRWorkspaceRecord(
            name=f"SAST {slug}", slug=f"sast-{slug}", description="", theme="custom", team_id="admin",
        )
        uow.session.add(workspace)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=workspace.id,
            team_id="admin",
            display_name=f"Source {slug}",
            kind="source_repo",
            descriptor_json=json.dumps({"repo_url": "https://example.test/repo", "ref": "main"}),
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json=json.dumps({"audit_mcp_index_id": "synthetic-index"}),
            status="active",
            analysis_state="ready" if ready else "pending",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _dispatch(client: AsyncClient, token: str, target_id: str):
    return await client.post(f"/vr/targets/{target_id}/sast-audit", headers=_auth(token))


@pytest.mark.asyncio
async def test_sast_dispatch_creates_all_skills_but_releases_only_analysis(
    async_client: AsyncClient, admin_token: str, test_db: None,
) -> None:
    del test_db
    target_id = await _source_target("dispatch")
    response = await _dispatch(async_client, admin_token, target_id)
    assert response.status_code == 201, response.text
    data = response.json()["data"]
    assert data["total_skills"] == 16
    assert data["total_detectors"] == 14
    assert len(data["child_investigation_ids"]) == 16
    assert set(data["enqueue_errors"]) <= {data["analysis_investigation_id"]}

    async with UnitOfWork() as uow:
        parent = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == data["parent_investigation_id"]),
        )).one()
        assert parent.kind == InvestigationKind.SAST_AUDIT.value
        children = list((await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.parent_investigation_id == parent.id),
        )).all())
        assert len(children) == 16
        by_skill = {}
        for child in children:
            refs = json.loads(child.secondary_target_refs_json)
            by_skill[refs[0]["sast_skill_id"]] = child
        assert set(by_skill) == {skill.id for skill in SAST_SKILLS}
        for skill in SAST_SKILLS:
            assert load_sast_skill(skill) in by_skill[skill.id].initial_question


@pytest.mark.asyncio
async def test_sast_dispatch_reuses_active_parent_and_requires_ready_source(
    async_client: AsyncClient, admin_token: str, test_db: None,
) -> None:
    del test_db
    target_id = await _source_target("idempotent")
    first = await _dispatch(async_client, admin_token, target_id)
    second = await _dispatch(async_client, admin_token, target_id)
    assert first.status_code == 201
    assert second.status_code == 200, second.text
    assert second.json()["data"]["idempotent_reuse"] is True
    assert second.json()["data"]["parent_investigation_id"] == first.json()["data"]["parent_investigation_id"]

    pending_id = await _source_target("pending", ready=False)
    pending = await _dispatch(async_client, admin_token, pending_id)
    assert pending.status_code == 409
    assert "completed source indexing" in pending.text


class _Queue:
    def __init__(self) -> None:
        self.submitted: list[str] = []

    async def enqueued_investigation_ids(self, ids: list[str]) -> set[str]:
        return set(self.submitted).intersection(ids)

    async def submit(self, *, kwargs: dict[str, str], **_: object) -> None:
        self.submitted.append(kwargs["investigation_id"])


async def _complete_child(child: VRInvestigationRecord, marker: str) -> None:
    async with UnitOfWork() as uow:
        current = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == child.id),
        )).one()
        branch = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(VRInvestigationBranchRecord.investigation_id == child.id),
        )).one()
        outcome = VRInvestigationOutcomeRecord(
            investigation_id=child.id,
            branch_id=branch.id,
            outcome_kind="assessment_report",
            payload_json=json.dumps({"summary": marker}),
            confidence="high",
            state="dispatched",
        )
        uow.session.add(outcome)
        await uow.session.flush()
        current.primary_outcome_id = outcome.id
        current.status = InvestigationStatus.COMPLETED.value
        uow.session.add(current)
        await uow.commit()


@pytest.mark.asyncio
async def test_sast_stage_gates_hand_off_architecture_then_all_detector_results(
    async_client: AsyncClient, admin_token: str, test_db: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    del test_db
    from aila.modules.vr.sast.orchestrator import advance_sast_batches  # noqa: PLC0415

    target_id = await _source_target("stages")
    response = await _dispatch(async_client, admin_token, target_id)
    assert response.status_code == 201
    data = response.json()["data"]
    queue = _Queue()
    monkeypatch.setattr("aila.modules.vr.sast.orchestrator.default_task_queue", lambda: queue)

    async with UnitOfWork() as uow:
        assert await advance_sast_batches(uow) == 0
    assert queue.submitted == []

    async with UnitOfWork() as uow:
        children = list((await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.parent_investigation_id == data["parent_investigation_id"]),
        )).all())
    by_skill = {json.loads(child.secondary_target_refs_json)[0]["sast_skill_id"]: child for child in children}
    await _complete_child(by_skill["sast-analysis"], "ARCHITECTURE_STAGE_MARKER")

    async with UnitOfWork() as uow:
        assert await advance_sast_batches(uow) == 14
        detectors = list((await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id.in_([
                child.id for skill, child in by_skill.items() if skill not in {"sast-analysis", "sast-report"}
            ])),
        )).all())
        assert all("ARCHITECTURE_STAGE_MARKER" in child.initial_question for child in detectors)
    assert len(queue.submitted) == 14
    assert by_skill["sast-report"].id not in queue.submitted

    for skill in SAST_DETECTION_SKILLS:
        await _complete_child(by_skill[skill.id], f"RESULT_STAGE_MARKER_{skill.id}")
    async with UnitOfWork() as uow:
        assert await advance_sast_batches(uow) == 1
        report = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == by_skill["sast-report"].id),
        )).one()
        assert "ARCHITECTURE_STAGE_MARKER" in report.initial_question
        for skill in SAST_DETECTION_SKILLS:
            assert f"RESULT_STAGE_MARKER_{skill.id}" in report.initial_question
    assert queue.submitted[-1] == by_skill["sast-report"].id

    aggregate = await async_client.get(
        f"/vr/targets/{target_id}/sast-audit-aggregate",
        params={"audit_id": data["parent_investigation_id"]},
        headers=_auth(admin_token),
    )
    assert aggregate.status_code == 200, aggregate.text
    assert len(aggregate.json()["data"]["results"]) == 16


@pytest.mark.asyncio
async def test_sast_workbench_projects_evidence_and_reads_confined_source(
    async_client: AsyncClient, admin_token: str, reader_key_record: ApiKeyRecord, test_db: None, tmp_path,
) -> None:
    del test_db
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("def handle(user_id):\n    return query(user_id)\n", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("secret", encoding="utf-8")
    target_id = await _source_target("workbench")
    response = await _dispatch(async_client, admin_token, target_id)
    assert response.status_code == 201
    parent_id = response.json()["data"]["parent_investigation_id"]

    async with UnitOfWork() as uow:
        target = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id),
        )).one()
        target.mcp_handles_json = json.dumps({
            "audit_mcp_index_id": "synthetic-index", "mcp_path": str(source),
        })
        child = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.parent_investigation_id == parent_id,
            ),
        )).all()
        sqli = next(row for row in child if "sast-sqli" in row.secondary_target_refs_json)
        branch = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id == sqli.id,
            ),
        )).one()
        outcome = VRInvestigationOutcomeRecord(
            investigation_id=sqli.id,
            branch_id=branch.id,
            outcome_kind="direct_finding",
            payload_json=json.dumps({
                "message": "User id reaches SQL query",
                "description": "Untrusted input is concatenated into a query.",
                "severity": "high",
                "source_ref": "app.py:2",
                "related_locations": [{"path": "app.py", "line_start": 1}],
            }),
            confidence="high",
            state="dispatched",
        )
        uow.session.add(outcome)
        sqli.primary_outcome_id = outcome.id
        await uow.commit()

    aggregate = await async_client.get(
        f"/vr/targets/{target_id}/sast-audit-aggregate",
        params={"audit_id": parent_id}, headers=_auth(admin_token),
    )
    assert aggregate.status_code == 200, aggregate.text
    diagnostic = aggregate.json()["data"]["diagnostics"][0]
    assert diagnostic["path"] == "app.py"
    assert diagnostic["line_start"] == 2
    assert diagnostic["related_locations"][0]["line_start"] == 1

    files = await async_client.get(
        f"/vr/targets/{target_id}/sast-audit-files",
        params={"audit_id": parent_id}, headers=_auth(admin_token),
    )
    assert files.status_code == 200, files.text
    assert files.json()["data"] == {
        "complete": True,
        "files": [{"path": "app.py", "language": "python", "diagnostic_count": 1}],
    }
    content = await async_client.get(
        f"/vr/targets/{target_id}/sast-audit-source",
        params={"audit_id": parent_id, "path": "app.py"}, headers=_auth(admin_token),
    )
    assert content.status_code == 200, content.text
    assert content.json()["data"]["content"].startswith("def handle")
    traversal = await async_client.get(
        f"/vr/targets/{target_id}/sast-audit-source",
        params={"audit_id": parent_id, "path": "../outside.py"}, headers=_auth(admin_token),
    )
    assert traversal.status_code == 400

    async with UnitOfWork() as uow:
        target = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id),
        )).one()
        target.team_id = "another-team"
        await uow.commit()
    async with UnitOfWork() as uow:
        scoped_key = await uow.session.get(ApiKeyRecord, reader_key_record.id)
        assert scoped_key is not None
        scoped_key.team_id = "admin"
        await uow.commit()
    reader_key_record.team_id = "admin"
    scoped_reader_token, _ = issue_jwt_token(reader_key_record)
    denied = await async_client.get(
        f"/vr/targets/{target_id}/sast-audit-source",
        params={"audit_id": parent_id, "path": "app.py"}, headers=_auth(scoped_reader_token),
    )
    assert denied.status_code == 404
