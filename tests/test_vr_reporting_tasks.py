"""VR reporting worker tasks: artifact storage, run_id threading, MASVS audit resolution.

The two report tasks run on the ``reporting`` track. These tests call the raw
coroutine (``__wrapped__``) with a ``TaskContext`` and stub the PDF renderer and
the artifact store. The DB-backed cases use the ``test_db`` fixture.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

import aila.modules.vr.reporting.tasks as report_tasks
from aila.modules.vr.contracts import InvestigationKind, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.worker import WorkerSettings
from aila.platform.uow import UnitOfWork

_PACKAGE = "com.example.demo"
_HANDLES: dict[str, Any] = {
    "android_mcp_static_summary": {"package": _PACKAGE},
    "android_mcp_package_name": _PACKAGE,
}


def _ctx(task_id: str = "task-1") -> TaskContext:
    return TaskContext(task_id=task_id, job_try=1, user_id="admin", team_id="admin")


class _Recorder:
    """Records store calls and hands back a fixed artifact id."""

    def __init__(self, artifact_id: int = 42) -> None:
        self.artifact_id = artifact_id
        self.pdf_calls: list[dict[str, Any]] = []
        self.json_calls: list[dict[str, Any]] = []

    async def store_pdf(self, **kwargs: Any) -> int:
        self.pdf_calls.append(kwargs)
        return self.artifact_id

    async def store_json(self, **kwargs: Any) -> None:
        self.json_calls.append(kwargs)


async def _insert_target(*, slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"reporting {slug}",
            slug=f"reporting-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"Demo {slug}",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/demo.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json=json.dumps(_HANDLES),
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _insert_investigation(
    *,
    target_id: str,
    kind: str,
    created_at: datetime,
) -> str:
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            secondary_target_refs_json="[]",
            kind=kind,
            title=f"{kind} {created_at.isoformat()}",
            initial_question="reporting task fixture",
            status=InvestigationStatus.CREATED.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.masvs_audit",
            cost_budget_usd=100.0,
            created_at=created_at,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        return inv.id


@pytest.mark.asyncio
async def test_investigation_report_stores_pdf_and_json_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder(artifact_id=42)
    render_calls: list[dict[str, Any]] = []

    async def _title(_inv_id: str, _team_id: str | None) -> str:
        return "Auth Bypass Hunt"

    async def _render(investigation_id: str, *, run_id: str | None = None) -> bytes:
        render_calls.append({"investigation_id": investigation_id, "run_id": run_id})
        return b"%PDF-1.4 stub"

    monkeypatch.setattr(report_tasks, "_investigation_title", _title)
    monkeypatch.setattr(report_tasks, "render_investigation_pdf", _render)
    monkeypatch.setattr(report_tasks, "store_task_pdf", recorder.store_pdf)
    monkeypatch.setattr(report_tasks, "store_task_json_result", recorder.store_json)

    result = await report_tasks.run_vr_investigation_report.__wrapped__(
        _ctx("task-inv"),
        investigation_id="inv-abcdef123456",
    )

    assert result == {
        "filename": "AILA_VR_Auth_Bypass_Hunt_inv-abcd.pdf",
        "artifact_id": 42,
    }
    assert render_calls == [
        {"investigation_id": "inv-abcdef123456", "run_id": "task-inv"},
    ], "every LLM call on the report path must carry the reporting task id"
    assert recorder.pdf_calls == [
        {"task_id": "task-inv", "content": b"%PDF-1.4 stub", "team_id": "admin"},
    ]
    assert recorder.json_calls == [
        {
            "task_id": "task-inv",
            "module_id": "vr",
            "payload": result,
            "team_id": "admin",
        },
    ]


@pytest.mark.asyncio
async def test_investigation_report_missing_investigation_raises_and_stores_nothing(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del test_db
    recorder = _Recorder()
    render_calls: list[str] = []

    async def _render(investigation_id: str, *, run_id: str | None = None) -> bytes:
        render_calls.append(investigation_id)
        return b"%PDF"

    monkeypatch.setattr(report_tasks, "render_investigation_pdf", _render)
    monkeypatch.setattr(report_tasks, "store_task_pdf", recorder.store_pdf)
    monkeypatch.setattr(report_tasks, "store_task_json_result", recorder.store_json)

    with pytest.raises(ValueError, match="not found"):
        await report_tasks.run_vr_investigation_report.__wrapped__(
            _ctx(),
            investigation_id="inv-does-not-exist",
        )

    assert render_calls == []
    assert recorder.pdf_calls == []
    assert recorder.json_calls == []


@pytest.mark.asyncio
async def test_masvs_report_without_audit_id_selects_latest_masvs_audit(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del test_db
    target_id = await _insert_target(slug="latest")
    await _insert_investigation(
        target_id=target_id,
        kind=InvestigationKind.MASVS_AUDIT.value,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    latest_audit_id = await _insert_investigation(
        target_id=target_id,
        kind=InvestigationKind.MASVS_AUDIT.value,
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    # Newer, but not a MASVS audit: must be skipped by the kind filter.
    await _insert_investigation(
        target_id=target_id,
        kind=InvestigationKind.AUDIT.value,
        created_at=datetime(2026, 9, 1, tzinfo=UTC),
    )

    recorder = _Recorder()
    collected: list[str] = []

    class _Aggregate:
        generated_at = datetime(2026, 6, 9, tzinfo=UTC)

    async def _collect(audit_id: str) -> _Aggregate:
        collected.append(audit_id)
        return _Aggregate()

    def _build(_aggregate: Any, _summary: Any, *, handles: dict[str, Any]) -> bytes:
        return b"%PDF-masvs"

    monkeypatch.setattr(report_tasks, "collect_findings", _collect)
    monkeypatch.setattr(report_tasks, "build_pdf", _build)
    monkeypatch.setattr(report_tasks, "store_task_pdf", recorder.store_pdf)
    monkeypatch.setattr(report_tasks, "store_task_json_result", recorder.store_json)

    result = await report_tasks.run_vr_masvs_report.__wrapped__(
        _ctx("task-masvs"),
        target_id=target_id,
        audit_id=None,
    )

    assert collected == [latest_audit_id]
    assert result == {
        "filename": f"masvs_{_PACKAGE}_20260609.pdf",
        "artifact_id": 42,
    }
    assert recorder.pdf_calls[0]["content"] == b"%PDF-masvs"


@pytest.mark.asyncio
async def test_masvs_report_rejects_audit_from_another_target(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del test_db
    target_a = await _insert_target(slug="owner")
    target_b = await _insert_target(slug="other")
    audit_a = await _insert_investigation(
        target_id=target_a,
        kind=InvestigationKind.MASVS_AUDIT.value,
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    recorder = _Recorder()
    collected: list[str] = []

    async def _collect(audit_id: str) -> None:
        collected.append(audit_id)

    monkeypatch.setattr(report_tasks, "collect_findings", _collect)
    monkeypatch.setattr(report_tasks, "store_task_pdf", recorder.store_pdf)
    monkeypatch.setattr(report_tasks, "store_task_json_result", recorder.store_json)

    with pytest.raises(ValueError, match="does not belong"):
        await report_tasks.run_vr_masvs_report.__wrapped__(
            _ctx(),
            target_id=target_b,
            audit_id=audit_a,
        )

    assert collected == []
    assert recorder.pdf_calls == []
    assert recorder.json_calls == []


def test_reporting_tasks_are_registered_on_worker() -> None:
    """Both report tasks are on the worker under their module-qualified names."""
    names = {getattr(fn, "name", None) for fn in WorkerSettings.functions}
    assert "aila.modules.vr.reporting.tasks.run_vr_investigation_report" in names
    assert "aila.modules.vr.reporting.tasks.run_vr_masvs_report" in names
