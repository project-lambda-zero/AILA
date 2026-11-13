"""Write-up artifact references and loader-failure visibility (#448).

Investigator steps cite their artifact under ``provenance.primary_artifact``
and answer rows carry ``primary_artifact_id``; both must reach the stored
reference list. A failed artefact inventory load must be recorded in the
write-up methodology rather than silently dropped.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.db_models import (
    AnswerCandidateRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    WriteUpRecord,
)
from aila.modules.forensics.reporting import writeup_builder
from aila.modules.forensics.workflow.states import writeup as writeup_state
from aila.platform import uow as uow_module
from aila.platform.llm.client import LLMResponse
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


class _Emitter:
    async def emit(self, stream: str, message: str, meta: dict[str, Any] | None = None) -> None:
        return None


class _OkClient:
    async def chat(self, **_kwargs: Any) -> LLMResponse:
        return LLMResponse(
            content="writeup body", model="", usage={},
            disabled=False, finish_reason="stop",
        )


def _stub_llm_and_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        writeup_builder, "ServiceFactory",
        lambda: SimpleNamespace(llm_client=_OkClient()),
    )
    monkeypatch.setattr(writeup_builder, "_load_writeup_prompt", lambda: "system prompt")


def _stub_empty_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_artefacts(_project_id: str) -> dict[str, list[dict[str, Any]]]:
        return {}

    monkeypatch.setattr(writeup_builder, "_load_artefacts_by_family", _no_artefacts)


def _step(provenance: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    step: dict[str, Any] = {
        "step_number": 1,
        "action": "tool_run",
        "command": "strings sample.bin",
        "reasoning": "r",
        "stdout": "",
        "stderr": "",
    }
    if provenance is not None:
        step["provenance"] = provenance
    step.update(extra)
    return step


async def _build(steps: list[dict[str, Any]], answer_ids: list[str]) -> dict[str, Any]:
    return await writeup_builder.build_writeup(
        project_id="p-1",
        investigation_id="inv-1",
        steps=steps,
        input_context={"question": "q"},
        answer_artifact_ids=answer_ids,
    )


async def test_step_provenance_artifacts_are_stored_deduplicated_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_llm_and_prompt(monkeypatch)
    _stub_empty_inventory(monkeypatch)

    steps = [
        _step({"primary_artifact": "a.exe"}),
        _step({"primary_artifact": "b.dll"}),
        _step({"primary_artifact": "a.exe"}),
        _step({}),
        _step(None),
    ]

    out = await _build(steps, answer_ids=[])

    assert json.loads(out["artifacts_json"]) == ["a.exe", "b.dll"]


async def test_answer_artifact_ids_follow_step_artifacts_without_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_llm_and_prompt(monkeypatch)
    _stub_empty_inventory(monkeypatch)

    steps = [_step({"primary_artifact": "a.exe"}), _step({"primary_artifact": "b.dll"})]

    out = await _build(steps, answer_ids=["c.sys", "a.exe"])

    assert json.loads(out["artifacts_json"]) == ["a.exe", "b.dll", "c.sys"]


async def test_artifact_loader_failure_is_recorded_in_methodology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_llm_and_prompt(monkeypatch)

    class _BrokenUnitOfWork:
        async def __aenter__(self) -> None:
            raise RuntimeError("inventory store unavailable")

        async def __aexit__(self, *_exc: object) -> None:
            return None

    monkeypatch.setattr(uow_module, "UnitOfWork", _BrokenUnitOfWork)

    out = await _build([_step({"primary_artifact": "a.exe"})], answer_ids=[])

    assert "Artifact load failed (RuntimeError)" in out["methodology"]
    assert "evidence sections" in out["methodology"]
    assert json.loads(out["artifacts_json"]) == ["a.exe"]


async def test_persisted_writeup_references_step_and_answer_artifacts(
    test_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_llm_and_prompt(monkeypatch)
    _stub_empty_inventory(monkeypatch)

    suffix = uuid4().hex[:8]
    investigation_id = f"inv-{suffix}"
    async with async_session_scope() as session:
        sys_rec = ManagedSystemRecord(name=f"sys-{suffix}", host="10.0.0.1", username="u")
        session.add(sys_rec)
        await session.flush()
        proj = ForensicsProjectRecord(
            name=f"proj-{suffix}", system_id=sys_rec.id, evidence_directory="/evidence",
        )
        session.add(proj)
        await session.flush()
        project_id = proj.id
        session.add(InvestigationRunRecord(id=investigation_id, project_id=project_id, question="q"))
        session.add(AnswerCandidateRecord(
            project_id=project_id, investigation_id=investigation_id,
            question_text="q1", primary_artifact_id="c.sys",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        ))
        session.add(AnswerCandidateRecord(
            project_id=project_id, investigation_id=investigation_id,
            question_text="q2", primary_artifact_id="a.exe",
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        ))
        session.add(AnswerCandidateRecord(
            project_id=project_id, investigation_id=investigation_id,
            question_text="q3", primary_artifact_id=None,
            created_at=datetime(2026, 1, 3, tzinfo=UTC),
        ))
        await session.commit()

    steps = [_step({"primary_artifact": "b.dll"}), _step({"primary_artifact": "a.exe"})]
    await writeup_state.state_writeup(
        {
            "project_id": project_id,
            "investigation_id": investigation_id,
            "steps": steps,
            "question": "q",
        },
        SimpleNamespace(emitter=_Emitter()),
    )

    async with async_session_scope() as session:
        record = (await session.exec(
            select(WriteUpRecord).where(WriteUpRecord.project_id == project_id)
        )).one()

    assert json.loads(record.artifacts_referenced_json) == ["b.dll", "a.exe", "c.sys"]
