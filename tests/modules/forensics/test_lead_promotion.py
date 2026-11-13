"""Lead promotion in the freeflow and full-analysis workflows.

Only investigator-written artifacts (``source_investigation_id`` set) become
leads. The freeflow workflow promotes the artifacts its own investigation
wrote before the writeup; full analysis promotes every investigator artifact
of the project that has no lead yet. Artifacts, leads, and the workflow
definition run against the test database; only the emitter is a fake.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.db_models import (
    ArtifactRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    LeadRecord,
)
from aila.modules.forensics.workflow.definitions import FORENSICS_FREEFLOW_V1
from aila.modules.forensics.workflow.states.promotion import state_promotion
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


class _Emitter:
    async def emit(self, stream: str, message: str, meta: dict[str, Any] | None = None) -> None:
        return None


def _services() -> SimpleNamespace:
    return SimpleNamespace(emitter=_Emitter())


async def _seed() -> dict[str, str]:
    suffix = uuid4().hex[:8]
    ids = {
        "project": f"proj-{suffix}",
        "inv_a": f"inv-a-{suffix}",
        "inv_b": f"inv-b-{suffix}",
        "summary_a": f"art-sa-{suffix}",
        "summary_b": f"art-sb-{suffix}",
        "collector": f"art-c-{suffix}",
    }
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=ids["project"], name=f"test-{suffix}", system_id=0,
            evidence_directory="/evidence", analyzer_os="linux",
        ))
        await session.flush()
        for inv in ("inv_a", "inv_b"):
            session.add(InvestigationRunRecord(
                id=ids[inv], project_id=ids["project"], question="what happened", status="running",
            ))
        await session.flush()
        for art, inv in (("summary_a", "inv_a"), ("summary_b", "inv_b")):
            session.add(ArtifactRecord(
                id=ids[art], project_id=ids["project"], artifact_type="investigation_summary",
                artifact_family="execution", source_investigation_id=ids[inv],
                data_json=json.dumps({"confidence": "strong", "answer": "persistence via run key"}),
            ))
        session.add(ArtifactRecord(
            id=ids["collector"], project_id=ids["project"], artifact_type="prefetch",
            artifact_family="execution", source_investigation_id=None,
            data_json=json.dumps({"path": "C:/Windows/Temp/backdoor.exe", "note": "malicious"}),
        ))
        await session.commit()
    return ids


async def _leads(project_id: str) -> list[str]:
    async with async_session_scope() as session:
        rows = (await session.exec(select(LeadRecord).where(LeadRecord.project_id == project_id))).all()
        return sorted(r.artifact_id for r in rows)


def _freeflow_output(ids: dict[str, str]) -> dict[str, Any]:
    return {
        "investigation_id": ids["inv_a"],
        "project_id": ids["project"],
        "question": "what happened",
        "answer": "persistence via run key",
        "confidence": "strong",
        "attempts_used": 2,
        "steps": [{"step_number": 1}],
    }


async def test_freeflow_promotes_only_its_own_investigator_artifacts() -> None:
    ids = await _seed()
    spec = FORENSICS_FREEFLOW_V1.states["promotion"]
    freeflow_output = _freeflow_output(ids)

    result = await spec.handler(freeflow_output, _services())

    assert await _leads(ids["project"]) == [ids["summary_a"]]
    assert result.next_state == spec.on_success == "writeup"
    assert result.output == freeflow_output

    # A retried promotion state creates no second lead.
    await spec.handler(freeflow_output, _services())
    assert await _leads(ids["project"]) == [ids["summary_a"]]


async def test_full_analysis_skips_artifacts_already_promoted_by_freeflow() -> None:
    ids = await _seed()
    await FORENSICS_FREEFLOW_V1.states["promotion"].handler(_freeflow_output(ids), _services())

    result = await state_promotion({"project_id": ids["project"]}, _services())

    assert await _leads(ids["project"]) == sorted([ids["summary_a"], ids["summary_b"]])
    assert result.output["lead_count"] == 1
    assert result.next_state == "resolution"


async def test_collector_artifacts_never_become_leads() -> None:
    ids = await _seed()

    await state_promotion({"project_id": ids["project"]}, _services())

    assert ids["collector"] not in await _leads(ids["project"])
