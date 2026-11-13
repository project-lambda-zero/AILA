"""Forensics ``artifact_query`` action and tool-key coverage (#453).

The investigator prompt names ``artifact_query`` as a decision action. The
shared ``ReasoningAction`` schema must accept it, and the investigator must
dispatch it against the real artifact store. Every alias in the forensics tool
catalog must also have a tool key.

Only the provider call and the SSH-backed tool methods are replaced. Artifact
rows, investigation rows, and the query itself run against the test database.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

import pytest

from aila.modules.forensics.agents import investigator as investigator_module
from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.modules.forensics.db_models import (
    ArtifactRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.tool_catalog import iter_tool_specs
from aila.modules.forensics.tool_keys import all_tool_keys
from aila.platform.contracts.reasoning import ReasoningTurnDecision
from aila.platform.prompts import LoadedPrompt
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.storage.database import async_session_scope

Decide = Callable[[int], Awaitable[ReasoningTurnDecision]]


class _Emitter:
    def __init__(self) -> None:
        self.stages: list[str] = []

    async def emit(self, stream: str, message: str, meta: dict[str, Any] | None = None) -> None:
        self.stages.append(str((meta or {}).get("stage", "")))


class _Graphs:
    async def save_snapshot(self, **_kwargs: Any) -> None:
        return None


@pytest.fixture
def ssh_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Ledger of shell commands the investigator would send to the analyzer."""
    ledger: list[str] = []

    async def fake_command(self: HonestInvestigator, command: str) -> dict[str, Any]:
        ledger.append(command)
        return {"stdout": "", "stderr": "", "exit_code": 0}

    async def fake_prompt(analyzer_os: str, *, investigation_id: str) -> LoadedPrompt:
        return LoadedPrompt(body="system prompt", version=None)

    monkeypatch.setattr(HonestInvestigator, "_execute_command", fake_command)
    monkeypatch.setattr(investigator_module, "_resolve_freeflow_prompt", fake_prompt)
    return ledger


def _artifact_query_decision(search_text: str) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        reasoning="look up the beacon artifacts",
        action="artifact_query",
        command=search_text,
    )


def _always(decision: ReasoningTurnDecision) -> Decide:
    async def decide(_call_number: int) -> ReasoningTurnDecision:
        return decision

    return decide


def _engine(decide: Decide) -> CyberReasoningEngine:
    engine = CyberReasoningEngine(None)  # type: ignore[arg-type]

    async def decide_next_turn(**_kwargs: Any) -> ReasoningTurnDecision:
        return await decide(1)

    engine.decide_next_turn = decide_next_turn  # type: ignore[method-assign]
    return engine


def _investigator(engine: CyberReasoningEngine, project_id: str, inv_id: str) -> HonestInvestigator:
    return HonestInvestigator(
        settings=None,  # type: ignore[arg-type]
        reasoning_engine=engine,
        reasoning_graphs=_Graphs(),  # type: ignore[arg-type]
        run_id=f"run-{inv_id}",
        integration={},
        project_id=project_id,
        investigation_id=inv_id,
        analyzer_os="linux",
    )


async def _seed_project_with_artifacts() -> tuple[str, str, str, str]:
    """Return (project_id, inv_id, matching_artifact_id, other_artifact_id)."""
    suffix = uuid4().hex[:8]
    project_id = f"proj-{suffix}"
    inv_id = f"inv-{suffix}"
    matching = ArtifactRecord(
        project_id=project_id,
        artifact_family="network",
        artifact_type="flow",
        source_tool="tshark_runner",
        data_json=json.dumps({"dst": "203.0.113.7", "note": "beacon interval 60s"}),
        lead_score=0.9,
    )
    other = ArtifactRecord(
        project_id=project_id,
        artifact_family="registry",
        artifact_type="run_key",
        source_tool="registry_viewer",
        data_json=json.dumps({"value": "Updater.exe"}),
        lead_score=0.1,
    )
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id,
            name=f"test-{suffix}",
            system_id=0,
            evidence_directory="/evidence",
            analyzer_os="linux",
        ))
        await session.flush()
        session.add(InvestigationRunRecord(
            id=inv_id,
            project_id=project_id,
            question="what beaconed",
            status="pending",
        ))
        session.add(matching)
        session.add(other)
        await session.commit()
    return project_id, inv_id, matching.id, other.id


def test_artifact_query_is_a_valid_reasoning_action() -> None:
    decision = _artifact_query_decision("beacon")

    assert decision.action == "artifact_query"
    assert decision.command == "beacon"


@pytest.mark.usefixtures("test_db")
async def test_artifact_query_turn_returns_matching_seeded_artifacts(
    ssh_calls: list[str],
) -> None:
    project_id, inv_id, matching_id, other_id = await _seed_project_with_artifacts()
    emitter = _Emitter()
    engine = _engine(_always(_artifact_query_decision("beacon")))

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what beaconed", max_attempts=1, emitter=emitter,
    )

    assert ssh_calls == []
    step = result["steps"][0]
    assert step["action"] == "artifact_query"
    assert step["exit_code"] == 0
    returned = json.loads(step["stdout"])
    assert [artifact["id"] for artifact in returned["artifacts"]] == [matching_id]
    assert other_id not in step["stdout"]
    assert "artifact_query" in emitter.stages


@pytest.mark.usefixtures("test_db")
async def test_artifact_query_without_search_text_lists_project_artifacts(
    ssh_calls: list[str],
) -> None:
    project_id, inv_id, matching_id, other_id = await _seed_project_with_artifacts()
    engine = _engine(_always(_artifact_query_decision("")))

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what beaconed", max_attempts=1, emitter=_Emitter(),
    )

    assert ssh_calls == []
    step = result["steps"][0]
    assert step["exit_code"] == 0
    returned_ids = {artifact["id"] for artifact in json.loads(step["stdout"])["artifacts"]}
    assert returned_ids == {matching_id, other_id}


def test_tool_keys_cover_every_forensics_catalog_alias() -> None:
    catalog_keys = {spec.key() for spec in iter_tool_specs()}

    assert catalog_keys == set(all_tool_keys())
