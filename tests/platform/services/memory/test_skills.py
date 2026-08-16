"""Procedural (skill-library) tier tests (issue #150).

Covers the observable contract of
:mod:`aila.platform.services.memory.skills`:

* the sweep reads confirmed-outcome investigations across every
  :class:`OutcomeRecordBase` subclass registered at import time and
  joins each to its own module's investigation table;
* for every candidate it either lifts a structured strategy blurb off
  the outcome payload OR runs a caller-supplied LLM stub to distill
  one, then writes ONE skill row per investigation under the
  team-scoped ``skill.team.<team_id>`` bucket the module scope helpers
  advertise;
* the resulting row is visible to the exact retrieval path an agent
  runs at investigation setup (``KnowledgeService.retrieve_routed``
  scoped to ``malware_knowledge_namespaces``), proving the writer
  feeds a live reader;
* a repeat sweep is idempotent per investigation (no re-charging the
  LLM, no duplicate rows).

Runs against the shared ``test_db`` fixture so the pgvector column,
FTS index, and HNSW index all evaluate under the driver a production
install uses.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select as sm_select

# Import the malware db_models so their SQLModel table classes register
# on the shared metadata AND their InvestigationRecordBase +
# OutcomeRecordBase subclasses are picked up by the sweep's
# ``__subclasses__`` scan.
from aila.modules.malware.db_models import (
    MalwareInvestigationBranchRecord,
    MalwareInvestigationOutcomeRecord,
    MalwareInvestigationRecord,
    MalwareTargetRecord,
    MalwareWorkspaceRecord,
)
from aila.modules.malware.services.knowledge_scope import (
    malware_knowledge_namespaces,
)
from aila.platform.contracts.enums import InvestigationStatus, OutcomeConfidence
from aila.platform.services import knowledge as knowledge_mod
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.memory.skills import (
    SKILL_DEDUP_PREFIX,
    SKILL_GLOBAL_NAMESPACE,
    _extract_structured_approach,
    _parse_approach,
    _problem_shape,
    extract_recent_skills,
    skill_namespace,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

pytestmark = pytest.mark.asyncio


_STUB_EMBEDDING: list[float] = [1.0] * 1024


class _StubEmbeddingProvider:
    """Deterministic embedding stub. Records every ``encode`` call."""

    def __init__(self) -> None:
        self.encode_calls: list[str] = []

    @property
    def dimension(self) -> int:
        return 1024

    @property
    def model_name(self) -> str:
        return "stub-skill-library"

    def encode(self, text: str) -> list[float]:
        self.encode_calls.append(text)
        return list(_STUB_EMBEDDING)

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


class _StubLLMResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _StubLLMClient:
    """Minimal ``AilaLLMClient`` surface the skill-library sweep uses.

    Records every call so tests can assert the LLM is skipped when a
    structured strategy is present on the payload and not re-invoked
    on a repeat sweep.
    """

    def __init__(self, payloads: dict[str, str], default_payload: str) -> None:
        self._payloads = payloads
        self._default = default_payload
        self.calls: list[dict[str, object]] = []

    async def chat_json(
        self,
        task_type: str,
        messages: list[dict[str, str]],
        schema: dict[str, object],
        *,
        run_id: str | None = None,
        team_id: str | None = None,
        max_output_tokens: int | None = None,
    ) -> _StubLLMResponse:
        del schema, max_output_tokens
        self.calls.append({
            "task_type": task_type,
            "run_id": run_id,
            "team_id": team_id,
            "user": messages[-1]["content"],
        })
        payload = self._payloads.get(run_id or "", self._default)
        return _StubLLMResponse(payload)


async def _seed_investigation_with_outcome(
    *,
    workspace_id: str,
    target_id: str,
    investigation_id: str,
    slug_suffix: str,
    outcome_kind: str,
    payload: dict[str, object],
    confidence: str = OutcomeConfidence.STRONG.value,
    status: str = InvestigationStatus.COMPLETED.value,
    updated_at: datetime | None = None,
    team_id: str | None = None,
    outcome_state: str = "dispatched",
    strategy_family: str = "malware.full_analysis",
) -> str:
    """Insert workspace + target + investigation + branch + outcome atomically.

    Returns the created outcome id so the caller can join back to the
    stored skill row.
    """
    stamp = updated_at or (datetime.now(UTC) - timedelta(days=2))
    async with async_session_scope() as session:
        session.add(MalwareWorkspaceRecord(
            id=workspace_id, team_id=team_id,
            name=f"ws-{slug_suffix}", slug=f"ws-{slug_suffix}",
        ))
        await session.flush()
        session.add(MalwareTargetRecord(
            id=target_id, team_id=team_id, workspace_id=workspace_id,
            display_name=f"sample-{slug_suffix}", kind="pe_sample",
        ))
        await session.flush()
        session.add(MalwareInvestigationRecord(
            id=investigation_id, team_id=team_id, target_id=target_id,
            title=f"inv-{slug_suffix}", strategy_family=strategy_family,
            status=status, updated_at=stamp,
        ))
        await session.flush()
        branch = MalwareInvestigationBranchRecord(
            investigation_id=investigation_id,
        )
        session.add(branch)
        await session.flush()
        outcome = MalwareInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch.id,
            outcome_kind=outcome_kind,
            payload_json=json.dumps(payload),
            confidence=confidence,
            state=outcome_state,
        )
        session.add(outcome)
        await session.commit()
        return outcome.id


def _build_knowledge_service() -> KnowledgeService:
    """A KnowledgeService whose embedder is the local deterministic stub.

    Also drops the process-wide stable-core cache so a prior test's
    seeded rows do not bleed into this one via the CAG preload.
    """
    knowledge_mod._STABLE_CORE_CACHE.invalidate()
    return KnowledgeService(provider=_StubEmbeddingProvider())


# ---------------------------------------------------------------------------
# Unit-level: pure helpers exercised without a DB round-trip
# ---------------------------------------------------------------------------


def test_skill_namespace_team_and_global() -> None:
    assert skill_namespace("team-42") == "skill.team.team-42"
    assert skill_namespace(None) == SKILL_GLOBAL_NAMESPACE == "skill.global"


def test_problem_shape_stable_prose() -> None:
    """The embedded ``content`` string is a stable, sortable prose line."""
    shape = _problem_shape(
        module_id="malware",
        target_kind="pe_sample",
        outcome_kind="yara_rule",
        strategy_family="malware.yara_generate",
    )
    assert shape == (
        "malware target_kind=pe_sample outcome_kind=yara_rule "
        "strategy_family=malware.yara_generate"
    )
    # A missing strategy_family collapses to ``generic`` -- the shape
    # never carries an empty handle.
    assert "strategy_family=generic" in _problem_shape(
        module_id="vr", target_kind="apk", outcome_kind="direct_finding",
        strategy_family=None,
    )


def test_extract_structured_approach_prefers_first_non_empty() -> None:
    """The structured extractor picks the highest-precedence non-empty field."""
    assert _extract_structured_approach({
        "strategy_summary": " lift the mutex hint ", "description": "other",
    }) == "lift the mutex hint"
    # Falls through to ``summary`` when the earlier keys are missing /
    # empty. Whitespace is collapsed.
    assert _extract_structured_approach({
        "summary": "keep\n\nreading section headers first",
    }) == "keep reading section headers first"
    # No structured field -> None so the caller can fall back to LLM.
    assert _extract_structured_approach({"other": "value"}) is None
    assert _extract_structured_approach({"summary": "   "}) is None


def test_parse_approach_returns_empty_on_junk() -> None:
    assert _parse_approach("") == ""
    assert _parse_approach("not json") == ""
    assert _parse_approach("[]") == ""
    assert _parse_approach('{"other": "x"}') == ""
    assert _parse_approach(
        '{"approach": "trim   whitespace\\nplease"}',
    ) == "trim whitespace please"


# ---------------------------------------------------------------------------
# DB-backed: end-to-end sweep against the shared test_db fixture
# ---------------------------------------------------------------------------


async def test_skill_extractor_writes_from_structured_payload_visible_to_reader(
    test_db,
) -> None:
    """Sweep prefers the structured strategy blurb and hits the live reader.

    Proves:
    * a payload that already carries a ``summary`` skips the LLM
      entirely (the STRONG-tier structured path is what covers most
      malware outcomes today);
    * the skill lands under the team-scoped ``skill.team.<team_id>``
      bucket the malware scope helper advertises;
    * a follow-up ``retrieve_routed`` scoped to
      ``malware_knowledge_namespaces`` -- i.e. the exact list an agent
      sees at investigation setup -- surfaces the skill row, so the
      writer feeds a live reader.
    """
    del test_db
    ws_id = "ws-skill-struct"
    target_id = "tgt-skill-struct"
    inv_id = "inv-skill-struct"
    team_id = "team-skill-1"
    outcome_id = await _seed_investigation_with_outcome(
        workspace_id=ws_id, target_id=target_id, investigation_id=inv_id,
        slug_suffix="struct", team_id=team_id,
        outcome_kind="yara_rule",
        payload={
            "summary": (
                "trigger on the unpacker's aplib decompressor call and "
                "the section-rename fingerprint together"
            ),
            "rule": "rule Foo { condition: true }",
        },
        strategy_family="malware.yara_generate",
    )

    # An LLM that would explode if called; a structured payload MUST
    # skip the model entirely.
    llm = _StubLLMClient(
        payloads={inv_id: json.dumps({"approach": "SHOULD NOT BE USED"})},
        default_payload="",
    )
    knowledge = _build_knowledge_service()

    report = await extract_recent_skills(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0, max_investigations=25,
    )
    assert report["scanned"] == 1
    assert report["skills_written"] == 1
    assert report["skipped_already"] == 0
    assert report["errors"] == 0
    assert llm.calls == [], (
        "structured strategy MUST short-circuit the LLM; got calls: "
        f"{llm.calls}"
    )

    expected_namespace = skill_namespace(team_id)
    assert expected_namespace == f"skill.team.{team_id}"
    expected_shape = _problem_shape(
        module_id="malware", target_kind="pe_sample",
        outcome_kind="yara_rule",
        strategy_family="malware.yara_generate",
    )

    async with async_session_scope() as session:
        rows = (await session.exec(
            sm_select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.namespace == expected_namespace,
            ),
        )).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.content == expected_shape
    assert row.dedup_key == f"{SKILL_DEDUP_PREFIX}:{inv_id}"
    stored_meta = json.loads(row.entry_metadata)
    assert stored_meta["source"] == "skill_library"
    assert stored_meta["investigation_id"] == inv_id
    assert stored_meta["outcome_id"] == outcome_id
    assert stored_meta["outcome_kind"] == "yara_rule"
    assert stored_meta["confidence"] == OutcomeConfidence.STRONG.value
    assert stored_meta["team_id"] == team_id
    assert stored_meta["target_kind"] == "pe_sample"
    assert stored_meta["strategy_family"] == "malware.yara_generate"
    assert "aplib decompressor" in stored_meta["approach"]
    assert stored_meta["resolved_at"], "resolved_at MUST be stamped"

    # LIVE READER: retrieve through the exact scope the setup-time
    # resolver seeds so a match proves the skill compound path is
    # wired end-to-end. Query the shape from a peer investigation's
    # perspective (different workspace, same team).
    peer_namespaces = malware_knowledge_namespaces("ws-peer", team_id)
    assert expected_namespace in peer_namespaces, (
        "team-scoped skill namespace MUST be part of the module scope"
    )
    routed = await knowledge.retrieve_routed(
        query=expected_shape,
        route="simple",
        namespaces=peer_namespaces,
        limit=5,
        min_score=0.0,
    )
    assert routed["count"] >= 1
    surfaced = next(
        (h for h in routed["results"] if h.get("namespace") == expected_namespace),
        None,
    )
    assert surfaced is not None, (
        f"live reader failed to surface team-scoped skill; hits={routed['results']}"
    )
    assert surfaced["content"] == expected_shape


async def test_skill_extractor_falls_back_to_llm_when_no_structured_field(
    test_db,
) -> None:
    """When no structured strategy is present the LLM stub is invoked.

    Also proves the second (repeat) sweep is idempotent: no additional
    LLM call, no duplicate row.
    """
    del test_db
    ws_id = "ws-skill-llm"
    target_id = "tgt-skill-llm"
    inv_id = "inv-skill-llm"
    team_id = "team-skill-2"
    await _seed_investigation_with_outcome(
        workspace_id=ws_id, target_id=target_id, investigation_id=inv_id,
        slug_suffix="llm", team_id=team_id,
        outcome_kind="config_extractor_script",
        # No summary/description/report_body -- forces the LLM path.
        payload={"language": "python", "extractor_source": "def x():\n  pass\n"},
        strategy_family="malware.config_extract",
    )

    approach = "grep the .rdata segment for the ordered key blob first"
    llm = _StubLLMClient(
        payloads={inv_id: json.dumps({"approach": approach})},
        default_payload="",
    )
    knowledge = _build_knowledge_service()

    first = await extract_recent_skills(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0, max_investigations=25,
    )
    assert first["skills_written"] == 1
    assert first["skipped_already"] == 0
    assert first["errors"] == 0
    assert len(llm.calls) == 1
    assert llm.calls[0]["run_id"] == inv_id
    assert llm.calls[0]["team_id"] == team_id

    second = await extract_recent_skills(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0, max_investigations=25,
    )
    assert second["skills_written"] == 0
    assert second["skipped_already"] == 1
    # Zero additional LLM calls -- the dedup-key existence check
    # short-circuited before dispatch.
    assert len(llm.calls) == 1

    expected_namespace = skill_namespace(team_id)
    async with async_session_scope() as session:
        rows = (await session.exec(
            sm_select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.namespace == expected_namespace,
            ),
        )).all()
    assert len(rows) == 1
    stored_meta = json.loads(rows[0].entry_metadata)
    assert stored_meta["approach"] == approach
    assert stored_meta["outcome_kind"] == "config_extractor_script"


async def test_skill_extractor_skips_stalled_and_draft_outcomes(
    test_db,
) -> None:
    """Non-terminal / draft / negative-outcome rows never produce a skill."""
    del test_db
    now = datetime.now(UTC)
    llm = _StubLLMClient(payloads={}, default_payload="")
    knowledge = _build_knowledge_service()

    # A stalled investigation with an otherwise-good outcome.
    await _seed_investigation_with_outcome(
        workspace_id="ws-skip-1", target_id="tgt-skip-1",
        investigation_id="inv-skip-1", slug_suffix="skip1",
        team_id="team-skip",
        outcome_kind="analysis_report",
        payload={"summary": "will not become a skill"},
        confidence=OutcomeConfidence.STRONG.value,
        status=InvestigationStatus.STALLED.value,
        updated_at=now - timedelta(days=2),
    )
    # A completed investigation whose outcome is still in draft.
    await _seed_investigation_with_outcome(
        workspace_id="ws-skip-2", target_id="tgt-skip-2",
        investigation_id="inv-skip-2", slug_suffix="skip2",
        team_id="team-skip",
        outcome_kind="analysis_report",
        payload={"summary": "not dispatched yet"},
        confidence=OutcomeConfidence.STRONG.value,
        updated_at=now - timedelta(days=2),
        outcome_state="draft",
    )
    # A completed investigation whose outcome is a negative /
    # stalled-report kind.
    await _seed_investigation_with_outcome(
        workspace_id="ws-skip-3", target_id="tgt-skip-3",
        investigation_id="inv-skip-3", slug_suffix="skip3",
        team_id="team-skip",
        outcome_kind="stalled_report",
        payload={"summary": "should never become a skill"},
        confidence=OutcomeConfidence.STRONG.value,
        updated_at=now - timedelta(days=2),
    )

    report = await extract_recent_skills(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0, max_investigations=25,
    )
    assert report["scanned"] == 0
    assert report["skills_written"] == 0
    assert llm.calls == []

    async with async_session_scope() as session:
        rows = (await session.exec(
            sm_select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.namespace == skill_namespace("team-skip"),
            ),
        )).all()
    assert rows == []


async def test_skill_extractor_empty_when_no_candidates(test_db) -> None:
    """Zero candidates -> zero LLM calls, zero writes, well-formed report."""
    del test_db
    llm = _StubLLMClient(payloads={}, default_payload="")
    knowledge = _build_knowledge_service()
    report = await extract_recent_skills(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=0.0, max_investigations=25,
    )
    assert report == {
        "scanned": 0,
        "skills_written": 0,
        "skipped_already": 0,
        "skipped_no_target": 0,
        "skipped_no_approach": 0,
        "errors": 0,
    }
    assert llm.calls == []
