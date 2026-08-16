"""Semantic-tier consolidator tests (issue #150).

Covers the observable contract of
:mod:`aila.platform.services.memory.consolidator`:

* the sweep reads terminal-status investigations across every
  :class:`InvestigationRecordBase` subclass registered at import time;
* runs a caller-supplied LLM stub to distill each investigation's
  ledger traces into de-contextualized facts;
* writes those facts to the module's live-read
  ``<module>.semantic.workspace.<id>`` namespace in the pgvector
  knowledge store;
* the resulting rows are visible to the exact retrieval path an
  agent runs (`KnowledgeService.retrieve_routed` scoped to the module's
  namespace list), proving the writer feeds a live reader; and
* a repeat sweep is idempotent per investigation (no re-charging the
  LLM, no duplicate rows) and a still-active investigation is skipped.

Runs against the shared ``test_db`` fixture so the pgvector column,
FTS index, and HNSW index all evaluate under the same driver a
production install uses.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select as sm_select

# Import the malware db_models so their SQLModel table classes register
# on the shared metadata AND their InvestigationRecordBase subclass is
# picked up by the consolidator's ``__subclasses__`` scan. Without this
# side-effect import the scan runs against an empty registry and the
# sweep sees zero candidates.
from aila.modules.malware.db_models import (
    MalwareInvestigationRecord,
    MalwareTargetRecord,
    MalwareWorkspaceRecord,
)
from aila.modules.malware.services.knowledge_scope import (
    malware_knowledge_namespaces,
)
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.services import knowledge as knowledge_mod
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.ledger import LedgerService
from aila.platform.services.memory.consolidator import (
    DEDUP_KEY_PREFIX,
    SEMANTIC_NAMESPACE_KIND,
    _parse_facts,
    _render_traces,
    consolidate_recent_investigations,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

pytestmark = pytest.mark.asyncio


# All-ones vector: matches the pgvector column width (1024) and keeps
# cosine_distance well-defined so the FTS + vector legs both rank
# deterministically. Mirrors the pattern in
# ``tests/platform/services/test_knowledge_retrieval.py``.
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
        return "stub-consolidator"

    def encode(self, text: str) -> list[float]:
        self.encode_calls.append(text)
        return list(_STUB_EMBEDDING)

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


class _StubLLMResponse:
    """Duck-typed shim mirroring ``LLMResponse`` for the consolidator."""

    def __init__(self, content: str) -> None:
        self.content = content


class _StubLLMClient:
    """Minimal ``AilaLLMClient`` surface the consolidator uses.

    Records every call so a test can assert that a re-run of an
    already-consolidated investigation does NOT re-invoke the model.
    Returns a caller-supplied JSON payload keyed off the incoming
    ``messages`` so a batch with multiple investigations can hand
    each one its own canned facts.
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


async def _seed_investigation(
    *,
    workspace_id: str,
    target_id: str,
    investigation_id: str,
    slug_suffix: str,
    status: str,
    updated_at: datetime,
    team_id: str | None = None,
) -> None:
    """Insert the workspace + target + investigation triple in one commit.

    Every FK is committed together so the consolidator's scan sees a
    self-consistent row set. ``updated_at`` is stamped explicitly so the
    inactivity-window filter fires deterministically against a controlled
    clock instead of the SQLModel default.
    """
    async with async_session_scope() as session:
        session.add(
            MalwareWorkspaceRecord(
                id=workspace_id,
                team_id=team_id,
                name=f"ws-{slug_suffix}",
                slug=f"ws-{slug_suffix}",
            ),
        )
        await session.flush()
        session.add(
            MalwareTargetRecord(
                id=target_id,
                team_id=team_id,
                workspace_id=workspace_id,
                display_name=f"sample-{slug_suffix}",
                kind="pe_sample",
            ),
        )
        await session.flush()
        session.add(
            MalwareInvestigationRecord(
                id=investigation_id,
                team_id=team_id,
                target_id=target_id,
                title=f"inv-{slug_suffix}",
                strategy_family="default",
                status=status,
                updated_at=updated_at,
            ),
        )
        await session.commit()


async def _seed_ledger_entries(
    investigation_id: str, entries: list[tuple[str, str, dict[str, object]]],
) -> None:
    """Append (kind, author_branch, payload) tuples to the shared ledger."""
    ledger = LedgerService()
    for index, (kind, author, payload) in enumerate(entries):
        await ledger.append_general(
            investigation_id, author, kind, payload,
            idempotency_key=f"seed:{investigation_id}:{index}",
        )


def _facts_json(facts: list[str]) -> str:
    return json.dumps({"facts": facts})


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


def test_parse_facts_returns_empty_on_junk_response() -> None:
    """Model reply that is not a JSON object with a ``facts`` list returns []."""
    assert _parse_facts("", cap=5) == []
    assert _parse_facts("not json", cap=5) == []
    assert _parse_facts('["bare", "array"]', cap=5) == []
    assert _parse_facts('{"other": []}', cap=5) == []


def test_parse_facts_caps_and_trims() -> None:
    """The parser drops empty strings, collapses whitespace, and honors cap."""
    raw = '{"facts": ["  fact one\\n", "", "fact two", "fact three"]}'
    assert _parse_facts(raw, cap=2) == ["fact one", "fact two"]


def test_render_traces_stays_within_char_budget() -> None:
    """The prompt block never exceeds the caller's character budget."""
    entries = [
        {
            "kind": "discovery",
            "author_branch_id": "branch-x",
            "payload": {"detail": "a" * 400},
        },
        {
            "kind": "note",
            "author_branch_id": "branch-y",
            "payload": {"detail": "b" * 400},
        },
    ]
    rendered = _render_traces(entries, char_budget=100)
    assert len(rendered) <= 100
    assert rendered.endswith("...")


# ---------------------------------------------------------------------------
# DB-backed: end-to-end sweep against the shared test_db fixture
# ---------------------------------------------------------------------------


async def test_consolidator_writes_semantic_facts_visible_to_live_reader(
    test_db,
) -> None:
    """Sweep writes to the exact namespace an agent's retrieval reads."""
    del test_db
    now = datetime.now(UTC)
    ws_id = "ws-cons-1"
    target_id = "tgt-cons-1"
    inv_id = "inv-cons-1"
    await _seed_investigation(
        workspace_id=ws_id,
        target_id=target_id,
        investigation_id=inv_id,
        slug_suffix="cons1",
        status=InvestigationStatus.COMPLETED.value,
        updated_at=now - timedelta(days=2),
    )
    await _seed_ledger_entries(inv_id, [
        ("discovery", "branch-a", {
            "finding": "packed",
            "detail": "sample uses UPX-like section renaming",
        }),
        ("note", "branch-b", {
            "text": "aplib decompressor called from the second stage",
        }),
    ])

    facts = [
        "packed samples that rename sections in-place often mimic UPX",
        "aplib decompressors called from a second stage suggest custom loaders",
    ]
    llm = _StubLLMClient(payloads={inv_id: _facts_json(facts)}, default_payload="")

    knowledge = _build_knowledge_service()
    report = await consolidate_recent_investigations(
        llm_client=llm,
        knowledge_service=knowledge,
        inactivity_hours=1.0,
        facts_per_investigation=5,
    )

    assert report["scanned"] == 1
    assert report["consolidated"] == 1
    assert report["facts_written"] == len(facts)
    assert report["errors"] == 0
    assert len(llm.calls) == 1
    assert llm.calls[0]["run_id"] == inv_id

    # Facts landed under the module's semantic namespace.
    expected_ns = f"malware.{SEMANTIC_NAMESPACE_KIND}.workspace.{ws_id}"
    async with async_session_scope() as session:
        stored = (await session.exec(
            sm_select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.namespace == expected_ns,
            ),
        )).all()
    stored_content = sorted(row.content for row in stored)
    assert stored_content == sorted(facts)
    for row in stored:
        assert row.dedup_key.startswith(f"{DEDUP_KEY_PREFIX}:{inv_id}:")

    # A live-reader retrieval scoped to this workspace's malware
    # namespaces surfaces the stored fact, proving the writer feeds
    # the exact bucket the agent already queries.
    routed = await knowledge.retrieve_routed(
        query="what does UPX-like renaming imply about packing?",
        route="simple",
        namespaces=malware_knowledge_namespaces(ws_id),
        limit=5,
        min_score=0.0,
    )
    assert routed["count"] >= 1
    hit_contents = [hit["content"] for hit in routed["results"]]
    assert any(fact == content for fact in facts for content in hit_contents), (
        f"live reader did not surface any consolidated fact; got {hit_contents}"
    )
    surfaced = next(hit for hit in routed["results"] if hit["content"] in facts)
    assert surfaced["namespace"] == expected_ns


async def test_consolidator_idempotent_second_run_makes_no_llm_call(
    test_db,
) -> None:
    """Repeat sweep skips the investigation without re-charging the model."""
    del test_db
    now = datetime.now(UTC)
    ws_id = "ws-cons-2"
    target_id = "tgt-cons-2"
    inv_id = "inv-cons-2"
    await _seed_investigation(
        workspace_id=ws_id,
        target_id=target_id,
        investigation_id=inv_id,
        slug_suffix="cons2",
        status=InvestigationStatus.COMPLETED.value,
        updated_at=now - timedelta(days=3),
    )
    await _seed_ledger_entries(inv_id, [
        ("discovery", "branch-a", {"finding": "config_present"}),
    ])
    facts = ["config-present hits often anchor cross-family attribution"]
    llm = _StubLLMClient(payloads={inv_id: _facts_json(facts)}, default_payload="")
    knowledge = _build_knowledge_service()

    first = await consolidate_recent_investigations(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0, facts_per_investigation=3,
    )
    assert first["consolidated"] == 1
    assert first["facts_written"] == 1
    assert len(llm.calls) == 1

    second = await consolidate_recent_investigations(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0, facts_per_investigation=3,
    )
    assert second["consolidated"] == 0
    assert second["skipped_already"] == 1
    assert second["facts_written"] == 0
    # Zero additional LLM calls -- the per-investigation existence
    # check short-circuited before dispatch.
    assert len(llm.calls) == 1


async def test_consolidator_skips_still_active_investigation(test_db) -> None:
    """A RUNNING investigation is filtered out before the LLM stage."""
    del test_db
    now = datetime.now(UTC)
    ws_id = "ws-cons-3"
    target_id = "tgt-cons-3"
    inv_id = "inv-cons-3"
    await _seed_investigation(
        workspace_id=ws_id,
        target_id=target_id,
        investigation_id=inv_id,
        slug_suffix="cons3",
        status="running",
        updated_at=now - timedelta(days=1),
    )
    await _seed_ledger_entries(inv_id, [
        ("discovery", "branch-a", {"finding": "packed"}),
    ])
    llm = _StubLLMClient(payloads={}, default_payload=_facts_json(["ignored"]))
    knowledge = _build_knowledge_service()

    report = await consolidate_recent_investigations(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=1.0,
    )
    assert report["scanned"] == 0
    assert report["consolidated"] == 0
    assert report["facts_written"] == 0
    assert len(llm.calls) == 0


async def test_consolidator_survives_bad_llm_output(test_db) -> None:
    """A malformed LLM reply is logged and counted, never aborts the batch."""
    del test_db
    now = datetime.now(UTC)
    ws_id = "ws-cons-4"
    target_id = "tgt-cons-4"
    inv_id = "inv-cons-4"
    await _seed_investigation(
        workspace_id=ws_id,
        target_id=target_id,
        investigation_id=inv_id,
        slug_suffix="cons4",
        status=InvestigationStatus.COMPLETED.value,
        updated_at=now - timedelta(days=1),
    )
    await _seed_ledger_entries(inv_id, [
        ("note", "branch-a", {"text": "some observation"}),
    ])
    llm = _StubLLMClient(payloads={inv_id: "not json at all"}, default_payload="")
    knowledge = _build_knowledge_service()

    report = await consolidate_recent_investigations(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=0.0,
    )
    assert report["scanned"] == 1
    assert report["consolidated"] == 0
    assert report["skipped_no_traces"] == 1
    assert report["errors"] == 0
    # Nothing landed in the knowledge store.
    expected_ns = f"malware.semantic.workspace.{ws_id}"
    async with async_session_scope() as session:
        rows = (await session.exec(
            sm_select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.namespace == expected_ns,
            ),
        )).all()
    assert rows == []


async def test_consolidator_empty_when_no_candidates(test_db) -> None:
    """Zero candidates -> zero LLM calls, zero writes, well-formed report."""
    del test_db
    llm = _StubLLMClient(payloads={}, default_payload="")
    knowledge = _build_knowledge_service()
    report = await consolidate_recent_investigations(
        llm_client=llm, knowledge_service=knowledge,
        inactivity_hours=0.0,
    )
    assert report == {
        "scanned": 0,
        "consolidated": 0,
        "skipped_already": 0,
        "skipped_no_workspace": 0,
        "skipped_no_traces": 0,
        "facts_written": 0,
        "errors": 0,
    }
    assert llm.calls == []
