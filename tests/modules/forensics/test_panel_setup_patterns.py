"""Forensics panel setup pattern retrieval (RFC-12 Phase 4).

Proves the two contract clauses the ticket adds to the forensics panel
setup:

* ``test_setup_surfaces_applicable_patterns_scoped_to_project`` --
  the handler calls :meth:`PatternStore.applicable` with
  ``workspace_id == project_id`` (the forensics module has no workspace
  table; the project IS the workspace, decided in the RFC-12 Phase 4
  foundation), threads ``team_id`` + ``question`` through unchanged,
  and surfaces the returned pattern summaries as JSON dicts in
  ``output["applicable_patterns"]``. Also asserts the scope snapshot
  is present under ``output["scope"]`` so operators / follow-up phases
  can observe what the retrieval was scoped against.

* ``test_setup_swallows_pattern_store_failure`` -- a
  :meth:`PatternStore.applicable` that raises MUST NOT propagate into
  the setup graph (the panel is not built on
  ``investigation_setup_base`` and has no framework-level safety net).
  The handler MUST return a valid ``StateResult`` with
  ``applicable_patterns == []`` so the phase graph advances into the
  loop instead of dead-lettering the run.

Deterministic + provider-independent: the ``_load_investigation_context``
DB read, the ``_resolve_or_create_primary_branch`` insert, the sibling
spawn, and the ``_mark_investigation_running`` update are all
monkeypatched to in-memory stubs, and the ``_pattern_store_factory``
seam is monkeypatched with a stand-in store. No live DB / KnowledgeService
/ embedding model.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.forensics.workflow.panel import setup as setup_mod


class _FakePatternSummary:
    """Stand-in for :class:`ForensicsPatternSummary` -- only ``model_dump``.

    Mirrors the shape the setup expects: a ``.pattern`` attribute on
    each retrieval result whose ``.model_dump(mode="json")`` returns a
    JSON-safe dict. Using a hand-rolled stand-in (rather than importing
    the real contract) keeps this test free of any Pydantic BaseModel
    validation overhead and proves the setup calls ``model_dump`` with
    ``mode="json"`` -- the exact call VR + malware make.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.dump_calls: list[str | None] = []

    def model_dump(self, mode: str | None = None) -> dict[str, Any]:
        self.dump_calls.append(mode)
        return dict(self._payload)


class _FakeRetrievalResult:
    """One ``PatternStore.applicable`` result -- ``.pattern`` + ``.score``."""

    def __init__(self, summary: _FakePatternSummary, score: float = 0.7) -> None:
        self.pattern = summary
        self.score = score
        self.matched_by = "both"


class _RecordingPatternStore:
    """PatternStore double that records every ``applicable`` kwargs call."""

    def __init__(self, results: list[_FakeRetrievalResult]) -> None:
        self._results = results
        self.calls: list[dict[str, Any]] = []

    async def applicable(self, **kwargs: Any) -> list[_FakeRetrievalResult]:
        self.calls.append(kwargs)
        return list(self._results)


class _RaisingPatternStore:
    """PatternStore double whose ``applicable`` raises to prove swallow path."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def applicable(self, **kwargs: Any) -> list[_FakeRetrievalResult]:
        self.calls.append(kwargs)
        raise self._exc


def _install_common_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    project_id: str,
    team_id: str | None,
    question: str,
    branch_id: str,
) -> dict[str, Any]:
    """Wire in the deterministic DB-side substitutes shared by both tests.

    Returns a recorder dict so each test can assert the spawn + mark
    calls happened exactly once with the expected arguments.
    """
    recorder: dict[str, Any] = {"spawn": [], "mark": []}

    async def _fake_load_ctx(inv_id: str) -> tuple[str | None, str, str]:
        assert inv_id == "inv-xyz"
        return team_id, project_id, question

    async def _fake_resolve_primary(inv_id: str) -> str:
        assert inv_id == "inv-xyz"
        return branch_id

    async def _fake_spawn(**kwargs: Any) -> None:
        recorder["spawn"].append(kwargs)

    async def _fake_mark_running(inv_id: str) -> None:
        recorder["mark"].append(inv_id)

    monkeypatch.setattr(setup_mod, "_load_investigation_context", _fake_load_ctx)
    monkeypatch.setattr(
        setup_mod, "_resolve_or_create_primary_branch", _fake_resolve_primary,
    )
    monkeypatch.setattr(setup_mod, "_spawn_forensics_panel", _fake_spawn)
    monkeypatch.setattr(setup_mod, "_mark_investigation_running", _fake_mark_running)
    return recorder


async def test_setup_surfaces_applicable_patterns_scoped_to_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup calls ``PatternStore.applicable`` with the project as workspace_id."""
    recorder = _install_common_stubs(
        monkeypatch,
        project_id="proj-abc",
        team_id="team-42",
        question="What is the earliest lateral-movement indicator?",
        branch_id="branch-primary-1",
    )

    summary = _FakePatternSummary(
        {
            "id": "pattern-1",
            "kind": "triage_rule",
            "summary": "Windows event 4624 logon-type-3 spike before 4672.",
            "body": "",
            "workspace_id": "proj-abc",
            "confidence": "supported",
            "status": "active",
            "scope": "workspace",
        },
    )
    store = _RecordingPatternStore([_FakeRetrievalResult(summary, score=0.83)])
    monkeypatch.setattr(setup_mod, "_pattern_store_factory", lambda: store)

    handler = setup_mod.state_forensics_panel_setup("panel.loop")
    result = await handler({"investigation_id": "inv-xyz"}, services=None)

    # PatternStore.applicable saw the project as its workspace scope, the
    # investigation's denormalised team_id (not the input dict's, which
    # was empty), and the free-flow question as the retrieval query.
    assert len(store.calls) == 1
    call = store.calls[0]
    assert call["workspace_id"] == "proj-abc"
    assert call["team_id"] == "team-42"
    assert call["query"] == "What is the earliest lateral-movement indicator?"
    assert call["k"] == 10

    # model_dump was called with mode="json" so the resulting dict is
    # ARQ-safe when the workflow engine persists the setup state input.
    assert summary.dump_calls == ["json"]

    # Output carries the retrieved pattern verbatim (as a dict list) and
    # the scope snapshot so operators / next phases can inspect what the
    # retrieval was bound against.
    assert result.next_state == "panel.loop"
    out = result.output
    assert out["investigation_id"] == "inv-xyz"
    assert out["branch_id"] == "branch-primary-1"
    assert out["project_id"] == "proj-abc"
    assert out["team_id"] == "team-42"
    assert out["question"] == "What is the earliest lateral-movement indicator?"
    assert out["applicable_patterns"] == [
        {
            "id": "pattern-1",
            "kind": "triage_rule",
            "summary": "Windows event 4624 logon-type-3 spike before 4672.",
            "body": "",
            "workspace_id": "proj-abc",
            "confidence": "supported",
            "status": "active",
            "scope": "workspace",
        },
    ]
    assert out["scope"] == {
        "project_id": "proj-abc",
        "team_id": "team-42",
        "question": "What is the earliest lateral-movement indicator?",
    }

    # Primary-task path also spawned siblings + marked the investigation
    # running exactly once, both with the resolved team_id (regression
    # cover for the #59 team-id stamp on child TaskRecords).
    assert len(recorder["spawn"]) == 1
    assert recorder["spawn"][0]["investigation_id"] == "inv-xyz"
    assert recorder["spawn"][0]["primary_branch_id"] == "branch-primary-1"
    assert recorder["spawn"][0]["team_id"] == "team-42"
    assert recorder["mark"] == ["inv-xyz"]


async def test_setup_swallows_pattern_store_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raising ``PatternStore.applicable`` MUST NOT break setup."""
    recorder = _install_common_stubs(
        monkeypatch,
        project_id="proj-abc",
        team_id=None,  # admin-owned project
        question="Which host initiated the outbound C2 beacon?",
        branch_id="branch-primary-2",
    )
    store = _RaisingPatternStore(RuntimeError("knowledge service unreachable"))
    monkeypatch.setattr(setup_mod, "_pattern_store_factory", lambda: store)

    handler = setup_mod.state_forensics_panel_setup("panel.loop")
    result = await handler({"investigation_id": "inv-xyz"}, services=None)

    # The failure surfaced through PatternStore.applicable and was
    # swallowed by the best-effort wrapper: setup still returned a valid
    # StateResult routed into the loop with an empty pattern list.
    assert len(store.calls) == 1
    assert result.next_state == "panel.loop"
    assert result.output["applicable_patterns"] == []
    assert result.output["scope"] == {
        "project_id": "proj-abc",
        "team_id": None,
        "question": "Which host initiated the outbound C2 beacon?",
    }

    # Spawn + mark-running still fired -- pattern retrieval is
    # augmentation, not a boot dependency.
    assert len(recorder["spawn"]) == 1
    assert recorder["spawn"][0]["team_id"] is None
    assert recorder["mark"] == ["inv-xyz"]
