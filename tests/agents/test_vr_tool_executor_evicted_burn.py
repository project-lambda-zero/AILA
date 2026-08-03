"""VR ToolExecutor._on_observables_evicted burn tests (RFC-12).

Contract:
  When the live-observables cap drops a batch of readings from case_state
  this turn, the VR ToolExecutor burns each string-valued observation into
  the workspace-scoped semantic store under ``vr.observation.workspace.<id>``
  so a later branch turn can recall it by query. The hook is best-effort
  and MUST NOT propagate a store failure -- the tool result row has
  already committed by the time the hook runs.

These tests stub ``_resolve_workspace_scope`` and swap in a fake writer,
so no live DB / no embedding service / no vector index is touched. Every
assertion inspects captured call kwargs on the fake writer.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.vr.agents.tool_executor import ToolExecutor


class _FakeBridge:
    async def forward(self, *, action: str, **kwargs: Any) -> dict:
        del action, kwargs
        return {"status": "ok"}


class _FakeKnowledgeWriter:
    """Captures every store() call; optionally raises to model a
    transient failure so the hook's swallow-and-log path is exercised.
    """

    def __init__(self, *, raise_exc: BaseException | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._raise_exc = raise_exc

    async def store(self, **kwargs: Any) -> dict:
        self.calls.append(kwargs)
        if self._raise_exc is not None:
            raise self._raise_exc
        return {"status": "ok"}


def _make_executor() -> ToolExecutor:
    return ToolExecutor(
        ida=_FakeBridge(), audit_mcp=_FakeBridge(), android_mcp=_FakeBridge(),
    )


def _stub_workspace(
    ex: ToolExecutor, workspace_id: str, team_id: str | None,
) -> None:
    async def _resolve(_inv_id: str) -> tuple[str, str | None]:
        return (workspace_id, team_id)
    ex._resolve_workspace_scope = _resolve  # type: ignore[assignment,method-assign]


@pytest.mark.asyncio
async def test_burn_writes_one_row_per_string_observation() -> None:
    """Two string readings -> two store() calls under the workspace-scoped
    VR observation namespace, with the batch Contract metadata + dedup_key
    on each. A non-string reading is filtered out entirely.
    """
    ex = _make_executor()
    _stub_workspace(ex, "ws-123", None)
    fake = _FakeKnowledgeWriter()
    ex._obs_knowledge_writer = fake  # type: ignore[assignment]

    await ex._on_observables_evicted(
        "inv-1", "br-1", 7,
        {
            "reading.a": "some code text",
            "reading.b": "more text",
            "nonstr": 42,
        },
    )

    assert len(fake.calls) == 2, (
        f"expected exactly 2 store calls (non-string filtered); "
        f"got {len(fake.calls)}"
    )

    by_key = {c["metadata"]["observable_key"]: c for c in fake.calls}
    assert set(by_key) == {"reading.a", "reading.b"}

    for observable_key, call in by_key.items():
        assert call["namespace"] == "vr.observation.workspace.ws-123"
        assert call["dedup_key"] == f"obs:inv-1:br-1:{observable_key}"
        assert call["extract_entities"] is False
        assert call["link_neighbors"] is False
        md = call["metadata"]
        assert md["investigation_id"] == "inv-1"
        assert md["branch_id"] == "br-1"
        assert md["turn_number"] == 7
        assert md["observable_key"] == observable_key
        assert md["workspace_id"] == "ws-123"
        assert md["source"] == "evicted_observation"

    assert by_key["reading.a"]["content"] == "some code text"
    assert by_key["reading.b"]["content"] == "more text"


@pytest.mark.asyncio
async def test_burn_swallows_store_runtime_error() -> None:
    """A RuntimeError raised by the writer does NOT propagate out of the
    hook -- the base-class contract says the result row has already
    committed, so a burn failure must only log.
    """
    ex = _make_executor()
    _stub_workspace(ex, "ws-123", None)
    fake = _FakeKnowledgeWriter(raise_exc=RuntimeError("transient upstream"))
    ex._obs_knowledge_writer = fake  # type: ignore[assignment]

    # If the hook re-raised, pytest would fail here. Explicit await
    # keeps the intent visible next to the assert on call count.
    await ex._on_observables_evicted(
        "inv-1", "br-1", 3,
        {"reading.a": "a body worth burning"},
    )
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_burn_skipped_when_workspace_unresolvable() -> None:
    """Empty workspace id from the resolver -> NO store call. Prevents
    writing observations under an ambiguous / global namespace when the
    investigation-to-workspace mapping is broken.
    """
    ex = _make_executor()
    _stub_workspace(ex, "", None)
    fake = _FakeKnowledgeWriter()
    ex._obs_knowledge_writer = fake  # type: ignore[assignment]

    await ex._on_observables_evicted(
        "inv-1", "br-1", 5,
        {"reading.a": "some code text"},
    )
    assert fake.calls == []
