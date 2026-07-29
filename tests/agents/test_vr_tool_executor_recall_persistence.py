"""Recall durable-history-backing tests for the VR ToolExecutor + reasoning.

Covers three contracts introduced when the recall action became lossless:

1. ``_persist_result_and_observables`` embeds ``_observable_bodies`` inside
   the message payload_json so the durable message row can be looked up
   by observable key after eviction.
2. The end-to-end VR wiring: an evicted observable key is retrievable
   via ``HonestVulnResearcher._build_recall_fetcher`` -> platform absorb,
   producing a rehydrated live observable in the returned case state.
3. Storage caps resolve from ConfigRegistry under the platform
   namespace with the schema defaults preserved.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.modules.vr.agents.vuln_researcher import HonestVulnResearcher
from aila.modules.vr.contracts import PayloadKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.agents.tool_executor import _OBSERVABLE_BODIES_KEY
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    ReasoningCaseState,
    ReasoningTurnDecision,
)
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.storage.database import session_scope


class _FakeBridge:
    async def forward(self, *, action: str, **kwargs) -> dict:  # noqa: ANN401 -- test stub
        del action, kwargs
        return {"status": "ok"}


def _seed() -> tuple[str, str]:
    suffix = uuid4().hex[:8]
    ws_id = f"ws-{suffix}"
    tgt_id = f"tgt-{suffix}"
    inv_id = f"inv-{suffix}"
    branch_id = f"br-{suffix}"
    with session_scope() as sess:
        sess.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        sess.flush()
        sess.add(VRTargetRecord(
            id=tgt_id, workspace_id=ws_id, display_name="tgt", kind="native_binary",
        ))
        sess.flush()
        sess.add(VRInvestigationRecord(
            id=inv_id, target_id=tgt_id, title="seed", kind="discovery",
            strategy_family="vulnerability_research.discovery_research",
        ))
        sess.flush()
        sess.add(VRInvestigationBranchRecord(id=branch_id, investigation_id=inv_id))
        sess.commit()
    return inv_id, branch_id


def _make_executor() -> ToolExecutor:
    return ToolExecutor(
        ida=_FakeBridge(), audit_mcp=_FakeBridge(), android_mcp=_FakeBridge(),
    )


# ----------------------------------------------------------------------
# (STEP 1 durable source): _persist_result_and_observables embeds the
# _observable_bodies map alongside the kind-specific payload fields.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persist_embeds_observable_bodies_reserved_key(test_db) -> None:
    """The stored message row carries a self-describing key->body map
    so later recall lookups do NOT need to re-derive observable keys
    from per-adapter suffix rules."""
    del test_db
    inv_id, branch_id = _seed()
    executor = _make_executor()

    msg_id = await executor._persist_result_and_observables(
        inv_id, branch_id,
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload={"function_name": "foo", "pseudocode": "int foo(void){return 1;}"},
        observables_delta={
            "audit_mcp.read_function.source.foo": "int foo(void){return 1;}",
            # Non-string values fall outside the recall contract and are dropped.
            "audit_mcp.read_function.meta.foo": {"lines": 3, "language": "c"},
        },
        at_turn=4,
    )

    with session_scope() as sess:
        msg = sess.get(VRInvestigationMessageRecord, msg_id)
        assert msg is not None
        payload = json.loads(msg.payload_json)
        assert payload["function_name"] == "foo"
        assert payload["pseudocode"] == "int foo(void){return 1;}"
        # Reserved key embeds ONLY the string-valued deltas.
        bodies = payload[_OBSERVABLE_BODIES_KEY]
        assert bodies == {
            "audit_mcp.read_function.source.foo": "int foo(void){return 1;}",
        }


@pytest.mark.asyncio
async def test_persist_omits_reserved_key_when_no_string_bodies(test_db) -> None:
    """No _observable_bodies key when the delta had nothing durable to
    persist -- avoids storing empty dicts in every result row."""
    del test_db
    inv_id, branch_id = _seed()
    executor = _make_executor()

    msg_id = await executor._persist_result_and_observables(
        inv_id, branch_id,
        payload_kind=PayloadKind.TEXT,
        payload={"text": "hello"},
        observables_delta={"only.numeric": 42},  # non-string, filtered out
        at_turn=1,
    )

    with session_scope() as sess:
        msg = sess.get(VRInvestigationMessageRecord, msg_id)
        payload = json.loads(msg.payload_json)
        assert _OBSERVABLE_BODIES_KEY not in payload


# ----------------------------------------------------------------------
# (STEP 2 VR binding): HonestVulnResearcher._build_recall_fetcher pulls
# _observable_bodies out of the branch's message history and hands
# absorb a sync closure that rehydrates the pinned key. End-to-end
# test: write a tool result -> evict from live observables -> recall ->
# expect the body back in the new case state.
# ----------------------------------------------------------------------


class _FakeLLMClient:
    async def chat_structured(self, **kwargs) -> object:  # noqa: ANN401 -- unused
        del kwargs
        raise AssertionError("engine.decide_next_turn must not be called in this test")


def _make_vr_researcher(inv_id: str, branch_id: str) -> HonestVulnResearcher:
    engine = CyberReasoningEngine(_FakeLLMClient())  # type: ignore[arg-type]
    return HonestVulnResearcher(
        reasoning_engine=engine,
        investigation_id=inv_id,
        branch_id=branch_id,
    )


@pytest.mark.asyncio
async def test_recall_of_evicted_key_rehydrates_from_history(test_db) -> None:
    """The lossless recall contract end-to-end.

    Sequence:
      1. tool_executor writes a tool result carrying
         ``audit_mcp.read_function.source.foo = <body>`` in _observable_bodies.
      2. The live case_state DOES NOT hold that key (simulating cap-driven
         eviction after many turns).
      3. The agent recalls the key.
      4. VR builds the fetcher, absorb calls it, the body reappears in the
         new case_state under the same key.
    """
    del test_db
    inv_id, branch_id = _seed()
    executor = _make_executor()

    body = "int strcpy_wrapper(char *dst, char *src) { return strcpy(dst, src) != NULL; }"
    await executor._persist_result_and_observables(
        inv_id, branch_id,
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload={"function_name": "strcpy_wrapper", "pseudocode": body},
        observables_delta={
            "audit_mcp.read_function.source.strcpy_wrapper": body,
        },
        at_turn=5,
    )

    # Simulate a case state whose observables no longer hold the body
    # (evicted by _MAX_OBSERVABLES on a long-running branch).
    starved_state = ReasoningCaseState(observables={"other.key": "irrelevant"})
    researcher = _make_vr_researcher(inv_id, branch_id)
    fetcher = await researcher._build_recall_fetcher(
        ["audit_mcp.read_function.source.strcpy_wrapper"],
    )
    assert fetcher is not None, "VR fetcher must return non-None when history has the key"

    engine = researcher._engine
    merged = engine.absorb(
        starved_state,
        ReasoningTurnDecision(
            reasoning="pull the strcpy_wrapper body back for close reading",
            action="recall",
            recall_keys=["audit_mcp.read_function.source.strcpy_wrapper"],
            provenance=EvidenceProvenance(),
        ),
        fetch_observable_body=fetcher,
    )

    assert merged.observables["audit_mcp.read_function.source.strcpy_wrapper"] == body
    assert merged.observables["_recall.pinned"] == [
        "audit_mcp.read_function.source.strcpy_wrapper",
    ]


@pytest.mark.asyncio
async def test_recall_of_never_written_key_returns_none_fetcher(test_db) -> None:
    """When NONE of the recall keys have a durable body in history, the
    VR fetcher returns None -- absorb then injects the not-available
    marker. Malware/forensics-style engines with no fetcher wired at all
    also degrade the same way (covered separately in the engine tests).
    """
    del test_db
    inv_id, branch_id = _seed()
    researcher = _make_vr_researcher(inv_id, branch_id)

    fetcher = await researcher._build_recall_fetcher(
        ["audit_mcp.read_function.source.never_written"],
    )
    assert fetcher is None

    engine = researcher._engine
    merged = engine.absorb(
        ReasoningCaseState(),
        ReasoningTurnDecision(
            reasoning="pull an evicted body",
            action="recall",
            recall_keys=["audit_mcp.read_function.source.never_written"],
            provenance=EvidenceProvenance(),
        ),
        fetch_observable_body=fetcher,
    )
    marker = merged.observables["audit_mcp.read_function.source.never_written"]
    assert isinstance(marker, str) and marker
    assert "recall" in marker.lower()


# ----------------------------------------------------------------------
# (STEP 3 config caps): _resolve_max_observables reads the live cap
# from ConfigRegistry under the platform namespace, falling back to
# _MAX_OBSERVABLES when the registry has nothing or errors.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_max_observables_returns_class_default_without_seed(
    test_db,
) -> None:
    """No DB row + no env override -> the schema default (400) wins."""
    del test_db
    executor = _make_executor()
    cap = await executor._resolve_max_observables()
    assert cap == 400  # matches class attr + schema default -- no drift


@pytest.mark.asyncio
async def test_resolve_max_observables_uses_registry_override(
    test_db, monkeypatch,
) -> None:
    """Registry returns a smaller int -> the executor uses it.

    Patched via AsyncMock on the ConfigRegistry class so the
    ConfigRegistry() call inside _resolve_max_observables sees the fake
    reader without touching the real DB path.
    """
    del test_db
    from aila.platform.agents import tool_executor as tool_executor_mod

    async def _fake_get(namespace: str, key: str) -> object:
        assert namespace == "platform"
        assert key == "reasoning_max_observables"
        return 25

    class _FakeRegistry:
        def __init__(self) -> None: ...
        get = AsyncMock(side_effect=_fake_get)

    monkeypatch.setattr(tool_executor_mod, "ConfigRegistry", _FakeRegistry)
    executor = _make_executor()
    cap = await executor._resolve_max_observables()
    assert cap == 25


@pytest.mark.asyncio
async def test_apply_observables_delta_uses_passed_cap(test_db) -> None:
    """The caller-supplied cap takes precedence over the class attr,
    proving config-driven caps flow all the way through the merge."""
    del test_db
    merged = ToolExecutor._apply_observables_delta(
        None,
        {f"scratch_{i}": i for i in range(30)},
        cap=10,
    )
    kept = json.loads(merged)["observables"]
    assert len(kept) == 10


@pytest.mark.asyncio
async def test_apply_observables_delta_no_cap_arg_uses_class_default(test_db) -> None:
    """Existing callers that pass no cap fall back to _MAX_OBSERVABLES
    -- preserves byte-for-byte backward-compat for the pure helper.
    """
    del test_db
    seed = {f"k{i}": i for i in range(500)}
    merged = ToolExecutor._apply_observables_delta(None, seed)
    kept = json.loads(merged)["observables"]
    assert len(kept) == ToolExecutor._MAX_OBSERVABLES
