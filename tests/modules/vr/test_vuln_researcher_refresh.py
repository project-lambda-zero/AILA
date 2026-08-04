"""RFC-12 Phase 1: per-pivot RETRIEVED-tier refresh control logic.

Locks the ``_refresh_retrieved_knowledge`` override on the VR agent: it
re-queries the knowledge base only when the branch's live focus (its
hypotheses) changes, skips when there is no focus yet or no workspace id, and
caches the last focus so an unchanged turn does not re-pay for retrieval. The
resolver call itself is exercised live over the real KB; here we mock it to
assert the control flow without a DB.
"""
from __future__ import annotations

import aila.modules.vr.agents.vuln_researcher as vr
from aila.platform.contracts.reasoning import Hypothesis, ReasoningCaseState


class _Inv:
    team_id = None


def _agent() -> vr.HonestVulnResearcher:
    return vr.HonestVulnResearcher(None, "inv-1", "branch-1")


def _snap() -> dict:
    return {"workspace_id": "ws-1", "kind": "source_repo", "primary_language": "c"}


async def test_refresh_retrieves_on_live_focus(monkeypatch) -> None:
    calls: list[str] = []

    async def _fake_resolve(*, query, **kwargs):
        calls.append(query)
        return [{"namespace": "vr.finding.workspace.ws-1", "content": "prior", "score": 0.5}]

    monkeypatch.setattr(vr, "_resolve_retrieved_knowledge", _fake_resolve)
    agent = _agent()
    cs = ReasoningCaseState(hypotheses=[Hypothesis(id="h1", claim="heap overflow in parse_hdr")])
    await agent._refresh_retrieved_knowledge(inv=_Inv(), target_snapshot=_snap(), case_state=cs)
    assert calls == ["heap overflow in parse_hdr"]  # keyed on the live focus
    assert len(agent._retrieved_knowledge) == 1


async def test_refresh_skips_when_focus_unchanged(monkeypatch) -> None:
    calls: list[str] = []

    async def _fake_resolve(*, query, **kwargs):
        calls.append(query)
        return []

    monkeypatch.setattr(vr, "_resolve_retrieved_knowledge", _fake_resolve)
    agent = _agent()
    cs = ReasoningCaseState(hypotheses=[Hypothesis(id="h1", claim="same claim")])
    await agent._refresh_retrieved_knowledge(inv=_Inv(), target_snapshot=_snap(), case_state=cs)
    await agent._refresh_retrieved_knowledge(inv=_Inv(), target_snapshot=_snap(), case_state=cs)
    assert calls == ["same claim"]  # second identical-focus turn does not re-query


async def test_refresh_skips_without_focus_or_workspace(monkeypatch) -> None:
    calls: list[str] = []

    async def _fake_resolve(*, query, **kwargs):
        calls.append(query)
        return [{"x": 1}]

    monkeypatch.setattr(vr, "_resolve_retrieved_knowledge", _fake_resolve)
    # no hypotheses -> no focus -> setup retrieval stands
    agent = _agent()
    await agent._refresh_retrieved_knowledge(
        inv=_Inv(), target_snapshot=_snap(), case_state=ReasoningCaseState(),
    )
    # focus present but no workspace id -> cannot scope -> skip
    cs = ReasoningCaseState(hypotheses=[Hypothesis(id="h1", claim="c")])
    await agent._refresh_retrieved_knowledge(
        inv=_Inv(), target_snapshot={"kind": "source_repo"}, case_state=cs,
    )
    assert calls == []
