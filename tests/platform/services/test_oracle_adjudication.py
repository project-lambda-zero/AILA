"""Oracle LLM-adjudication of open request_specialist entries.

When no distinct sibling casts the ratifying vote, the oracle judges the
request itself and records its own distinct-approver decision so a warranted
specialist still spawns. These drive the real LedgerService + Oracle against
the test DB with only the model call faked.
"""
from __future__ import annotations

import json

import aila.platform.agents.idempotent_llm as idem
import aila.platform.services.factory as factory
from aila.platform.services.ledger import LedgerService
from aila.platform.services.oracle import Oracle


class _Resp:
    def __init__(self, content: str, *, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled


def _install_fake_llm(monkeypatch, *, warranted: bool, content: str | None = None) -> list[dict]:
    """Patch the oracle's lazy LLM deps; return a list that records each call."""
    calls: list[dict] = []

    async def _fake_call(client, *, method, task_type, messages, investigation_id, **kw):
        calls.append({"task_type": task_type, "investigation_id": investigation_id})
        body = content if content is not None else json.dumps(
            {"warranted": warranted, "rationale": "adjudicated in test"}
        )
        return _Resp(body), False

    class _FakeFactory:
        @property
        def llm_client(self):
            return object()

    monkeypatch.setattr(idem, "idempotent_llm_call", _fake_call)
    monkeypatch.setattr(factory, "ServiceFactory", _FakeFactory)
    return calls


async def _seed_request(inv: str, capability: str = "binary-audit") -> int:
    return await LedgerService().append_general(
        inv, "maddie-branch", "request",
        {"intent": "request_specialist", "target_capability": capability,
         "reason": "verify exec_run behavior for a string cmd"},
    )


async def test_oracle_ratifies_warranted_request(test_db, monkeypatch) -> None:
    del test_db
    inv = "inv-adj-yes"
    req_id = await _seed_request(inv)
    calls = _install_fake_llm(monkeypatch, warranted=True)
    oracle = Oracle()
    assert await oracle.ratified_specialist_capabilities(inv) == []
    ruled = await oracle.adjudicate_specialist_requests(
        inv, task_type="t", extra_context="does X escape the sandbox?",
    )
    assert len(calls) == 1
    assert ruled and ruled[0]["warranted"] is True
    assert ruled[0]["capability"] == "binary-audit"
    # The oracle's own decision reaches quorum as a distinct approver.
    assert await oracle.is_ratified(inv, req_id, quorum_k=1) is True
    assert await oracle.ratified_specialist_capabilities(inv) == ["binary-audit"]


async def test_oracle_rejects_unwarranted_request(test_db, monkeypatch) -> None:
    del test_db
    inv = "inv-adj-no"
    req_id = await _seed_request(inv)
    _install_fake_llm(monkeypatch, warranted=False)
    oracle = Oracle()
    ruled = await oracle.adjudicate_specialist_requests(inv, task_type="t")
    assert ruled and ruled[0]["warranted"] is False
    # A rejection does not ratify and never spawns.
    assert await oracle.is_ratified(inv, req_id, quorum_k=1) is False
    assert await oracle.ratified_specialist_capabilities(inv) == []


async def test_oracle_adjudication_is_idempotent(test_db, monkeypatch) -> None:
    del test_db
    inv = "inv-adj-idem"
    await _seed_request(inv)
    calls = _install_fake_llm(monkeypatch, warranted=True)
    oracle = Oracle()
    await oracle.adjudicate_specialist_requests(inv, task_type="t")
    await oracle.adjudicate_specialist_requests(inv, task_type="t")
    # Second pass sees the oracle_adjudicated marker and does not re-judge.
    assert len(calls) == 1
    assert await oracle.ratified_specialist_capabilities(inv) == ["binary-audit"]


async def test_oracle_defers_to_a_real_sibling_vote(test_db, monkeypatch) -> None:
    del test_db
    inv = "inv-adj-sibling"
    req_id = await _seed_request(inv)
    # A distinct sibling already ratified it -> the oracle must not judge.
    await Oracle().record_decision(inv, req_id, "halvar-branch", approve=True)
    calls = _install_fake_llm(monkeypatch, warranted=False)
    ruled = await Oracle().adjudicate_specialist_requests(inv, task_type="t")
    assert calls == []
    assert ruled == []
    assert await Oracle().is_ratified(inv, req_id, quorum_k=1) is True


async def test_oracle_leaves_request_open_on_unparseable_verdict(test_db, monkeypatch) -> None:
    del test_db
    inv = "inv-adj-bad"
    req_id = await _seed_request(inv)
    _install_fake_llm(monkeypatch, warranted=True, content="not json at all")
    oracle = Oracle()
    ruled = await oracle.adjudicate_specialist_requests(inv, task_type="t")
    # Unparseable -> no decision recorded, request stays open for a later pass.
    assert ruled == []
    assert await oracle.is_ratified(inv, req_id, quorum_k=1) is False
    assert await oracle.ratified_specialist_capabilities(inv) == []
