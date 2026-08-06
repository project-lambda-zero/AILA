"""The forensics resolver LLM call is idempotency-cached (RFC-03 audit fix).

ResolverAgent.resolve() runs in the ARQ-backed forensics resolution
workflow state; on a worker crash + ARQ redelivery the resolver would
re-pay the model for the same question. The call now routes through
idempotent_llm_call, so a repeat of the same (project_id, messages) is
served from the cache and the model is called once.
"""
from __future__ import annotations

import pytest

from aila.modules.forensics.agents.resolver_agent import ResolverAgent
from aila.platform.llm.client import LLMResponse

_ANSWER = (
    '{"resolved": true, "answer": "x", "confidence": "firm", '
    '"reasoning": "r", "primary_artifact_id": null}'
)


class _FakeClient:
    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, task_type, messages, *, run_id=None, team_id=None):
        self.calls += 1
        return LLMResponse(
            content=_ANSWER,
            model="fake-model",
            usage={},
            disabled=False,
            finish_reason="stop",
        )


class _Services:
    def __init__(self, client: _FakeClient) -> None:
        self.llm_client = client


@pytest.mark.asyncio
async def test_resolver_llm_call_is_idempotent(test_db) -> None:
    del test_db
    client = _FakeClient()
    agent = ResolverAgent(_Services(client), project_id="proj-idem")
    artifacts = [{"artifact_id": "a1", "family": "process"}]
    leads = [{"id": "l1", "reason": "match"}]

    first = await agent._attempt_resolution("who ran it?", artifacts, leads)
    second = await agent._attempt_resolution("who ran it?", artifacts, leads)

    assert first["resolved"] is True
    assert second["resolved"] is True
    # Second identical resolution replays the cached response.
    assert client.calls == 1


@pytest.mark.asyncio
async def test_resolver_distinct_questions_each_call(test_db) -> None:
    del test_db
    client = _FakeClient()
    agent = ResolverAgent(_Services(client), project_id="proj-idem2")
    artifacts = [{"artifact_id": "a1"}]
    leads = [{"id": "l1"}]

    await agent._attempt_resolution("question one", artifacts, leads)
    await agent._attempt_resolution("question two", artifacts, leads)

    # Different messages -> different key -> the model is called twice.
    assert client.calls == 2
