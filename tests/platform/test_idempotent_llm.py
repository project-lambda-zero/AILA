"""Idempotent LLM call wrapper (RFC-03 Phase 2).

Uses a call-counting stub llm_client against the real idempotency cache
(UnitOfWork -> aila_test). Verifies the retry-safe contract: a miss calls
the model once and stores; an identical replay reads the cache without a
second call; a different request misses; a disabled response is not cached.
"""
from __future__ import annotations

import uuid

import pytest

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.llm.client import LLMResponse


class _StubClient:
    def __init__(self, *, disabled: bool = False) -> None:
        self.calls = 0
        self._disabled = disabled

    async def chat(self, task_type, messages, *, run_id=None, team_id=None):
        self.calls += 1
        return LLMResponse(
            content=f"answer-{self.calls}", model="stub-model",
            usage={"prompt_tokens": 10, "completion_tokens": 5},
            disabled=self._disabled, finish_reason="stop",
        )


def _msgs() -> list[dict]:
    return [{"role": "user", "content": "verify h1"}]


@pytest.mark.usefixtures("test_db")
async def test_miss_calls_once_then_hit_replays() -> None:
    client = _StubClient()
    inv = uuid.uuid4().hex

    resp1, hit1 = await idempotent_llm_call(
        client, method="chat", task_type="scoring", messages=_msgs(),
        investigation_id=inv, branch_id="b1", turn_number=1,
    )
    assert hit1 is False
    assert resp1.content == "answer-1"
    assert client.calls == 1

    # Identical request -> cache hit, no second model call, same content.
    resp2, hit2 = await idempotent_llm_call(
        client, method="chat", task_type="scoring", messages=_msgs(),
        investigation_id=inv, branch_id="b1", turn_number=1,
    )
    assert hit2 is True
    assert resp2.content == "answer-1"
    assert client.calls == 1  # NOT called again


@pytest.mark.usefixtures("test_db")
async def test_different_messages_miss() -> None:
    client = _StubClient()
    inv = uuid.uuid4().hex

    await idempotent_llm_call(
        client, method="chat", task_type="scoring", messages=_msgs(),
        investigation_id=inv, branch_id="b1", turn_number=1,
    )
    # Different message content -> different key -> miss -> second call.
    _resp, hit = await idempotent_llm_call(
        client, method="chat", task_type="scoring",
        messages=[{"role": "user", "content": "verify h2"}],
        investigation_id=inv, branch_id="b1", turn_number=1,
    )
    assert hit is False
    assert client.calls == 2


@pytest.mark.usefixtures("test_db")
async def test_disabled_response_not_cached() -> None:
    client = _StubClient(disabled=True)
    inv = uuid.uuid4().hex

    resp1, hit1 = await idempotent_llm_call(
        client, method="chat", task_type="scoring", messages=_msgs(),
        investigation_id=inv, branch_id="b1", turn_number=1,
    )
    assert hit1 is False
    assert resp1.disabled is True
    # A disabled response is not stored, so the retry calls the model again.
    _resp2, hit2 = await idempotent_llm_call(
        client, method="chat", task_type="scoring", messages=_msgs(),
        investigation_id=inv, branch_id="b1", turn_number=1,
    )
    assert hit2 is False
    assert client.calls == 2
