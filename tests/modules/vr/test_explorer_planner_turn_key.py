"""Explorer LLM proposal cache is keyed per turn (GitHub issue #316).

Runs the real idempotency cache (``test_db``) against a call-counting fake
``AilaLLMClient``. A same-turn worker retry must replay the cached proposal
(one model call, ``cache HIT`` logged). A later turn with an identical prompt
must make a fresh model call: an unchanged branch must not get the prior
turn's lead replayed as new work.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest

import aila.modules.vr.agents.explorer_planner as ep
from aila.platform.contracts.reasoning import Hypothesis, ReasoningCaseState
from aila.platform.llm.client import LLMResponse

_IDEMPOTENT_LOGGER = "aila.platform.agents.idempotent_llm"
_REPLY = "src/parse.c|parse_hdr|unchecked length"


class _FakeAilaLLMClient:
    """Stands in for ``AilaLLMClient``; counts model calls."""

    calls = 0

    def __init__(self, **_: Any) -> None:
        pass

    async def chat(self, task_type, messages, *, run_id=None, team_id=None):
        type(self).calls += 1
        return LLMResponse(
            content=_REPLY, model="fake", usage={},
            disabled=False, finish_reason="stop",
        )


def _case_state() -> ReasoningCaseState:
    return ReasoningCaseState(
        hypotheses=[Hypothesis(id="h1", claim="heap overflow in parse_hdr")],
    )


async def _propose(inv: str, turn_number: int):
    return await ep._llm_propose_direction(
        investigation_id=inv,
        branch_id="b1",
        case_state=_case_state(),
        ledger_candidates=[],
        turn_number=turn_number,
    )


def _cache_hit_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records
        if r.name == _IDEMPOTENT_LOGGER and "cache HIT" in r.getMessage()
    ]


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> type[_FakeAilaLLMClient]:
    _FakeAilaLLMClient.calls = 0
    monkeypatch.setattr(
        "aila.platform.llm.client.AilaLLMClient", _FakeAilaLLMClient,
    )
    return _FakeAilaLLMClient


@pytest.mark.usefixtures("test_db")
async def test_same_turn_retry_replays_cached_proposal(
    fake_client: type[_FakeAilaLLMClient], caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=_IDEMPOTENT_LOGGER)
    inv = uuid.uuid4().hex

    first = await _propose(inv, turn_number=3)
    assert first is not None
    assert fake_client.calls == 1
    assert not _cache_hit_records(caplog)

    caplog.clear()
    retry = await _propose(inv, turn_number=3)

    assert fake_client.calls == 1  # the retry did not re-pay
    assert len(_cache_hit_records(caplog)) == 1
    assert retry is not None
    assert (retry.file, retry.function) == (first.file, first.function)


@pytest.mark.usefixtures("test_db")
async def test_next_turn_with_identical_prompt_calls_model_again(
    fake_client: type[_FakeAilaLLMClient], caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=_IDEMPOTENT_LOGGER)
    inv = uuid.uuid4().hex

    await _propose(inv, turn_number=3)
    assert fake_client.calls == 1

    caplog.clear()
    later = await _propose(inv, turn_number=4)

    assert fake_client.calls == 2  # a fresh proposal for the new turn
    assert not _cache_hit_records(caplog)
    assert later is not None
