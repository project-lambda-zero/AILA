"""Tests for async StructuredAgent.run_structured() (LLM-02)."""
from __future__ import annotations

import inspect
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from aila.platform.routing.agent import StructuredAgent


def test_run_structured_is_async():
    """run_structured must be an async def (coroutine function)."""
    assert inspect.iscoroutinefunction(StructuredAgent.run_structured), (
        "run_structured must be async def"
    )


@pytest.mark.asyncio
async def test_run_structured_awaits_chat_structured():
    """run_structured must call await self.model.chat_structured(), not chat_structured_sync()."""
    from pydantic import BaseModel

    class DummyResponse(BaseModel):
        answer: str = "test"

    mock_model = MagicMock()
    mock_model.chat_structured = AsyncMock(return_value=MagicMock(
        content=json.dumps({"answer": "test"}),
        model="test-model",
    ))

    agent = StructuredAgent(
        model=mock_model,
        name="test_agent",
        description="test",
        response_model=DummyResponse,
    )
    agent.task_type = "test"

    result = await agent.run_structured(task="test task")
    mock_model.chat_structured.assert_awaited_once()
    assert isinstance(result, DummyResponse)
