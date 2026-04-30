"""Tests for async routing in ModuleRouter (LLM-01)."""
from __future__ import annotations

import asyncio
import inspect
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from aila.platform.routing.router import ModuleRouter


def test_route_with_model_is_async():
    """_route_with_model must be an async def (coroutine function)."""
    assert inspect.iscoroutinefunction(ModuleRouter._route_with_model), (
        "_route_with_model must be async def"
    )


@pytest.mark.asyncio
async def test_route_with_model_awaits_chat_json():
    """_route_with_model must call await self.model.chat_json(), not chat_json_sync()."""
    mock_model = MagicMock()
    mock_model.chat_json = AsyncMock(return_value=MagicMock(
        content=json.dumps({
            "module_id": "vulnerability",
            "action_id": "analyze",
            "confidence": 0.9,
            "rationale": "test",
            "alternates": [],
        })
    ))
    router = ModuleRouter.__new__(ModuleRouter)
    router.model = mock_model
    router.minimum_confidence = 0.5
    router.decision_cache = None

    from aila.platform.routing.router import ModuleCapabilityProfile
    profile = MagicMock(spec=ModuleCapabilityProfile)
    profile.module_id = "vulnerability"
    profile.action_id = "analyze"
    profile.description = "test"
    profile.capabilities = []

    await router._route_with_model("test query", [profile])
    mock_model.chat_json.assert_awaited_once()
    # Verify chat_json_sync was never called
    assert not hasattr(mock_model, 'chat_json_sync') or not mock_model.chat_json_sync.called
