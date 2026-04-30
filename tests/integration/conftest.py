"""Shared fixtures for integration tests.

Provides AilaLLMClient configured for gpt-4o-mini via OpenRouter.
"""
from __future__ import annotations

import os

import pytest


def _resolve_openai_api_key() -> str | None:
    """Resolve OpenAI API key from environment or SecretStore."""
    env_key = os.getenv("OPENAI_API_KEY")
    if env_key:
        return env_key
    try:
        from aila.config import get_settings
        from aila.storage.secrets import SecretStore
        store = SecretStore(get_settings())
        return store.resolve_provider_secret("openai_api_key")
    except Exception:
        return None


def _detect_base_url(api_key: str) -> str:
    """Detect the correct base_url based on API key prefix."""
    explicit = os.getenv("OPENAI_BASE_URL")
    if explicit:
        return explicit
    if api_key.startswith("sk-or-"):
        return "https://openrouter.ai/api/v1"
    return "https://api.openai.com/v1"


@pytest.fixture(scope="session")
def openai_api_key() -> str:
    """Session-scoped fixture that resolves the OpenAI API key."""
    key = _resolve_openai_api_key()
    if not key:
        pytest.skip("OpenAI API key not available (set OPENAI_API_KEY or store in SecretStore)")
    return key


@pytest.fixture(scope="session")
def openai_base_url(openai_api_key: str) -> str:
    """Session-scoped base_url derived from the API key type."""
    return _detect_base_url(openai_api_key)


@pytest.fixture(scope="session")
def llm_client(openai_api_key: str, openai_base_url: str):
    """Session-scoped AilaLLMClient using gpt-4o-mini for integration tests.

    Creates a minimal ConfigRegistry pre-loaded with model routing and
    base URL, and a mock SecretStore that returns the resolved API key.
    """
    from unittest.mock import MagicMock
    from aila.platform.llm import AilaLLMClient

    # Build a minimal ConfigRegistry with the values the client needs
    registry = MagicMock()
    config_values = {
        ("platform", "llm_default_model"): "openai/gpt-4o-mini",
        ("platform", "llm_base_url"): openai_base_url,
        ("platform", "llm_kill_switch"): None,
        ("platform", "llm_default_max_tokens"): 4096,
        ("platform", "llm_default_temperature"): 0.0,
    }
    registry.get = lambda ns, key: config_values.get((ns, key))

    # Build a mock SecretStore that returns the API key
    secret_store = MagicMock()
    secret_store.resolve_provider_secret = lambda name: openai_api_key if name == "openai_api_key" else None

    return AilaLLMClient(registry=registry, secret_store=secret_store)
