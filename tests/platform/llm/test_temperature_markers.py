"""Temperature-rejection marker matching (issue #44).

Markers that disable the ``temperature`` kwarg must match on alphanumeric
boundaries. The prior ``marker in model_id`` substring test made short markers
like ``o1`` fire inside unrelated ids (``proto1``, ``audio1``), silently
stripping temperature from models that accept it.
"""
from __future__ import annotations

import pytest

from aila.platform.llm import client as client_mod

_MARKERS = ("o1", "o3", "o4", "claude-opus-4-6", "gpt-5", "hadi")


@pytest.fixture(autouse=True)
def _fixed_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the resolved marker list so the test does not read env/DB."""
    monkeypatch.setattr(client_mod, "_resolved_markers", _MARKERS)


@pytest.mark.parametrize(
    "model_id",
    [
        "openai/o1-preview",
        "o3-mini",
        "o4",
        "anthropic/claude-opus-4-6-thinking",
        "claude-opus-4-6",
        "gpt-5",
        "gpt-5-turbo",
        "hadi",
    ],
)
def test_rejecting_models_disable_temperature(model_id: str) -> None:
    assert client_mod._model_supports_temperature(model_id) is False


@pytest.mark.parametrize(
    "model_id",
    [
        "proto1",       # ends with "o1" but not on a boundary
        "audio1-model",  # contains "o1" mid-token
        "gpt-4o-mini",   # no marker
        "claude-sonnet-4-5",
        "",
    ],
)
def test_non_rejecting_models_keep_temperature(model_id: str) -> None:
    assert client_mod._model_supports_temperature(model_id) is True
