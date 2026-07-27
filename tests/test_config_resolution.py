"""ConfigRegistry.describe_resolution pure-unit tests.

describe_resolution is the transparency helper the config API uses to expose
WHICH layer (env > db > default) supplies the effective value, alongside the
raw contributions from each layer. It mirrors ``get``/``get_sync`` precedence
but performs NO DB read -- the caller passes ``db_value`` (the
``ConfigEntryRecord.value`` it already holds, or None).

These tests are hermetic: no DB, no network, no async event loop. Schema
registration is done by assigning directly into ``reg._schemas`` so the async
``register()`` path (which writes defaults into the DB) never fires.
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from aila.storage.registry import ConfigRegistry, ConfigResolution


class _S(BaseModel):
    base_url: str = "https://default.example/api"


def _registry() -> ConfigRegistry:
    reg = ConfigRegistry()
    reg._schemas["testns"] = _S
    return reg


def test_env_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILA_TESTNS_BASE_URL", "http://override")
    res = _registry().describe_resolution(
        "testns", "base_url", db_value="https://db.example"
    )
    assert isinstance(res, ConfigResolution)
    assert res.source == "env"
    assert res.effective_value == "http://override"
    assert res.env_value == "http://override"
    assert res.env_key == "AILA_TESTNS_BASE_URL"
    assert res.db_value == "https://db.example"
    assert res.default_value == "https://default.example/api"


def test_db_value_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILA_TESTNS_BASE_URL", raising=False)
    res = _registry().describe_resolution(
        "testns", "base_url", db_value="https://db.example"
    )
    assert res.source == "db"
    assert res.effective_value == "https://db.example"
    assert res.env_value is None
    assert res.db_value == "https://db.example"
    assert res.default_value == "https://default.example/api"


def test_default_when_no_env_no_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILA_TESTNS_BASE_URL", raising=False)
    res = _registry().describe_resolution("testns", "base_url", db_value=None)
    assert res.source == "default"
    assert res.effective_value == "https://default.example/api"
    assert res.env_value is None
    assert res.db_value is None
    assert res.default_value == "https://default.example/api"


def test_unknown_key_with_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILA_TESTNS_MISSING_KEY", raising=False)
    res = _registry().describe_resolution("testns", "missing_key", db_value=None)
    assert res.source == "default"
    assert res.effective_value == ""
    assert res.default_value is None
    assert res.env_value is None
    assert res.db_value is None
    assert res.env_key == "AILA_TESTNS_MISSING_KEY"
