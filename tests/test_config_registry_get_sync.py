"""ConfigRegistry.get_sync resolution tests (issue #65/#38, contract C3).

get_sync is the synchronous twin of the async get, for sync call sites that
must not produce an un-awaited coroutine. Resolution order matches get:
env var > cache > DB value > schema default. The DB branches patch
session_scope so the test stays hermetic (no DB writes).
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from aila.storage.registry import ConfigRegistry, _CacheEntry


class _Schema(BaseModel):
    foo: int = 42
    name: str = "default"


def _registry() -> ConfigRegistry:
    reg = ConfigRegistry()
    reg._schemas["testns"] = _Schema
    return reg


def _session_cm(row: object | None) -> MagicMock:
    session = MagicMock()
    session.exec.return_value.first.return_value = row
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False
    return cm


def test_env_override_is_cast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILA_TESTNS_FOO", "7")
    assert _registry().get_sync("testns", "foo") == 7


def test_cache_hit_returned() -> None:
    reg = _registry()
    reg._cache[("testns", "foo")] = _CacheEntry(value=99, expires_at=time.monotonic() + 100)
    assert reg.get_sync("testns", "foo") == 99


def test_db_value_cast_and_cached() -> None:
    reg = _registry()
    row = MagicMock()
    row.value = "13"
    with patch("aila.storage.registry.session_scope", return_value=_session_cm(row)):
        assert reg.get_sync("testns", "foo") == 13
    # cached after the read
    assert reg._cache[("testns", "foo")].value == 13


def test_schema_default_when_row_absent() -> None:
    reg = _registry()
    with patch("aila.storage.registry.session_scope", return_value=_session_cm(None)):
        assert reg.get_sync("testns", "foo") == 42


def test_never_returns_a_coroutine() -> None:
    """The whole point: a sync caller gets a value, never an awaitable."""
    reg = _registry()
    with patch("aila.storage.registry.session_scope", return_value=_session_cm(None)):
        value = reg.get_sync("testns", "name")
    assert value == "default"
    assert not hasattr(value, "__await__")
