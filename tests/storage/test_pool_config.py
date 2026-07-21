"""Env-tunable asyncpg connection pool sizing (#45).

_resolve_pool_config reads AILA_DB_POOL_SIZE / _MAX_OVERFLOW / _POOL_TIMEOUT /
_POOL_RECYCLE, falling back to the previous hardcoded defaults so behaviour is
unchanged unless an operator opts in.
"""
from __future__ import annotations

import pytest

from aila.storage.database import _resolve_pool_config

_POOL_VARS = (
    "AILA_DB_POOL_SIZE",
    "AILA_DB_MAX_OVERFLOW",
    "AILA_DB_POOL_TIMEOUT",
    "AILA_DB_POOL_RECYCLE",
)


def test_pool_config_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _POOL_VARS:
        monkeypatch.delenv(var, raising=False)
    assert _resolve_pool_config() == {
        "pool_size": 10,
        "max_overflow": 10,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    }


def test_pool_config_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0 (no overflow) and -1 (recycle disabled) are legitimate operator values
    # and must pass through unchanged, not be coerced back to a default.
    monkeypatch.setenv("AILA_DB_POOL_SIZE", "40")
    monkeypatch.setenv("AILA_DB_MAX_OVERFLOW", "0")
    monkeypatch.setenv("AILA_DB_POOL_TIMEOUT", "5")
    monkeypatch.setenv("AILA_DB_POOL_RECYCLE", "-1")
    assert _resolve_pool_config() == {
        "pool_size": 40,
        "max_overflow": 0,
        "pool_timeout": 5,
        "pool_recycle": -1,
    }


def test_pool_config_non_integer_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILA_DB_POOL_SIZE", "not-a-number")
    monkeypatch.delenv("AILA_DB_MAX_OVERFLOW", raising=False)
    cfg = _resolve_pool_config()
    assert cfg["pool_size"] == 10  # malformed value keeps the default
    assert cfg["max_overflow"] == 10
