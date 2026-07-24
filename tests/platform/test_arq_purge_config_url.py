"""Tests for arq_purge redis-url resolution (RFC-04 Phase 0 audit fix).

purge_arq_jobs_for_investigation resolves the Redis URL as param -> env ->
ConfigRegistry. The ConfigRegistry fallback previously imported a module
that does not exist, so the ImportError was swallowed and the purge
silently no-op'd whenever AILA_PLATFORM_REDIS_URL was unset. This pins that
the fallback now resolves through the real ConfigRegistry and reaches the
Redis layer with the resolved URL.
"""
from __future__ import annotations

import pytest
import redis.asyncio as aredis

import aila.storage.registry as registry_mod
from aila.platform.tasks.arq_purge import purge_arq_jobs_for_investigation


@pytest.mark.asyncio
async def test_redis_url_resolves_from_config_registry(monkeypatch) -> None:
    """Env unset -> the URL is resolved through ConfigRegistry and handed to
    the Redis client, not dropped by a dead import."""
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

    async def _fake_get(self, namespace: str, key: str) -> str:
        return "redis://fake-config:6379"

    monkeypatch.setattr(registry_mod.ConfigRegistry, "get", _fake_get)

    captured: dict[str, str] = {}

    class _FakeClient:
        async def zrange(self, *args, **kwargs) -> list[bytes]:
            return []

        async def aclose(self) -> None:
            return None

    def _fake_from_url(url: str, **kwargs):
        captured["url"] = url
        return _FakeClient()

    monkeypatch.setattr(aredis, "from_url", _fake_from_url)

    result = await purge_arq_jobs_for_investigation("inv-x", track="vr")

    assert captured.get("url") == "redis://fake-config:6379"
    assert result == {"scanned": 0, "matched": 0, "purged_jobs": 0}


@pytest.mark.asyncio
async def test_no_redis_url_returns_zero(monkeypatch) -> None:
    """Env unset and ConfigRegistry yields nothing -> clean zero result, no
    Redis client constructed."""
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

    async def _empty_get(self, namespace: str, key: str) -> str:
        return ""

    monkeypatch.setattr(registry_mod.ConfigRegistry, "get", _empty_get)

    def _fake_from_url(url: str, **kwargs):
        raise AssertionError("from_url must not be called with no URL")

    monkeypatch.setattr(aredis, "from_url", _fake_from_url)

    result = await purge_arq_jobs_for_investigation("inv-y", track="malware")
    assert result == {"scanned": 0, "matched": 0, "purged_jobs": 0}
