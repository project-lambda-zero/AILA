"""Registry-aware Redis pool URL resolution is awaited and reaches the pool."""

from __future__ import annotations

import pytest

from aila.platform.services import redis_pool
from aila.storage import registry as registry_module


class _FakeRegistry:
    def __init__(self, value: str | None) -> None:
        self._value = value
        self.calls: list[tuple[str, str]] = []

    async def get(self, namespace: str, key: str) -> str | None:
        self.calls.append((namespace, key))
        return self._value


async def test_configured_url_is_awaited_from_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRegistry("redis://registry-host:6379/0")
    monkeypatch.setattr(registry_module, "ConfigRegistry", lambda: fake)

    resolved = await redis_pool._configured_redis_url()

    assert resolved == "redis://registry-host:6379/0"
    assert fake.calls == [("platform", "redis_url")]


async def test_unconfigured_url_resolves_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_module, "ConfigRegistry", lambda: _FakeRegistry(None))

    assert await redis_pool._configured_redis_url() is None


async def test_registry_failure_resolves_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Broken:
        async def get(self, namespace: str, key: str) -> str | None:
            raise RuntimeError("registry unavailable")

    monkeypatch.setattr(registry_module, "ConfigRegistry", lambda: _Broken())

    assert await redis_pool._configured_redis_url() is None


async def test_init_uses_registry_url_when_no_explicit_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry_module,
        "ConfigRegistry",
        lambda: _FakeRegistry("redis://registry-host:6379/0"),
    )
    seen: list[str] = []

    class _Pool:
        @classmethod
        def from_url(cls, url: str, **_kwargs: object) -> _Pool:
            seen.append(url)
            return cls()

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def ping(self) -> bool:
            return True

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(redis_pool.aioredis, "ConnectionPool", _Pool)
    monkeypatch.setattr(redis_pool.aioredis, "Redis", _Client)

    await redis_pool.init_redis_pool()

    assert seen == ["redis://registry-host:6379/0"]
