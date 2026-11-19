"""Per-track ARQ worker liveness in probe_arq_worker (deterministic, no Redis).

Tracks come from the platform config key ``worker_health_tracks``; the env var
``AILA_PLATFORM_WORKER_HEALTH_TRACKS`` is read before any DB or Redis lookup.
"""

from __future__ import annotations

import fnmatch
from collections.abc import AsyncIterator
from typing import Any

import pytest
import redis.asyncio as aioredis

from aila.platform.config import PlatformConfigSchema
from aila.platform.services.health_probes import probe_arq_worker
from aila.platform.tasks.constants import ARQ_QUEUE_KEY_TEMPLATE

REDIS_URL = "redis://fake:6379/0"
ENV_NAME = "AILA_PLATFORM_WORKER_HEALTH_TRACKS"


class _FakeRedis:
    """Async stand-in for redis.asyncio.Redis exposing only what the probe calls.

    ``ttls_ms`` maps full key names to their remaining TTL; keys absent from it
    do not exist (``pttl`` returns -2), mirroring Redis.
    """

    def __init__(self, ttls_ms: dict[str, int]) -> None:
        self._ttls_ms = ttls_ms

    async def pttl(self, key: str) -> int:
        return self._ttls_ms.get(key, -2)

    async def scan_iter(self, match: str, count: int) -> AsyncIterator[str]:
        for key in list(self._ttls_ms):
            if fnmatch.fnmatchcase(key, match):
                yield key

    async def zcard(self, key: str) -> int:
        return 0

    async def aclose(self) -> None:
        return None


def _track_key(track: str) -> str:
    return f"{ARQ_QUEUE_KEY_TEMPLATE.format(track=track)}:health-check"


def _install_ttls(
    monkeypatch: pytest.MonkeyPatch, configured: str | None, ttls_ms: dict[str, int]
) -> list[str]:
    if configured is None:
        monkeypatch.delenv(ENV_NAME, raising=False)
    else:
        monkeypatch.setenv(ENV_NAME, configured)
    opened_urls: list[str] = []
    fake = _FakeRedis(ttls_ms)

    def _from_url(url: str, **_kwargs: Any) -> _FakeRedis:
        opened_urls.append(url)
        return fake

    monkeypatch.setattr(aioredis.Redis, "from_url", _from_url)
    return opened_urls


def _install(monkeypatch: pytest.MonkeyPatch, configured: str, live_tracks: set[str]) -> None:
    _install_ttls(monkeypatch, configured, {_track_key(track): 60_000 for track in live_tracks})


class _RegistryReturning:
    """ConfigRegistry stand-in that resolves only the worker-health key."""

    def __init__(self, value: str | None) -> None:
        self._value = value

    async def get(self, namespace: str, key: str) -> str | None:
        assert (namespace, key) == ("platform", "worker_health_tracks")
        return self._value


class _RegistryRaising:
    async def get(self, namespace: str, key: str) -> str | None:
        raise RuntimeError("config store unavailable")


def _details(result: Any) -> dict[str, Any]:
    assert result.details is not None
    return dict(result.details)


@pytest.mark.asyncio
async def test_all_configured_tracks_live_reports_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, "vr,vulnerability,malware", {"vr", "vulnerability", "malware"})

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "running"
    details = _details(result)
    assert details["tracks_total"] == 3
    assert details["tracks_live"] == ["malware", "vr", "vulnerability"]
    assert details["tracks_missing"] == []


@pytest.mark.asyncio
async def test_one_missing_track_reports_degraded_naming_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, "vr,vulnerability,malware", {"vr", "vulnerability"})

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "degraded"
    assert _details(result)["tracks_missing"] == ["malware"]
    assert "malware" in result.message


@pytest.mark.asyncio
async def test_no_live_track_reports_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, "vr,vulnerability", set())

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "offline"
    assert _details(result)["tracks_missing"] == ["vr", "vulnerability"]


@pytest.mark.asyncio
async def test_empty_config_reports_unknown_without_contacting_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_NAME, " , ")

    def _refuse(_url: str, **_kwargs: Any) -> None:
        raise AssertionError("redis must not be contacted when no tracks are configured")

    monkeypatch.setattr(aioredis.Redis, "from_url", _refuse)

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "unknown"
    assert result.message == "no worker health tracks configured"


@pytest.mark.asyncio
async def test_config_value_is_trimmed_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, " vr , malware,,vr ", {"vr", "malware"})

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "running"
    details = _details(result)
    assert details["tracks_total"] == 2
    assert details["tracks_live"] == ["malware", "vr"]


def test_schema_default_is_the_nine_full_stack_tracks() -> None:
    default = PlatformConfigSchema.model_fields["worker_health_tracks"].default

    assert sorted(default.split(",")) == sorted(
        [
            "default",
            "vr",
            "vulnerability",
            "forensics",
            "malware",
            "pentest",
            "pentest_runtime",
            "forensics_readiness",
            "reporting",
        ]
    )


@pytest.mark.asyncio
async def test_track_stays_live_while_another_replica_key_is_fresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Replica A stopped (its key is gone); replica B on another host is still beating.
    _install_ttls(
        monkeypatch,
        "vr",
        {"arq:queue:vr:health-check:hostB:222": 45_000},
    )

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "running"
    assert _details(result)["tracks_live"] == ["vr"]


@pytest.mark.asyncio
async def test_track_with_one_stale_and_one_fresh_replica_key_is_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_ttls(
        monkeypatch,
        "vr",
        {
            "arq:queue:vr:health-check:hostA:111": -2,
            "arq:queue:vr:health-check:hostB:222": 45_000,
        },
    )

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "running"
    assert _details(result)["tracks_live"] == ["vr"]


@pytest.mark.asyncio
async def test_track_with_only_stale_replica_keys_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_ttls(
        monkeypatch,
        "vr",
        {"arq:queue:vr:health-check:hostA:111": -2},
    )

    result = await probe_arq_worker(redis_url=REDIS_URL)

    assert result.status == "offline"
    assert _details(result)["tracks_missing"] == ["vr"]


@pytest.mark.asyncio
async def test_exact_redis_url_is_opened(monkeypatch: pytest.MonkeyPatch) -> None:
    opened = _install_ttls(monkeypatch, "vr", {_track_key("vr"): 60_000})
    url = "rediss://user:secret@cache.example:6380/3"

    await probe_arq_worker(redis_url=url)

    assert opened == [url]


@pytest.mark.asyncio
async def test_no_registry_and_no_env_uses_schema_default_tracks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_ttls(monkeypatch, None, {})

    result = await probe_arq_worker(redis_url=REDIS_URL)

    default = PlatformConfigSchema.model_fields["worker_health_tracks"].default
    assert result.status == "offline"
    assert _details(result)["tracks_total"] == len(default.split(","))
    assert _details(result)["tracks_missing"] == sorted(default.split(","))


@pytest.mark.asyncio
async def test_registry_value_is_used_when_provided(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_ttls(monkeypatch, None, {_track_key("malware"): 60_000})

    result = await probe_arq_worker(
        redis_url=REDIS_URL, config_registry=_RegistryReturning("malware")  # type: ignore[arg-type]
    )

    assert result.status == "running"
    assert _details(result)["tracks_live"] == ["malware"]


@pytest.mark.asyncio
async def test_registry_failure_reports_configuration_error_without_contacting_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _refuse(_url: str, **_kwargs: Any) -> None:
        raise AssertionError("redis must not be contacted when worker health config fails")

    monkeypatch.setattr(aioredis.Redis, "from_url", _refuse)

    result = await probe_arq_worker(
        redis_url=REDIS_URL, config_registry=_RegistryRaising()  # type: ignore[arg-type]
    )

    assert result.status == "error"
    assert "configuration" in result.message
    assert "RuntimeError" in result.message
