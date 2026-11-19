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
    """Async stand-in for redis.asyncio.Redis exposing only what the probe calls."""

    def __init__(self, live_tracks: set[str]) -> None:
        self._live_keys = {
            f"{ARQ_QUEUE_KEY_TEMPLATE.format(track=track)}:health-check" for track in live_tracks
        }

    async def pttl(self, key: str) -> int:
        return 60_000 if key in self._live_keys else -2

    async def scan_iter(self, match: str, count: int) -> AsyncIterator[str]:
        for key in ():
            if fnmatch.fnmatchcase(key, match):
                yield key

    async def zcard(self, key: str) -> int:
        return 0

    async def aclose(self) -> None:
        return None


def _install(
    monkeypatch: pytest.MonkeyPatch, configured: str, live_tracks: set[str]
) -> None:
    monkeypatch.setenv(ENV_NAME, configured)
    fake = _FakeRedis(live_tracks)
    monkeypatch.setattr(aioredis.Redis, "from_url", lambda _url, **_kwargs: fake)


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
