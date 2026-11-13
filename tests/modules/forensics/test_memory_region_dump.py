"""Dumped memory regions are recorded as metadata under a per-run byte cap.

A fake analyzer answers the malfind dump flow: mkdir, the volatility dump,
the region listing, one base64 readback per region, and cleanup. No host is
contacted and nothing is executed.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest

from aila.modules.forensics.workflow.states.collectors import memory

_REGION = b"MZ" + b"\x90" * 1022  # 1 KiB


class _Analyzer:
    def __init__(self, region_count: int) -> None:
        self.paths = [f"/tmp/out/pid.{100 + i}.vad.0x1000-0x1fff.dmp" for i in range(region_count)]
        self.readbacks: list[str] = []

    async def run_command(self, _integration: dict[str, Any], command: str, **_: Any) -> str:
        if command.startswith("ls -1 "):
            return "\n".join(self.paths)
        if command.startswith("head -c "):
            self.readbacks.append(command)
            return base64.b64encode(_REGION).decode("ascii")
        return ""


class _Emitter:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def emit(self, stream: str, _message: str, meta: dict[str, Any] | None = None) -> None:
        self.events.append((stream, meta or {}))


async def _dump(analyzer: _Analyzer, emitter: _Emitter) -> list[dict[str, Any]]:
    return await memory._dump_malfind_regions(
        analyzer, {"id": 1}, "/evidence/mem.raw", "linux", "windows", "2>/dev/null", emitter,
    )


async def test_region_artifacts_carry_metadata_without_base64_bytes() -> None:
    analyzer = _Analyzer(region_count=2)

    artifacts = await _dump(analyzer, _Emitter())

    assert len(artifacts) == 2
    for art in artifacts:
        assert "content_b64" not in art["data"]
        assert art["data"]["sha256"] == hashlib.sha256(_REGION).hexdigest()
        assert art["data"]["size"] == len(_REGION)
        assert art["data"]["has_mz_header"] is True


async def test_aggregate_byte_cap_stops_pulls_and_reports_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(memory, "_MAX_DUMPED_TOTAL_BYTES", 3 * len(_REGION))
    analyzer = _Analyzer(region_count=10)
    emitter = _Emitter()

    artifacts = await _dump(analyzer, emitter)

    assert len(artifacts) == 3
    assert len(analyzer.readbacks) == 3
    done = [meta for _stream, meta in emitter.events if meta.get("stage") == "memory_region_dump_done"]
    assert done == [{
        "stage": "memory_region_dump_done",
        "plugin": "windows.malfind",
        "region_count": 3,
        "skipped_count": 7,
        "pulled_bytes": 3 * len(_REGION),
    }]
