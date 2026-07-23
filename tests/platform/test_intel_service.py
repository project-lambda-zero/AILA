"""RFC-05 concern (e): IntelServiceProtocol via the platform runtime.

The vr CVE resolver must resolve intel through the platform-published
``PlatformRuntime.intel_service`` slot, never by naming the vulnerability
module. These tests cover the builder collection helper and the resolver's
read of the platform slot (found + provider-absent paths).
"""
from __future__ import annotations

import types

from aila.modules.vr.services.cve_intel_resolver import resolve_cve_intel
from aila.platform.runtime.builder import _collect_intel_service


class _FakeIntel:
    """Minimal IntelServiceProtocol implementation for tests."""

    def __init__(self, knowledge: object | None) -> None:
        self._knowledge = knowledge
        self.calls: list[str] = []

    async def fetch_cve_intel(self, cve_id: str, force_refresh: bool = False) -> object | None:
        self.calls.append(cve_id)
        return self._knowledge


def _runtime_with(provider_result: object | None) -> object:
    """A module runtime that publishes provider_result via provides_intel_service."""
    rt = types.SimpleNamespace()
    rt.provides_intel_service = lambda: provider_result
    return rt


def _runtime_without() -> object:
    """A module runtime that publishes no intel service."""
    return types.SimpleNamespace(handle=lambda req: None)


class TestCollectIntelService:
    def test_returns_published_service(self) -> None:
        svc = _FakeIntel(None)
        result = _collect_intel_service({"vulnerability": _runtime_with(svc)})
        assert result is svc

    def test_none_when_no_module_publishes(self) -> None:
        result = _collect_intel_service({"vr": _runtime_without()})
        assert result is None

    def test_skips_runtime_without_method(self) -> None:
        svc = _FakeIntel(None)
        runtimes = {"vr": _runtime_without(), "vulnerability": _runtime_with(svc)}
        assert _collect_intel_service(runtimes) is svc

    def test_provider_returning_none_is_skipped(self) -> None:
        # A runtime whose provider yields None does not win; the next does.
        svc = _FakeIntel(None)
        runtimes = {"a": _runtime_with(None), "b": _runtime_with(svc)}
        assert _collect_intel_service(runtimes) is svc

    def test_empty_runtimes_is_none(self) -> None:
        assert _collect_intel_service({}) is None


def _fake_knowledge() -> types.SimpleNamespace:
    """A knowledge object carrying every field the resolver reads."""
    return types.SimpleNamespace(
        description="heap overflow in parser",
        cvss_score=9.8,
        base_severity="CRITICAL",
        epss_score=0.42,
        epss_percentile=0.97,
        kev_listed=True,
        kev_date_added="2026-01-02",
        attack_vector="NETWORK",
        privileges_required="NONE",
        user_interaction="NONE",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        published_at="2026-01-01",
        notes=["kev", "epss-high"],
    )


def _patch_platform(monkeypatch, intel_service: object | None) -> None:
    """Point get_worker_platform at a fake platform whose runtime exposes
    the given intel_service slot."""
    platform = types.SimpleNamespace(
        runtime=types.SimpleNamespace(intel_service=intel_service),
    )

    async def _fake_get() -> object:
        return platform

    monkeypatch.setattr(
        "aila.platform.runtime.orchestrator.get_worker_platform", _fake_get,
    )


class TestResolverReadsPlatformSlot:
    async def test_found_via_platform_intel_service(self, monkeypatch) -> None:
        svc = _FakeIntel(_fake_knowledge())
        _patch_platform(monkeypatch, svc)
        out = await resolve_cve_intel(["CVE-2026-0001"])
        assert len(out) == 1
        assert out[0].status == "found"
        assert out[0].description == "heap overflow in parser"
        assert out[0].kev_listed is True
        assert svc.calls == ["CVE-2026-0001"]

    async def test_error_when_no_intel_service(self, monkeypatch) -> None:
        _patch_platform(monkeypatch, None)
        out = await resolve_cve_intel(["CVE-2026-0001", "CVE-2026-0002"])
        assert len(out) == 2
        assert all(r.status == "error" for r in out)
