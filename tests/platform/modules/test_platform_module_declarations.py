"""Regression tests for module-declared worker tracks and idempotency opt-outs."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from aila.platform.config import PlatformConfigSchema
from aila.platform.modules import builtin
from aila.platform.modules.protocol import ModuleRouteSpec
from aila.platform.services.health_probes import _parse_worker_health_tracks

PLATFORM_SRC = Path(__file__).resolve().parents[3] / "src" / "aila"

FULL_STACK_TRACKS = (
    "default",
    "forensics",
    "forensics_readiness",
    "malware",
    "pentest",
    "pentest_runtime",
    "reporting",
    "vr",
    "vulnerability",
)


def _fake_module(tracks: tuple[str, ...], specs: list[ModuleRouteSpec] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        worker_tracks=tracks,
        route_specs=lambda: specs or [],
    )


def test_declared_worker_tracks_are_deduplicated_and_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = [_fake_module(("beta", "alpha")), _fake_module(("alpha", "gamma"))]
    monkeypatch.setattr(builtin, "builtin_module_factories", lambda: tuple(lambda m=m: m for m in modules))

    assert builtin.declared_worker_tracks() == ("alpha", "beta", "gamma")


def test_schema_default_defers_track_resolution_to_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    assert PlatformConfigSchema().worker_health_tracks == "auto"

    monkeypatch.setattr(builtin, "declared_worker_tracks", lambda: ("alpha", "beta"))

    assert _parse_worker_health_tracks("auto") == ["alpha", "beta"]


@pytest.mark.usefixtures("test_db")
def test_real_modules_declare_the_full_stack_tracks() -> None:
    assert builtin.declared_worker_tracks() == FULL_STACK_TRACKS


@pytest.mark.usefixtures("test_db")
def test_real_modules_declare_pentest_campaign_create_opt_outs() -> None:
    assert builtin.declared_idempotency_exempt_post_paths() == (
        "/pentest/live/campaigns",
        "/pentest/live/templates/{template_id}/campaigns",
    )


def test_route_spec_defaults_to_no_idempotency_opt_outs() -> None:
    spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)

    assert spec.idempotency_exempt_post_paths == ()


def test_platform_sources_do_not_name_a_module() -> None:
    platform_sources = [
        PLATFORM_SRC / "platform" / "config.py",
        PLATFORM_SRC / "api" / "middleware" / "idempotency.py",
        *(PLATFORM_SRC / "platform" / "modules").rglob("*.py"),
    ]
    offenders = [
        str(path)
        for path in platform_sources
        if "pentest" in path.read_text(encoding="utf-8").lower()
    ]
    assert offenders == []
