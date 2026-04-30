from __future__ import annotations

from unittest.mock import MagicMock

from fastapi import APIRouter

from aila.modules.sbd_nfr.module import create_module
from aila.platform.modules.protocol import ModuleProtocol
from aila.platform.modules.standard import build_module_factory, validate_module_layout


def test_sbd_nfr_layout_validation() -> None:
    validate_module_layout("aila.modules.sbd_nfr")


def test_sbd_nfr_factory_validation() -> None:
    factory = build_module_factory("aila.modules.sbd_nfr")
    instance = factory()
    assert isinstance(instance, ModuleProtocol)
    assert instance.module_id == "sbd_nfr"


def test_sbd_nfr_route_spec_and_runtime() -> None:
    module = create_module()
    specs = module.route_specs()
    assert specs[0].prefix == "/sbd_nfr"
    assert isinstance(specs[0].router_factory(), APIRouter)
    runtime = module.build_runtime(MagicMock())
    assert runtime.module_id == "sbd_nfr"


def test_sbd_nfr_required_tools_and_profiles() -> None:
    module = create_module()
    assert module.required_tools()
    profiles = module.capability_profiles()
    assert profiles
    assert profiles[0].action_id.startswith("sbd_nfr.")


def test_module_status_in_platform_tool_keys() -> None:
    """Verify module_status tool is declared in PLATFORM_TOOL_KEYS (D-04)."""
    from aila.platform.runtime.builder import PLATFORM_TOOL_KEYS

    assert "module_status" in PLATFORM_TOOL_KEYS, "module_status missing from PLATFORM_TOOL_KEYS"
