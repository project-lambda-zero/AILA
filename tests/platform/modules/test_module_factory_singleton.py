"""Module-factory single-instantiation test for #41.

build_module_factory returned the raw create_module, so validation plus each
load_builtin_modules pass reconstructed the module -- create_module side
effects (platform_task registration, thread pools, metric counters) fired
multiple times at startup. The factory now constructs exactly once and every
call returns that same instance.
"""
from __future__ import annotations

from aila.platform.modules.protocol import ModuleProtocol
from aila.platform.modules.standard import build_module_factory


def test_factory_returns_same_instance_across_calls() -> None:
    factory = build_module_factory("aila.modules.hello_world")
    first = factory()
    second = factory()
    assert first is second
    assert isinstance(first, ModuleProtocol)
    assert first.module_id == "hello_world"
