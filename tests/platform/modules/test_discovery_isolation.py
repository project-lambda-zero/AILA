"""Discovery isolation + deterministic ordering tests.

Covers issues #190 (a broken create_module must not abort the whole platform)
and #200 (module discovery order must not depend on filesystem traversal).

We reach through ``_discover_feature_module_factories`` by monkey-patching
``build_module_factory`` and ``pkgutil.iter_modules`` on the ``builtin``
module, then clearing its ``lru_cache`` so the test-controlled inputs are
what gets scanned. The real feature packages are untouched.
"""
from __future__ import annotations

import types

import pytest

from aila.platform.modules import builtin
from aila.platform.modules.protocol import ModuleProtocol


class _StubModule:
    """Tiny stand-in for a ModuleProtocol instance used only in these tests."""

    def __init__(self, module_id: str) -> None:
        self.module_id = module_id

    # ModuleProtocol is a @runtime_checkable Protocol; presence of the
    # attributes it enumerates is enough for isinstance checks that the
    # discovery path may run downstream. We deliberately do NOT satisfy
    # every method -- the discovery code under test only stashes the factory
    # and does not invoke it during discovery.


def _fake_module_info(name: str) -> types.SimpleNamespace:
    """Mimic the ``ModuleInfo`` shape ``pkgutil.iter_modules`` yields."""

    return types.SimpleNamespace(name=name, ispkg=True)


@pytest.fixture
def _patched_discovery(monkeypatch):
    """Redirect discovery to a controllable in-memory package listing."""

    fake_package = types.SimpleNamespace(__path__=["<test>"], __name__="test_pkg")
    monkeypatch.setattr(builtin, "_import_modules_package", lambda: fake_package)

    # Reset the memoised discovery result -- the real feature packages have
    # almost certainly been cached during collection of unrelated tests.
    builtin._discover_feature_module_factories.cache_clear()
    builtin.builtin_module_factories.cache_clear()
    yield
    builtin._discover_feature_module_factories.cache_clear()
    builtin.builtin_module_factories.cache_clear()


def test_broken_module_is_isolated_at_load(monkeypatch, _patched_discovery, caplog):
    """#190: a raising create_module skips that module and keeps the rest."""

    listing = [
        _fake_module_info("test_pkg.zulu"),
        _fake_module_info("test_pkg.broken"),
        _fake_module_info("test_pkg.alpha"),
        _fake_module_info("test_pkg._private"),  # underscore prefix -> ignored
    ]
    monkeypatch.setattr(
        builtin.pkgutil,
        "iter_modules",
        lambda path, prefix: iter(listing),
    )

    def _fake_build(package_name: str):
        short = package_name.rsplit(".", 1)[-1]
        if short == "broken":
            raise ValueError("simulated create_module failure")
        instance = _StubModule(short)
        return lambda: instance

    monkeypatch.setattr(builtin, "build_module_factory", _fake_build)

    with caplog.at_level("WARNING", logger=builtin.__name__):
        factories = builtin._discover_feature_module_factories()

    module_ids = [factory().module_id for factory in factories]
    assert "broken" not in module_ids, "broken module must be skipped"
    assert {"alpha", "zulu"}.issubset(set(module_ids)), (
        "well-formed modules must still load"
    )
    assert any(
        "broken" in record.getMessage() and "disabled" in record.getMessage()
        for record in caplog.records
    ), "failure must produce a visible WARNING naming the module"


def test_discovery_order_is_deterministic(monkeypatch, _patched_discovery):
    """#200: iteration order must be stable regardless of scan order."""

    module_short_names = ["mike", "alpha", "zulu", "bravo", "yankee"]
    forward = [_fake_module_info(f"test_pkg.{name}") for name in module_short_names]
    reverse = list(reversed(forward))

    def _fake_build(package_name: str):
        instance = _StubModule(package_name.rsplit(".", 1)[-1])
        return lambda: instance

    monkeypatch.setattr(builtin, "build_module_factory", _fake_build)

    monkeypatch.setattr(
        builtin.pkgutil,
        "iter_modules",
        lambda path, prefix: iter(forward),
    )
    builtin._discover_feature_module_factories.cache_clear()
    forward_ids = [f().module_id for f in builtin._discover_feature_module_factories()]

    monkeypatch.setattr(
        builtin.pkgutil,
        "iter_modules",
        lambda path, prefix: iter(reverse),
    )
    builtin._discover_feature_module_factories.cache_clear()
    reverse_ids = [f().module_id for f in builtin._discover_feature_module_factories()]

    assert forward_ids == sorted(module_short_names)
    assert forward_ids == reverse_ids, (
        "discovery must be filesystem-order-independent"
    )


def test_protocol_stub_shape_matches_expectations():
    """Guard: the stub is only used as a container for module_id."""

    stub = _StubModule("smoke")
    assert stub.module_id == "smoke"
    assert not isinstance(stub, ModuleProtocol)  # not a full protocol impl
