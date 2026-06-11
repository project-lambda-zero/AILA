"""Tests for the generic periodic-sweep registry.

The registry exposes three operations:
  - register_periodic_sweep(name, callable)
  - all_periodic_sweeps() -> dict[str, callable]

It is process-local + insertion-ordered + raises on duplicate name.
This file exercises every branch so a future refactor that lets two
modules accidentally share a name or smuggles in a non-callable trips
red here.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.tasks import sweeps


@pytest.fixture(autouse=True)
def _clear_registry() -> None:
    """Per-test isolation: snapshot + restore the registry."""
    snapshot = dict(sweeps._PERIODIC_SWEEPS)
    sweeps._PERIODIC_SWEEPS.clear()
    yield
    sweeps._PERIODIC_SWEEPS.clear()
    sweeps._PERIODIC_SWEEPS.update(snapshot)


async def _noop_sweep() -> int:
    return 0


async def _truthy_sweep() -> dict[str, Any]:
    return {"ran": True}


def test_register_single_sweep() -> None:
    sweeps.register_periodic_sweep("tests.alpha", _noop_sweep)
    registered = sweeps.all_periodic_sweeps()
    assert "tests.alpha" in registered
    assert registered["tests.alpha"] is _noop_sweep


def test_register_preserves_insertion_order() -> None:
    sweeps.register_periodic_sweep("tests.first", _noop_sweep)
    sweeps.register_periodic_sweep("tests.second", _noop_sweep)
    sweeps.register_periodic_sweep("tests.third", _noop_sweep)
    names = list(sweeps.all_periodic_sweeps())
    assert names == ["tests.first", "tests.second", "tests.third"]


def test_duplicate_name_raises() -> None:
    sweeps.register_periodic_sweep("tests.dup", _noop_sweep)
    with pytest.raises(ValueError, match="already registered"):
        sweeps.register_periodic_sweep("tests.dup", _truthy_sweep)


def test_empty_name_raises() -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        sweeps.register_periodic_sweep("", _noop_sweep)


def test_non_str_name_raises() -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        sweeps.register_periodic_sweep(None, _noop_sweep)  # type: ignore[arg-type]


def test_non_callable_sweep_raises() -> None:
    with pytest.raises(ValueError, match="must be callable"):
        sweeps.register_periodic_sweep("tests.bad", "not_a_function")  # type: ignore[arg-type]


def test_all_periodic_sweeps_returns_copy_not_reference() -> None:
    sweeps.register_periodic_sweep("tests.copy", _noop_sweep)
    snapshot1 = sweeps.all_periodic_sweeps()
    snapshot1["tests.injected"] = _truthy_sweep
    snapshot2 = sweeps.all_periodic_sweeps()
    assert "tests.injected" not in snapshot2


def test_vr_module_registers_expected_sweep_names() -> None:
    """The VR module's create_module() registers four sweeps.

    Phase C dropped vr.investigation_reaper (finalize covers its work)
    so the expected set is exactly:
      - vr.stage_tracker
      - vr.branch_reaper
      - vr.masvs_parent_reconciler
      - vr.finalize
    """
    from aila.modules.vr.module import create_module  # noqa: PLC0415
    create_module()
    names = list(sweeps.all_periodic_sweeps())
    assert set(names) == {
        "vr.stage_tracker",
        "vr.branch_reaper",
        "vr.masvs_parent_reconciler",
        "vr.finalize",
    }
    # vr.finalize must come AFTER the other VR sweeps so that finalize's
    # per-id helper delegates run after the lower-level reapers update
    # branch / stage state on the same cron tick.
    finalize_idx = names.index("vr.finalize")
    for peer in ("vr.stage_tracker", "vr.branch_reaper", "vr.masvs_parent_reconciler"):
        assert names.index(peer) < finalize_idx, (
            f"{peer} must register before vr.finalize (got order {names})"
        )


def test_vr_module_create_module_is_idempotent() -> None:
    """Calling create_module() twice in one process doesn't crash.

    Phase C added a module-level flag to guard against re-registration
    on hot-reload / test-fixture-driven re-instantiation.
    """
    from aila.modules.vr.module import create_module  # noqa: PLC0415
    create_module()
    first_snapshot = list(sweeps.all_periodic_sweeps())
    create_module()
    second_snapshot = list(sweeps.all_periodic_sweeps())
    assert first_snapshot == second_snapshot


@pytest.mark.asyncio
async def test_async_callable_compatibility() -> None:
    """Sweeps are awaitable; verify the registry stores async functions."""
    sweeps.register_periodic_sweep("tests.async", _truthy_sweep)
    fn = sweeps.all_periodic_sweeps()["tests.async"]
    result = await fn()
    assert result == {"ran": True}

