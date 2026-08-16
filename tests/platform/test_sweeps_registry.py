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


def test_duplicate_name_different_callable_raises() -> None:
    sweeps.register_periodic_sweep("tests.dup", _noop_sweep)
    with pytest.raises(ValueError, match="already registered"):
        sweeps.register_periodic_sweep("tests.dup", _truthy_sweep)


def test_duplicate_name_same_callable_is_idempotent() -> None:
    # Re-registering the identical callable under the same name (double import
    # of a module __init__) is benign and must not raise.
    sweeps.register_periodic_sweep("tests.dup2", _noop_sweep)
    sweeps.register_periodic_sweep("tests.dup2", _noop_sweep)
    assert sweeps.all_periodic_sweeps()["tests.dup2"] is _noop_sweep


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
    """The VR module's create_module() registers six sweeps.

    Expected set is exactly:
      - vr.stage_tracker
      - vr.branch_reaper
      - vr.masvs_parent_reconciler
      - vr.finalize
      - vr.stall_recovery
      - vr.stuck_healer
    """
    from aila.modules.vr.module import create_module  # noqa: PLC0415
    create_module()
    names = list(sweeps.all_periodic_sweeps())
    assert set(names) == {
        "vr.stage_tracker",
        "vr.branch_reaper",
        "vr.masvs_parent_reconciler",
        "vr.finalize",
        "vr.stall_recovery",
        "vr.stuck_healer",
    }
    # vr.finalize must run AFTER the lower-level reapers so its
    # per-id helper delegates operate on already-converged branch /
    # stage state on the same cron tick. The RFC #208 SweepPriority
    # bins encode this: CAP_EXCEEDED_REAPER < ORPHAN_BRANCH_REAPER <
    # STALE_BRANCH_ABANDONMENT < NO_FINDING_SYNTHESIS.
    finalize_idx = names.index("vr.finalize")
    for peer in ("vr.stage_tracker", "vr.branch_reaper", "vr.masvs_parent_reconciler"):
        assert names.index(peer) < finalize_idx, (
            f"{peer} must run before vr.finalize (got order {names})"
        )
    # vr.stall_recovery is the recovery backstop -- must run AFTER
    # vr.finalize so finalize gets the first crack at every inv.
    # stall_recovery only re-enqueues invs that finalize chose not
    # to terminate (still in status=running with no live task).
    stall_idx = names.index("vr.stall_recovery")
    assert finalize_idx < stall_idx, (
        f"vr.stall_recovery must run AFTER vr.finalize "
        f"(got order {names})"
    )
    # vr.stuck_healer runs LAST in the VR pipeline: it heals the
    # narrow RUNNING-without-live-task zombie that survives every
    # earlier sweep on the tick.
    healer_idx = names.index("vr.stuck_healer")
    assert stall_idx < healer_idx, (
        f"vr.stuck_healer must run AFTER vr.stall_recovery "
        f"(got order {names})"
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


# -----------------------------------------------------------------
# RFC #208 ordering + failure-isolation (SAFE step of issue #133)
# -----------------------------------------------------------------


def test_registration_order_overridden_by_declared_priority() -> None:
    """Sweeps registered late but at low priority run first.

    Insertion order alone is not a contract because three module
    ``create_module()`` factories populate the registry in whatever
    order the platform imports them. The runner MUST honor the
    declared ``order`` so the cap-exceeded reaper always runs before
    the no-finding synthesis regardless of module import order.
    """
    sweeps.register_periodic_sweep(
        "tests.late_but_high_priority",
        _noop_sweep,
        order=sweeps.SweepPriority.CAP_EXCEEDED_REAPER,
    )
    sweeps.register_periodic_sweep(
        "tests.early_but_low_priority",
        _noop_sweep,
        order=sweeps.SweepPriority.STUCK_HEALER,
    )
    sweeps.register_periodic_sweep(
        "tests.middle",
        _noop_sweep,
        order=sweeps.SweepPriority.NO_FINDING_SYNTHESIS,
    )
    names = list(sweeps.all_periodic_sweeps())
    assert names == [
        "tests.late_but_high_priority",
        "tests.middle",
        "tests.early_but_low_priority",
    ]


def test_ties_on_order_break_on_registration_index() -> None:
    """Two sweeps at the same priority preserve their registration order.

    This is the compatibility contract for callers that never pass
    ``order=``: they all land on ``SweepPriority.DEFAULT`` and the
    tiebreaker gives them the pre-existing insertion-order behavior.
    """
    sweeps.register_periodic_sweep("tests.tie_a", _noop_sweep)
    sweeps.register_periodic_sweep("tests.tie_b", _noop_sweep)
    sweeps.register_periodic_sweep("tests.tie_c", _noop_sweep)
    names = list(sweeps.all_periodic_sweeps())
    assert names == ["tests.tie_a", "tests.tie_b", "tests.tie_c"]


def test_canonical_sweep_priority_bin_ordering() -> None:
    """The seven canonical bins run in the RFC #208 pipeline order.

    A stray reordering of the enum values (typo, merge conflict)
    would silently break the invariant that the cap-exceeded reaper
    runs before finalize. Pin the order here.
    """
    assert sweeps.SweepPriority.CAP_EXCEEDED_REAPER < sweeps.SweepPriority.STALE_BRANCH_ABANDONMENT
    assert sweeps.SweepPriority.STALE_BRANCH_ABANDONMENT < sweeps.SweepPriority.ORPHAN_BRANCH_REAPER
    assert sweeps.SweepPriority.ORPHAN_BRANCH_REAPER < sweeps.SweepPriority.NO_FINDING_SYNTHESIS
    assert sweeps.SweepPriority.NO_FINDING_SYNTHESIS < sweeps.SweepPriority.STUCK_HEALER
    assert sweeps.SweepPriority.STUCK_HEALER < sweeps.SweepPriority.CURSOR_REAPER


@pytest.mark.asyncio
async def test_run_periodic_sweeps_invokes_in_declared_order() -> None:
    """The runner iterates sweeps by declared priority, not insertion."""
    calls: list[str] = []

    async def make_sweep(name: str) -> Any:
        calls.append(name)
        return None

    # Register out of order so insertion order and declared order disagree.
    sweeps.register_periodic_sweep(
        "tests.finalize",
        lambda: make_sweep("tests.finalize"),
        order=sweeps.SweepPriority.NO_FINDING_SYNTHESIS,
    )
    sweeps.register_periodic_sweep(
        "tests.stage_tracker",
        lambda: make_sweep("tests.stage_tracker"),
        order=sweeps.SweepPriority.CAP_EXCEEDED_REAPER,
    )
    sweeps.register_periodic_sweep(
        "tests.branch_reaper",
        lambda: make_sweep("tests.branch_reaper"),
        order=sweeps.SweepPriority.ORPHAN_BRANCH_REAPER,
    )
    sweeps.register_periodic_sweep(
        "tests.stuck_healer",
        lambda: make_sweep("tests.stuck_healer"),
        order=sweeps.SweepPriority.STUCK_HEALER,
    )

    await sweeps.run_periodic_sweeps()

    assert calls == [
        "tests.stage_tracker",
        "tests.branch_reaper",
        "tests.finalize",
        "tests.stuck_healer",
    ]


@pytest.mark.asyncio
async def test_run_periodic_sweeps_isolates_failures() -> None:
    """One sweep raising does not abort the remaining sweeps in the tick.

    Failure isolation is the second half of the SAFE step: sweep 4
    exploding must not prevent sweeps 5, 6, 7 from running on the
    same tick. The runner logs and swallows per sweep and continues.
    """
    calls: list[str] = []

    async def _ok(name: str) -> str:
        calls.append(name)
        return f"{name}-done"

    async def _raise(name: str) -> None:
        calls.append(name)
        raise RuntimeError(f"{name} boom")

    sweeps.register_periodic_sweep(
        "tests.iso_first",
        lambda: _ok("tests.iso_first"),
        order=sweeps.SweepPriority.CAP_EXCEEDED_REAPER,
    )
    sweeps.register_periodic_sweep(
        "tests.iso_raiser",
        lambda: _raise("tests.iso_raiser"),
        order=sweeps.SweepPriority.NO_FINDING_SYNTHESIS,
    )
    sweeps.register_periodic_sweep(
        "tests.iso_last",
        lambda: _ok("tests.iso_last"),
        order=sweeps.SweepPriority.STUCK_HEALER,
    )

    results = await sweeps.run_periodic_sweeps()

    # Every sweep was invoked, in the correct order, despite the raise.
    assert calls == ["tests.iso_first", "tests.iso_raiser", "tests.iso_last"]

    # Results carry the exception for the failed sweep and the return
    # value (or None) for the others.
    assert results["tests.iso_first"] == "tests.iso_first-done"
    assert isinstance(results["tests.iso_raiser"], RuntimeError)
    assert results["tests.iso_last"] == "tests.iso_last-done"


def test_module_generic_partial_binding_survives_ordering() -> None:
    """The registry stores callables opaquely: functools.partial-bound
    sweeps (module-generic function bound per module with the module's
    model classes) sort by their declared priority just like plain
    async functions. The ordering key never inspects the callable, so
    the per-module partial binding is preserved across the sort.
    """
    from functools import partial  # noqa: PLC0415

    async def _generic(*, label: str) -> str:
        return label

    a_bound = partial(_generic, label="a")
    b_bound = partial(_generic, label="b")
    sweeps.register_periodic_sweep(
        "tests.partial_a",
        a_bound,
        order=sweeps.SweepPriority.STUCK_HEALER,
    )
    sweeps.register_periodic_sweep(
        "tests.partial_b",
        b_bound,
        order=sweeps.SweepPriority.CAP_EXCEEDED_REAPER,
    )
    ordered = sweeps.all_periodic_sweeps()
    names = list(ordered)
    assert names == ["tests.partial_b", "tests.partial_a"]
    # The stored callables are the exact partial objects the module
    # passed in -- not wrapped, not re-bound.
    assert ordered["tests.partial_a"] is a_bound
    assert ordered["tests.partial_b"] is b_bound


# -----------------------------------------------------------------
# Phase B.5 cancellation token tests
# ─────────────────────────────────────────────────────────────────


def test_cancellation_token_starts_un_cancelled() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        CancellationToken,
    )
    t = CancellationToken("test-inv-1")
    assert t.is_cancelled() is False
    assert t.id == "test-inv-1"


def test_cancellation_token_cancel_is_idempotent() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        CancellationToken,
    )
    t = CancellationToken("test-inv-2")
    t.cancel()
    assert t.is_cancelled() is True
    t.cancel()  # second call no-op
    assert t.is_cancelled() is True


def test_cancellation_token_raise_if_cancelled() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        CancellationToken,
        LLMCancelledError,
    )
    t = CancellationToken("test-inv-3")
    t.raise_if_cancelled()  # un-cancelled is a no-op
    t.cancel()
    import pytest  # noqa: PLC0415
    with pytest.raises(LLMCancelledError, match="test-inv-3"):
        t.raise_if_cancelled()


def test_registry_shares_token_across_callers() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        clear_for_investigation,
        get_cancellation_token,
    )
    clear_for_investigation("test-inv-4")
    a = get_cancellation_token("test-inv-4")
    b = get_cancellation_token("test-inv-4")
    assert a is b
    assert a.is_cancelled() is False


def test_cancel_for_investigation_flips_token() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        cancel_for_investigation,
        clear_for_investigation,
        get_cancellation_token,
    )
    clear_for_investigation("test-inv-5")
    t = get_cancellation_token("test-inv-5")
    assert t.is_cancelled() is False
    assert cancel_for_investigation("test-inv-5") is True
    assert t.is_cancelled() is True


def test_cancel_for_missing_investigation_returns_false() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        cancel_for_investigation,
        clear_for_investigation,
    )
    clear_for_investigation("test-inv-6-nonexistent")
    assert cancel_for_investigation("test-inv-6-nonexistent") is False


def test_clear_for_investigation_drops_token() -> None:
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        clear_for_investigation,
        get_cancellation_token,
        token_registry_snapshot,
    )
    get_cancellation_token("test-inv-7")
    assert "test-inv-7" in token_registry_snapshot()
    clear_for_investigation("test-inv-7")
    assert "test-inv-7" not in token_registry_snapshot()
