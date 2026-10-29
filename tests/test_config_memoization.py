from __future__ import annotations

"""Tests for get_settings() memoization and init_directories() separation.

Requirement: CONC-04 -- get_settings() returns the same Settings instance
on every call; mkdir side effects extracted into init_directories().
"""


def test_get_settings_returns_same_instance() -> None:
    """get_settings() must return the same object identity on every call."""
    # Clear cache to get a fresh baseline for this test
    from aila.config import _build_settings

    _build_settings.cache_clear()

    from aila.config import get_settings

    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2, "get_settings() must return same instance (object identity)"


def test_get_settings_stable_across_1000_calls() -> None:
    """1000 consecutive get_settings() calls must return identical object."""
    from aila.config import _build_settings, get_settings

    _build_settings.cache_clear()

    first = get_settings()
    results = [get_settings() for _ in range(999)]
    assert all(r is first for r in results), (
        "get_settings() must be stable across 1000 calls"
    )


def test_init_directories_is_callable() -> None:
    """init_directories() must exist and run without error."""
    from aila.config import init_directories

    # Must be callable
    assert callable(init_directories)
    # Must run without error (dirs may already exist)
    init_directories()


