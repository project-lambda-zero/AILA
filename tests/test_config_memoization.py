from __future__ import annotations

"""Tests for get_settings() memoization and init_directories() separation.

Requirement: CONC-04 — get_settings() returns the same Settings instance
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


def test_build_settings_has_lru_cache() -> None:
    """_build_settings must be wrapped with functools.lru_cache."""
    from aila.config import _build_settings

    assert hasattr(_build_settings, "cache_info"), (
        "_build_settings must be decorated with @functools.lru_cache(maxsize=1)"
    )
    info = _build_settings.cache_info()
    assert info.maxsize == 1, "_build_settings lru_cache maxsize must be 1"


def test_get_settings_is_thin_wrapper() -> None:
    """get_settings() should not contain any mkdir calls; it delegates to _build_settings."""
    import inspect

    from aila import config

    src = inspect.getsource(config.get_settings)
    assert "mkdir" not in src, (
        "get_settings() must not contain mkdir calls — delegate to _build_settings()"
    )


def test_init_directories_is_callable() -> None:
    """init_directories() must exist and run without error."""
    from aila.config import init_directories

    # Must be callable
    assert callable(init_directories)
    # Must run without error (dirs may already exist)
    init_directories()


def test_init_directories_accepts_optional_settings() -> None:
    """init_directories() must accept an optional Settings argument."""
    import inspect

    from aila.config import init_directories

    sig = inspect.signature(init_directories)
    params = list(sig.parameters.values())
    # Must have exactly one optional parameter (settings=None) or zero required params
    assert len(params) <= 1, "init_directories() should have at most one parameter"
    if params:
        assert params[0].default is not inspect.Parameter.empty, (
            "init_directories() settings parameter must have a default value"
        )


def test_settings_fields_intact() -> None:
    """Settings dataclass has exactly 5 infrastructure fields after HONEST-01 slim."""
    import dataclasses

    from aila.config import _build_settings, get_settings

    _build_settings.cache_clear()

    s = get_settings()
    fields = {f.name for f in dataclasses.fields(s)}
    expected = {
        "database_url",
        "report_dir",
        "secret_keyring_path",
        "secret_active_key_version",
        "request_timeout_seconds",
        # Added in Phase 52 Plan 01 for API server support
        "jwt_secret_key",
        "api_host",
        "api_port",
    }
    assert fields == expected, f"Settings fields mismatch: {fields}"
