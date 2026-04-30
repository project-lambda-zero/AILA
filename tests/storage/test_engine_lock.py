"""Tests for CONC-01: engine lock protects both _ASYNC_ENGINES and _INITIALIZED_URLS.

Covers: 124-04-01, CONC-01
TDD red phase -- these tests will fail until Plan 04 fixes the
engine lock race condition in aila.storage.database.
"""
from __future__ import annotations

import ast
import inspect

import pytest

__all__: list[str] = []


def test_dispose_engine_discards_inside_lock():
    """_INITIALIZED_URLS.discard() must be inside _ENGINE_LOCK context in dispose_engine."""
    from aila.storage import database

    source = inspect.getsource(database.dispose_engine)
    tree = ast.parse(source)

    # Find the With node (the _ENGINE_LOCK context manager)
    found_discard_inside_lock = False
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            # Check if this With block contains _INITIALIZED_URLS.discard
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func = child.func
                    if (
                        isinstance(func, ast.Attribute)
                        and func.attr == "discard"
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "_INITIALIZED_URLS"
                    ):
                        found_discard_inside_lock = True

    assert found_discard_inside_lock, (
        "CONC-01: _INITIALIZED_URLS.discard() must be inside "
        "_ENGINE_LOCK block in dispose_engine()"
    )


def test_dispose_engine_pops_session_factories():
    """dispose_engine clears session factory cache for the URL."""
    from aila.storage import database

    source = inspect.getsource(database.dispose_engine)
    assert "_SESSION_FACTORIES" in source, (
        "dispose_engine should clear _SESSION_FACTORIES"
    )


@pytest.mark.asyncio
async def test_concurrent_dispose_no_race(pg_url):
    """Concurrent dispose_engine calls do not raise or corrupt state."""
    import asyncio

    from aila.storage.database import dispose_engine, get_async_engine

    # Create engine first
    get_async_engine()

    # Concurrent dispose should not raise
    results = await asyncio.gather(
        dispose_engine(),
        dispose_engine(),
        dispose_engine(),
        return_exceptions=True,
    )
    for r in results:
        assert not isinstance(r, Exception), (
            f"Concurrent dispose raised: {r}"
        )
