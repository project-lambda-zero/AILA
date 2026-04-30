"""Tests for config pre-resolution in AILAPlatform._ensure_initialized (CFG-02)."""
from __future__ import annotations

import ast

import pytest


def test_ensure_initialized_source_contains_resolved_config():
    """_ensure_initialized must call build_platform_settings with resolved_config after DB init."""
    from pathlib import Path

    source_path = Path("src/aila/platform/runtime/orchestrator.py")
    source = source_path.read_text()
    tree = ast.parse(source)

    # Find _ensure_initialized method
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_ensure_initialized":
            body_source = ast.dump(node)
            assert "all_entries_by_namespace" in body_source or "resolved_config" in ast.get_source_segment(source, node), (
                "_ensure_initialized must call all_entries_by_namespace or use resolved_config"
            )
            break
    else:
        pytest.fail("_ensure_initialized not found as async def in orchestrator.py")


def test_build_platform_settings_called_with_resolved_config_in_ensure_initialized():
    """Verify that the source code of _ensure_initialized re-calls build_platform_settings."""
    from pathlib import Path

    source = Path("src/aila/platform/runtime/orchestrator.py").read_text()
    # Find _ensure_initialized method body
    start = source.find("async def _ensure_initialized")
    assert start != -1, "_ensure_initialized must exist"
    # Find the next method definition to bound the search
    next_def = source.find("\n    async def ", start + 1)
    if next_def == -1:
        next_def = source.find("\n    def ", start + 1)
    if next_def == -1:
        next_def = len(source)
    body = source[start:next_def]
    assert "build_platform_settings" in body, (
        "_ensure_initialized must call build_platform_settings with resolved_config"
    )
    assert "resolved_config" in body, (
        "_ensure_initialized must pass resolved_config to build_platform_settings"
    )
