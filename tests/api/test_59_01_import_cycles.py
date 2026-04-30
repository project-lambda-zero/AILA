"""Import cycle detection test for Phase 59 Plan 01 (QUALITY-04).

Dynamically discovers all .py modules in src/aila/api/ and
src/aila/platform/tasks/ and imports each one individually via
importlib.import_module(). If any circular import exists, the import
raises ImportError and the test fails.

This test replaces manual verification of import ordering. It runs
during CI and catches circular dependencies introduced by refactoring.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

# Project source root
_SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src"


def _discover_modules(package_path: Path, package_name: str) -> list[str]:
    """Discover all .py modules under a package directory.

    Args:
        package_path: Absolute filesystem path to the package directory.
        package_name: Dotted Python package name (e.g. 'aila.api').

    Returns:
        Sorted list of fully-qualified module names found under the package.
        Excludes __pycache__ directories. __init__.py files are resolved to
        the package name rather than a ..__init__ dotted path.
    """
    modules: list[str] = []
    for py_file in sorted(package_path.rglob("*.py")):
        if "__pycache__" in str(py_file):
            continue
        relative = py_file.relative_to(package_path)
        parts = list(relative.with_suffix("").parts)
        if parts == ["__init__"]:
            # Top-level __init__.py -> the package itself
            modules.append(package_name)
        elif parts[-1] == "__init__":
            # Sub-package __init__.py -> e.g. aila.api.routers
            sub = ".".join(parts[:-1])
            modules.append(f"{package_name}.{sub}")
        else:
            dotted = ".".join(parts)
            modules.append(f"{package_name}.{dotted}")
    return modules


# Discover modules at import time so parametrize IDs are readable
_API_PACKAGE = _SRC_ROOT / "aila" / "api"
_TASKS_PACKAGE = _SRC_ROOT / "aila" / "platform" / "tasks"

_API_MODULES = _discover_modules(_API_PACKAGE, "aila.api")
_TASKS_MODULES = _discover_modules(_TASKS_PACKAGE, "aila.platform.tasks")


class TestNoImportCyclesAPI:
    """Every module in src/aila/api/ imports without circular dependency."""

    @pytest.mark.parametrize("module_name", _API_MODULES)
    def test_import(self, module_name: str) -> None:
        """Import a single API module -- fails on circular import."""
        mod = importlib.import_module(module_name)
        assert mod is not None, f"import_module returned None for {module_name}"


class TestNoImportCyclesTasks:
    """Every module in src/aila/platform/tasks/ imports without circular dependency."""

    @pytest.mark.parametrize("module_name", _TASKS_MODULES)
    def test_import(self, module_name: str) -> None:
        """Import a single tasks module -- fails on circular import."""
        mod = importlib.import_module(module_name)
        assert mod is not None, f"import_module returned None for {module_name}"
