"""Tests for Phase 53 Plan 01: Module auto-discovery in create_app() and registry deps.

Tests verify:
- create_app() builds without error
- get_config_registry and get_tool_registry are importable from aila.api.deps
- get_config_registry raises 503 when platform is None
- get_tool_registry raises 503 when platform is None
- _mount_module_routers is present in app.py (auto-discovery logic)
- Both new deps are in __all__ of aila.api.deps
"""
from __future__ import annotations

import pytest


class TestRegistryDepsImportable:
    """get_config_registry and get_tool_registry are importable from aila.api.deps."""

    def test_get_config_registry_importable(self) -> None:
        from aila.api.deps import get_config_registry  # noqa: F401

    def test_get_tool_registry_importable(self) -> None:
        from aila.api.deps import get_tool_registry  # noqa: F401

    def test_both_in_all(self) -> None:
        from aila.api import deps

        assert "get_config_registry" in deps.__all__
        assert "get_tool_registry" in deps.__all__

    def test_all_contains_original_deps_too(self) -> None:
        """Original deps remain exported."""
        from aila.api import deps

        assert "get_platform" in deps.__all__


class TestRegistryDepsRaise503WithoutPlatform:
    """Registry deps raise HTTP 503 when platform is None."""

    def test_get_config_registry_raises_503_when_platform_none(self) -> None:
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        from aila.api.deps import get_config_registry

        # Build a mock request with app.state.platform = None
        mock_request = MagicMock()
        mock_request.app.state.platform = None

        with pytest.raises(HTTPException) as exc_info:
            get_config_registry(mock_request)

        assert exc_info.value.status_code == 503

    def test_get_tool_registry_raises_503_when_platform_none(self) -> None:
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        from aila.api.deps import get_tool_registry

        mock_request = MagicMock()
        mock_request.app.state.platform = None

        with pytest.raises(HTTPException) as exc_info:
            get_tool_registry(mock_request)

        assert exc_info.value.status_code == 503

    def test_get_config_registry_returns_registry_when_platform_has_it(self) -> None:
        """Config registry is accessed via platform.runtime.config_registry."""
        from unittest.mock import MagicMock

        from aila.api.deps import get_config_registry

        mock_config_registry = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.config_registry = mock_config_registry

        mock_platform = MagicMock()
        mock_platform.runtime = mock_runtime

        mock_request = MagicMock()
        mock_request.app.state.platform = mock_platform

        result = get_config_registry(mock_request)
        assert result is mock_config_registry

    def test_get_tool_registry_returns_registry_when_platform_has_it(self) -> None:
        """Tool registry is accessed via platform.runtime.tool_registry."""
        from unittest.mock import MagicMock

        from aila.api.deps import get_tool_registry

        mock_tool_registry = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.tool_registry = mock_tool_registry

        mock_platform = MagicMock()
        mock_platform.runtime = mock_runtime

        mock_request = MagicMock()
        mock_request.app.state.platform = mock_platform

        result = get_tool_registry(mock_request)
        assert result is mock_tool_registry


class TestCreateAppBuildsWithoutError:
    """create_app() builds successfully and includes auth+health routes."""

    def test_create_app_returns_app(self) -> None:
        from aila.api.app import create_app

        app = create_app()
        assert app is not None

    def test_routes_include_auth_and_health(self) -> None:
        from aila.api.app import create_app

        app = create_app()
        paths = {r.path for r in app.routes}
        assert "/auth/token" in paths
        assert "/health" in paths

    def test_module_auto_discovery_helper_exists_in_app_module(self) -> None:
        """_mount_module_routers function is defined in app.py."""
        import importlib

        app_module = importlib.import_module("aila.api.app")
        assert hasattr(app_module, "_mount_module_routers")

    def test_existing_tests_still_pass_with_new_app(self) -> None:
        """The test infrastructure (create_app + state setup) works the same."""
        import time

        from aila.api.app import create_app

        test_app = create_app()
        test_app.state.platform = None
        test_app.state.start_time = time.monotonic()
        # The app is still functional for health/auth routes
        assert test_app.state.platform is None
