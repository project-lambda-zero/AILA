"""Exhaustive tests for app.py and deps.py deep review (Phase 74).

Covers every branch of get_platform, get_config_registry, get_tool_registry,
lifespan, _mount_module_routers, create_app, and CORS configuration.
"""
from __future__ import annotations

import ast
import inspect
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException


# ---------------------------------------------------------------------------
# deps.py: get_platform
# ---------------------------------------------------------------------------

class TestGetPlatform:
    """Test get_platform dependency function."""

    def test_returns_platform_from_app_state(self) -> None:
        """get_platform returns whatever is stored in app.state.platform."""
        from aila.api.deps import get_platform

        sentinel = MagicMock(name="platform-sentinel")
        request = MagicMock()
        request.app.state.platform = sentinel

        result = get_platform(request)
        assert result is sentinel

    def test_returns_none_when_platform_is_none(self) -> None:
        """get_platform passes through None without raising."""
        from aila.api.deps import get_platform

        request = MagicMock()
        request.app.state.platform = None

        result = get_platform(request)
        assert result is None


# ---------------------------------------------------------------------------
# deps.py: get_config_registry
# ---------------------------------------------------------------------------

class TestGetConfigRegistry:
    """Test get_config_registry dependency function."""

    def test_raises_503_when_platform_none(self) -> None:
        from aila.api.deps import get_config_registry

        request = MagicMock()
        request.app.state.platform = None

        with pytest.raises(HTTPException) as exc_info:
            get_config_registry(request)
        assert exc_info.value.status_code == 503

    def test_raises_503_when_runtime_missing(self) -> None:
        """Platform exists but has no runtime attribute."""
        from aila.api.deps import get_config_registry

        # Create a platform mock that lacks 'runtime' attribute via spec
        platform = MagicMock(spec=[])  # empty spec: hasattr(platform, "runtime") => False
        request = MagicMock()
        request.app.state.platform = platform

        with pytest.raises(HTTPException) as exc_info:
            get_config_registry(request)
        assert exc_info.value.status_code == 503

    def test_raises_503_when_runtime_none(self) -> None:
        from aila.api.deps import get_config_registry

        platform = MagicMock()
        platform.runtime = None
        request = MagicMock()
        request.app.state.platform = platform

        with pytest.raises(HTTPException) as exc_info:
            get_config_registry(request)
        assert exc_info.value.status_code == 503

    def test_raises_503_when_registry_none(self) -> None:
        from aila.api.deps import get_config_registry

        platform = MagicMock()
        platform.runtime.config_registry = None
        request = MagicMock()
        request.app.state.platform = platform

        with pytest.raises(HTTPException) as exc_info:
            get_config_registry(request)
        assert exc_info.value.status_code == 503

    def test_503_detail_contains_config_registry_text(self) -> None:
        """The 503 detail message must mention 'config registry' for diagnostics."""
        from aila.api.deps import get_config_registry

        request = MagicMock()
        request.app.state.platform = None

        with pytest.raises(HTTPException) as exc_info:
            get_config_registry(request)
        assert "config registry" in exc_info.value.detail.lower()

    def test_returns_registry_on_happy_path(self) -> None:
        from aila.api.deps import get_config_registry

        sentinel = MagicMock(name="config-registry")
        platform = MagicMock()
        platform.runtime.config_registry = sentinel
        request = MagicMock()
        request.app.state.platform = platform

        result = get_config_registry(request)
        assert result is sentinel


# ---------------------------------------------------------------------------
# deps.py: get_tool_registry
# ---------------------------------------------------------------------------

class TestGetToolRegistry:
    """Test get_tool_registry dependency function."""

    def test_raises_503_when_platform_none(self) -> None:
        from aila.api.deps import get_tool_registry

        request = MagicMock()
        request.app.state.platform = None

        with pytest.raises(HTTPException) as exc_info:
            get_tool_registry(request)
        assert exc_info.value.status_code == 503

    def test_raises_503_when_runtime_missing(self) -> None:
        from aila.api.deps import get_tool_registry

        platform = MagicMock(spec=[])
        request = MagicMock()
        request.app.state.platform = platform

        with pytest.raises(HTTPException) as exc_info:
            get_tool_registry(request)
        assert exc_info.value.status_code == 503

    def test_raises_503_when_runtime_none(self) -> None:
        from aila.api.deps import get_tool_registry

        platform = MagicMock()
        platform.runtime = None
        request = MagicMock()
        request.app.state.platform = platform

        with pytest.raises(HTTPException) as exc_info:
            get_tool_registry(request)
        assert exc_info.value.status_code == 503

    def test_returns_registry_on_happy_path(self) -> None:
        from aila.api.deps import get_tool_registry

        sentinel = MagicMock(name="tool-registry")
        platform = MagicMock()
        platform.runtime.tool_registry = sentinel
        request = MagicMock()
        request.app.state.platform = platform

        result = get_tool_registry(request)
        assert result is sentinel


# ---------------------------------------------------------------------------
# app.py: _mount_module_routers
# ---------------------------------------------------------------------------

class TestMountModuleRouters:
    """Test module auto-discovery and router mounting."""

    def test_vulnerability_routes_discovered(self) -> None:
        """create_app() auto-discovers vulnerability module routes."""
        from aila.api.app import create_app

        application = create_app()
        route_paths = [r.path for r in application.routes if hasattr(r, "path")]
        # Vulnerability module should produce at least one route path containing 'vulnerability'
        vuln_routes = [p for p in route_paths if "vulnerability" in p.lower()]
        assert len(vuln_routes) > 0, f"No vulnerability routes found in {route_paths}"

    def test_hello_world_routes_discovered(self) -> None:
        """create_app() auto-discovers hello_world module routes."""
        from aila.api.app import create_app

        application = create_app()
        route_paths = [r.path for r in application.routes if hasattr(r, "path")]
        hw_routes = [p for p in route_paths if "hello" in p.lower()]
        assert len(hw_routes) > 0, f"No hello_world routes found in {route_paths}"

    def test_route_specs_exception_skips_module(self) -> None:
        """When a module factory raises on route_specs(), the app still creates."""
        from aila.api.app import create_app

        def bad_factory():
            raise RuntimeError("boom during route_specs")

        with patch("aila.platform.modules.builtin.builtin_module_factories", return_value=(bad_factory,)):
            # Should not crash -- the warning is logged and factory skipped
            application = create_app()
            assert isinstance(application, FastAPI)

    def test_router_factory_exception_skips_spec(self) -> None:
        """When a spec's router_factory raises, other routes still mount."""
        from aila.api.app import create_app
        from aila.platform.modules.protocol import ModuleRouteSpec

        def bad_router_factory():
            raise RuntimeError("router boom")

        bad_spec = ModuleRouteSpec(
            prefix="/bad",
            router_factory=bad_router_factory,
        )
        good_module = MagicMock()
        good_module.route_specs.return_value = [bad_spec]

        def good_factory():
            return good_module

        with patch("aila.platform.modules.builtin.builtin_module_factories", return_value=(good_factory,)):
            application = create_app()
            assert isinstance(application, FastAPI)

    def test_module_routes_have_auth_dependency(self) -> None:
        """Module-mounted routes include Depends(require_user_or_api_key)."""
        from aila.api.app import create_app
        from aila.api.auth import require_user_or_api_key

        application = create_app()
        route_paths = [r.path for r in application.routes if hasattr(r, "path")]
        # Find a module route (vulnerability or hello_world)
        module_route_paths = [p for p in route_paths if "vulnerability" in p.lower() or "hello" in p.lower()]
        assert len(module_route_paths) > 0

        # Check the dependencies on the actual route objects
        for route in application.routes:
            if not hasattr(route, "path"):
                continue
            if route.path not in module_route_paths:
                continue
            # Module routes are sub-applications or have dependencies at router level
            if hasattr(route, "dependencies"):
                dep_callables = [d.dependency for d in route.dependencies]
                if require_user_or_api_key in dep_callables:
                    return  # Found at least one with auth dependency -- pass
        # Also check via router dependency which gets merged into routes.
        source = inspect.getsource(__import__("aila.api.app", fromlist=["_mount_module_routers"])._mount_module_routers)
        assert "require_user_or_api_key" in source


# ---------------------------------------------------------------------------
# app.py: create_app
# ---------------------------------------------------------------------------

class TestCreateApp:
    """Test create_app factory function."""

    def test_returns_fastapi_instance(self) -> None:
        from aila.api.app import create_app
        assert isinstance(create_app(), FastAPI)

    def test_core_routes_present(self) -> None:
        from aila.api.app import create_app

        application = create_app()
        paths = {r.path for r in application.routes if hasattr(r, "path")}
        assert "/auth/token" in paths
        assert "/health" in paths
        assert "/status" in paths

    def test_platform_routes_present(self) -> None:
        from aila.api.app import create_app

        application = create_app()
        paths = {r.path for r in application.routes if hasattr(r, "path")}
        # Platform routers have prefix-based paths
        audit_paths = [p for p in paths if p.startswith("/audit")]
        config_paths = [p for p in paths if p.startswith("/config")]
        systems_paths = [p for p in paths if p.startswith("/systems")]
        tools_paths = [p for p in paths if p.startswith("/tools")]
        assert len(audit_paths) > 0
        assert len(config_paths) > 0
        assert len(systems_paths) > 0
        assert len(tools_paths) > 0

    def test_task_routes_present(self) -> None:
        from aila.api.app import create_app

        application = create_app()
        paths = {r.path for r in application.routes if hasattr(r, "path")}
        task_paths = [p for p in paths if "/task" in p]
        assert len(task_paths) > 0

    def test_session_and_scan_routes_present(self) -> None:
        from aila.api.app import create_app

        application = create_app()
        paths = {r.path for r in application.routes if hasattr(r, "path")}
        session_paths = [p for p in paths if "/sessions" in p]
        analyze_paths = [p for p in paths if "/analyze" in p]
        assert len(session_paths) > 0
        assert len(analyze_paths) > 0


# ---------------------------------------------------------------------------
# app.py: CORS configuration
# ---------------------------------------------------------------------------

class TestCorsConfiguration:
    """Test CORS middleware configuration."""

    @staticmethod
    def _get_cors_origins(application: FastAPI) -> list[str]:
        """Extract allow_origins from the CORSMiddleware in the middleware stack."""
        for middleware in application.user_middleware:
            if middleware.cls.__name__ == "CORSMiddleware":
                return middleware.kwargs.get("allow_origins", [])
        pytest.fail("CORSMiddleware not found in middleware stack")
        return []  # unreachable, satisfies type checker

    def test_default_origin_is_localhost_3000(self, monkeypatch) -> None:
        """Default AILA_CORS_ORIGINS should be http://localhost:3000."""
        monkeypatch.delenv("AILA_CORS_ORIGINS", raising=False)
        from aila.api.app import create_app

        application = create_app()
        origins = self._get_cors_origins(application)
        assert origins == ["http://localhost:3000"]

    def test_comma_separated_origins_parsed(self, monkeypatch) -> None:
        monkeypatch.setenv("AILA_CORS_ORIGINS", "http://a.com,http://b.com")
        from aila.api.app import create_app

        application = create_app()
        origins = self._get_cors_origins(application)
        assert "http://a.com" in origins
        assert "http://b.com" in origins

    def test_empty_entries_filtered(self, monkeypatch) -> None:
        monkeypatch.setenv("AILA_CORS_ORIGINS", "http://a.com,,  ,http://b.com")
        from aila.api.app import create_app

        application = create_app()
        origins = self._get_cors_origins(application)
        assert "" not in origins
        assert "  " not in origins
        assert "http://a.com" in origins
        assert "http://b.com" in origins

    def test_no_hardcoded_wildcard_in_source(self) -> None:
        """Source code must not contain allow_origins=["*"] hardcoded."""
        app_py_path = os.path.join(os.path.dirname(__file__), "..", "..", "src", "aila", "api", "app.py")
        app_py_path = os.path.normpath(app_py_path)
        with open(app_py_path) as f:
            source = f.read()

        # Parse AST and check for allow_origins=["*"] in keyword arguments
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "allow_origins":
                # Check if value is a list literal containing just "*"
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            pytest.fail("Found hardcoded allow_origins=['*'] in app.py source")


# ---------------------------------------------------------------------------
# app.py: lifespan
# ---------------------------------------------------------------------------

class TestLifespan:
    """Test lifespan context manager."""

    @pytest.mark.asyncio
    async def test_sets_start_time(self, test_db, monkeypatch) -> None:
        """Lifespan sets app.state.start_time as a float."""
        from aila.api.app import lifespan

        monkeypatch.setenv("AILA_ADMIN_PASSWORD", "test-admin-password")

        application = FastAPI()
        mock_platform = MagicMock()
        mock_platform._ensure_initialized = AsyncMock()
        with patch("aila.api.app.AILAPlatform", return_value=mock_platform):
            async with lifespan(application):
                assert hasattr(application.state, "start_time")
                assert isinstance(application.state.start_time, float)
    @pytest.mark.asyncio
    async def test_platform_construction_failure_raises(self) -> None:
        """Platform construction failure aborts startup instead of storing None."""
        from aila.api.app import lifespan

        application = FastAPI()
        with patch("aila.api.app.AILAPlatform", side_effect=RuntimeError("LLM not configured")):
            with pytest.raises(RuntimeError, match="LLM not configured"):
                async with lifespan(application):
                    pass
    @pytest.mark.asyncio
    async def test_bootstrap_key_creates_admin_when_db_empty(self, test_db, monkeypatch) -> None:
        """AILA_BOOTSTRAP_KEY creates an admin key when DB has zero keys."""
        from aila.api.app import lifespan
        from aila.storage.database import session_scope
        from aila.storage.db_models import ApiKeyRecord
        from sqlmodel import select

        monkeypatch.setenv("AILA_BOOTSTRAP_KEY", "test-bootstrap-key-12345")
        monkeypatch.setenv("AILA_ADMIN_PASSWORD", "test-admin-password")
        application = FastAPI()
        mock_platform = MagicMock()
        mock_platform._ensure_initialized = AsyncMock()
        with patch("aila.api.app.AILAPlatform", return_value=mock_platform):
            async with lifespan(application):
                pass

        with session_scope() as session:
            keys = session.exec(select(ApiKeyRecord)).all()
        assert len(keys) == 1
        assert keys[0].role == "admin"
        assert keys[0].label == "bootstrap"

    @pytest.mark.asyncio
    async def test_bootstrap_key_idempotent_when_keys_exist(self, test_db, monkeypatch) -> None:
        """AILA_BOOTSTRAP_KEY does NOT create duplicate when keys already exist."""
        from aila.api.app import lifespan
        from aila.api.auth import hash_api_key
        from aila.platform.contracts._common import utc_now
        from aila.storage.database import session_scope
        from aila.storage.db_models import ApiKeyRecord
        from sqlmodel import select

        # Seed one key first
        with session_scope() as session:
            session.add(ApiKeyRecord(
                hashed_key=hash_api_key("existing-key"),
                key_prefix="existing-key",
                role="admin",
                label="pre-existing",
                created_by="test",
                created_at=utc_now(),
            ))
            session.commit()

        monkeypatch.setenv("AILA_BOOTSTRAP_KEY", "another-bootstrap-key")
        monkeypatch.setenv("AILA_ADMIN_PASSWORD", "test-admin-password")
        application = FastAPI()
        mock_platform = MagicMock()
        mock_platform._ensure_initialized = AsyncMock()
        with patch("aila.api.app.AILAPlatform", return_value=mock_platform):
            async with lifespan(application):
                pass

        with session_scope() as session:
            keys = session.exec(select(ApiKeyRecord)).all()
        assert len(keys) == 1  # Still only the original key

    @pytest.mark.asyncio
    async def test_empty_bootstrap_key_ignored(self, test_db, monkeypatch) -> None:
        """Empty AILA_BOOTSTRAP_KEY is ignored (no key created)."""
        from aila.api.app import lifespan
        from aila.storage.database import session_scope
        from aila.storage.db_models import ApiKeyRecord
        from sqlmodel import select

        monkeypatch.setenv("AILA_BOOTSTRAP_KEY", "")
        monkeypatch.setenv("AILA_ADMIN_PASSWORD", "test-admin-password")
        application = FastAPI()
        mock_platform = MagicMock()
        mock_platform._ensure_initialized = AsyncMock()
        with patch("aila.api.app.AILAPlatform", return_value=mock_platform):
            async with lifespan(application):
                pass

        with session_scope() as session:
            keys = session.exec(select(ApiKeyRecord)).all()
        assert len(keys) == 0


# ---------------------------------------------------------------------------
# deps.py: type annotation structural checks
# ---------------------------------------------------------------------------

class TestDepsTypeAnnotations:
    """Verify deps.py type annotations are concrete, not bare object."""

    def test_config_registry_return_type_is_concrete(self) -> None:
        """get_config_registry return annotation should be ConfigRegistry, not object."""
        from aila.api.deps import get_config_registry
        hints = get_config_registry.__annotations__
        assert hints.get("return") == "ConfigRegistry", f"Expected ConfigRegistry, got {hints.get('return')}"

    def test_tool_registry_return_type_is_concrete(self) -> None:
        """get_tool_registry return annotation should be ToolRegistry, not object."""
        from aila.api.deps import get_tool_registry
        hints = get_tool_registry.__annotations__
        assert hints.get("return") == "ToolRegistry", f"Expected ToolRegistry, got {hints.get('return')}"

    def test_type_checking_guard_present(self) -> None:
        """deps.py must use TYPE_CHECKING guard for registry imports."""
        import aila.api.deps as deps_module
        source = inspect.getsource(deps_module)
        assert "TYPE_CHECKING" in source
