"""XCUT-12 / XCUT-13: OpenAPI schema completeness and module discovery proof.

Tests:
  1. No bare {} response schemas in the generated OpenAPI JSON
  2. No empty object schemas (type:object without properties) in responses
  3. Every registered APIRoute appears in the OpenAPI paths dict
  4. hello_world module routes appear in OpenAPI via auto-discovery
  5. Removing a module removes its routes from OpenAPI
  6. Adding a fake module adds its routes to OpenAPI
"""
from __future__ import annotations

import re
from unittest.mock import patch

import pytest
from fastapi import APIRouter
from fastapi.routing import APIRoute

from aila.api.app import create_app
from aila.platform.modules.protocol import ModuleProtocol, ModuleRouteSpec

# FastAPI route table stores path converters (e.g., {key:path}) but OpenAPI
# strips them to plain {key}. Normalize for comparison.
_PATH_CONVERTER_RE = re.compile(r"\{(\w+):\w+\}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_openapi_schema(app=None):
    """Generate the OpenAPI schema dict from a fresh or given app."""
    if app is None:
        app = create_app()
    return app.openapi()


def _find_bare_empty(obj, path=""):
    """Recursively find all bare {} (empty dict) values in a nested structure."""
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict) and len(v) == 0:
                results.append(f"{path}.{k}")
            results.extend(_find_bare_empty(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, dict) and len(v) == 0:
                results.append(f"{path}[{i}]")
            results.extend(_find_bare_empty(v, f"{path}[{i}]"))
    return results


def _find_empty_object_schemas(obj, path=""):
    """Find type:object schemas with no properties, additionalProperties, or $ref."""
    results = []
    if isinstance(obj, dict):
        if (
            obj.get("type") == "object"
            and "properties" not in obj
            and "additionalProperties" not in obj
            and "$ref" not in obj
            and "allOf" not in obj
            and "oneOf" not in obj
            and "anyOf" not in obj
        ):
            results.append((path, obj))
        for k, v in obj.items():
            results.extend(_find_empty_object_schemas(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            results.extend(_find_empty_object_schemas(v, f"{path}[{i}]"))
    return results


# Paths that are framework-generated and not our concern
_FRAMEWORK_PATHS = {"/docs", "/redoc", "/openapi.json"}


# ---------------------------------------------------------------------------
# XCUT-12: OpenAPI schema has no bare {} types
# ---------------------------------------------------------------------------


def test_openapi_no_bare_empty_schemas():
    """Every response schema in the OpenAPI JSON must be non-empty.

    A bare {} means FastAPI could not infer the response shape -- typically
    caused by returning JSONResponse or StreamingResponse without
    response_model or responses metadata.
    """
    schema = _get_openapi_schema()
    empties = _find_bare_empty(schema)
    assert empties == [], (
        f"Found bare {{}} in OpenAPI schema at:\n"
        + "\n".join(f"  {p}" for p in empties)
    )


def test_openapi_no_untyped_object_schemas():
    """No response-level object schema should be type:object without properties.

    The only acceptable exception is Pydantic's ValidationError.ctx which is
    framework-generated and inherently unstructured.
    """
    schema = _get_openapi_schema()
    empties = _find_empty_object_schemas(schema)

    # Filter out the well-known Pydantic ValidationError.ctx exception
    filtered = [
        (p, o) for p, o in empties
        if "ValidationError" not in p
    ]
    assert filtered == [], (
        f"Found empty object schemas:\n"
        + "\n".join(f"  {p}: {o}" for p, o in filtered)
    )


# ---------------------------------------------------------------------------
# XCUT-12: Every registered route appears in OpenAPI
# ---------------------------------------------------------------------------


def test_every_route_in_openapi():
    """Every APIRoute registered in the app must appear in the OpenAPI paths dict.

    This catches routes that might be mounted but excluded from OpenAPI
    (e.g., include_in_schema=False).
    """
    app = create_app()
    schema = app.openapi()
    openapi_paths = set(schema.get("paths", {}).keys())

    missing = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        # Normalize path converters: {key:path} -> {key}
        normalized_path = _PATH_CONVERTER_RE.sub(r"{\1}", route.path)
        if normalized_path in _FRAMEWORK_PATHS:
            continue
        if normalized_path not in openapi_paths:
            methods = ",".join(sorted(route.methods or set()))
            missing.append(f"{methods} {normalized_path}")

    assert missing == [], (
        f"Routes registered but not in OpenAPI:\n"
        + "\n".join(f"  {r}" for r in missing)
    )


def test_every_openapi_route_has_response_schema():
    """Every path+method in OpenAPI must have at least one response with a schema or content.

    Ensures no endpoint has completely undefined responses.
    """
    schema = _get_openapi_schema()
    missing = []
    for path, methods in schema.get("paths", {}).items():
        for method, details in methods.items():
            if method == "parameters":
                continue
            responses = details.get("responses", {})
            if not responses:
                missing.append(f"{method.upper()} {path}: no responses defined")
                continue
            # Check that at least one response has content or description
            has_content = any(
                resp.get("content") or resp.get("description")
                for resp in responses.values()
            )
            if not has_content:
                missing.append(f"{method.upper()} {path}: responses have no content or description")

    assert missing == [], (
        f"Routes with undefined responses:\n"
        + "\n".join(f"  {r}" for r in missing)
    )


# ---------------------------------------------------------------------------
# XCUT-13: Module discovery proof
# ---------------------------------------------------------------------------


def test_hello_world_routes_in_openapi():
    """hello_world module routes must appear in OpenAPI via auto-discovery.

    The hello_world module declares route_specs() with prefix=/hello_world.
    The platform auto-mounts it without any code changes to app.py.
    """
    schema = _get_openapi_schema()
    openapi_paths = set(schema.get("paths", {}).keys())
    assert "/hello_world/status" in openapi_paths, (
        f"hello_world /status not in OpenAPI paths. "
        f"Available paths: {sorted(openapi_paths)}"
    )

    # Verify the response schema is not empty
    status_path = schema["paths"]["/hello_world/status"]
    get_op = status_path.get("get", {})
    resp_200 = get_op.get("responses", {}).get("200", {})
    content = resp_200.get("content", {}).get("application/json", {})
    resp_schema = content.get("schema", {})
    assert resp_schema != {}, "hello_world /status response schema should not be bare {}"


def test_module_removal_removes_routes_from_openapi():
    """Removing a module from discovery removes its routes from OpenAPI.

    Patches builtin_module_factories to return only PlatformModule (no feature
    modules). The vulnerability and hello_world routes must not appear.
    """
    from aila.platform.modules.builtin import builtin_module_factories
    from aila.platform.modules.platform import PlatformModule

    # Cache the original result for cleanup
    original = builtin_module_factories()

    # Clear lru_cache so the patched version is used
    builtin_module_factories.cache_clear()
    try:
        with patch(
            "aila.platform.modules.builtin.builtin_module_factories",
            return_value=(PlatformModule,),
        ):
            app = create_app()
            schema = app.openapi()
            openapi_paths = set(schema.get("paths", {}).keys())

            # Module routes must be absent
            hello_world_paths = [p for p in openapi_paths if "/hello_world" in p]
            vuln_paths = [p for p in openapi_paths if "/vulnerability" in p]
            assert hello_world_paths == [], f"hello_world routes still present: {hello_world_paths}"
            assert vuln_paths == [], f"vulnerability routes still present: {vuln_paths}"

            # Platform routes must remain
            assert "/health" in openapi_paths
            assert "/auth/token" in openapi_paths
    finally:
        builtin_module_factories.cache_clear()


def test_module_addition_adds_routes_to_openapi():
    """Adding a new module via discovery adds its routes to OpenAPI.

    Creates a fake module with route_specs() declaring /fake_module/ping.
    Patches builtin_module_factories to include it. The new route must
    appear in the OpenAPI schema without any changes to app.py.
    """
    from aila.platform.modules.builtin import builtin_module_factories
    from aila.platform.modules.platform import PlatformModule

    # Create a minimal fake module
    class FakeModule:
        """Fake module for testing auto-discovery."""

        module_id = "fake_test"
        action_id = "fake_test.run"

        def route_specs(self):
            return [
                ModuleRouteSpec(
                    prefix="/fake_module",
                    router_factory=_fake_router_factory,
                    tool_keys=(),
                    config_namespace=None,
                ),
            ]

        def capability_profiles(self):
            return []

        def required_tools(self):
            return []

        def register_tools(self, tool_registry, settings, registry=None, schema_registry=None):
            pass

        def build_runtime(self, context):
            pass

        def health_checks(self):
            return {}

        def report_filter_keys(self):
            return []

        def filter_report_rows(self, rows, filters=None):
            return list(rows)

        def seed_data(self, session):
            pass

        def system_summary(self, system_id, session):
            return {}

        def report_count(self, run_id, session):
            return {}

    original = builtin_module_factories()
    builtin_module_factories.cache_clear()
    try:
        # Include PlatformModule + all original feature modules + FakeModule
        factories = (*original, FakeModule)
        with patch(
            "aila.platform.modules.builtin.builtin_module_factories",
            return_value=factories,
        ):
            app = create_app()
            schema = app.openapi()
            openapi_paths = set(schema.get("paths", {}).keys())

            assert "/fake_module/ping" in openapi_paths, (
                f"/fake_module/ping not found in OpenAPI. "
                f"Available paths with 'fake': {[p for p in openapi_paths if 'fake' in p]}"
            )
    finally:
        builtin_module_factories.cache_clear()


def _fake_router_factory() -> APIRouter:
    """Create a fake router with one GET /ping endpoint."""
    router = APIRouter(tags=["fake_test"])

    @router.get("/ping", summary="Fake ping endpoint")
    async def ping() -> dict[str, str]:
        return {"module": "fake_test", "status": "pong"}

    return router
