"""Automated module standards compliance test suite (Phase 63-02).

Verifies three compliance dimensions:

1. TestVulnerabilityModuleCompliance -- every ModuleProtocol method is satisfied
   by the vulnerability module (MOD-STD-02).
2. TestImportBoundaryV15Coverage -- honesty_audit import_boundary rule covers
   all v1.5 directories: api/, platform/tasks/, platform/ (MOD-STD-05).
3. TestPlatformModuleBoundary -- platform and storage code never imports from
   aila.modules.vulnerability.* internals (MOD-STD-07).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from aila.modules.vulnerability.module import create_module
from aila.platform.modules.protocol import ModuleProtocol, ModuleRouteSpec
from aila.platform.modules.standard import build_module_factory, validate_module_layout
from aila.tools.honesty_audit import HonestyAuditor

__all__ = [
    "TestVulnerabilityModuleCompliance",
    "TestImportBoundaryV15Coverage",
    "TestPlatformModuleBoundary",
]

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "aila"


@pytest.fixture()
def module():
    """Return a fresh VulnerabilityModule instance via create_module()."""
    return create_module()


@pytest.fixture()
def auditor():
    """Return an HonestyAuditor with no whitelist."""
    return HonestyAuditor()


# ---------------------------------------------------------------------------
# Class 1: TestVulnerabilityModuleCompliance (MOD-STD-02)
# ---------------------------------------------------------------------------


class TestVulnerabilityModuleCompliance:
    """Verify the vulnerability module satisfies every ModuleProtocol method."""

    def test_isinstance_module_protocol(self, module):
        """Module instance must satisfy the runtime-checkable ModuleProtocol."""
        assert isinstance(module, ModuleProtocol)

    def test_module_id_matches_folder(self, module):
        """module_id must match the package directory name 'vulnerability'."""
        assert module.module_id == "vulnerability"

    def test_capability_profiles_non_empty(self, module):
        """capability_profiles() must return at least one profile."""
        profiles = module.capability_profiles()
        assert len(profiles) >= 1

    def test_capability_profile_module_id_matches(self, module):
        """Every profile.module_id must equal module.module_id."""
        for profile in module.capability_profiles():
            assert profile.module_id == module.module_id

    def test_capability_profile_action_id_prefix(self, module):
        """Every profile.action_id must start with 'vulnerability.'."""
        for profile in module.capability_profiles():
            assert profile.action_id.startswith("vulnerability.")

    def test_required_tools_non_empty(self, module):
        """required_tools() must return at least one tool key."""
        tools = module.required_tools()
        assert len(tools) >= 1

    def test_required_tools_no_duplicates(self, module):
        """required_tools() must not contain duplicate keys."""
        tools = module.required_tools()
        assert len(tools) == len(set(tools))

    def test_report_filter_keys_returns_list(self, module):
        """report_filter_keys() must return a list of strings."""
        keys = module.report_filter_keys()
        assert isinstance(keys, list)
        for key in keys:
            assert isinstance(key, str)

    def test_route_specs_returns_list(self, module):
        """route_specs() must return a list of ModuleRouteSpec."""
        specs = module.route_specs()
        assert isinstance(specs, list)
        for spec in specs:
            assert isinstance(spec, ModuleRouteSpec)

    def test_route_specs_has_prefix(self, module):
        """Each route spec must have a non-empty prefix."""
        for spec in module.route_specs():
            assert spec.prefix, "route spec prefix must be non-empty"

    def test_route_specs_router_factory_callable(self, module):
        """Each spec.router_factory must be callable."""
        for spec in module.route_specs():
            assert callable(spec.router_factory)

    def test_route_specs_tool_keys_is_tuple(self, module):
        """Each spec.tool_keys must be a tuple (frozen dataclass constraint)."""
        for spec in module.route_specs():
            assert isinstance(spec.tool_keys, tuple)

    @pytest.mark.asyncio
    async def test_system_summary_returns_dict(self, module):
        """system_summary() with session=None must return {} safely."""
        result = await module.system_summary(system_id=0, session=None)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_report_count_returns_dict(self, module):
        """report_count() with session=None must return {} safely."""
        result = await module.report_count(run_id="nonexistent", session=None)
        assert isinstance(result, dict)

    def test_filter_report_rows_passthrough(self, module):
        """filter_report_rows with filters=None must return all rows unchanged."""
        rows = [
            {"cve_id": "CVE-2024-0001", "host": "web-01"},
            {"cve_id": "CVE-2024-0002", "host": "web-02"},
        ]
        result = module.filter_report_rows(rows, filters=None)
        assert len(result) == 2
        assert result[0]["cve_id"] == "CVE-2024-0001"
        assert result[1]["cve_id"] == "CVE-2024-0002"

    def test_filter_report_rows_exact_match(self, module):
        """filter_report_rows must filter by a known key (host)."""
        rows = [
            {"cve_id": "CVE-2024-0001", "host": "web-01", "criticality": "High"},
            {"cve_id": "CVE-2024-0002", "host": "web-02", "criticality": "Low"},
        ]
        result = module.filter_report_rows(rows, filters={"host": "web-01"})
        assert len(result) == 1
        assert result[0]["host"] == "web-01"

    def test_create_module_factory(self):
        """build_module_factory('aila.modules.vulnerability') must succeed."""
        factory = build_module_factory("aila.modules.vulnerability")
        assert callable(factory)

    def test_validate_module_layout(self):
        """validate_module_layout('aila.modules.vulnerability') must not raise."""
        validate_module_layout("aila.modules.vulnerability")

    def test_health_checks_returns_dict(self, module):
        """health_checks() must return a dict (possibly empty)."""
        result = module.health_checks()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Class 2: TestImportBoundaryV15Coverage (MOD-STD-05)
# ---------------------------------------------------------------------------


class TestImportBoundaryV15Coverage:
    """Verify honesty_audit import_boundary rule covers v1.5 directories.

    Note: import_boundary only fires for files owned by a module (under
    aila/modules/{id}/). For platform and api directories, the auditor runs
    without boundary violations because those files are not module-owned.
    Platform-to-module boundary is verified separately in Class 3.
    """

    def test_api_directory_no_import_boundary_violations(self, auditor):
        """No import_boundary violations in src/aila/api/."""
        api_dir = _SRC_ROOT / "api"
        if not api_dir.is_dir():
            pytest.skip("src/aila/api/ does not exist")
        findings = auditor.audit_directory(api_dir)
        boundary_violations = [f for f in findings if f.rule == "import_boundary"]
        assert boundary_violations == [], (
            f"import_boundary violations in api/: "
            f"{[(v.file, v.line, v.message) for v in boundary_violations]}"
        )

    def test_platform_tasks_no_import_boundary_violations(self, auditor):
        """No import_boundary violations in src/aila/platform/tasks/."""
        tasks_dir = _SRC_ROOT / "platform" / "tasks"
        if not tasks_dir.is_dir():
            pytest.skip("src/aila/platform/tasks/ does not exist")
        findings = auditor.audit_directory(tasks_dir)
        boundary_violations = [f for f in findings if f.rule == "import_boundary"]
        assert boundary_violations == [], (
            f"import_boundary violations in platform/tasks/: "
            f"{[(v.file, v.line, v.message) for v in boundary_violations]}"
        )

    def test_platform_modules_no_import_boundary_violations(self, auditor):
        """No import_boundary violations in src/aila/platform/."""
        platform_dir = _SRC_ROOT / "platform"
        if not platform_dir.is_dir():
            pytest.skip("src/aila/platform/ does not exist")
        findings = auditor.audit_directory(platform_dir)
        boundary_violations = [f for f in findings if f.rule == "import_boundary"]
        assert boundary_violations == [], (
            f"import_boundary violations in platform/: "
            f"{[(v.file, v.line, v.message) for v in boundary_violations]}"
        )


# ---------------------------------------------------------------------------
# Class 3: TestPlatformModuleBoundary (MOD-STD-07)
# ---------------------------------------------------------------------------


def _collect_module_imports(directory: Path, forbidden_prefix: str) -> list[tuple[str, int, str]]:
    """Scan all .py files under *directory* for imports matching *forbidden_prefix*.

    Uses ast.parse to walk Import and ImportFrom nodes. Returns a list of
    (file_path, line_number, imported_module) tuples for every violation.
    """
    violations: list[tuple[str, int, str]] = []
    if not directory.is_dir():
        return violations
    for py_file in sorted(directory.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(forbidden_prefix):
                        violations.append((str(py_file), node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module is not None and node.module.startswith(forbidden_prefix):
                    violations.append((str(py_file), node.lineno, node.module))
    return violations


class TestPlatformModuleBoundary:
    """Verify platform and storage code never import from vulnerability module internals."""

    def test_no_platform_imports_from_vulnerability(self):
        """Zero imports of aila.modules.vulnerability.* in src/aila/platform/."""
        platform_dir = _SRC_ROOT / "platform"
        violations = _collect_module_imports(platform_dir, "aila.modules.vulnerability")
        assert violations == [], (
            f"Platform imports from vulnerability module internals: "
            f"{[(v[0], v[1], v[2]) for v in violations]}"
        )

    def test_no_api_imports_from_vulnerability(self):
        """No NEW imports of aila.modules.vulnerability.* in src/aila/api/.

        Known pre-existing violation (to be fixed in a future plan):
          - api/routers/systems.py imports LatestFindingRecord directly
            instead of going through the module's system_summary() or a
            materialized query callback.
        """
        api_dir = _SRC_ROOT / "api"
        violations = _collect_module_imports(api_dir, "aila.modules.vulnerability")
        # One known pre-existing violation in systems.py (LatestFindingRecord import).
        # Filter it out so the test catches NEW violations only.
        known_violations = {
            ("routers/systems.py", "aila.modules.vulnerability.db_models"),
        }
        new_violations = [
            v for v in violations
            if not any(
                v[0].replace("\\", "/").endswith(kf) and v[2] == km
                for kf, km in known_violations
            )
        ]
        assert new_violations == [], (
            f"NEW API imports from vulnerability module internals: "
            f"{[(v[0], v[1], v[2]) for v in new_violations]}"
        )

    def test_no_storage_imports_from_vulnerability(self):
        """Zero imports of aila.modules.vulnerability.* in src/aila/storage/."""
        storage_dir = _SRC_ROOT / "storage"
        violations = _collect_module_imports(storage_dir, "aila.modules.vulnerability")
        assert violations == [], (
            f"Storage imports from vulnerability module internals: "
            f"{[(v[0], v[1], v[2]) for v in violations]}"
        )
