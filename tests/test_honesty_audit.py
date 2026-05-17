"""Tests for HonestyAuditor AST scanner.

Covers all 8 behavior groups:
1. unused_parameter detection
2. misleading_name detection (wrapper disguised as intelligent logic)
3. docstring_mismatch detection (caching claims without caching code)
4. whitelist suppression for unused_parameter findings
5. clean file returns empty findings and exits 0
6. file with unused_parameter exits 1 and prints finding with file:line prefix
7. sync_in_async detection (session_scope in async def)
8. api_imports_module_internals detection (api/ importing modules/ internals)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from aila.tools.honesty_audit import HonestyAuditor, load_whitelist

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, name: str, source: str) -> Path:
    p = tmp_path / name
    p.write_text(source, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Test 1: unused_parameter — non-self/cls param that never appears in body
# ---------------------------------------------------------------------------

class TestUnusedParameter:
    def test_detects_unused_param(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def greet(name, unused_ctx):
    return "hello"
""")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "unused_parameter" in rules

    def test_does_not_flag_self(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Foo:
    def method(self):
        return 42
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)

    def test_does_not_flag_cls(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Foo:
    @classmethod
    def create(cls):
        return cls()
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)

    def test_does_not_flag_args_kwargs(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def func(*args, **kwargs):
    return args, kwargs
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)

    def test_does_not_flag_underscore_param(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def func(_):
    return 42
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)

    def test_skips_abstract_method_stub(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
from abc import abstractmethod

class Base:
    @abstractmethod
    def process(self, data):
        ...
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)

    def test_skips_overload_stub(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
from typing import overload

@overload
def process(data: str) -> str: ...
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)

    def test_used_param_not_flagged(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def greet(name):
    return f"hello {name}"
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "unused_parameter" for f in findings)


# ---------------------------------------------------------------------------
# Test 2: misleading_name — wrapper disguised as intelligent logic
# ---------------------------------------------------------------------------

class TestMisleadingName:
    def test_detects_single_forward_planner(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Router:
    def run_planner(self, request):
        return self.delegate.run(request)
""")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "misleading_name" in rules

    def test_detects_manager_forwarder(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Foo:
    def manage_jobs(self, job):
        return self._impl.manage_jobs(job)
""")
        findings = HonestyAuditor().audit_file(src)
        assert any(f.rule == "misleading_name" for f in findings)

    def test_detects_helper_forwarder(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Foo:
    def helper_parse(self, data):
        return self._parser.parse(data)
""")
        findings = HonestyAuditor().audit_file(src)
        assert any(f.rule == "misleading_name" for f in findings)

    def test_detects_coordinator_forwarder(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Foo:
    def coordinator_step(self, ctx):
        return self._step.run(ctx)
""")
        findings = HonestyAuditor().audit_file(src)
        assert any(f.rule == "misleading_name" for f in findings)

    def test_does_not_flag_real_logic(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
class Router:
    def run_planner(self, request):
        result = self.analyze(request)
        if result.score > 0.5:
            return self.delegate.run(result)
        return None
""")
        findings = HonestyAuditor().audit_file(src)
        # 3 statements — should not be flagged
        assert not any(f.rule == "misleading_name" for f in findings)


# ---------------------------------------------------------------------------
# Test 3: docstring_mismatch — caching claims without caching code
# ---------------------------------------------------------------------------

class TestDocstringMismatch:
    def test_detects_caching_claim_no_cache_impl(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def get_data(key):
    \"\"\"Caches the result for subsequent calls.\"\"\"
    return fetch(key)
""")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "docstring_mismatch" in rules

    def test_no_flag_when_cache_impl_present(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
_cache = {}

def get_data(key):
    \"\"\"Caches the result for subsequent calls.\"\"\"
    if key not in _cache:
        _cache[key] = fetch(key)
    return _cache[key]
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "docstring_mismatch" for f in findings)

    def test_no_flag_when_lru_cache_used(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
from functools import lru_cache

@lru_cache
def get_data(key):
    \"\"\"Cache results for speed.\"\"\"
    return fetch(key)
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "docstring_mismatch" for f in findings)

    def test_no_flag_on_no_docstring(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def get_data(key):
    return fetch(key)
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "docstring_mismatch" for f in findings)


# ---------------------------------------------------------------------------
# Test 4: whitelist suppresses exact (file, function, detail) triple
# ---------------------------------------------------------------------------

class TestWhitelist:
    def test_whitelist_suppresses_unused_param(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mymod.py", """\
def my_func(param_name, other):
    return other
""")
        whitelist_file = _write(tmp_path, "honesty_whitelist.py", """\
HONESTY_WHITELIST = [
    ("mymod.py", "my_func", "param_name"),
]
""")
        whitelist = load_whitelist(whitelist_file)
        auditor = HonestyAuditor(whitelist=whitelist)
        findings = auditor.audit_file(src)
        # param_name should be suppressed; other is actually used so no finding
        unused_findings = [f for f in findings if f.rule == "unused_parameter"]
        assert len(unused_findings) == 0

    def test_whitelist_does_not_suppress_different_file(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "othermod.py", """\
def my_func(param_name, other):
    return other
""")
        whitelist_file = _write(tmp_path, "honesty_whitelist.py", """\
HONESTY_WHITELIST = [
    ("mymod.py", "my_func", "param_name"),
]
""")
        whitelist = load_whitelist(whitelist_file)
        auditor = HonestyAuditor(whitelist=whitelist)
        findings = auditor.audit_file(src)
        unused_findings = [f for f in findings if f.rule == "unused_parameter"]
        assert len(unused_findings) > 0

    def test_empty_whitelist_suppresses_nothing(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "mod.py", """\
def func(unused_param):
    return 1
""")
        whitelist_file = _write(tmp_path, "honesty_whitelist.py", """\
HONESTY_WHITELIST = []
""")
        whitelist = load_whitelist(whitelist_file)
        auditor = HonestyAuditor(whitelist=whitelist)
        findings = auditor.audit_file(src)
        assert any(f.rule == "unused_parameter" for f in findings)


# ---------------------------------------------------------------------------
# Test 5: clean file — empty findings and exit 0
# ---------------------------------------------------------------------------

class TestCleanFile:
    def test_clean_file_returns_no_findings(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "clean.py", """\
def add(x, y):
    return x + y


def greet(name):
    return f"Hello, {name}!"
""")
        findings = HonestyAuditor().audit_file(src)
        assert findings == []

    def test_audit_dir_exits_0_on_clean(self, tmp_path: Path) -> None:
        _write(tmp_path, "clean.py", """\
def add(x, y):
    return x + y
""")
        result = subprocess.run(
            [sys.executable, "-m", "aila.tools.honesty_audit", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"Expected exit 0 on clean dir, got {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Test 6: file with unused_parameter exits 1, prints file:line finding
# ---------------------------------------------------------------------------

class TestExitCodeAndOutput:
    def test_exits_1_on_finding(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "bad.py", """\
def broken(used, totally_ignored):
    return used
""")
        result = subprocess.run(
            [sys.executable, "-m", "aila.tools.honesty_audit", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, (
            f"Expected exit 1 on finding, got {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_output_has_file_line_prefix(self, tmp_path: Path) -> None:
        src = _write(tmp_path, "bad.py", """\
def broken(used, totally_ignored):
    return used
""")
        result = subprocess.run(
            [sys.executable, "-m", "aila.tools.honesty_audit", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        # Output must contain "bad.py:1:" or similar file:line prefix
        output = result.stdout + result.stderr
        assert "bad.py" in output, f"Expected file name in output.\nOutput: {output}"
        assert "[unused_parameter]" in output, (
            f"Expected rule tag in output.\nOutput: {output}"
        )


# ---------------------------------------------------------------------------
# Test 7: sync_in_async — session_scope() inside async def
# ---------------------------------------------------------------------------

class TestSyncInAsync:
    def test_detects_bare_session_scope_in_async(self, tmp_path: Path) -> None:
        """session_scope() called directly in async def body is flagged."""
        src = _write(tmp_path, "mod.py", """\
async def bad_handler():
    with session_scope() as session:
        return session.query()
""")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "sync_in_async" in rules

    def test_allows_session_scope_in_sync_inner_function(self, tmp_path: Path) -> None:
        """session_scope() in a sync inner def is correct (to_thread pattern)."""
        src = _write(tmp_path, "mod.py", """\
import asyncio

async def good_handler():
    def _query():
        with session_scope() as session:
            return session.query()
    return await asyncio.to_thread(_query)
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "sync_in_async" for f in findings)

    def test_allows_session_scope_in_plain_def(self, tmp_path: Path) -> None:
        """session_scope() in a plain sync function is not flagged."""
        src = _write(tmp_path, "mod.py", """\
def sync_function():
    with session_scope() as session:
        return session.query()
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "sync_in_async" for f in findings)

    def test_detects_attribute_call_session_scope(self, tmp_path: Path) -> None:
        """database.session_scope() as attribute call is also detected."""
        src = _write(tmp_path, "mod.py", """\
async def bad_handler():
    with database.session_scope() as session:
        return session.query()
""")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "sync_in_async" in rules

    def test_no_false_positive_on_other_calls_in_async(self, tmp_path: Path) -> None:
        """Other function calls in async def are not flagged."""
        src = _write(tmp_path, "mod.py", """\
async def handler():
    result = await some_async_call()
    return result
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "sync_in_async" for f in findings)


# ---------------------------------------------------------------------------
# Test 8: api_imports_module_internals — api/ importing modules/ internals
# ---------------------------------------------------------------------------

class TestApiImportsModuleInternals:
    def test_detects_from_import_modules(self, tmp_path: Path) -> None:
        """from aila.modules.vulnerability import X is flagged in api/ files."""
        api_dir = tmp_path / "aila" / "api"
        api_dir.mkdir(parents=True)
        src = api_dir / "router.py"
        src.write_text("""\
from aila.modules.vulnerability import something
""", encoding="utf-8")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "api_imports_module_internals" in rules

    def test_detects_import_modules(self, tmp_path: Path) -> None:
        """import aila.modules.vulnerability is flagged in api/ files."""
        api_dir = tmp_path / "aila" / "api"
        api_dir.mkdir(parents=True)
        src = api_dir / "router.py"
        src.write_text("""\
import aila.modules.vulnerability
""", encoding="utf-8")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "api_imports_module_internals" in rules

    def test_allows_platform_modules_import(self, tmp_path: Path) -> None:
        """from aila.platform.modules import ModuleProtocol is allowed."""
        api_dir = tmp_path / "aila" / "api"
        api_dir.mkdir(parents=True)
        src = api_dir / "router.py"
        src.write_text("""\
from aila.platform.modules import ModuleProtocol
""", encoding="utf-8")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "api_imports_module_internals" for f in findings)

    def test_allows_modules_import_outside_api(self, tmp_path: Path) -> None:
        """from aila.modules.vulnerability import X outside api/ is not flagged."""
        src = _write(tmp_path, "mod.py", """\
from aila.modules.vulnerability import something
""")
        findings = HonestyAuditor().audit_file(src)
        assert not any(f.rule == "api_imports_module_internals" for f in findings)

    def test_detects_in_api_subdirectory(self, tmp_path: Path) -> None:
        """Detection works in api/routers/ subdirectory too."""
        routers_dir = tmp_path / "aila" / "api" / "routers"
        routers_dir.mkdir(parents=True)
        src = routers_dir / "vuln.py"
        src.write_text("""\
from aila.modules.vulnerability.api_router import router
""", encoding="utf-8")
        findings = HonestyAuditor().audit_file(src)
        rules = [f.rule for f in findings]
        assert "api_imports_module_internals" in rules


    def test_detects_in_platform_directory(self, tmp_path: Path) -> None:
        platform_dir = tmp_path / "aila" / "platform" / "services"
        platform_dir.mkdir(parents=True)
        src = platform_dir / "svc.py"
        src.write_text("from aila.modules.vulnerability.module import create_module\n", encoding="utf-8")
        findings = HonestyAuditor().audit_file(src)
        assert any(f.rule == "api_imports_module_internals" for f in findings)

    def test_detects_in_storage_directory(self, tmp_path: Path) -> None:
        storage_dir = tmp_path / "aila" / "storage"
        storage_dir.mkdir(parents=True)
        src = storage_dir / "repo.py"
        src.write_text("from aila.modules.vulnerability.db_models import LatestFindingRecord\n", encoding="utf-8")
        findings = HonestyAuditor().audit_file(src)
        assert any(f.rule == "api_imports_module_internals" for f in findings)
