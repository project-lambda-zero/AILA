"""Unit tests for honesty_audit Rules 18-21.

Each rule has:
  - positive test: source containing the violation → rule fires.
  - negative test: source without the violation → rule is silent.
  - whitelist test: violation present but suppressed by HONESTY_WHITELIST.

Tests use real temporary file fixtures written to tmp_path -- no mocks on
production paths.
"""
from __future__ import annotations

from pathlib import Path

from aila.tools.honesty_audit import Finding, HonestyAuditor, load_whitelist

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(base: Path, rel: str, source: str) -> Path:
    """Write *source* to *base/rel*, creating parent directories as needed."""
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(source, encoding="utf-8")
    return p


def _audit(path: Path, whitelist_path: Path | None = None) -> list[Finding]:
    """Run HonestyAuditor on a single file or directory."""
    wl = load_whitelist(whitelist_path) if whitelist_path else set()
    auditor = HonestyAuditor(whitelist=wl)
    if path.is_dir():
        return auditor.audit_directory(path)
    return auditor.audit_file(path)


def _rules(findings: list[Finding]) -> list[str]:
    return [f.rule for f in findings]


# ---------------------------------------------------------------------------
# Rule 18 -- asyncio_in_module
# ---------------------------------------------------------------------------


class TestAsyncioInModule:
    """Rule 18: asyncio/threading primitives banned inside aila/modules/."""

    def test_asyncio_to_thread_flagged(self, tmp_path: Path) -> None:
        """asyncio.to_thread() inside modules/ fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/service.py",
            "import asyncio\nasync def f():\n    await asyncio.to_thread(lambda: 1)\n",
        )
        findings = _audit(src)
        assert any(f.rule == "asyncio_in_module" for f in findings)

    def test_asyncio_run_flagged(self, tmp_path: Path) -> None:
        """asyncio.run() inside modules/ fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/service.py",
            "import asyncio\ndef f():\n    asyncio.run(main())\n",
        )
        findings = _audit(src)
        assert any(f.rule == "asyncio_in_module" for f in findings)

    def test_thread_pool_executor_flagged(self, tmp_path: Path) -> None:
        """ThreadPoolExecutor() inside modules/ fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/service.py",
            "from concurrent.futures import ThreadPoolExecutor\n"
            "def f():\n    ex = ThreadPoolExecutor(max_workers=2)\n",
        )
        findings = _audit(src)
        assert any(f.rule == "asyncio_in_module" for f in findings)

    def test_concurrent_futures_import_flagged(self, tmp_path: Path) -> None:
        """from concurrent.futures import ... inside modules/ fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/worker.py",
            "from concurrent.futures import ProcessPoolExecutor\n",
        )
        findings = _audit(src)
        assert any(f.rule == "asyncio_in_module" for f in findings)

    def test_run_until_complete_flagged(self, tmp_path: Path) -> None:
        """loop.run_until_complete() inside modules/ fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/service.py",
            "import asyncio\ndef f():\n    loop = asyncio.new_event_loop()\n    loop.run_until_complete(coro())\n",
        )
        findings = _audit(src)
        assert any(f.rule == "asyncio_in_module" for f in findings)

    def test_platform_file_not_flagged(self, tmp_path: Path) -> None:
        """asyncio.to_thread() inside platform/ does NOT fire asyncio_in_module."""
        src = _write(
            tmp_path,
            "aila/platform/services/svc.py",
            "import asyncio\nasync def f():\n    await asyncio.to_thread(lambda: 1)\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "asyncio_in_module" for f in findings)

    def test_api_file_not_flagged(self, tmp_path: Path) -> None:
        """asyncio usage in api/ does NOT fire asyncio_in_module."""
        src = _write(
            tmp_path,
            "aila/api/routers/thing.py",
            "import asyncio\nasync def f():\n    return await asyncio.sleep(0)\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "asyncio_in_module" for f in findings)

    def test_whitelist_suppresses_asyncio_in_module(self, tmp_path: Path) -> None:
        """A whitelist entry with matching suffix suppresses the finding."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/service.py",
            "import asyncio\nasync def f():\n    await asyncio.to_thread(lambda: 1)\n",
        )
        wl_path = tmp_path / "honesty_whitelist.py"
        wl_path.write_text(
            "HONESTY_WHITELIST = [\n"
            "    (\n"
            "        \"aila/modules/mymod/service.py\",\n"
            "        \"asyncio_in_module\",\n"
            "        \"asyncio.to_thread\",\n"
            "    ),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = _audit(src, whitelist_path=wl_path)
        assert not any(f.rule == "asyncio_in_module" for f in findings)


# ---------------------------------------------------------------------------
# Rule 19 -- response_model_dict
# ---------------------------------------------------------------------------


class TestResponseModelDict:
    """Rule 19: @router.* decorator must not use response_model=dict."""

    def test_response_model_dict_flagged(self, tmp_path: Path) -> None:
        """response_model=dict on a GET endpoint fires the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/x', response_model=dict)\n"
            "async def endpoint():\n"
            "    return {}\n",
        )
        findings = _audit(src)
        assert any(f.rule == "response_model_dict" for f in findings)

    def test_response_model_Dict_flagged(self, tmp_path: Path) -> None:
        """response_model=Dict (uppercase) also fires the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "from typing import Dict\n"
            "router = APIRouter()\n"
            "@router.post('/y', response_model=Dict)\n"
            "async def create():\n"
            "    return {}\n",
        )
        findings = _audit(src)
        assert any(f.rule == "response_model_dict" for f in findings)

    def test_response_model_typing_Dict_flagged(self, tmp_path: Path) -> None:
        """response_model=typing.Dict fires the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "import typing\n"
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/z', response_model=typing.Dict)\n"
            "async def get_z():\n"
            "    return {}\n",
        )
        findings = _audit(src)
        assert any(f.rule == "response_model_dict" for f in findings)

    def test_typed_schema_not_flagged(self, tmp_path: Path) -> None:
        """response_model=MySchema does NOT fire the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "from pydantic import BaseModel\n"
            "class MySchema(BaseModel):\n"
            "    value: int\n"
            "router = APIRouter()\n"
            "@router.get('/x', response_model=MySchema)\n"
            "async def endpoint():\n"
            "    return MySchema(value=1)\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "response_model_dict" for f in findings)

    def test_no_response_model_not_flagged(self, tmp_path: Path) -> None:
        """Endpoint without response_model keyword does NOT fire the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/simple')\n"
            "async def endpoint():\n"
            "    return 'ok'\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "response_model_dict" for f in findings)

    def test_whitelist_suppresses_response_model_dict(self, tmp_path: Path) -> None:
        """A matching whitelist entry suppresses the response_model_dict finding."""
        src = _write(
            tmp_path,
            "aila/api/routers/legacy.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/old', response_model=dict)\n"
            "async def legacy_endpoint():\n"
            "    return {}\n",
        )
        wl_path = tmp_path / "honesty_whitelist.py"
        wl_path.write_text(
            "HONESTY_WHITELIST = [\n"
            "    (\n"
            "        \"aila/api/routers/legacy.py\",\n"
            "        \"legacy_endpoint\",\n"
            "        \"response_model=dict\",\n"
            "    ),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = _audit(src, whitelist_path=wl_path)
        assert not any(f.rule == "response_model_dict" for f in findings)


# ---------------------------------------------------------------------------
# Rule 20 -- bare_dict_return_endpoint
# ---------------------------------------------------------------------------


class TestBareDictReturnEndpoint:
    """Rule 20: @router.* handler must not return a raw dict literal or dict()."""

    def test_dict_literal_return_flagged(self, tmp_path: Path) -> None:
        """return {...} inside an endpoint fires the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/x')\n"
            "async def endpoint():\n"
            "    return {'status': 'ok'}\n",
        )
        findings = _audit(src)
        assert any(f.rule == "bare_dict_return_endpoint" for f in findings)

    def test_dict_call_return_flagged(self, tmp_path: Path) -> None:
        """return dict(...) inside an endpoint fires the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.post('/y')\n"
            "async def create():\n"
            "    return dict(status='ok')\n",
        )
        findings = _audit(src)
        assert any(f.rule == "bare_dict_return_endpoint" for f in findings)

    def test_jsonresponse_with_dict_content_flagged(self, tmp_path: Path) -> None:
        """return JSONResponse(content={...}) inside an endpoint fires the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "from fastapi.responses import JSONResponse\n"
            "router = APIRouter()\n"
            "@router.get('/z')\n"
            "async def get_z():\n"
            "    return JSONResponse(content={'key': 'val'})\n",
        )
        findings = _audit(src)
        assert any(f.rule == "bare_dict_return_endpoint" for f in findings)

    def test_pydantic_model_return_not_flagged(self, tmp_path: Path) -> None:
        """return MySchema(...) does NOT fire the rule."""
        src = _write(
            tmp_path,
            "router.py",
            "from fastapi import APIRouter\n"
            "from pydantic import BaseModel\n"
            "class MySchema(BaseModel):\n"
            "    value: int\n"
            "router = APIRouter()\n"
            "@router.get('/x')\n"
            "async def endpoint():\n"
            "    return MySchema(value=42)\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "bare_dict_return_endpoint" for f in findings)

    def test_plain_function_dict_return_not_flagged(self, tmp_path: Path) -> None:
        """A plain function (not @router.*) returning dict does NOT fire the rule."""
        src = _write(
            tmp_path,
            "utils.py",
            "def helper():\n"
            "    return {'key': 'val'}\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "bare_dict_return_endpoint" for f in findings)

    def test_whitelist_suppresses_bare_dict_return(self, tmp_path: Path) -> None:
        """A matching whitelist entry suppresses the bare_dict_return_endpoint finding."""
        src = _write(
            tmp_path,
            "aila/api/routers/compat.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/compat')\n"
            "async def compat_endpoint():\n"
            "    return {'legacy': True}\n",
        )
        wl_path = tmp_path / "honesty_whitelist.py"
        wl_path.write_text(
            "HONESTY_WHITELIST = [\n"
            "    (\n"
            "        \"aila/api/routers/compat.py\",\n"
            "        \"compat_endpoint\",\n"
            "        \"raw dict literal\",\n"
            "    ),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = _audit(src, whitelist_path=wl_path)
        assert not any(f.rule == "bare_dict_return_endpoint" for f in findings)


# ---------------------------------------------------------------------------
# Rule 21 -- noqa_inline
# ---------------------------------------------------------------------------


class TestNoqaInline:
    """Rule 21: # noqa comments in production source are banned."""

    def test_noqa_comment_flagged(self, tmp_path: Path) -> None:
        """A line with # noqa fires the rule."""
        src = _write(
            tmp_path,
            "module.py",
            "x = 1  # noqa: E501\n",
        )
        findings = _audit(src)
        assert any(f.rule == "noqa_inline" for f in findings)

    def test_bare_noqa_flagged(self, tmp_path: Path) -> None:
        """A bare # noqa (without a code) also fires the rule."""
        src = _write(
            tmp_path,
            "module.py",
            "import os  # noqa\n",
        )
        findings = _audit(src)
        assert any(f.rule == "noqa_inline" for f in findings)

    def test_clean_file_not_flagged(self, tmp_path: Path) -> None:
        """A file without # noqa does NOT fire the rule."""
        src = _write(
            tmp_path,
            "module.py",
            "def f():\n    return 42\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "noqa_inline" for f in findings)

    def test_honesty_audit_self_exempt(self, tmp_path: Path) -> None:
        """honesty_audit.py itself is never flagged for noqa_inline."""
        src = _write(
            tmp_path,
            "aila/tools/honesty_audit.py",
            "x = 1  # noqa: N802\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "noqa_inline" for f in findings)

    def test_honesty_whitelist_self_exempt(self, tmp_path: Path) -> None:
        """honesty_whitelist.py itself is never flagged for noqa_inline."""
        src = _write(
            tmp_path,
            "aila/tools/honesty_whitelist.py",
            "# noqa: some-rule -- this file may reference suppression codes\nx = 1\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "noqa_inline" for f in findings)

    def test_alembic_migration_exempt(self, tmp_path: Path) -> None:
        """Alembic migration files are exempt from noqa_inline."""
        src = _write(
            tmp_path,
            "alembic/versions/0001_init.py",
            "x = 1  # noqa: E501 -- generated migration\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "noqa_inline" for f in findings)

    def test_whitelist_suppresses_noqa_inline(self, tmp_path: Path) -> None:
        """A matching whitelist entry suppresses the noqa_inline finding."""
        src = _write(
            tmp_path,
            "aila/platform/services/legacy.py",
            "import os  # noqa: F401\n",
        )
        wl_path = tmp_path / "honesty_whitelist.py"
        wl_path.write_text(
            "HONESTY_WHITELIST = [\n"
            "    (\n"
            "        \"aila/platform/services/legacy.py\",\n"
            "        \"noqa_inline\",\n"
            "        \"noqa_inline: inline\",\n"
            "    ),\n"
            "]\n",
            encoding="utf-8",
        )
        findings = _audit(src, whitelist_path=wl_path)
        assert not any(f.rule == "noqa_inline" for f in findings)


# ---------------------------------------------------------------------------
# Rule 34 -- hoisted_enum_redeclared (RFC-01)
# ---------------------------------------------------------------------------


class TestHoistedEnumRedeclared:
    """Rule 34: a unified vr/malware module redeclares a hoisted platform enum."""

    def test_vr_redeclaring_hoisted_enum_flagged(self, tmp_path: Path) -> None:
        """A vr contracts file declaring class InvestigationStatus(StrEnum) fires."""
        src = _write(
            tmp_path,
            "aila/modules/vr/contracts/status.py",
            'from enum import StrEnum\n\n\nclass InvestigationStatus(StrEnum):\n    CREATED = "created"\n',
        )
        findings = _audit(src)
        assert "hoisted_enum_redeclared" in _rules(findings)

    def test_forensics_same_name_enum_not_flagged(self, tmp_path: Path) -> None:
        """forensics is not a unified module -- its own InvestigationStatus is silent."""
        src = _write(
            tmp_path,
            "aila/modules/forensics/contracts/status.py",
            'from enum import StrEnum\n\n\nclass InvestigationStatus(StrEnum):\n    PENDING = "pending"\n',
        )
        findings = _audit(src)
        assert "hoisted_enum_redeclared" not in _rules(findings)

    def test_module_owned_enum_not_flagged(self, tmp_path: Path) -> None:
        """A vr enum whose name is not hoisted (WorkspaceTheme) is silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/contracts/theme.py",
            'from enum import StrEnum\n\n\nclass WorkspaceTheme(StrEnum):\n    CUSTOM = "custom"\n',
        )
        findings = _audit(src)
        assert "hoisted_enum_redeclared" not in _rules(findings)

    def test_reexport_import_not_flagged(self, tmp_path: Path) -> None:
        """Importing the hoisted enum (the correct pattern) is silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/contracts/status.py",
            "from aila.platform.contracts.enums import InvestigationStatus\n\n__all__ = [\"InvestigationStatus\"]\n",
        )
        findings = _audit(src)
        assert "hoisted_enum_redeclared" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 35 -- unnamed_derived_constraint (RFC-01)
# ---------------------------------------------------------------------------


class TestUnnamedDerivedConstraint:
    """Rule 35: a unified table hard-codes a UQ name that is not the derived form."""

    def test_nonconforming_uq_flagged(self, tmp_path: Path) -> None:
        """A vr unified table with uq_vr_workspace_team_slug (pre-derived) fires."""
        src = _write(
            tmp_path,
            "aila/modules/vr/db_models/workspace.py",
            "from sqlalchemy import UniqueConstraint\n"
            "from sqlmodel import Field, SQLModel\n\n\n"
            "class VRWorkspaceRecord(SQLModel, table=True):\n"
            '    __tablename__ = "vr_workspaces"\n'
            "    __table_args__ = (\n"
            '        UniqueConstraint("team_id", "slug", name="uq_vr_workspace_team_slug"),\n'
            "    )\n"
            "    id: str = Field(primary_key=True)\n",
        )
        findings = _audit(src)
        assert "unnamed_derived_constraint" in _rules(findings)

    def test_derived_uq_name_not_flagged(self, tmp_path: Path) -> None:
        """The derived name uq_vr_workspaces_team_slug is silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/db_models/workspace.py",
            "from sqlalchemy import UniqueConstraint\n"
            "from sqlmodel import Field, SQLModel\n\n\n"
            "class VRWorkspaceRecord(SQLModel, table=True):\n"
            '    __tablename__ = "vr_workspaces"\n'
            "    __table_args__ = (\n"
            '        UniqueConstraint("team_id", "slug", name="uq_vr_workspaces_team_slug"),\n'
            "    )\n"
            "    id: str = Field(primary_key=True)\n",
        )
        findings = _audit(src)
        assert "unnamed_derived_constraint" not in _rules(findings)

    def test_nonunified_module_uq_not_flagged(self, tmp_path: Path) -> None:
        """A vulnerability table with a short hand-name is out of scope, silent."""
        src = _write(
            tmp_path,
            "aila/modules/vulnerability/db_models/findings.py",
            "from sqlalchemy import UniqueConstraint\n"
            "from sqlmodel import Field, SQLModel\n\n\n"
            "class LatestFindingRecord(SQLModel, table=True):\n"
            '    __tablename__ = "latest_finding_records"\n'
            "    __table_args__ = (\n"
            '        UniqueConstraint("host", name="uq_latestfinding_target"),\n'
            "    )\n"
            "    id: str = Field(primary_key=True)\n",
        )
        findings = _audit(src)
        assert "unnamed_derived_constraint" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 36 -- shadowed_platform_base (RFC-01)
# ---------------------------------------------------------------------------


_WORKSPACE_BASE_SRC = (
    "from sqlmodel import Field, SQLModel\n\n\n"
    "class WorkspaceRecordBase(SQLModel):\n"
    "    id: str = Field(primary_key=True)\n"
    "    name: str = Field()\n"
    "    slug: str = Field()\n"
    "    status: str = Field()\n"
)


class TestShadowedPlatformBase:
    """Rule 36: a unified table recreates a platform base's columns."""

    def test_shadowing_table_flagged(self, tmp_path: Path) -> None:
        """A vr_workspaces table that redeclares base columns without subclassing fires."""
        _write(tmp_path, "aila/platform/contracts/workspace_base.py", _WORKSPACE_BASE_SRC)
        src = _write(
            tmp_path,
            "aila/modules/vr/db_models/workspace.py",
            "from sqlmodel import Field, SQLModel\n\n\n"
            "class VRWorkspaceRecord(SQLModel, table=True):\n"
            '    __tablename__ = "vr_workspaces"\n'
            "    id: str = Field(primary_key=True)\n"
            "    name: str = Field()\n"
            "    slug: str = Field()\n"
            "    status: str = Field()\n",
        )
        findings = _audit(src)
        assert "shadowed_platform_base" in _rules(findings)

    def test_correct_subclass_not_flagged(self, tmp_path: Path) -> None:
        """A vr_workspaces table that subclasses the base is silent."""
        _write(tmp_path, "aila/platform/contracts/workspace_base.py", _WORKSPACE_BASE_SRC)
        src = _write(
            tmp_path,
            "aila/modules/vr/db_models/workspace.py",
            "from aila.platform.contracts.workspace_base import WorkspaceRecordBase\n\n\n"
            "class VRWorkspaceRecord(WorkspaceRecordBase, table=True):\n"
            '    __tablename__ = "vr_workspaces"\n',
        )
        findings = _audit(src)
        assert "shadowed_platform_base" not in _rules(findings)

    def test_nonunified_module_not_flagged(self, tmp_path: Path) -> None:
        """forensics is out of scope even if a table name matches a role."""
        _write(tmp_path, "aila/platform/contracts/workspace_base.py", _WORKSPACE_BASE_SRC)
        src = _write(
            tmp_path,
            "aila/modules/forensics/db_models/workspace.py",
            "from sqlmodel import Field, SQLModel\n\n\n"
            "class ForensicsWorkspaceRecord(SQLModel, table=True):\n"
            '    __tablename__ = "forensics_workspaces"\n'
            "    id: str = Field(primary_key=True)\n"
            "    name: str = Field()\n"
            "    slug: str = Field()\n"
            "    status: str = Field()\n",
        )
        findings = _audit(src)
        assert "shadowed_platform_base" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 37 -- module_config_schema_base
# ---------------------------------------------------------------------------


class TestModuleConfigSchemaBase:
    """Rule 37: a module config schema must subclass ModuleConfigBase."""

    def test_bare_basemodel_config_schema_flagged(self, tmp_path: Path) -> None:
        """A *ConfigSchema subclassing bare BaseModel fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/config_schema.py",
            "from pydantic import BaseModel\n\n\n"
            "class MymodConfigSchema(BaseModel):\n"
            '    llm_model: str = "x"\n',
        )
        findings = _audit(src)
        assert "module_config_schema_base" in _rules(findings)

    def test_module_config_base_subclass_not_flagged(self, tmp_path: Path) -> None:
        """A *ConfigSchema subclassing ModuleConfigBase is silent."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/config_schema.py",
            "from aila.platform.config_base import ModuleConfigBase\n\n\n"
            "class MymodConfigSchema(ModuleConfigBase):\n"
            '    llm_model: str = "x"\n',
        )
        findings = _audit(src)
        assert "module_config_schema_base" not in _rules(findings)

    def test_config_schema_class_outside_config_schema_file_not_flagged(
        self, tmp_path: Path
    ) -> None:
        """A *ConfigSchema class outside config_schema.py is out of scope."""
        src = _write(
            tmp_path,
            "aila/modules/mymod/other.py",
            "from pydantic import BaseModel\n\n\n"
            "class MymodConfigSchema(BaseModel):\n"
            '    llm_model: str = "x"\n',
        )
        findings = _audit(src)
        assert "module_config_schema_base" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 38 -- service_copy_of_platform
# ---------------------------------------------------------------------------


_PLATFORM_SERVICE_SRC = '''\
"""A platform service that does real work."""
from __future__ import annotations

import logging

_log = logging.getLogger(__name__)


class PlatformThingService:
    """Does the thing for the platform module."""

    def __init__(self, table_name: str) -> None:
        self._table_name = table_name
        self._counter = 0

    def process(self, rows: list[dict]) -> int:
        total = 0
        for row in rows:
            if row.get("active"):
                total += 1
                self._counter += 1
        _log.info("processed %d rows from %s", total, self._table_name)
        return total

    def reset(self) -> None:
        self._counter = 0
        _log.info("counter reset for %s", self._table_name)

    def summary(self) -> dict:
        return {"table": self._table_name, "count": self._counter}
'''


class TestServiceCopyOfPlatform:
    """Rule 38: a vr/malware service must not be a full copy of a platform service."""

    def test_vr_service_copy_flagged(self, tmp_path: Path) -> None:
        """A near-copy of a platform service under vr/services fires the rule."""
        _write(tmp_path, "aila/platform/services/thing.py", _PLATFORM_SERVICE_SRC)
        copy = _PLATFORM_SERVICE_SRC.replace("Platform", "VR").replace("platform", "vr")
        src = _write(tmp_path, "aila/modules/vr/services/thing.py", copy)
        findings = _audit(src)
        assert "service_copy_of_platform" in _rules(findings)

    def test_thin_binding_not_flagged(self, tmp_path: Path) -> None:
        """A short thin binding stays under the length ceiling and is silent."""
        _write(tmp_path, "aila/platform/services/thing.py", _PLATFORM_SERVICE_SRC)
        binding = (
            '"""VR thing -- thin binding of the platform service."""\n'
            "from __future__ import annotations\n\n"
            "from aila.platform.services.thing import PlatformThingService\n\n"
            'vr_thing = PlatformThingService("vr_things")\n'
        )
        src = _write(tmp_path, "aila/modules/vr/services/thing.py", binding)
        findings = _audit(src)
        assert "service_copy_of_platform" not in _rules(findings)

    def test_forensics_copy_not_flagged(self, tmp_path: Path) -> None:
        """forensics is out of the copy-set scope even for a full copy."""
        _write(tmp_path, "aila/platform/services/thing.py", _PLATFORM_SERVICE_SRC)
        copy = _PLATFORM_SERVICE_SRC.replace("Platform", "Forensics").replace(
            "platform", "forensics"
        )
        src = _write(tmp_path, "aila/modules/forensics/services/thing.py", copy)
        findings = _audit(src)
        assert "service_copy_of_platform" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 39 -- cost_read_stored_actual
# ---------------------------------------------------------------------------


class TestCostReadStoredActual:
    """Rule 39: a vr/malware api_router must not read the dead
    cost_actual_usd column in a response without aggregating live cost."""

    def test_stored_read_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path, "aila/modules/vr/api_router.py",
            '"""vr router."""\n'
            "from __future__ import annotations\n\n\n"
            "async def get_cost(record):\n"
            '    return {"actual_usd": record.cost_actual_usd}\n',
        )
        findings = _audit(src)
        assert "cost_read_stored_actual" in _rules(findings)

    def test_read_with_aggregator_not_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path, "aila/modules/malware/api_router.py",
            '"""malware router."""\n'
            "from __future__ import annotations\n\n\n"
            "async def get_cost(record, uow):\n"
            "    live = await compute_live_investigation_cost(uow, record.id)\n"
            "    stored = record.cost_actual_usd\n"
            '    return {"actual_usd": live or stored}\n',
        )
        findings = _audit(src)
        assert "cost_read_stored_actual" not in _rules(findings)

    def test_create_kwarg_not_flagged(self, tmp_path: Path) -> None:
        """cost_actual_usd=0.0 at row creation is an insert, not a read."""
        src = _write(
            tmp_path, "aila/modules/vr/api_router.py",
            '"""vr router."""\n'
            "from __future__ import annotations\n\n\n"
            "def make(record_cls):\n"
            "    return record_cls(cost_actual_usd=0.0)\n",
        )
        findings = _audit(src)
        assert "cost_read_stored_actual" not in _rules(findings)

    def test_forensics_out_of_scope(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path, "aila/modules/forensics/api_router.py",
            '"""forensics router."""\n'
            "from __future__ import annotations\n\n\n"
            "async def get_cost(record):\n"
            '    return {"actual_usd": record.cost_actual_usd}\n',
        )
        findings = _audit(src)
        assert "cost_read_stored_actual" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 40 -- lifecycle_handler_bypass_service
# ---------------------------------------------------------------------------


class TestLifecycleHandlerBypass:
    """Rule 40: a pause/resume/re-enqueue route handler must not write
    .status directly instead of routing through the lifecycle service."""

    def test_pause_status_write_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path, "aila/modules/malware/api_router.py",
            '"""malware router."""\n'
            "from __future__ import annotations\n\n\n"
            '@router.post("/investigations/{investigation_id}/pause")\n'
            "async def pause_investigation(record):\n"
            '    record.status = "paused"\n'
            "    return record\n",
        )
        findings = _audit(src)
        assert "lifecycle_handler_bypass_service" in _rules(findings)

    def test_delegating_handler_not_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path, "aila/modules/malware/api_router.py",
            '"""malware router."""\n'
            "from __future__ import annotations\n\n\n"
            '@router.post("/investigations/{investigation_id}/pause")\n'
            "async def pause_investigation(record):\n"
            "    result = await pause_investigation_atomic(record.id)\n"
            "    return result\n",
        )
        findings = _audit(src)
        assert "lifecycle_handler_bypass_service" not in _rules(findings)

    def test_reset_handler_excluded(self, tmp_path: Path) -> None:
        """reset is a full-wipe that legitimately resets status."""
        src = _write(
            tmp_path, "aila/modules/malware/api_router.py",
            '"""malware router."""\n'
            "from __future__ import annotations\n\n\n"
            '@router.post("/investigations/{investigation_id}/reset")\n'
            "async def reset_investigation(record):\n"
            '    record.status = "created"\n'
            "    return record\n",
        )
        findings = _audit(src)
        assert "lifecycle_handler_bypass_service" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 41 -- workflow_state_copy_of_platform
# ---------------------------------------------------------------------------


_WORKFLOW_BASE_SRC = '''\
"""A platform workflow-state base that does real work."""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger(__name__)


def state_investigation_setup(bindings: Any, hooks: Any) -> Any:
    """Build the setup handler."""

    async def _handler(input: dict, services: Any) -> Any:
        investigation_id = str(input.get("investigation_id") or "")
        if not investigation_id:
            raise ValueError("missing investigation_id")
        total = 0
        for key in sorted(input):
            if key.startswith("x"):
                total += 1
                _log.info("counted %s for %s", key, investigation_id)
        branch_id = str(input.get("branch_id") or "")
        result = {"investigation_id": investigation_id, "branch_id": branch_id}
        _log.info("setup ready %s total=%d", investigation_id, total)
        return result

    return _handler
'''


class TestWorkflowStateCopyOfPlatform:
    """Rule 41: a vr/malware state file must not be a full copy of a
    platform workflow-state base."""

    def test_state_copy_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "aila/platform/workflows/investigation_setup_base.py",
            _WORKFLOW_BASE_SRC,
        )
        copy = _WORKFLOW_BASE_SRC.replace("platform", "vr")
        src = _write(
            tmp_path,
            "aila/modules/vr/workflow/states/investigation_setup.py",
            copy,
        )
        findings = _audit(src)
        assert "workflow_state_copy_of_platform" in _rules(findings)

    def test_thin_binding_not_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "aila/platform/workflows/investigation_setup_base.py",
            _WORKFLOW_BASE_SRC,
        )
        binding = (
            '"""VR setup -- thin binding of the platform factory."""\n'
            "from __future__ import annotations\n\n"
            "from aila.platform.workflows.investigation_setup_base import (\n"
            "    state_investigation_setup as _build,\n"
            ")\n\n"
            "state_investigation_setup = _build(object(), object())\n"
        )
        src = _write(
            tmp_path,
            "aila/modules/vr/workflow/states/investigation_setup.py",
            binding,
        )
        findings = _audit(src)
        assert "workflow_state_copy_of_platform" not in _rules(findings)

    def test_forensics_out_of_scope(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "aila/platform/workflows/investigation_setup_base.py",
            _WORKFLOW_BASE_SRC,
        )
        copy = _WORKFLOW_BASE_SRC.replace("platform", "forensics")
        src = _write(
            tmp_path,
            "aila/modules/forensics/workflow/states/investigation_setup.py",
            copy,
        )
        findings = _audit(src)
        assert "workflow_state_copy_of_platform" not in _rules(findings)


# ---------------------------------------------------------------------------
# Rule 42 -- agent_primitive_reimplementation
# ---------------------------------------------------------------------------


class TestAgentPrimitiveReimplementation:
    """Rule 42: modules must import the platform agent primitives, not
    redefine them (RFC-03 Phase 1)."""

    def test_classify_intent_def_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/intent_classifier.py",
            "def classify_intent(text):\n    return 'x'\n",
        )
        assert "agent_primitive_reimplementation" in _rules(_audit(src))

    def test_maybe_post_auto_steering_def_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/auto_steering.py",
            "async def maybe_post_auto_steering(**kw):\n    return None\n",
        )
        assert "agent_primitive_reimplementation" in _rules(_audit(src))

    def test_reexport_import_not_flagged(self, tmp_path: Path) -> None:
        """An import re-export is a statement, not a def -- never fires."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/wiring.py",
            "from aila.platform.agents import classify_intent\n"
            "__all__ = ['classify_intent']\n",
        )
        assert "agent_primitive_reimplementation" not in _rules(_audit(src))

    def test_platform_definition_not_flagged(self, tmp_path: Path) -> None:
        """The platform's own definition is out of scope."""
        src = _write(
            tmp_path,
            "aila/platform/agents/intent_classifier.py",
            "def classify_intent(text):\n    return 'x'\n",
        )
        assert "agent_primitive_reimplementation" not in _rules(_audit(src))


# ---------------------------------------------------------------------------
# Rule 43 -- agent_llm_chat_bypass
# ---------------------------------------------------------------------------


class TestAgentLlmChatBypass:
    """Rule 43: module agents/ must route llm_client.chat() through the
    platform idempotent wrapper (RFC-03 Phase 2)."""

    def test_direct_chat_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/claim_verifier.py",
            "async def f(services):\n"
            "    return await services.llm_client.chat(task_type='x', messages=[])\n",
        )
        assert "agent_llm_chat_bypass" in _rules(_audit(src))

    def test_idempotent_wrapper_not_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/claim_verifier.py",
            "async def f(services):\n"
            "    return await idempotent_llm_call(services.llm_client, method='chat')\n",
        )
        assert "agent_llm_chat_bypass" not in _rules(_audit(src))

    def test_chat_json_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/pattern_extractor.py",
            "async def f(c):\n    return await c.llm_client.chat_json('x', [], {})\n",
        )
        assert "agent_llm_chat_bypass" in _rules(_audit(src))

    def test_self_llm_chat_json_flagged(self, tmp_path: Path) -> None:
        """pattern_extractor uses self._llm, not services.llm_client."""
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/pattern_extractor.py",
            "class E:\n    async def f(self):\n"
            "        return await self._llm.chat_json('x', [], {})\n",
        )
        assert "agent_llm_chat_bypass" in _rules(_audit(src))

    def test_chat_structured_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/synthesis_agent.py",
            "async def f(services):\n"
            "    return await services.llm_client.chat_structured('x', [], M)\n",
        )
        assert "agent_llm_chat_bypass" in _rules(_audit(src))

    def test_platform_chat_not_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/platform/agents/idempotent_llm.py",
            "async def f(services):\n"
            "    return await services.llm_client.chat(task_type='x', messages=[])\n",
        )
        assert "agent_llm_chat_bypass" not in _rules(_audit(src))
