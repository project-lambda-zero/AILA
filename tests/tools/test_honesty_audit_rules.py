"""Unit tests for honesty_audit Rules 18-21.

Each rule has:
  - positive test: source containing the violation → rule fires.
  - negative test: source without the violation → rule is silent.
  - whitelist test: violation present but suppressed by HONESTY_WHITELIST.

Tests use real temporary file fixtures written to tmp_path — no mocks on
production paths.
"""
from __future__ import annotations

from pathlib import Path

import pytest

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
# Rule 18 — asyncio_in_module
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
# Rule 19 — response_model_dict
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
# Rule 20 — bare_dict_return_endpoint
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
# Rule 21 — noqa_inline
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
            "# noqa: some-rule — this file may reference suppression codes\nx = 1\n",
        )
        findings = _audit(src)
        assert not any(f.rule == "noqa_inline" for f in findings)

    def test_alembic_migration_exempt(self, tmp_path: Path) -> None:
        """Alembic migration files are exempt from noqa_inline."""
        src = _write(
            tmp_path,
            "alembic/versions/0001_init.py",
            "x = 1  # noqa: E501 — generated migration\n",
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
