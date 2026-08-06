"""RFC-11 Tier C -- AuditMcpMiddleware behaviour tests.

Every scenario runs against a FAKE transport monkeypatched onto
:class:`aila.platform.mcp.client.McpClient._http_post` -- no live
audit-mcp server, no live registry, no live catalog. Class-level
middleware caches (spec cache, alias map, index roots, tool
semaphores) are snapshotted per test so cross-test bleed cannot
mask a bug.

Coverage:

* ``read_lines`` reads a real temp file slice and returns
  ``total_lines_in_file`` / ``content`` without writing a recorder
  row (the virtual tool is disk-local).
* ``read_function(name='toString')`` refuses BEFORE the HTTP hop
  with ``_bridge_policy: 'generic_name_blocked'``.
* An unknown kwarg on a known tool short-circuits with a
  :mod:`difflib` "did you mean" suggestion and never posts.
* ``read_function`` returning ``not indexed`` + ``file_path`` set
  falls back to the disk read and returns a ``_bridge_note`` while
  the single recorder row records the final ``ready`` status.
* A plain success round-trips: one HTTP post, one recorder row with
  final ``ready`` status, payload verbatim from the fake transport.
"""
from __future__ import annotations

import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from aila.platform.mcp.client import McpClient
from aila.platform.mcp.middleware.audit import AuditMcpMiddleware
from aila.platform.mcp.server_specs import spec_for

__all__: list[str] = []


# ── fake transport + recorder ────────────────────────────────────────


class _FakeResponse:
    """Minimal ``httpx.Response`` stand-in for the middleware's parser."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        json_body: Any = None,
        text_body: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_body if json_body is not None else {"status": "ready"}
        self.text = text_body

    def json(self) -> Any:
        return self._json


class _FakeTransport:
    """Records every ``_http_post`` call; serves queued responses per action.

    ``client._http_post`` is the private hook the middleware reaches into
    for every server call (primary dispatch + prewarm + fallback). Each
    invocation records ``{url, payload, timeout}`` and returns the
    response registered for the tool name in ``responses``. Unknown
    tools default to an empty ``{"status": "ready"}`` body so tests
    only need to name the responses that actually matter for the
    scenario under test.
    """

    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.responses: dict[str, _FakeResponse] = {}

    def set_response(self, action: str, response: _FakeResponse) -> None:
        self.responses[action] = response

    async def http_post(
        self, url: str, payload: dict[str, Any], timeout: float,
    ) -> _FakeResponse:
        self.posts.append(
            {"url": url, "payload": payload, "timeout": timeout},
        )
        action = url.rsplit("/tools/", 1)[-1]
        resp = self.responses.get(action)
        if resp is None:
            return _FakeResponse(
                status_code=200, json_body={"status": "ready"},
            )
        return resp


class _RecordingRecorder:
    """Captures every ``recorder_context`` envelope + its final ctx dict.

    The middleware calls ``client.recorder_context(action)`` exactly
    once per non-virtual ``forward``. The recorder factory receives
    ``server_id`` / ``base_url`` / ``action`` / ``instance_id`` kwargs
    and yields a mutable dict the middleware annotates with the final
    ``status`` / ``http_status`` / ``error_excerpt``. Storing the same
    dict reference in ``self.rows`` before the yield means the test can
    read the middleware's final annotation after the context exits.
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        return self._context(kwargs)

    @asynccontextmanager
    async def _context(self, kwargs: dict[str, Any]):
        row = dict(kwargs)
        self.rows.append(row)
        yield row


def _make_client_and_transport(
    recorder: _RecordingRecorder | None = None,
) -> tuple[McpClient, _FakeTransport]:
    """Build an ``McpClient`` pinned at a fake URL with the fake transport."""
    transport = _FakeTransport()
    client = McpClient(
        server_id="audit_mcp",
        base_url="http://fake-audit",
        timeout=30.0,
        recorder=recorder,
    )
    # Monkey-patch the private transport hook so no real httpx call
    # ever fires. Preserves the client's ctx-handling + status
    # normalisation on top.
    client._http_post = transport.http_post  # type: ignore[method-assign]
    return client, transport


# ── shared fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_middleware_class_state():
    """Snapshot and restore every class-level cache the middleware owns.

    ``_SPEC_CACHE`` / ``_SPEC_CACHE_FETCHED_AT`` / ``_AUTO_ALIAS_MAP`` /
    ``_INDEX_ROOTS`` / ``_TOOL_SEMAPHORES`` are class attributes shared
    across every middleware instance in the process -- restoring them
    per test guarantees one test's cache mutation cannot mask the next
    test's assertion.
    """
    cls = AuditMcpMiddleware
    prev = {
        "_SPEC_CACHE": cls._SPEC_CACHE,
        "_SPEC_CACHE_FETCHED_AT": cls._SPEC_CACHE_FETCHED_AT,
        "_AUTO_ALIAS_MAP": cls._AUTO_ALIAS_MAP,
        "_INDEX_ROOTS": cls._INDEX_ROOTS,
        "_TOOL_SEMAPHORES": cls._TOOL_SEMAPHORES,
    }
    cls._SPEC_CACHE = None
    cls._SPEC_CACHE_FETCHED_AT = None
    cls._AUTO_ALIAS_MAP = {}
    cls._INDEX_ROOTS = {}
    cls._TOOL_SEMAPHORES = {}
    yield
    cls._SPEC_CACHE = prev["_SPEC_CACHE"]
    cls._SPEC_CACHE_FETCHED_AT = prev["_SPEC_CACHE_FETCHED_AT"]
    cls._AUTO_ALIAS_MAP = prev["_AUTO_ALIAS_MAP"]
    cls._INDEX_ROOTS = prev["_INDEX_ROOTS"]
    cls._TOOL_SEMAPHORES = prev["_TOOL_SEMAPHORES"]


@pytest.fixture(autouse=True)
def _no_prewarm_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ``AUDIT_MCP_WORKERS`` is unset so prewarm fan-out skips.

    With workers >= 2 the middleware fires 8+ parallel ``summary`` /
    ``semble_stats`` posts against ``client._http_post``, which would
    pollute the transport's ``posts`` list and break the strict
    "one HTTP post per success case" assertions below.
    """
    monkeypatch.delenv("AUDIT_MCP_WORKERS", raising=False)


def _seed_spec_cache(specs: list[dict[str, Any]]) -> None:
    """Prime the class-level spec cache so no ``GET /tools`` fetch fires."""
    AuditMcpMiddleware._SPEC_CACHE = specs
    AuditMcpMiddleware._SPEC_CACHE_FETCHED_AT = time.monotonic()


def _new_middleware() -> AuditMcpMiddleware:
    return AuditMcpMiddleware(spec=spec_for("audit_mcp"), module_id="test")


# ── (a) read_lines virtual tool ──────────────────────────────────────


async def test_read_lines_returns_slice_and_writes_no_recorder_row() -> None:
    """The virtual ``read_lines`` reads disk, returns the slice, records nothing."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        rel = Path("src") / "hello.py"
        target = root / rel
        target.parent.mkdir(parents=True)
        target.write_text(
            "line1\nline2\nline3\nline4\nline5\n", encoding="utf-8",
        )

        recorder = _RecordingRecorder()
        client, transport = _make_client_and_transport(recorder=recorder)
        # Pre-populate the class-level index-root cache so no
        # list_indexes HTTP hop is needed. The disk read stays local.
        AuditMcpMiddleware._INDEX_ROOTS = {"idx1": str(root)}

        mw = _new_middleware()
        result = await mw.forward(client, "read_lines", {
            "index_id": "idx1",
            "file_path": "src/hello.py",
            "start": 2,
            "end": 4,
        })

    assert result["status"] == "ready"
    assert result["file_path"] == "src/hello.py"
    assert result["start_line"] == 2
    assert result["end_line"] == 4
    assert result["total_lines_in_file"] == 5
    assert result["content"] == "line2\nline3\nline4\n"

    # Virtual tool: no recorder envelope opened.
    assert recorder.rows == []
    # Virtual tool: no HTTP post fired.
    assert transport.posts == []


# ── (b) generic-Java-name pre-refuse ──────────────────────────────────


async def test_generic_java_name_read_function_returns_policy_error() -> None:
    """``read_function(name='toString')`` is refused BEFORE any HTTP hop."""
    recorder = _RecordingRecorder()
    client, transport = _make_client_and_transport(recorder=recorder)
    # Seed the schema so _validate_kwargs passes (no unknown-kwarg refusal).
    _seed_spec_cache([{
        "name": "read_function",
        "description": "read a function body",
        "params": [
            {"name": "index_id", "type": "string", "required": True},
            {"name": "name", "type": "string", "required": True},
            {"name": "file_path", "type": "string", "required": False},
        ],
        "required": ["index_id", "name"],
    }])

    mw = _new_middleware()
    result = await mw.forward(client, "read_function", {
        "index_id": "idx1",
        "name": "toString",
    })

    assert result["status"] == "error"
    assert result["_bridge_policy"] == "generic_name_blocked"
    assert "toString" in result["error"]
    assert "generic Java" in result["error"]
    # Refusal fires BEFORE recorder_context + BEFORE the HTTP POST.
    assert recorder.rows == []
    assert transport.posts == []


# ── (c) unknown-kwarg validation with difflib suggestion ─────────────


async def test_unknown_kwarg_short_circuits_with_difflib_suggestion() -> None:
    """An LLM-hallucinated kwarg is blocked pre-HTTP with a "did you mean"."""
    recorder = _RecordingRecorder()
    client, transport = _make_client_and_transport(recorder=recorder)
    _seed_spec_cache([{
        "name": "fuzzing_targets",
        "description": "rank targets by fuzz priority",
        "params": [
            {"name": "index_id", "type": "string", "required": True},
            {"name": "top_k", "type": "integer", "required": False},
        ],
        "required": ["index_id"],
    }])

    mw = _new_middleware()
    result = await mw.forward(client, "fuzzing_targets", {
        "index_id": "idx1",
        "top_p": 5,  # LLM habit -- fuzzing_targets does not take this
    })

    assert result["status"] == "error"
    # Names the offending kwarg + the closest valid one via difflib.
    assert "unknown kwarg" in result["error"]
    assert "'top_p'" in result["error"]
    assert "did you mean 'top_k'" in result["error"]
    # Validation short-circuit fires BEFORE recorder_context.
    assert recorder.rows == []
    assert transport.posts == []


# ── (d) read_function NOT-INDEXED + file_hint -> file fallback ──────


async def test_read_function_not_indexed_falls_back_to_read_lines() -> None:
    """``not indexed`` + ``file_path`` chains to disk read + ``_bridge_note``."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "src" / "app.java"
        target.parent.mkdir(parents=True)
        # 15 lines, well under the fallback's start=1 end=400 window.
        target.write_text(
            "\n".join(f"line{i}" for i in range(1, 16)) + "\n",
            encoding="utf-8",
        )

        recorder = _RecordingRecorder()
        client, transport = _make_client_and_transport(recorder=recorder)
        _seed_spec_cache([{
            "name": "read_function",
            "description": "read a function body",
            "params": [
                {"name": "index_id", "type": "string", "required": True},
                {"name": "name", "type": "string", "required": True},
                {"name": "file_path", "type": "string", "required": False},
            ],
            "required": ["index_id", "name"],
        }])
        AuditMcpMiddleware._INDEX_ROOTS = {"idx1": str(root)}

        # Primary read_function returns 200 with an in-body error the
        # middleware detects via the ``not indexed`` substring match.
        transport.set_response(
            "read_function",
            _FakeResponse(json_body={
                "status": "error",
                "error": "function 'someMethod' is not indexed",
            }),
        )

        mw = _new_middleware()
        result = await mw.forward(client, "read_function", {
            "index_id": "idx1",
            # Lowercase-first + no separators: class-rewrite skips,
            # bare-name retry skips, file fallback fires.
            "name": "someMethod",
            "file_path": "src/app.java",
        })

    assert result["status"] == "ready"
    assert result["file_path"] == "src/app.java"
    assert result["start_line"] == 1
    assert result["end_line"] == 15
    assert result["total_lines_in_file"] == 15
    assert result["content"].startswith("line1\n")
    assert "_bridge_note" in result
    assert "not in the function index" in result["_bridge_note"]

    # Exactly one HTTP post -- the primary read_function. The file
    # fallback is a local disk read.
    assert len(transport.posts) == 1
    assert transport.posts[0]["url"].endswith("/tools/read_function")

    # Exactly one recorder envelope; the fallback overwrites the
    # status so the recorded row shows the final resolution.
    assert len(recorder.rows) == 1
    row = recorder.rows[0]
    assert row["action"] == "read_function"
    assert row["status"] == "ready"


# ── (e) plain success round-trip ─────────────────────────────────────


async def test_plain_success_roundtrips_one_post_one_row() -> None:
    """Success path: one HTTP post, one recorder row, payload preserved."""
    recorder = _RecordingRecorder()
    client, transport = _make_client_and_transport(recorder=recorder)
    _seed_spec_cache([{
        "name": "search_functions",
        "description": "regex search of function names",
        "params": [
            {"name": "index_id", "type": "string", "required": True},
            {"name": "pattern", "type": "string", "required": True},
            {"name": "limit", "type": "integer", "required": False},
        ],
        "required": ["index_id", "pattern"],
    }])
    transport.set_response(
        "search_functions",
        _FakeResponse(json_body={
            "matches": [{"name": "fooBar"}, {"name": "fooBaz"}],
            "total": 2,
        }),
    )

    mw = _new_middleware()
    result = await mw.forward(client, "search_functions", {
        "index_id": "idx1",
        "pattern": "foo",
    })

    # Status was missing from the fake body; client.post injects
    # "ready" on HTTP 2xx and the middleware's status injection is
    # then a no-op.
    assert result["status"] == "ready"
    assert result["matches"] == [{"name": "fooBar"}, {"name": "fooBaz"}]
    assert result["total"] == 2

    assert len(transport.posts) == 1
    post = transport.posts[0]
    assert post["url"] == "http://fake-audit/tools/search_functions"
    assert post["payload"] == {"index_id": "idx1", "pattern": "foo"}

    assert len(recorder.rows) == 1
    row = recorder.rows[0]
    assert row["action"] == "search_functions"
    assert row["server_id"] == "audit_mcp"
    assert row["status"] == "ready"
    assert row["http_status"] == 200
