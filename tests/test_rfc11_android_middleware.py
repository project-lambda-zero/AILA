"""RFC-11 Tier C -- AndroidMcpMiddleware behaviour tests.

Verify the ported plugin preserves the pre-Tier-C bridge's four
signature behaviours end-to-end without a live server:

1. pipeline-only tool blocking with ``_bridge_policy=pipeline_only_blocked``
   (bypassable via ``_agent_bypass=True``),
2. APK path typo recovery against a temp uploads dir seeded with a
   SHA-derived filename,
3. unknown-kwarg rejection with a structured error and the valid-param
   list included so the agent can self-correct,
4. plain success round-trips: dict body flows through unchanged and
   picks up ``status: ready`` if the tool omitted it.

Transport is faked by monkey-patching :meth:`McpClient.post` on the
per-test client instance so no HTTP round-trip fires. The
:class:`AndroidMcpMiddleware` class-level ``_SPEC_CACHE`` is reset per
test so fixtures compose without cross-test bleed.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.mcp.client import McpClient
from aila.platform.mcp.middleware.android import (
    AndroidMcpMiddleware,
    _resolve_apk_path,
)
from aila.platform.mcp.server_specs import spec_for


@pytest.fixture(autouse=True)
def _reset_spec_cache() -> Any:
    """Clear class-level spec cache between tests so fixtures compose."""
    AndroidMcpMiddleware._SPEC_CACHE = None
    yield
    AndroidMcpMiddleware._SPEC_CACHE = None


def _make_middleware() -> AndroidMcpMiddleware:
    return AndroidMcpMiddleware(spec=spec_for("android_mcp"), module_id="vr")


def _make_client() -> McpClient:
    # Fixed base_url short-circuits the resolver and never touches
    # the DB/env resolver path.
    return McpClient(server_id="android_mcp", base_url="http://test.invalid")


async def test_pipeline_only_tool_blocked_without_bypass() -> None:
    """jadx_decompile without _agent_bypass returns the policy envelope."""
    mw = _make_middleware()
    client = _make_client()
    result = await mw.forward(
        client, "jadx_decompile", {"apk_path": "/tmp/x.apk"},
    )
    assert result["status"] == "ready"
    assert result["_bridge_policy"] == "pipeline_only_blocked"
    assert result["matches"] == []
    assert result["results"] == []
    assert "jadx_decompile" in result["_bridge_note"]
    assert "pipeline-only" in result["_bridge_note"]


async def test_pipeline_only_tool_bypass_allows_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_agent_bypass=True pops the sentinel and hits the transport."""
    mw = _make_middleware()
    client = _make_client()
    # Empty cache -> _validate_kwargs short-circuits to None so the
    # call reaches the transport.
    AndroidMcpMiddleware._SPEC_CACHE = []

    captured: dict[str, Any] = {}

    async def fake_post(
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        captured["action"] = action
        captured["payload"] = dict(payload)
        if ctx is not None:
            ctx["http_status"] = 200
            ctx["status"] = "ready"
        return {"status": "ready", "output_dir": "/decompiled"}

    monkeypatch.setattr(client, "post", fake_post)

    result = await mw.forward(
        client,
        "jadx_decompile",
        {"_agent_bypass": True, "apk_path": "/tmp/x.apk"},
    )
    assert captured["action"] == "jadx_decompile"
    # The sentinel is popped before the transport sees the payload.
    assert "_agent_bypass" not in captured["payload"]
    assert captured["payload"] == {"apk_path": "/tmp/x.apk"}
    assert result["status"] == "ready"
    assert result["output_dir"] == "/decompiled"


async def test_apk_path_typo_recovery_via_sha_prefix(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo'd apk_path resolves to the canonical file via 8-char SHA prefix."""
    uploads = tmp_path / "shared"
    uploads.mkdir()
    # Realistic 64-hex-char SHA256 filename.
    real_sha = "b810b2bbec0bb9217e090fb82773d80fefdd12576b449b3d126f49dd9a159c39"
    real_apk = uploads / f"{real_sha}.apk"
    real_apk.write_bytes(b"PK\x03\x04fake-apk-bytes")
    monkeypatch.setenv("ANDROID_MCP_UPLOADS_DIR", str(uploads))

    # Sanity-check the resolver in isolation before running through
    # the middleware: drop 5 chars mid-SHA to simulate the observed
    # PRIVACY-1 typo class. Prefix-8 must still match uniquely.
    typo_sha = real_sha[:8] + real_sha[13:]
    typo_path = str(uploads / f"{typo_sha}.apk")
    canonical, note = _resolve_apk_path(typo_path)
    assert canonical == str(real_apk)
    assert note is not None and "typo recovered" in note

    mw = _make_middleware()
    client = _make_client()
    # Empty cache -> validation skipped so the recovery pass runs.
    AndroidMcpMiddleware._SPEC_CACHE = []

    captured_payload: dict[str, Any] = {}

    async def fake_post(
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        captured_payload.update(payload)
        if ctx is not None:
            ctx["http_status"] = 200
            ctx["status"] = "ready"
        return {"status": "ready", "ok": True}

    monkeypatch.setattr(client, "post", fake_post)

    # Use a non-pipeline-only tool so the transport is reached.
    result = await mw.forward(
        client, "verify_capabilities", {"apk_path": typo_path},
    )
    # The apk_path kwarg is substituted before the transport sees it.
    assert captured_payload["apk_path"] == str(real_apk)
    assert result["status"] == "ready"


async def test_unknown_kwarg_validation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown kwarg is rejected before the HTTP roundtrip."""
    mw = _make_middleware()
    client = _make_client()
    # Pre-seed a fake catalog with one tool that has one required
    # param. The validator will reject any other kwarg.
    AndroidMcpMiddleware._SPEC_CACHE = [
        {
            "name": "find_secrets",
            "description": "",
            "params": [
                {
                    "name": "decompiled_dir",
                    "type": "string",
                    "required": True,
                },
            ],
            "required": ["decompiled_dir"],
        },
    ]

    async def refuse_post(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError(
            "client.post must not be called when validation rejects the call",
        )

    monkeypatch.setattr(client, "post", refuse_post)

    result = await mw.forward(
        client,
        "find_secrets",
        {"apk_path": "/tmp/x.apk"},  # wrong kwarg name
    )
    assert result["status"] == "error"
    assert "rejected" in result["error"]
    assert "unknown kwarg" in result["error"].lower()
    # The offending kwarg name is echoed back so the agent can see
    # exactly what to fix.
    assert "'apk_path'" in result["error"]
    # The valid-param list is included so the agent can self-correct
    # without another schema fetch.
    assert "decompiled_dir" in result["error"]


async def test_plain_success_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed call flows the transport's dict body through unchanged."""
    mw = _make_middleware()
    client = _make_client()
    AndroidMcpMiddleware._SPEC_CACHE = []

    async def fake_post(
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if ctx is not None:
            ctx["http_status"] = 200
            ctx["status"] = "ready"
        return {"status": "ready", "secrets": ["AKIA..."], "count": 1}

    monkeypatch.setattr(client, "post", fake_post)

    result = await mw.forward(
        client, "find_secrets", {"decompiled_dir": "/tmp/decomp"},
    )
    assert result == {"status": "ready", "secrets": ["AKIA..."], "count": 1}


async def test_unknown_status_coerced_to_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tool returning a non-whitelisted status ('partial_failure') is coerced."""
    mw = _make_middleware()
    client = _make_client()
    AndroidMcpMiddleware._SPEC_CACHE = []

    async def fake_post(
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if ctx is not None:
            ctx["http_status"] = 200
            # Client.post sets ctx.status=error for unknown statuses
            # but returns the body verbatim; middleware wraps.
            ctx["status"] = "error"
        return {"status": "partial_failure", "errors": ["one thing"]}

    monkeypatch.setattr(client, "post", fake_post)

    result = await mw.forward(
        client, "find_secrets", {"decompiled_dir": "/tmp/decomp"},
    )
    assert result["status"] == "error"
    assert "unknown status" in result["error"]
    assert "'partial_failure'" in result["error"]


async def test_non_2xx_wrapped_with_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 500 response with a ``detail`` field is wrapped into a uniform error."""
    mw = _make_middleware()
    client = _make_client()
    AndroidMcpMiddleware._SPEC_CACHE = []

    async def fake_post(
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if ctx is not None:
            ctx["http_status"] = 500
            # Client.post's None-status + 4xx/5xx branch marks ctx
            # error but returns the body unchanged; middleware wraps.
            ctx["status"] = "error"
        return {"detail": "FileNotFoundError: /nope.apk"}

    monkeypatch.setattr(client, "post", fake_post)

    result = await mw.forward(
        client, "find_secrets", {"decompiled_dir": "/tmp/decomp"},
    )
    assert result["status"] == "error"
    assert "HTTP 500" in result["error"]
    assert "FileNotFoundError" in result["error"]
    assert "find_secrets" in result["error"]
