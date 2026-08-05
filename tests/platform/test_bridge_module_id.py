"""RFC-05 concern (b) + crit 4 hardening: platform MCP bridges parameterized by module_id.

The bridge tool name and config namespace derive from a REQUIRED
constructor ``module_id`` kwarg (RFC-05 crit 4 hardening removed the
historical ``"vr"`` default). These tests assert the derived-name
parameterization and that omitting ``module_id`` raises ``TypeError``
so no callsite can silently pick up the platform's private opinion
about who owns the bridge.
"""
from __future__ import annotations

import pytest

from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool


class TestBridgeModuleId:
    def test_module_id_required(self) -> None:
        with pytest.raises(TypeError):
            AuditMcpBridgeTool()  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            IDABridgeTool()  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            AndroidMcpBridgeTool()  # type: ignore[call-arg]

    def test_vr_module_id_derives_vr_names(self) -> None:
        assert AuditMcpBridgeTool(module_id="vr").name == "vr.audit_mcp_bridge"
        assert IDABridgeTool(module_id="vr").name == "vr.ida_bridge"
        assert AndroidMcpBridgeTool(module_id="vr").name == "vr.android_mcp_bridge"

    def test_vr_module_id_stored(self) -> None:
        assert AuditMcpBridgeTool(module_id="vr").module_id == "vr"
        assert IDABridgeTool(module_id="vr").module_id == "vr"
        assert AndroidMcpBridgeTool(module_id="vr").module_id == "vr"

    def test_explicit_module_id_derives_name(self) -> None:
        assert AuditMcpBridgeTool(module_id="malware").name == "malware.audit_mcp_bridge"
        assert IDABridgeTool(module_id="malware").name == "malware.ida_bridge"
        assert (
            AndroidMcpBridgeTool(module_id="malware").name
            == "malware.android_mcp_bridge"
        )

    def test_explicit_module_id_stored(self) -> None:
        assert AuditMcpBridgeTool(module_id="malware").module_id == "malware"

    def test_recorder_still_accepted_with_module_id(self) -> None:
        # The existing recorder kwarg co-exists with the required module_id kwarg.
        tool = AuditMcpBridgeTool(recorder=None, module_id="malware")
        assert tool.name == "malware.audit_mcp_bridge"
