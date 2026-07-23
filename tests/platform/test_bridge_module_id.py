"""RFC-05 concern (b): platform MCP bridges parameterized by module_id.

The bridge tool name and config namespace derive from a constructor
``module_id`` (default "vr", preserving the historical names) instead of a
hard-coded literal. These tests assert behavior-preservation (default names
unchanged) and the parameterization (an explicit module_id derives the name).
"""
from __future__ import annotations

from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool


class TestBridgeModuleId:
    def test_default_module_id_preserves_vr_names(self) -> None:
        assert AuditMcpBridgeTool().name == "vr.audit_mcp_bridge"
        assert IDABridgeTool().name == "vr.ida_bridge"
        assert AndroidMcpBridgeTool().name == "vr.android_mcp_bridge"

    def test_default_module_id_is_vr(self) -> None:
        assert AuditMcpBridgeTool().module_id == "vr"
        assert IDABridgeTool().module_id == "vr"
        assert AndroidMcpBridgeTool().module_id == "vr"

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
        # The existing recorder kwarg co-exists with the new module_id kwarg.
        tool = AuditMcpBridgeTool(recorder=None, module_id="malware")
        assert tool.name == "malware.audit_mcp_bridge"
