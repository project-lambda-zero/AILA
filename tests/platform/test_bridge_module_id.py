"""RFC-05 concern (b) + crit 4 hardening + RFC-11 Tier C: platform MCP
bridges parameterized by module_id.

The bridge tool name and module_id derive from the ``module_id`` kwarg
that :func:`aila.platform.mcp.factory.make_bridge` requires. These
tests assert the Tier C generic :class:`McpBridgeTool` preserves the
pre-Tier-C ``.name`` / ``.module_id`` contract for every server id in
:data:`~aila.platform.mcp.server_specs.SERVER_SPECS` so external callers
that read those attributes continue to work.
"""
from __future__ import annotations

from aila.platform.mcp.factory import make_bridge


class TestBridgeModuleId:
    def test_vr_module_id_derives_vr_names(self) -> None:
        assert make_bridge("audit_mcp", module_id="vr").name == "vr.audit_mcp_bridge"
        assert make_bridge("ida_headless", module_id="vr").name == "vr.ida_bridge"
        assert (
            make_bridge("android_mcp", module_id="vr").name
            == "vr.android_mcp_bridge"
        )

    def test_vr_module_id_stored(self) -> None:
        assert make_bridge("audit_mcp", module_id="vr").module_id == "vr"
        assert make_bridge("ida_headless", module_id="vr").module_id == "vr"
        assert make_bridge("android_mcp", module_id="vr").module_id == "vr"

    def test_malware_module_id_derives_names(self) -> None:
        assert (
            make_bridge("audit_mcp", module_id="malware").name
            == "malware.audit_mcp_bridge"
        )
        # malware runs the experimental IDA endpoint under the shared
        # ``ida_bridge`` agent-facing tool name.
        assert (
            make_bridge("ida_headless_exp", module_id="malware").name
            == "malware.ida_bridge"
        )

    def test_malware_module_id_stored(self) -> None:
        assert (
            make_bridge("audit_mcp", module_id="malware").module_id == "malware"
        )
        assert (
            make_bridge("ida_headless", module_id="malware").module_id
            == "malware"
        )

    def test_recorder_still_accepted_with_module_id(self) -> None:
        # The recorder kwarg co-exists with the required module_id kwarg.
        tool = make_bridge("audit_mcp", module_id="malware", recorder=None)
        assert tool.name == "malware.audit_mcp_bridge"
