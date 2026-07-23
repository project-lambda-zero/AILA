"""VR binding of the platform McpRegistryServiceBase.

Owns the VR-side ``MCP_SERVERS`` catalog and binds it (with the ``"vr"``
ConfigRegistry namespace) onto the platform base. The platform base owns
the resolve / probe / update logic; this module is module residue only.

To add a new MCP, append here AND add a matching field to
``VRConfigSchema``. The operator-facing UI auto-discovers from this list.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.mcp.registry import McpRegistryServiceBase

__all__ = ["MCP_SERVERS", "McpRegistryService"]


MCP_SERVERS: tuple[dict[str, str], ...] = (
    {
        "id": "audit_mcp",
        "name": "audit-mcp",
        "description": (
            "Source-code audit MCP. Owns git clones, indexing, graph "
            "queries, scanners, taint analysis, fuzzing target ranking."
        ),
        "env_var": "AUDIT_MCP_URL",
        "config_key": "audit_mcp_url",
        "default_url": "http://127.0.0.1:18822",
    },
    {
        "id": "ida_headless",
        "name": "ida-headless-mcp",
        "description": (
            "Binary analysis MCP. Owns IDA Pro disassembly, decompilation, "
            "CFF deobfuscation, taint analysis, exploitability proofs."
        ),
        "env_var": "IDA_HEADLESS_URL",
        "config_key": "ida_headless_url",
        "default_url": "http://127.0.0.1:18821",
    },
    {
        "id": "android_mcp",
        "name": "android-mcp",
        "description": (
            "Android APK audit MCP. Owns apktool/jadx decoding, androguard "
            "static analysis, MobSF scanning, signing-scheme verification, "
            "native-lib hardening, and composite mobile risk scoring."
        ),
        "env_var": "ANDROID_MCP_URL",
        "config_key": "android_mcp_url",
        "default_url": "http://127.0.0.1:18823",
    },
)


class McpRegistryService(McpRegistryServiceBase):
    """Resolve current URL + probe health for each registered VR MCP."""

    _module_id: ClassVar[str] = "vr"
    _servers: ClassVar[tuple[dict[str, str], ...]] = MCP_SERVERS
