"""tshark network capture analysis runner -- executes tshark commands over SSH.

Supports 16 analysis actions covering NetworkMiner-equivalent functionality:
hosts, sessions, DNS, HTTP, files, images, credentials, endpoints,
protocol hierarchy, TLS handshakes, SMTP, FTP, streams, anomalies, and more.
"""
from __future__ import annotations

import logging

from aila.config import Settings
from aila.platform.exceptions import AILAError
from aila.platform.tools._common import Tool

_log = logging.getLogger(__name__)


async def _resolve_tshark_cmd(ssh: object, integration: dict) -> str:
    """Resolve the full quoted path to ``tshark.exe`` on a Windows analyzer.

    Wireshark's Windows installer does not extend PATH, so bare ``tshark``
    invocations fail with "not recognized". ``where /R`` walks the default
    install roots to find the binary; on any failure we fall back to
    ``tshark`` so callers on PATH-configured hosts keep working.
    """
    probe = (
        'where tshark.exe 2>NUL || '
        'where /R "C:\\Program Files\\Wireshark" tshark.exe 2>NUL || '
        'where /R "C:\\Program Files (x86)\\Wireshark" tshark.exe 2>NUL'
    )
    try:
        out = await ssh.run_command(integration, probe, timeout_seconds=15.0)  # type: ignore[attr-defined]
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("tshark path probe failed: %s", exc)
        return "tshark"
    first = next((line.strip() for line in out.splitlines() if line.strip()), "")
    return f'"{first}"' if first else "tshark"


TOOL_ALIAS = "tshark_runner"
CAPABILITY = (
    "Run tshark commands for comprehensive PCAP analysis -- summary, HTTP, DNS, conversations, "
    "stream following, endpoints, protocol hierarchy, HTTP objects, TLS handshakes, SMTP, FTP, "
    "stream listing, credentials, file extraction, anomalies, and custom filters."
)

_ACTIONS = (
    "summary, http, dns, conversations, follow_stream, endpoints, protocol_hierarchy, "
    "http_objects, tls_handshakes, smtp, ftp, streams_list, credentials, files, anomalies, custom"
)

__all__ = ["TsharkRunnerTool"]


class TsharkRunnerTool(Tool):
    """Execute tshark commands on the analyzer machine."""

    name = "tshark_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": f"One of: {_ACTIONS}."},
        "pcap_path": {"type": "string", "description": "Path to PCAP file on analyzer."},
        "stream_index": {"type": "integer", "description": "TCP stream index for follow_stream.", "nullable": True},
        "display_filter": {"type": "string", "description": "Custom display filter.", "nullable": True},
        "output_dir": {"type": "string", "description": "Directory for file extraction output.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "summary",
        pcap_path: str = "",
        stream_index: int | None = None,
        display_filter: str | None = None,
        output_dir: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        if not pcap_path:
            raise ValueError("pcap_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        q = '"' if analyzer_os == "windows" else ""
        p = f"{q}{pcap_path}{q}"

        cmd = self._build_command(action, p, stream_index, display_filter, output_dir, analyzer_os)

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)

        # Windows: Wireshark MSI does not add tshark.exe to PATH. Resolve
        # the real path once and substitute it for the bare ``tshark`` token
        # that _build_command emits.
        if analyzer_os == "windows":
            tshark_cmd = await _resolve_tshark_cmd(ssh, integration)
            if tshark_cmd != "tshark":
                cmd = cmd.replace("tshark ", f"{tshark_cmd} ")

        return await ssh.run_command(integration, cmd, timeout_seconds=300.0)

    @staticmethod
    def _build_command(
        action: str,
        pcap: str,
        stream_index: int | None,
        display_filter: str | None,
        output_dir: str | None,
        analyzer_os: str,
    ) -> str:
        q = '"' if analyzer_os == "windows" else "'"
        out = output_dir or ("/tmp/tshark_export" if analyzer_os != "windows" else "%TEMP%\\tshark_export")

        cmd_map: dict[str, str] = {
            "summary": f"tshark -r {pcap} -q -z conv,tcp",
            "http": (
                f"tshark -r {pcap} -Y http.request "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
                f"-e http.host -e http.request.method -e http.request.uri -e http.user_agent"
            ),
            "dns": (
                f"tshark -r {pcap} -Y dns "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
                f"-e dns.qry.name -e dns.qry.type -e dns.a -e dns.aaaa -e dns.cname -e dns.resp.ttl"
            ),
            "conversations": f"tshark -r {pcap} -q -z conv,tcp",
            "follow_stream": f"tshark -r {pcap} -q -z follow,tcp,ascii,{stream_index or 0}",
            "endpoints": (
                f"tshark -r {pcap} -q -z endpoints,tcp && "
                f"tshark -r {pcap} -q -z endpoints,udp"
            ),
            "protocol_hierarchy": f"tshark -r {pcap} -q -z io,phs",
            "http_objects": f"tshark -r {pcap} --export-objects http,{out}",
            "tls_handshakes": (
                f"tshark -r {pcap} -Y tls.handshake.type==1 "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport "
                f"-e tls.handshake.extensions_server_name -e tls.handshake.version"
            ),
            "smtp": (
                f"tshark -r {pcap} -Y smtp "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
                f"-e smtp.req.command -e smtp.req.parameter -e smtp.rsp.parameter"
            ),
            "ftp": (
                f"tshark -r {pcap} -Y ftp "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
                f"-e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg"
            ),
            "streams_list": (
                f"tshark -r {pcap} -T fields -e tcp.stream -e ip.src -e tcp.srcport "
                f"-e ip.dst -e tcp.dstport -e frame.protocols | sort -u"
                if analyzer_os != "windows"
                else f'tshark -r {pcap} -T fields -e tcp.stream -e ip.src -e tcp.srcport '
                     f'-e ip.dst -e tcp.dstport -e frame.protocols | sort /unique'
            ),
            "credentials": (
                f"tshark -r {pcap} -Y {q}http.authorization or ftp.request.command==PASS "
                f"or ftp.request.command==USER or smtp.req.command==AUTH "
                f"or pop.request.parameter or imap.request{q} "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
                f"-e http.authorization -e ftp.request.command -e ftp.request.arg "
                f"-e smtp.req.command -e smtp.req.parameter"
            ),
            "files": (
                f"tshark -r {pcap} --export-objects http,{out} && "
                f"tshark -r {pcap} --export-objects smb,{out} && "
                f"tshark -r {pcap} --export-objects dicom,{out} && "
                f"tshark -r {pcap} --export-objects tftp,{out}"
                if analyzer_os != "windows"
                else f'tshark -r {pcap} --export-objects http,{out} & '
                     f'tshark -r {pcap} --export-objects smb,{out} & '
                     f'tshark -r {pcap} --export-objects tftp,{out}'
            ),
            "anomalies": (
                f"tshark -r {pcap} -Y {q}tcp.analysis.retransmission or tcp.analysis.duplicate_ack "
                f"or tcp.analysis.zero_window or icmp.type==3 or dns.flags.rcode!=0 "
                f"or http.response.code>=400{q} "
                f"-T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst "
                f"-e _ws.col.Protocol -e _ws.col.Info"
            ),
        }

        if action == "custom" and display_filter:
            filt = f'"{display_filter}"' if analyzer_os == "windows" else f"'{display_filter}'"
            return f"tshark -r {pcap} -Y {filt}"

        if action not in cmd_map:
            raise ValueError(f"Unknown tshark action '{action}'. Supported: {_ACTIONS}.")

        cmd = cmd_map[action]
        if display_filter and action not in ("follow_stream", "credentials", "anomalies", "custom"):
            filt = f'"{display_filter}"' if analyzer_os == "windows" else f"'{display_filter}'"
            cmd = f"tshark -r {pcap} -Y {filt}"

        return cmd


def create_tool(settings: Settings) -> TsharkRunnerTool:
    """Construct a TsharkRunnerTool with the given settings."""
    return TsharkRunnerTool(settings)
