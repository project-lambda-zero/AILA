"""Zeek network security monitor runner -- PCAP analysis over SSH.

Zeek (formerly Bro) processes PCAPs into structured log files with deep
protocol analysis that goes far beyond tshark. It generates:

- conn.log      -- every connection (TCP/UDP/ICMP) with duration, bytes, state
- dns.log       -- full DNS transactions with query/response/TTL
- http.log      -- HTTP requests with host, URI, method, user-agent, MIME type, status
- ssl.log       -- TLS/SSL handshakes with SNI, issuer, subject, JA3/JA3S hashes
- files.log     -- every file transferred over any protocol with MIME type and hashes
- x509.log      -- certificate details
- smtp.log      -- email metadata
- pe.log        -- portable executable metadata from transferred files
- notice.log    -- Zeek's built-in anomaly/threat detections
- weird.log     -- protocol violations and anomalies
- dhcp.log      -- DHCP leases (IP assignment history)
- kerberos.log  -- Kerberos auth events
- smb_files.log -- SMB file transfers
- dpd.log       -- dynamic protocol detection events
- ssh.log       -- SSH connection attempts with version strings
- ftp.log       -- FTP commands and responses

What Zeek can do that tshark cannot:
- JA3/JA3S TLS fingerprinting (identify malware by TLS handshake pattern)
- Automatic file extraction from any protocol with hash computation
- Connection state tracking (S0, SF, REJ, RSTO, etc.) for behavioral analysis
- Built-in anomaly detection via notice framework
- Protocol-independent file and PE analysis
- Scriptable threat intelligence matching (Intel framework)
- Community ID flow hashing for cross-tool correlation
"""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools import Tool

TOOL_ALIAS = "zeek_runner"
CAPABILITY = (
    "Run Zeek network security monitor for deep PCAP analysis -- structured logs, "
    "JA3 fingerprinting, file extraction, anomaly detection, and protocol analysis."
)

_ACTIONS = (
    "analyze, read_log, connections, dns, http, ssl, files, notices, "
    "weird, extract_files, ja3, smtp, ssh, kerberos, smb, custom_script"
)

__all__ = ["ZeekRunnerTool"]


_LOG_MAP: dict[str, str] = {
    "connections": "conn.log",
    "dns": "dns.log",
    "http": "http.log",
    "ssl": "ssl.log",
    "files": "files.log",
    "notices": "notice.log",
    "weird": "weird.log",
    "smtp": "smtp.log",
    "ssh": "ssh.log",
    "kerberos": "kerberos.log",
    "smb": "smb_files.log",
}


def _zeek_run(pcap: str, out: str, extra: str = "") -> str:
    return f"mkdir -p {out} && cd {out} && zeek -r {pcap} Log::default_logdir={out} {extra}"


def _zeek_read_log(out: str, log_file: str) -> str:
    return f"zeek-cut < {out}/{log_file} 2>/dev/null || cat {out}/{log_file}"


def _ensure_then_read(pcap: str, out: str, log_file: str) -> str:
    return (
        f"if [ ! -f {out}/{log_file} ]; then "
        f"  {_zeek_run(pcap, out)}; "
        f"fi && {_zeek_read_log(out, log_file)}"
    )


def _cmd_analyze(pcap: str, out: str, **_kw: object) -> str:
    return f"{_zeek_run(pcap, out)} && echo '--- Generated logs ---' && ls -la {out}/*.log 2>/dev/null"


def _cmd_read_log(_pcap: str, out: str, log_name: str | None = None, **_kw: object) -> str:
    return _zeek_read_log(out, log_name or "conn.log")


def _cmd_log_reader(pcap: str, out: str, log_name: str | None = None, **_kw: object) -> str:
    log_file = _LOG_MAP.get(log_name or "", log_name or "conn.log")
    return _ensure_then_read(pcap, out, log_file)


def _cmd_extract_files(pcap: str, out: str, **_kw: object) -> str:
    return (
        f"{_zeek_run(pcap, out, f'FileExtract::prefix={out}/extracted')} && "
        f"echo '--- Extracted files ---' && ls -la {out}/extracted* 2>/dev/null && "
        f"echo '--- Files log ---' && cat {out}/files.log"
    )


def _cmd_ja3(pcap: str, out: str, **_kw: object) -> str:
    return (
        f"{_zeek_run(pcap, out)} && cat {out}/ssl.log 2>/dev/null | "
        f"zeek-cut ja3 ja3s server_name issuer subject 2>/dev/null || cat {out}/ssl.log"
    )


def _cmd_custom_script(pcap: str, out: str, script_content: str | None = None, **_kw: object) -> str:
    if not script_content:
        raise ValueError("script_content is required for custom_script action.")
    return (
        f"mkdir -p {out} && echo '{script_content}' > {out}/_custom.zeek && "
        f"cd {out} && zeek -r {pcap} {out}/_custom.zeek Log::default_logdir={out}"
    )


_ACTION_HANDLERS = {
    "analyze": _cmd_analyze,
    "read_log": _cmd_read_log,
    "extract_files": _cmd_extract_files,
    "ja3": _cmd_ja3,
    "custom_script": _cmd_custom_script,
}
for _log_action in _LOG_MAP:
    _ACTION_HANDLERS[_log_action] = _cmd_log_reader


def _build_zeek_command(
    action: str,
    pcap_path: str,
    log_name: str | None,
    output_dir: str,
    script_content: str | None,
    analyzer_os: str,
) -> str:
    """Build the SSH command for the requested Zeek action."""
    if analyzer_os == "windows":
        raise ValueError("Zeek is Linux-only. Use tshark for Windows analysis.")

    handler = _ACTION_HANDLERS.get(action)
    if handler is None:
        raise ValueError(f"Unknown zeek action '{action}'. Supported: {_ACTIONS}.")
    return handler(pcap=pcap_path, out=output_dir, log_name=log_name, script_content=script_content)


class ZeekRunnerTool(Tool):
    """Execute Zeek network analysis on the analyzer machine."""

    name = "zeek_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": f"One of: {_ACTIONS}."},
        "pcap_path": {"type": "string", "description": "Path to PCAP file on analyzer."},
        "log_name": {"type": "string", "description": "Log file name for read_log action.", "nullable": True},
        "output_dir": {"type": "string", "description": "Zeek output directory.", "nullable": True},
        "script_content": {"type": "string", "description": "Custom Zeek script for custom_script action.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "analyze",
        pcap_path: str = "",
        log_name: str | None = None,
        output_dir: str | None = None,
        script_content: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        if not pcap_path:
            raise ValueError("pcap_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        out = output_dir or f"/tmp/zeek_output_{hash(pcap_path) % 100000}"

        cmd = _build_zeek_command(action, pcap_path, log_name, out, script_content, analyzer_os)

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=600.0)


def create_tool(settings: Settings) -> ZeekRunnerTool:
    """Construct a ZeekRunnerTool with the given settings."""
    return ZeekRunnerTool(settings)
