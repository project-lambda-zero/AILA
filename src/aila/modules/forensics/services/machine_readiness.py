"""Analyzer machine readiness checker.

Connects to the analyzer machine via SSH and verifies that all required
forensic tools are installed.  When a tool is missing, the service
attempts a three-tier install cascade:

1. **Online install** -- runs the tool's ``install_commands`` (apt, pip,
   winget, brew) directly on the analyzer.
2. **Offline install** -- if the online attempt fails (air-gapped machine,
   no internet), delegates to ``OfflineInstallerService`` which prepares
   bundles on the platform server, uploads them via SFTP, and installs
   locally on the analyzer.
3. **Skip** -- if both tiers fail and the tool is optional, marks it as
   ``missing``; if required, sets ``all_required_ok = False``.

Supports Linux, macOS, and Windows analyzer machines.
"""
from __future__ import annotations

import json
import logging
import shlex
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from aila.config import Settings
from aila.modules.forensics.contracts.machine import MachineReadinessResult, ToolCheckResult
from aila.modules.forensics.tools._ssh_helper import ps_literal, run_tool_probe
from aila.platform.exceptions import AILAError

_log = logging.getLogger(__name__)

__all__ = ["MachineReadinessService"]


def _load_tool_requirements() -> dict[str, list[dict[str, Any]]]:
    """Load tool requirements from the bundled JSON file."""
    data_path = Path(__file__).parent.parent / "data" / "tool_requirements.json"
    return json.loads(data_path.read_text(encoding="utf-8"))


async def _evidence_directory_error(
    ssh: Any, integration: dict[str, Any], evidence_directory: str, analyzer_os: str,
) -> str | None:
    """Return why ``evidence_directory`` is unusable, or None when it is a readable directory."""
    if analyzer_os == "windows":
        literal = ps_literal(evidence_directory)
        probe = (
            'powershell -NoProfile -Command "'
            f"if (-not (Test-Path -LiteralPath {literal} -PathType Container)) {{ exit 2 }}; "
            f"Get-ChildItem -LiteralPath {literal} -Force -ErrorAction Stop | Select-Object -First 1 | Out-Null"
            '"'
        )
    else:
        quoted = shlex.quote(evidence_directory)
        probe = f"test -d {quoted} && test -r {quoted} && test -x {quoted}"
    try:
        await ssh.run_command(integration, probe, timeout_seconds=30.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        return (
            f"Evidence directory {evidence_directory} is missing or unreadable on the analyzer "
            f"({str(exc)[:200]})."
        )
    return None


class MachineReadinessService:
    """Check and install forensic tools on an analyzer machine."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def detect_os(self, integration: dict[str, Any]) -> str:
        """Auto-detect the analyzer machine OS via SSH.

        Tries ``uname -s`` first (succeeds on Linux/macOS).
        Falls back to ``ver`` which prints a Windows version string.

        Returns:
            ``"linux"``, ``"macos"``, or ``"windows"``.
        """
        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        try:
            output = await ssh.run_command(integration, "uname -s", timeout_seconds=10.0)
            kernel = output.strip().lower()
            if "darwin" in kernel:
                return "macos"
            if "linux" in kernel:
                return "linux"
        except (OSError, TimeoutError, ConnectionError, RuntimeError):
            _log.debug("uname probe failed -- trying Windows detection", exc_info=True)

        try:
            output = await ssh.run_command(integration, "ver", timeout_seconds=10.0)
            if "windows" in output.lower():
                return "windows"
        except (OSError, TimeoutError, ConnectionError, RuntimeError):
            _log.debug("Windows ver probe failed after uname probe failure", exc_info=True)

        raise RuntimeError("Unable to detect analyzer OS via uname -s or ver")

    async def check_readiness(
        self,
        integration: dict[str, Any],
        system_id: int,
        system_name: str,
        evidence_directory: str,
        analyzer_os: str = "linux",
        install_missing: bool = True,
        progress_cb: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> MachineReadinessResult:
        """Check tool readiness and evidence access on the analyzer machine.

        For each missing tool, attempts online install first, then falls
        back to offline install (SFTP + local install) if that fails. The
        project's evidence directory must also be a readable directory on
        the analyzer; otherwise the result is not ready and says why.

        Args:
            integration: SSH connection fields.
            system_id: Platform system ID.
            system_name: System display name.
            evidence_directory: The project's evidence directory on the analyzer.
            analyzer_os: Target OS -- ``"linux"``, ``"macos"``, or ``"windows"``.
            install_missing: If True, attempt to install missing tools.

        Returns:
            MachineReadinessResult with per-tool status.
        """
        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        requirements = _load_tool_requirements()

        results: list[ToolCheckResult] = []
        all_required_ok = True

        for _category, tools in requirements.items():
            for tool_def in tools:
                tool_name = tool_def["name"]
                required = tool_def.get("required", False)

                os_block = tool_def.get(analyzer_os)
                if not os_block:
                    results.append(ToolCheckResult(
                        tool_name=tool_name,
                        required=required,
                        status="skipped",
                        message=f"No definition for {analyzer_os}.",
                    ))
                    continue

                check_cmd = os_block["check_command"]
                install_cmds = os_block.get("install_commands", [])

                # --- Tier 0: already installed? ---
                if progress_cb:
                    await progress_cb({
                        "stage": "checking",
                        "tool": tool_name,
                        "required": required,
                        "message": f"Checking {tool_name}...",
                    })

                check_error: str | None = None
                try:
                    version = await run_tool_probe(ssh, integration, check_cmd)
                    result_entry = ToolCheckResult(
                        tool_name=tool_name,
                        required=required,
                        status="installed",
                        version=version,
                        install_method="pre_installed",
                    )
                    results.append(result_entry)
                    if progress_cb:
                        await progress_cb({
                            "stage": "tool_done",
                            "tool": tool_name,
                            "status": "installed",
                            "version": version,
                            "install_method": "pre_installed",
                            "message": f"{tool_name} OK{f' ({version})' if version else ''}",
                        })
                    continue
                except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
                    check_error = str(exc)
                    _log.info("Tier-0 check failed for %s: %s", tool_name, check_error)
                    if progress_cb:
                        await progress_cb({
                            "stage": "check_failed",
                            "tool": tool_name,
                            "message": f"{tool_name} not present -- {check_error[:300]}",
                            "error": check_error,
                            "command": check_cmd,
                        })

                if not install_missing:
                    if required:
                        all_required_ok = False
                    result_entry = ToolCheckResult(
                        tool_name=tool_name,
                        required=required,
                        status="missing",
                        message=f"Not found (install_missing=False). Error: {check_error}",
                    )
                    results.append(result_entry)
                    if progress_cb:
                        await progress_cb({
                            "stage": "tool_done",
                            "tool": tool_name,
                            "status": "missing",
                            "message": f"{tool_name} not found",
                        })
                    continue

                # --- Tier 1: online install ---
                if progress_cb:
                    await progress_cb({
                        "stage": "installing",
                        "tool": tool_name,
                        "message": f"Installing {tool_name} (online)...",
                    })

                online_ok = False
                if install_cmds:
                    online_ok = await self._try_online_install(
                        ssh, integration, tool_name, install_cmds, check_cmd,
                        progress_cb=progress_cb,
                    )

                if online_ok:
                    result_entry = ToolCheckResult(
                        tool_name=tool_name,
                        required=required,
                        status="installed",
                        message="Installed via online package manager.",
                        install_method="online",
                    )
                    results.append(result_entry)
                    if progress_cb:
                        await progress_cb({
                            "stage": "tool_done",
                            "tool": tool_name,
                            "status": "installed",
                            "install_method": "online",
                            "message": f"{tool_name} installed (online)",
                        })
                    continue

                # --- Tier 2: offline install ---
                offline_type = os_block.get("offline_type") or "(none)"
                offline_bundle = os_block.get("offline_bundle") or os_block.get("offline_package") or "(none)"
                offline_note = os_block.get("offline_note") or ""
                if progress_cb:
                    await progress_cb({
                        "stage": "installing",
                        "tool": tool_name,
                        "message": (
                            f"Installing {tool_name} offline -- type={offline_type}, "
                            f"bundle={offline_bundle}" + (f" -- {offline_note}" if offline_note else "")
                        ),
                        "offline_type": offline_type,
                        "offline_bundle": offline_bundle,
                    })

                offline_ok = await self._try_offline_install(
                    integration, tool_def, analyzer_os, progress_cb=progress_cb,
                )

                if offline_ok:
                    result_entry = ToolCheckResult(
                        tool_name=tool_name,
                        required=required,
                        status="installed",
                        message="Installed via offline bundle from platform server.",
                        install_method=f"offline_{os_block.get('offline_type', 'unknown')}",
                    )
                    results.append(result_entry)
                    if progress_cb:
                        await progress_cb({
                            "stage": "tool_done",
                            "tool": tool_name,
                            "status": "installed",
                            "install_method": f"offline_{os_block.get('offline_type', 'unknown')}",
                            "message": f"{tool_name} installed (offline)",
                        })
                    continue

                # --- Both tiers failed ---
                if required:
                    all_required_ok = False
                severity = "REQUIRED" if required else "optional"
                result_entry = ToolCheckResult(
                    tool_name=tool_name,
                    required=required,
                    status="missing",
                    message=(
                        f"[{severity.upper()}] Failed to install {tool_name}. "
                        f"Initial check: {check_error}. "
                        "Online and offline install both failed. "
                        + ("Manual installation is required -- contact your admin." if required else "System can proceed without this tool.")
                    ),
                )
                results.append(result_entry)
                if progress_cb:
                    await progress_cb({
                        "stage": "tool_done",
                        "tool": tool_name,
                        "status": "missing",
                        "required": required,
                        "message": f"{tool_name} [{severity.upper()}] MISSING -- {check_error}",
                    })

        evidence_error = await _evidence_directory_error(ssh, integration, evidence_directory, analyzer_os)
        if progress_cb:
            await progress_cb({
                "stage": "evidence_checked",
                "ok": evidence_error is None,
                "message": evidence_error or f"Evidence directory {evidence_directory} is readable.",
            })

        ready = all_required_ok and evidence_error is None
        installed_count = sum(1 for r in results if r.status == "installed")
        missing_count = sum(1 for r in results if r.status == "missing")
        message = (
            f"{installed_count} tools ready, {missing_count} missing. "
            + ("All required tools are installed." if all_required_ok else "Some required tools are missing.")
        )
        if evidence_error is not None:
            message = f"{evidence_error} {message}"

        return MachineReadinessResult(
            ready=ready,
            system_id=system_id,
            system_name=system_name,
            analyzer_os=analyzer_os,
            tools=results,
            message=message,
        )

    async def _try_online_install(
        self,
        ssh: Any,
        integration: dict[str, Any],
        tool_name: str,
        install_cmds: list[str],
        check_cmd: str,
        progress_cb: Any = None,
    ) -> bool:
        """Attempt online install via the tool's install_commands.

        Runs each install command, then re-verifies with check_cmd. Streams
        stdout/stderr through progress_cb so the UI sees exactly why an
        install fails (package not found, network error, sudo denied, etc.).
        """
        # Per-tool install wall times. bulk_extractor builds from source in WSL
        # (clone + autotools + make) which routinely runs 8-12 minutes. Zeek pulls
        # ~50 deps from the OBS repo (~5 min). binwalk via cargo compiles from
        # source (~4 min). Everything else is a fast apt/zip/pip op.
        _long_build_tools = {"bulk_extractor": 900.0, "zeek": 600.0, "binwalk": 600.0}
        timeout = _long_build_tools.get(tool_name, 180.0)

        for cmd in install_cmds:
            if progress_cb:
                await progress_cb({
                    "stage": "install_exec",
                    "tool": tool_name,
                    "command": cmd[:500],
                    "message": f"{tool_name}: running install command",
                })
            try:
                output = await ssh.run_command(integration, cmd, timeout_seconds=timeout)
                _log.info("Online install command succeeded for %s: %s", tool_name, cmd)
                if progress_cb:
                    tail = "\n".join(output.strip().splitlines()[-20:])[:2000]
                    await progress_cb({
                        "stage": "install_output",
                        "tool": tool_name,
                        "message": f"{tool_name}: install command returned 0",
                        "output_tail": tail,
                    })
            except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
                err = str(exc)
                _log.info("Online install failed for %s: %s -- %s", tool_name, cmd, err)
                if progress_cb:
                    await progress_cb({
                        "stage": "install_failed",
                        "tool": tool_name,
                        "command": cmd[:500],
                        "message": f"{tool_name}: install failed -- {err[:300]}",
                        "error": err,
                    })
                continue

            try:
                verified_version = await run_tool_probe(ssh, integration, check_cmd)
                _log.info("Online install verified for %s", tool_name)
                if progress_cb:
                    await progress_cb({
                        "stage": "install_verified",
                        "tool": tool_name,
                        "message": f"{tool_name}: verified after online install",
                        "version": verified_version,
                    })
                return True
            except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
                err = str(exc)
                _log.info("Post-online-install check failed for %s: %s", tool_name, err)
                if progress_cb:
                    await progress_cb({
                        "stage": "install_verify_failed",
                        "tool": tool_name,
                        "message": f"{tool_name}: installed but verify still fails -- {err[:300]}",
                        "error": err,
                    })

        return False

    async def _try_offline_install(
        self,
        integration: dict[str, Any],
        tool_def: dict[str, Any],
        analyzer_os: str,
        progress_cb: Any = None,
    ) -> bool:
        """Attempt offline install via OfflineInstallerService."""
        tool_name = tool_def.get("name", "?")
        try:
            from aila.modules.forensics.services.offline_installer import OfflineInstallerService

            offline_svc = OfflineInstallerService(self.settings)
            ok = await offline_svc.install_tool_offline(integration, tool_def, analyzer_os)
            if progress_cb and not ok:
                await progress_cb({
                    "stage": "offline_install_failed",
                    "tool": tool_name,
                    "message": f"{tool_name}: offline bundle install returned False (no bundle or apply failed)",
                })
            return ok
        except (OSError, TimeoutError, RuntimeError, ValueError, AILAError) as exc:
            err = str(exc)
            _log.warning(
                "Offline install failed for %s on %s: %s",
                tool_name, analyzer_os, err,
            )
            if progress_cb:
                await progress_cb({
                    "stage": "offline_install_failed",
                    "tool": tool_name,
                    "message": f"{tool_name}: offline install errored -- {err[:300]}",
                    "error": err,
                })
            return False
