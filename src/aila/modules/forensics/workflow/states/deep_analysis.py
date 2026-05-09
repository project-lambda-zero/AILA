"""Deep analysis state handler — heavy extraction pass.

Runs AFTER basic collection and BEFORE lead promotion. Targets suspicious
files identified during collection with expensive tools: SHA-256 hashing,
strings IOC extraction, FLOSS deobfuscation, capa ATT&CK mapping, and
Ghidra headless function listing (on PE/ELF binaries where Ghidra is
available on the analyzer machine).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from aila.platform.exceptions import AILAError

__all__ = ["state_deep_analysis"]

_log = logging.getLogger(__name__)

state_deep_analysis_parallel_safe = False
state_deep_analysis_writes_fields = ["deep_artifacts"]

_SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".drv", ".scr", ".cpl", ".ocx",
    ".elf", ".ko", ".so",
    ".sh", ".bash", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
    ".msi", ".jar", ".war", ".class",
})

_MAX_BINARY_SIZE = 100 * 1024 * 1024  # 100 MB upper limit for tool runs


async def state_deep_analysis(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Run expensive extractors on suspicious files and evidence.

    This state reads artifacts already collected and evidence files, then:
    1. Hashes every suspicious file (SHA-256).
    2. Runs ``strings`` / ``FLOSS`` on binaries to extract IOCs.
    3. Runs ``capa`` on executables to map ATT&CK capabilities.
    4. Parses extracted strings for IPs, URLs, domains, API names.
    5. Persists rich artifacts the promotion and freeflow stages consume.
    """
    project_id = input.get("project_id", "")
    evidence_files = input.get("evidence_files", [])
    integration = input.get("integration", services.integration)
    analyzer_os = input.get("analyzer_os", "linux")

    await services.emitter.emit(
        "deep_analysis", "Starting deep analysis — hashing, strings, capa on suspicious files..."
    )

    from aila.modules.forensics.tools._ssh_helper import get_ssh_service

    ssh = await get_ssh_service(services.settings)
    err_sink = "2>NUL" if analyzer_os == "windows" else "2>/dev/null"

    targets = _select_analysis_targets(evidence_files)
    _log.info("Deep analysis: %d targets selected out of %d files", len(targets), len(evidence_files))

    from aila.modules.forensics.db_models import ArtifactRecord
    from aila.platform.uow import UnitOfWork

    artifact_count = 0
    artifacts_by_family: dict[str, int] = {}

    async with UnitOfWork() as uow:
        for target in targets:
            path = target["file_path"]
            try:
                file_artifacts = await _analyze_single_file(
                    ssh, integration, path, analyzer_os, err_sink,
                )
                for art in file_artifacts:
                    record = ArtifactRecord(
                        project_id=project_id,
                        artifact_family=art["family"],
                        artifact_type=art["type"],
                        source_tool=art["source_tool"],
                        source_evidence_id=target.get("id"),
                        data_json=json.dumps(art["data"]),
                    )
                    uow.session.add(record)
                    artifact_count += 1
                    family = art["family"]
                    artifacts_by_family[family] = artifacts_by_family.get(family, 0) + 1
            except (OSError, TimeoutError, RuntimeError, AILAError):
                _log.warning("Deep analysis failed for %s", path, exc_info=True)

        await uow.commit()

    await services.emitter.emit(
        "deep_analysis",
        f"Deep analysis complete — {artifact_count} artifacts extracted from {len(targets)} files.",
        {"artifact_count": artifact_count, "by_family": artifacts_by_family},
    )

    from aila.platform.workflows.types import StateResult

    return StateResult(
        next_state="promotion",
        output={
            "deep_artifact_count": artifact_count,
            "deep_artifacts_by_family": artifacts_by_family,
            "project_id": project_id,
            "integration": integration,
            "evidence_directory": input.get("evidence_directory", ""),
            "analyzer_os": analyzer_os,
        },
    )


def _select_analysis_targets(evidence_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pick files worth running expensive tools on.

    Deep-analysis tools (certutil, strings, FLOSS, capa, Ghidra) are designed
    for single executable samples on the MB scale. Running them on a 64 GB
    raw disk image takes tens of minutes (certutil) to forever (Ghidra),
    and most don't understand disk-image formats at all.  We restrict deep
    analysis to actual executable files + small suspicious samples. Disk
    images, memory dumps and pcaps are handled by their respective lane
    collectors (dissect/volatility/tshark) and never enter this stage.
    """
    targets: list[dict[str, Any]] = []
    for f in evidence_files:
        name = f.get("file_name", "").lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        size = f.get("size_bytes", 0) or 0

        if ext in _SUSPICIOUS_EXTENSIONS and size <= _MAX_BINARY_SIZE:
            targets.append(f)
        # Intentionally NOT adding disk_image / memory_dump / pcap —
        # those are handled by collection-stage collectors, and running
        # binary-analysis tools on them hangs the workflow.
    return targets


_GHIDRA_BINARY_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".drv", ".scr", ".cpl", ".ocx",
    ".elf", ".ko", ".so",
})


async def _analyze_single_file(
    ssh: Any,
    integration: dict[str, Any],
    path: str,
    analyzer_os: str,
    err_sink: str,
) -> list[dict[str, Any]]:
    """Run all deep-analysis tools on a single file."""
    artifacts: list[dict[str, Any]] = []

    sha256 = await _compute_hash(ssh, integration, path, analyzer_os)
    if sha256:
        artifacts.append({
            "family": "filesystem",
            "type": "sha256_hash",
            "source_tool": "sha256sum",
            "data": {"hash": sha256, "file_path": path},
        })

    strings_iocs = await _extract_strings_iocs(ssh, integration, path, analyzer_os, err_sink)
    if strings_iocs:
        artifacts.append({
            "family": "malware",
            "type": "strings_iocs",
            "source_tool": "strings",
            "data": {**strings_iocs, "file_path": path},
        })

    floss_output = await _run_floss(ssh, integration, path, analyzer_os, err_sink)
    if floss_output:
        artifacts.append({
            "family": "malware",
            "type": "floss_decoded_strings",
            "source_tool": "floss",
            "data": {"raw_output": floss_output[:6000], "file_path": path},
        })

    capa_output = await _run_capa(ssh, integration, path, analyzer_os, err_sink)
    if capa_output:
        artifacts.append({
            "family": "malware",
            "type": "capa_capabilities",
            "source_tool": "capa",
            "data": {"raw_output": capa_output[:6000], "file_path": path},
        })

    ext = ("." + path.rsplit(".", 1)[-1]).lower() if "." in path else ""
    if ext in _GHIDRA_BINARY_EXTENSIONS:
        ghidra_funcs = await _run_ghidra_list_functions(ssh, integration, path, analyzer_os)
        if ghidra_funcs:
            artifacts.append({
                "family": "malware",
                "type": "ghidra_functions",
                "source_tool": "ghidra",
                "data": {"raw_output": ghidra_funcs[:8000], "file_path": path},
            })

    return artifacts


async def _compute_hash(ssh: Any, integration: dict, path: str, analyzer_os: str) -> str | None:
    """Compute SHA-256 of the file on the analyzer machine."""
    from aila.modules.forensics.tools._ssh_helper import hash_cmd as build_hash_cmd

    try:
        output = await ssh.run_command(
            integration, build_hash_cmd(path, analyzer_os), timeout_seconds=60.0,
        )
        for line in output.strip().splitlines():
            candidate = line.strip().split()[0] if line.strip() else ""
            if re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
                return candidate.lower()
    except (OSError, TimeoutError, RuntimeError, AILAError):
        _log.debug("hash failed for %s", path, exc_info=True)
    return None


async def _extract_strings_iocs(
    ssh: Any, integration: dict, path: str, analyzer_os: str, err_sink: str,
) -> dict[str, Any] | None:
    """Run strings and extract IPs, URLs, domains, APIs, and file paths."""
    strings_bin = "strings.exe" if analyzer_os == "windows" else "strings"
    try:
        output = await ssh.run_command(
            integration,
            f'{strings_bin} "{path}" {err_sink}',
            timeout_seconds=120.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError):
        _log.debug("strings failed for %s", path, exc_info=True)
        return None

    if not output.strip():
        return None

    ips = sorted(set(re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        output,
    )))
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]{4,200}", output)))
    domains = sorted(set(re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|tk|cc|info|biz|top)\b",
        output, re.IGNORECASE,
    )))
    win_apis = sorted(set(re.findall(
        r"\b(?:Nt|Zw|Rtl)?(?:CreateFile|WriteFile|ReadFile|VirtualAlloc|VirtualProtect"
        r"|CreateProcess|CreateRemoteThread|WriteProcessMemory|QueueUserAPC"
        r"|NtQueueApcThread|SetThreadContext|ResumeThread|SuspendThread"
        r"|LoadLibrary|GetProcAddress|InternetOpen|HttpOpenRequest"
        r"|WSAStartup|connect|send|recv|socket|WinHttpOpen"
        r"|AmsiScanBuffer|EtwEventWrite|NtUnmapViewOfSection)[AW]?\b",
        output,
    )))
    file_paths = sorted(set(re.findall(
        r"(?:[A-Z]:\\[^\s\"']{4,200})|(?:/(?:usr|etc|var|tmp|home|opt|bin|sbin)/[^\s\"']{2,200})",
        output,
    )))[:30]

    if not any([ips, urls, domains, win_apis, file_paths]):
        return None

    return {
        "ips": ips[:50],
        "urls": urls[:30],
        "domains": domains[:30],
        "win_apis": win_apis[:40],
        "file_paths": file_paths,
        "total_strings": len(output.splitlines()),
    }


async def _run_floss(
    ssh: Any, integration: dict, path: str, _analyzer_os: str, err_sink: str,
) -> str | None:
    """Run FLOSS for obfuscated string recovery."""
    try:
        output = await ssh.run_command(
            integration,
            f'floss "{path}" {err_sink}',
            timeout_seconds=300.0,
        )
        return output.strip() if output.strip() else None
    except (OSError, TimeoutError, RuntimeError, AILAError):
        _log.debug("floss failed for %s", path, exc_info=True)
        return None


async def _run_capa(
    ssh: Any, integration: dict, path: str, _analyzer_os: str, err_sink: str,
) -> str | None:
    """Run capa for ATT&CK capability mapping."""
    try:
        output = await ssh.run_command(
            integration,
            f'capa "{path}" {err_sink}',
            timeout_seconds=300.0,
        )
        return output.strip() if output.strip() else None
    except (OSError, TimeoutError, RuntimeError, AILAError):
        _log.debug("capa failed for %s", path, exc_info=True)
        return None


async def _run_ghidra_list_functions(
    ssh: Any, integration: dict, path: str, analyzer_os: str,
) -> str | None:
    """Run Ghidra headless to list functions in a binary.

    Attempts to run ``analyzeHeadless`` with a ListFunctions script. If
    Ghidra is not installed or the script is missing, this gracefully
    returns None — the analysis continues with other tools.
    """
    from aila.modules.forensics.tools._ssh_helper import temp_dir

    headless = "analyzeHeadless.bat" if analyzer_os == "windows" else "analyzeHeadless"
    project_dir = f"{temp_dir(analyzer_os)}\\ghidra_projects" if analyzer_os == "windows" else "/tmp/ghidra_projects"
    script_dir = temp_dir(analyzer_os)

    mkdir_cmd = (
        f'if not exist "{project_dir}" mkdir "{project_dir}"'
        if analyzer_os == "windows"
        else f"mkdir -p {project_dir}"
    )
    analyze_cmd = (
        f"{headless} {project_dir} aila_deep_analysis "
        f"-import \"{path}\" -overwrite "
        f"-scriptPath {script_dir} -postScript ListFunctions.java "
        f"-noanalysis"
    )

    try:
        await ssh.run_command(integration, mkdir_cmd, timeout_seconds=10.0)
        output = await ssh.run_command(integration, analyze_cmd, timeout_seconds=900.0)
        if output.strip():
            return output.strip()
    except (OSError, TimeoutError, RuntimeError, AILAError):
        _log.debug("Ghidra function listing failed for %s (may not be installed)", path, exc_info=True)
    return None


state_deep_analysis.parallel_safe = state_deep_analysis_parallel_safe  # type: ignore[attr-defined]
state_deep_analysis.writes_fields = state_deep_analysis_writes_fields  # type: ignore[attr-defined]
