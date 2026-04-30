"""Evidence directory scanner and classifier.

Supports both Linux and Windows analyzer machines with OS-appropriate
directory listing commands.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from aila.config import Settings
from aila.platform.exceptions import AILAError

_log = logging.getLogger(__name__)

__all__ = ["classify_evidence_directory"]

# Patterns are evaluated in definition order — more specific patterns
# must come first. Previously ``\.raw$ -> disk_image`` shadowed every
# memory image named ``*.raw`` (DumpIt / FTK Imager / winpmem output),
# so the memory lane never activated on Windows analyzer workflows.
_EVIDENCE_PATTERNS: dict[str, str] = {
    # memory dumps — must be listed BEFORE the generic ``\.raw$`` disk
    # pattern so memory names win. Covers common Windows/Linux tools:
    # winpmem / DumpIt / FTK Imager / Belkasoft / MagnetRAM / AVML / LiME.
    r"\.mem$": "memory_dump",
    r"\.dmp$": "memory_dump",
    r"\.lime$": "memory_dump",
    r"\.core$": "memory_dump",
    r"\.vmem$": "memory_dump",
    r"\.vmss$": "memory_dump",
    r"\.vmsn$": "memory_dump",
    r"\.avml$": "memory_dump",
    r"\.crash$": "memory_dump",
    r"\.raw\.gz$": "memory_dump",
    # Name-shape matches — anything whose basename looks like a memory
    # image wins over the generic ``.raw`` disk fallback.
    r"memory[^/\\]*\\.raw$": "memory_dump",
    r"memory[^/\\]*\.raw\.gz$": "memory_dump",
    r"memdump[^/\\]*\.raw$": "memory_dump",
    r"physmem[^/\\]*\.raw$": "memory_dump",
    r"ram[^/\\]*\.raw$": "memory_dump",
    r"ram[^/\\]*\.raw\.gz$": "memory_dump",
    r"dumpit[^/\\]*\.raw$": "memory_dump",
    r"winpmem[^/\\]*\.raw$": "memory_dump",
    r"winpmem[^/\\]*\.raw\.gz$": "memory_dump",
    # disk images
    r"\.e01$": "disk_image",
    r"\.raw$": "disk_image",
    r"\.raw\.\d+$": "disk_image",
    r"\.dd$": "disk_image",
    r"\.vmdk$": "disk_image",
    r"\.qcow2?$": "disk_image",
    r"\.vhd$": "disk_image",
    r"\.vhdx$": "disk_image",
    r"\.dmg$": "disk_image",
    r"\.sparseimage$": "disk_image",
    r"\.sparsebundle$": "disk_image",
    r"\.aff4?$": "disk_image",
    # network captures
    r"\.pcap$": "pcap",
    r"\.pcapng$": "pcap",
    r"\.cap$": "pcap",
    # logs
    r"\.evtx$": "log_file",
    r"\.log$": "log_file",
    r"\.journal$": "log_file",
    r"\.tracev3$": "log_file",
    # mobile
    r"\.apk$": "apk",
    r"\.ipa$": "mobile_app",
    r"\.tar\.gz$": "archive",
    r"\.zip$": "archive",
}

# Extensions that are plain text in practice and worth surfacing as
# ``text_file`` on a raw_directory project so the investigator knows it
# can just ``cat`` / ``Get-Content`` them. Matched after the primary
# evidence patterns so a ``.log`` still wins as ``log_file``.
_TEXT_FILE_PATTERNS: tuple[str, ...] = (
    r"\.txt$",
    r"\.md$",
    r"\.json$",
    r"\.csv$",
    r"\.tsv$",
    r"\.xml$",
    r"\.yaml$",
    r"\.yml$",
    r"\.toml$",
    r"\.conf$",
    r"\.cfg$",
    r"\.ini$",
    r"\.env$",
    r"\.sh$",
    r"\.bash$",
    r"\.ps1$",
    r"\.bat$",
    r"\.cmd$",
)


def _classify_file(filename: str, project_kind: str = "disk_evidence") -> str:
    """Classify a single file by its extension or name pattern.

    For ``project_kind == "raw_directory"`` the classifier is less strict
    about unknowns: text-ish extensions become ``text_file`` and anything
    else becomes ``raw_file`` so the investigator always sees it in its
    artefact snapshot.
    """
    lower = filename.lower()
    for pattern, evidence_type in _EVIDENCE_PATTERNS.items():
        if re.search(pattern, lower):
            return evidence_type
    if project_kind == "raw_directory":
        for pattern in _TEXT_FILE_PATTERNS:
            if re.search(pattern, lower):
                return "text_file"
        return "raw_file"
    return "unknown"


async def classify_evidence_directory(
    settings: Settings,
    integration: dict[str, Any],
    evidence_directory: str,
    analyzer_os: str = "linux",
    emitter: Any = None,
    project_kind: str = "disk_evidence",
) -> dict:
    """Scan evidence directory on analyzer machine and classify files.

    Args:
        settings: Application settings for SSH service construction.
        integration: SSH connection fields.
        evidence_directory: Absolute path on the analyzer machine.
        analyzer_os: Target OS — ``"linux"`` or ``"windows"``.
        emitter: Optional progress emitter for xray visibility.
        project_kind: ``"disk_evidence"`` (default) or ``"raw_directory"``.
            Raw-directory scans tag unknown files as ``raw_file`` / text
            extensions as ``text_file`` and skip the split-disk image
            collapse step.

    Returns:
        Dict with 'files' list, each containing path, type, and size.
    """
    from aila.modules.forensics.tools._ssh_helper import get_ssh_service

    async def _xray(stage_tag: str, msg: str, meta: dict[str, Any] | None = None) -> None:
        if emitter is not None:
            try:
                await emitter.emit("intake", msg, {"xray_stage": stage_tag, **(meta or {})})
            except (OSError, RuntimeError, TimeoutError) as exc:
                _log.debug("emitter failure (non-fatal): %s", exc)

    await _xray("ssh_connect", "xray: opening SSH service to analyzer")
    ssh = await get_ssh_service(settings)
    await _xray("ssh_ready", "xray: SSH service ready")

    if analyzer_os == "windows":
        cmd = (
            f'powershell -NoProfile -Command "'
            f"Get-ChildItem -Recurse -File -Path '{evidence_directory}' "
            f"| ForEach-Object {{ $_.Length.ToString() + ' ' + $_.FullName }}"
            f'"'
        )
        await _xray("ls_issued", f"xray: issuing Get-ChildItem -Recurse on {evidence_directory} (60s timeout)")
    else:
        cmd = (
            f"find {evidence_directory} -type f -printf '%s %p\\n' 2>/dev/null || "
            f"ls -lR {evidence_directory}"
        )
        await _xray("ls_issued", f"xray: issuing find on {evidence_directory} (60s timeout)")

    ls_output = await ssh.run_command(integration, cmd, timeout_seconds=60.0)
    await _xray(
        "ls_returned",
        f"xray: directory listing returned — {len(ls_output)} bytes, {len(ls_output.splitlines())} lines",
        {"bytes": len(ls_output), "lines": len(ls_output.splitlines())},
    )

    await _xray("parse_start", "xray: parsing directory listing")
    files: list[dict[str, Any]] = []
    current_dir = ""
    for line in ls_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[0].isdigit():
            size_bytes = int(parts[0])
            file_path = parts[1]
        elif line.endswith(":") and not line.startswith("-"):
            current_dir = line.rstrip(":")
            continue
        elif line.startswith("total "):
            continue
        elif line.startswith("-") or line.startswith("l"):
            ls_parts = line.split()
            if len(ls_parts) >= 9:
                try:
                    size_bytes = int(ls_parts[4])
                except (ValueError, IndexError):
                    size_bytes = 0
                filename_part = " ".join(ls_parts[8:])
                sep = "\\" if analyzer_os == "windows" else "/"
                file_path = f"{current_dir}{sep}{filename_part}" if current_dir else filename_part
            else:
                continue
        else:
            file_path = line
            size_bytes = 0

        sep = "\\" if analyzer_os == "windows" else "/"
        filename = file_path.rsplit(sep, 1)[-1] if sep in file_path else file_path
        files.append({
            "file_path": file_path,
            "evidence_type": _classify_file(filename, project_kind=project_kind),
            "size_bytes": size_bytes,
            "file_name": filename,
        })

    if project_kind == "raw_directory":
        # Raw-directory projects treat every file as itself — no split-disk
        # collapsing, no disk-image semantics. Skip straight to return.
        _log.info(
            "intake (raw_directory): classified %d file(s); skipping split-disk collapse",
            len(files),
        )
        return {"files": files, "total": len(files)}

    # Collapse split disk images to their head piece. A split raw (.raw.001,
    # .raw.002, ...) or E01 (.E01, .E02, ...) is ONE logical disk — dissect
    # auto-loads the remaining parts from the .001/.E01 head. Running every
    # split member as a standalone evidence item would multiply every dissect
    # query by the number of parts (e.g. 7×20=140 queries for a 7-part disk)
    # and all parts ≥ .002 would fail because they aren't valid images on
    # their own. We keep the head and tag the others as split members so the
    # UI still shows they exist but downstream collectors skip them.
    _files_by_path: dict[str, dict[str, Any]] = {f["file_path"]: f for f in files}
    split_head_re = re.compile(r"(?i)^(.+?)\.(raw\.001|e01)$")
    split_part_re = re.compile(r"(?i)^(.+?)\.(raw\.0*[2-9]\d*|raw\.0*[1-9]\d{1,}|e0*[2-9]|e[1-9]\d+)$")
    heads: set[str] = set()
    for f in files:
        m = split_head_re.match(f["file_name"])
        if m:
            heads.add(m.group(1).lower())
    for f in files:
        if f.get("evidence_type") != "disk_image":
            continue
        m = split_part_re.match(f["file_name"])
        if m and m.group(1).lower() in heads:
            f["evidence_type"] = "disk_image_split_member"
            f["file_name_original"] = f["file_name"]
    removed_parts = [f for f in files if f["evidence_type"] == "disk_image_split_member"]
    files = [f for f in files if f["evidence_type"] != "disk_image_split_member"]
    if removed_parts:
        _log.info(
            "intake: collapsed %d split-disk member(s) under their .001/.E01 head "
            "— dissect auto-loads the parts", len(removed_parts),
        )
        await _xray(
            "split_collapsed",
            f"xray: collapsed {len(removed_parts)} split disk member(s) under their heads",
            {"removed": [f["file_name_original"] for f in removed_parts], "head_count": len(heads)},
        )

    # Hashing is deferred: huge E01/mem images take 5-15 min each via certutil/sha256sum,
    # which blocks intake for hours on realistic evidence sets. Downstream tools (collection,
    # freeflow agent) hash files on-demand when they actually open them. If callers need the
    # hash earlier, they can call _compute_file_hash() directly on a specific file_path.
    _log.info("intake: deferring SHA-256 hashing for %d file(s); hash on-demand downstream", len(files))

    return {"files": files, "total": len(files)}


async def _compute_file_hash(
    ssh: Any,
    integration: dict[str, Any],
    file_path: str,
    analyzer_os: str,
) -> str | None:
    """Compute SHA-256 hash of a file on the analyzer machine."""
    import re as _re

    from aila.modules.forensics.tools._ssh_helper import hash_cmd

    try:
        output = await ssh.run_command(
            integration, hash_cmd(file_path, analyzer_os), timeout_seconds=60.0,
        )
        for line in output.strip().splitlines():
            candidate = line.strip().split()[0] if line.strip() else ""
            if _re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
                return candidate.lower()
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("hash computation failed for %s: %s", file_path, exc, exc_info=True)
    return None