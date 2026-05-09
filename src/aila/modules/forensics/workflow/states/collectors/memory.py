"""Memory-dump collector — profile detection + Volatility 3 plugin sweep.

Three tiers of pre-analysis, all computed ``-r json`` so every plugin
result is a typed row array the UI can filter, sort, and the timeline
miner can walk for real event times:

  Tier 1: structured plugin output + extra high-signal plugins
          (psscan/psxview/ldrmodules/getsids/privileges/...) + derived
          cross-plugin artifacts (process tree, injection heatmap,
          network-by-process, handle anomalies, rootkit ghosts, registry
          exec history). See ``memory_enrich.py``.

  Tier 2: region dumping (malfind --dump → base64 readback → memory
          region artifact) and a memory-string IOC triage pass using a
          curated wordlist.

  Tier 3: credential-extraction plugins (hashdump, cachedump, lsadump,
          skeleton_key_check) that only run when an analyst directive
          explicitly authorises it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time as _time
from pathlib import Path
from typing import Any

from aila.platform.exceptions import AILAError

from ._helpers import err_sink, safe_emit, sq, truncate, vol_cmd
from .memory_enrich import derive_all

__all__ = ["collect_memory_artifacts"]

_log = logging.getLogger(__name__)

# --- plugin sets --------------------------------------------------------------
# (plugin_name, family) — ``family`` is what ends up on the persisted
# artifact row; the UI groups by it.

_WINDOWS_MEMORY_PLUGINS: list[tuple[str, str]] = [
    # --- process discovery: four independent enumerators, compared in
    # memory_enrich to surface hidden/unlinked/orphan processes. psxview
    # is the cheap cross-view, psscan walks pool tags (catches dead/
    # terminated/hidden), thrdscan covers orphan threads, sessions links
    # back to logon IDs for attribution.
    ("windows.pslist",                    "memory"),
    ("windows.pstree",                    "memory"),
    ("windows.psscan",                    "memory"),
    ("windows.psxview",                   "memory"),
    ("windows.thrdscan",                  "memory"),
    ("windows.sessions",                  "execution"),
    # --- execution identity & environment
    ("windows.cmdline",                   "execution"),
    ("windows.getsids",                   "execution"),
    ("windows.privileges",                "execution"),
    ("windows.envars",                    "execution"),
    ("windows.getservicesids",            "execution"),
    # --- loaded code & injection surface (ldrmodules + malfind are the
    # core injection-detection pair; dlllist gives reference, vadinfo +
    # vadwalk expose suspicious RWX regions, hollowfind / injector
    # catch classic PE hollowing.)
    ("windows.dlllist",                   "execution"),
    ("windows.ldrmodules",                "malware"),
    ("windows.malfind",                   "malware"),
    ("windows.vadinfo",                   "memory"),
    ("windows.vadwalk",                   "memory"),
    ("windows.modules",                   "execution"),
    ("windows.modscan",                   "malware"),
    ("windows.driverscan",                "malware"),
    ("windows.driverirp",                 "malware"),
    ("windows.drivermodule",              "malware"),
    ("windows.devicetree",                "malware"),
    # --- rootkit & hooking surface
    ("windows.ssdt",                      "malware"),
    ("windows.callbacks",                 "malware"),
    ("windows.mutantscan",                "malware"),
    ("windows.poolscanner",               "malware"),
    ("windows.unloadedmodules",           "malware"),
    # --- handles, kernel objects, synchronization primitives
    ("windows.handles",                   "execution"),
    ("windows.getservices",               "execution"),
    ("windows.svcscan",                   "execution"),
    ("windows.svcdiff",                   "execution"),
    # --- network state
    ("windows.netscan",                   "network"),
    ("windows.netstat",                   "network"),
    # --- filesystem view (timestamps, cached paths, open files)
    ("windows.filescan",                  "filesystem"),
    ("windows.mftscan.MFTScan",           "filesystem"),
    ("windows.mbrscan",                   "filesystem"),
    # --- registry: execution-history sources first, then configuration
    ("windows.registry.hivelist",         "filesystem"),
    ("windows.registry.userassist",       "execution"),
    ("windows.registry.amcache",          "execution"),
    ("windows.registry.shellbags",        "filesystem"),
    ("windows.registry.hivescan",         "filesystem"),
    ("windows.registry.certificates",     "credentials"),
    ("windows.registry.printkey",         "filesystem"),
    ("windows.shimcachemem",              "execution"),
    # --- scheduled tasks, startup, persistence
    ("windows.scheduled_tasks",           "execution"),
    # --- GUI / desktop state (useful for interactive-session forensics)
    ("windows.desktops",                  "execution"),
    # --- suspicious-region detection and crypto material scans
    ("windows.vadregexscan",              "malware"),
    ("windows.crashinfo",                 "memory"),
    ("windows.pe_symbols",                "execution"),
    ("windows.truecrypt.Passphrase",      "credentials"),
    # --- virtualization & AMCache-backed execution history
    ("windows.virtmap",                   "memory"),
    # --- kernel info (cheap, re-run post-warmup for artifact row)
    ("windows.info",                      "memory"),
]
_LINUX_MEMORY_PLUGINS: list[tuple[str, str]] = [
    ("linux.pslist",       "memory"),
    ("linux.pstree",       "memory"),
    ("linux.psaux",        "execution"),
    ("linux.pidhashtable", "memory"),
    ("linux.sockstat",     "network"),
    ("linux.bash",         "execution"),
    ("linux.check_syscall","malware"),
    ("linux.elfs",         "malware"),
    ("linux.proc.maps",    "memory"),
    ("linux.lsmod",        "execution"),
    ("linux.tty_check",    "execution"),
    ("linux.check_idt",    "malware"),
]
_MACOS_MEMORY_PLUGINS: list[tuple[str, str]] = [
    ("mac.pslist",          "memory"),
    ("mac.pstree",          "memory"),
    ("mac.netstat",         "network"),
    ("mac.bash",            "execution"),
    ("mac.lsof",            "execution"),
    ("mac.malfind",         "malware"),
    ("mac.kauth_listeners", "malware"),
    ("mac.socket_filters",  "malware"),
    ("mac.mount",           "filesystem"),
    ("mac.ifconfig",        "network"),
    ("mac.check_sysctl",    "malware"),
    ("mac.proc_maps",       "memory"),
]
_PLUGINS_BY_OS: dict[str, list[tuple[str, str]]] = {
    "windows": _WINDOWS_MEMORY_PLUGINS,
    "linux":   _LINUX_MEMORY_PLUGINS,
    "macos":   _MACOS_MEMORY_PLUGINS,
}

# Tier 3 — credential extraction. Only runs when an active directive on
# the project explicitly authorises it (see ``_credential_directive_allows``).
_WINDOWS_CREDENTIAL_PLUGINS: list[tuple[str, str]] = [
    ("windows.hashdump",            "credentials"),
    ("windows.cachedump",           "credentials"),
    ("windows.lsadump",             "credentials"),
    ("windows.skeleton_key_check",  "credentials"),
]

_CREDENTIAL_DIRECTIVE_KEYWORDS = re.compile(
    r"\b(credentials?|hash(?:es|dump)?|password|mimikatz|lsass|lsa[- ]?secrets?|"
    r"cached[- ]?creds|kerberos|ntlm|skeleton[- ]?key)\b",
    re.I,
)

# Plugins that support ``--dump`` to write binary regions to disk. We
# re-invoke them with a dump directory and then read the resulting
# files back for the binary_analysis lane.
_DUMP_PLUGINS: dict[str, tuple[str, str]] = {
    "windows": ("windows.malfind", "malfind"),
}

# Per-run limits so a pathological dump can't flood the artifact store.
_MAX_DUMPED_REGIONS = 40
_MAX_REGION_BYTES = 8 * 1024 * 1024  # 8 MB per region
_MAX_IOC_HITS = 500


# --- profile detection --------------------------------------------------------
# unchanged from prior tuning — the verifier + analyzer_os bias stays

async def _tier1_banners(
    ssh: Any, integration: dict, path: str, analyzer_os: str, esink: str,
) -> str | None:
    # ``esink`` intentionally unused: we leave stderr on the channel so
    # ``run_command`` surfaces the real Volatility traceback in the raised
    # ``UpstreamError`` on failure. Silencing stderr here turned every
    # failure into a bare ``exit code 1:`` with no cause.
    del esink
    try:
        output = await ssh.run_command(
            integration,
            f'{vol_cmd(analyzer_os)} -f {sq(path, analyzer_os)} banners.Banners',
            timeout_seconds=120.0,
        )
        lower = output.lower()
        if "darwin" in lower or "xnu" in lower or "mac os" in lower:
            return "macos"
        if "linux" in lower:
            return "linux"
        if "windows" in lower or "ntkrnl" in lower:
            return "windows"
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.info("tier1 banners failed for %s: %s", path, exc)
    return None


async def _tier2_strings(ssh: Any, integration: dict, path: str, analyzer_os: str, esink: str) -> str | None:
    """strings grep for kernel signatures — catches compressed dumps (AVML/LiME).

    Windows: cap the scan to the first 200 MB so a 4 GB+ dump doesn't
    hang for tens of minutes. Kernel banners live in early-allocated
    kernel memory, so 200 MB is plenty.
    """
    qpath = sq(path, analyzer_os)
    if analyzer_os == "windows":
        win_path = path.replace("\\", "\\\\")
        cmd = (
            f'powershell -NoProfile -Command "'
            f'$fs=[System.IO.File]::OpenRead(\'{win_path}\'); '
            f'$buf=New-Object byte[] (200*1024*1024); '
            f'$n=$fs.Read($buf,0,$buf.Length); $fs.Close(); '
            f'$txt=[System.Text.Encoding]::ASCII.GetString($buf,0,$n); '
            f'[regex]::Matches($txt,\'Linux version [0-9][^\\x00]{{0,80}}|'
            f'ntkrnlmp\\.exe|ntoskrnl\\.exe|Darwin Kernel Version[^\\x00]{{0,80}}\') | '
            f'Select-Object -First 50 | ForEach-Object {{ $_.Value }}"'
        )
    else:
        cmd = (
            f"dd if={qpath} bs=1M count=200 {esink} | strings -n 10 | "
            f"grep -E '(Linux version [0-9]|ntkrnlmp\\.exe|ntoskrnl\\.exe|"
            f"Darwin Kernel Version)' | head -50"
        )
    try:
        output = await ssh.run_command(integration, cmd, timeout_seconds=180.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("tier2 strings failed for %s: %s", path, exc, exc_info=True)
        return None
    lower = output.lower()
    votes = {
        "windows": lower.count("ntkrnlmp.exe") + lower.count("ntoskrnl.exe"),
        "linux":   lower.count("linux version "),
        "macos":   lower.count("darwin kernel version"),
    }
    top, count = max(votes.items(), key=lambda kv: kv[1])
    if count >= 2:
        return top
    return None


async def _tier3_windows_info(
    ssh: Any, integration: dict, path: str, analyzer_os: str, esink: str,
) -> str | None:
    del esink
    try:
        output = await ssh.run_command(
            integration,
            f'{vol_cmd(analyzer_os)} -f {sq(path, analyzer_os)} windows.info',
            timeout_seconds=60.0,
        )
        if output.strip() and "unsatisfied" not in output.lower():
            return "windows"
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.info("tier3 windows.info failed for %s: %s", path, exc)
    return None


async def _tier4_mac_probe(
    ssh: Any, integration: dict, path: str, analyzer_os: str, esink: str,
) -> str | None:
    del esink
    try:
        output = await ssh.run_command(
            integration,
            f'{vol_cmd(analyzer_os)} -f {sq(path, analyzer_os)} mac.pslist',
            timeout_seconds=90.0,
        )
        if output.strip() and "unsatisfied" not in output.lower() and "PID" in output:
            return "macos"
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.info("tier4 mac.pslist probe failed for %s: %s", path, exc)
    return None


async def _tier5_linux_probe(
    ssh: Any, integration: dict, path: str, analyzer_os: str, esink: str,
) -> str | None:
    del esink
    try:
        output = await ssh.run_command(
            integration,
            f'{vol_cmd(analyzer_os)} -f {sq(path, analyzer_os)} linux.pslist',
            timeout_seconds=90.0,
        )
        if output.strip() and "unsatisfied" not in output.lower() and "PID" in output:
            return "linux"
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.info("tier5 linux.pslist probe failed for %s: %s", path, exc)
    return None


async def _verify_profile(
    ssh: Any, integration: dict, path: str, profile: str,
    analyzer_os: str, esink: str,
) -> bool:
    """Confirm vol actually accepts ``profile`` for this dump."""
    del esink
    probe_map = {
        "windows": "windows.info",
        "linux":   "linux.pslist",
        "macos":   "mac.pslist",
    }
    probe = probe_map.get(profile)
    if not probe:
        return False
    try:
        out = await ssh.run_command(
            integration,
            f'{vol_cmd(analyzer_os)} -f {sq(path, analyzer_os)} {probe}',
            timeout_seconds=120.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.info("verify %s (%s) failed for %s: %s", profile, probe, path, exc)
        return False
    stripped = out.strip()
    if not stripped:
        return False
    low = stripped.lower()
    for bad in ("unsatisfied", "symbols not found", "no valid operating",
                "could not locate", "no suitable", "error"):
        if bad in low and (bad != "error" or "volatility" in low or "traceback" in low):
            return False
    return True


async def _detect_memory_profile(
    ssh: Any, integration: dict, path: str, analyzer_os: str, emitter: Any,
) -> str:
    """Cascade with verification gate + analyzer_os bias."""
    esink = err_sink(analyzer_os)
    tiers: list[tuple[str, Any]] = [
        ("tier1_banners",       lambda: _tier1_banners(ssh, integration, path, analyzer_os, esink)),
        ("tier2_strings",       lambda: _tier2_strings(ssh, integration, path, analyzer_os, esink)),
        ("tier3_windows_info",  lambda: _tier3_windows_info(ssh, integration, path, analyzer_os, esink)),
        ("tier4_mac_probe",     lambda: _tier4_mac_probe(ssh, integration, path, analyzer_os, esink)),
        ("tier5_linux_probe",   lambda: _tier5_linux_probe(ssh, integration, path, analyzer_os, esink)),
    ]

    hints: dict[str, str] = {}
    for tier_name, tier_fn in tiers:
        await safe_emit(
            emitter, f"memory_{tier_name}_begin",
            f"memory: trying {tier_name} on {path}",
            {"path": path, "tier": tier_name},
        )
        detected = await tier_fn()
        if detected and detected not in hints:
            hints[detected] = tier_name

    if not hints:
        _log.warning("All memory profile probes failed for %s — defaulting to %s", path, analyzer_os)
        await safe_emit(
            emitter, "memory_profile_default",
            f"memory: no probe matched for {path}, defaulting to {analyzer_os}",
            {"path": path, "detected_os": analyzer_os},
        )
        return analyzer_os if analyzer_os in ("windows", "linux", "macos") else "linux"

    ordered: list[str] = []
    if analyzer_os in hints:
        ordered.append(analyzer_os)
    ordered.extend(k for k in ("windows", "linux", "macos") if k in hints and k not in ordered)

    for candidate in ordered:
        via = hints[candidate]
        await safe_emit(
            emitter, "memory_profile_verify",
            f"memory: verifying {candidate} (hint from {via}) on {path}",
            {"path": path, "candidate": candidate, "via": via},
        )
        if await _verify_profile(ssh, integration, path, candidate, analyzer_os, esink):
            await safe_emit(
                emitter, "memory_profile_detected",
                f"memory: {path} → {candidate} (verified, hint from {via})",
                {"path": path, "detected_os": candidate, "via": via, "verified": True},
            )
            return candidate
        await safe_emit(
            emitter, "memory_profile_verify_failed",
            f"memory: {candidate} candidate rejected by verifier on {path}",
            {"path": path, "candidate": candidate, "via": via},
        )

    fallback = analyzer_os if analyzer_os in ("windows", "linux", "macos") else "linux"
    await safe_emit(
        emitter, "memory_profile_default",
        f"memory: no candidate verified on {path}, defaulting to {fallback}",
        {"path": path, "detected_os": fallback, "candidates": list(hints.keys())},
    )
    return fallback


# --- structured output parsing ------------------------------------------------

def _parse_vol_json(output: str) -> list[dict[str, Any]]:
    """Parse ``vol -r json`` output into a list of row dicts.

    Volatility emits either a JSON array of objects or (rarely) a JSON
    object with a nested array under some key. We normalise both shapes
    into ``list[dict]``.
    """
    s = output.strip()
    if not s:
        return []
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        # Some plugins still print banner/log lines before the JSON.
        # Scan for the first '[' or '{' and re-try.
        for start in ("[", "{"):
            idx = s.find(start)
            if idx >= 0:
                try:
                    obj = json.loads(s[idx:])
                    break
                except (json.JSONDecodeError, ValueError):
                    continue
        else:
            return []
    if isinstance(obj, list):
        return [r for r in obj if isinstance(r, dict)]
    if isinstance(obj, dict):
        for key in ("rows", "records", "data", "result"):
            if isinstance(obj.get(key), list):
                return [r for r in obj[key] if isinstance(r, dict)]
    return []


# --- directive gate (Tier 3) --------------------------------------------------

async def _credential_directive_allows(project_id: str | None) -> tuple[bool, str]:
    """Return ``(allowed, reason)``. Blocks Tier 3 when no directive matches."""
    if not project_id:
        return False, "no_project_id"
    try:
        from sqlmodel import select as _select
        from aila.modules.forensics.db_models.directive import AnalystDirectiveRecord
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(AnalystDirectiveRecord.text).where(
                    AnalystDirectiveRecord.project_id == project_id,
                    AnalystDirectiveRecord.active.is_(True),  # type: ignore[union-attr]
                )
            )).all()
    except (OSError, RuntimeError, AILAError) as exc:
        _log.debug("credential directive lookup failed: %s", exc)
        return False, f"directive_lookup_error:{exc}"

    for text in rows:
        if text and _CREDENTIAL_DIRECTIVE_KEYWORDS.search(text):
            snippet = (text or "")[:120]
            return True, f"matched_directive:{snippet!r}"
    return False, f"no_matching_directive_of_{len(rows)}"


# --- region dumping (Tier 2) --------------------------------------------------

async def _dump_malfind_regions(
    ssh: Any, integration: dict, path: str, analyzer_os: str,
    dump_os: str, esink: str, emitter: Any,
) -> list[dict[str, Any]]:
    """Run ``<os>.malfind --dump`` and pull the resulting files back as artifacts.

    Each dumped region becomes one artifact with base64-encoded bytes
    plus PID / VAD coordinates, ready for the existing PE/YARA pipeline
    to consume.
    """
    plugin_entry = _DUMP_PLUGINS.get(dump_os)
    if plugin_entry is None:
        return []
    plugin, short_name = plugin_entry

    # Temp directory — analyzer-local, cleaned up after readback.
    if analyzer_os == "windows":
        tmpdir = f"C:\\Windows\\Temp\\vol3_{short_name}_{int(_time.time())}"
        mkdir_cmd = f'powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path \'{tmpdir}\' | Out-Null"'
        list_cmd = f'powershell -NoProfile -Command "Get-ChildItem -Path \'{tmpdir}\' -File | ForEach-Object {{ $_.FullName }}"'
        cleanup_cmd = f'powershell -NoProfile -Command "Remove-Item -Recurse -Force \'{tmpdir}\'"'
    else:
        tmpdir = f"/tmp/vol3_{short_name}_{int(_time.time())}"
        mkdir_cmd = f"mkdir -p {sq(tmpdir, analyzer_os)}"
        list_cmd = f"ls -1 {sq(tmpdir, analyzer_os)}/* 2>/dev/null"
        cleanup_cmd = f"rm -rf {sq(tmpdir, analyzer_os)}"

    try:
        await ssh.run_command(integration, mkdir_cmd, timeout_seconds=30.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("malfind dump mkdir failed: %s", exc)
        return []

    dump_cmd = (
        f'{vol_cmd(analyzer_os)} -f {sq(path, analyzer_os)} '
        f'-o {sq(tmpdir, analyzer_os)} {plugin} --dump {esink}'
    )
    await safe_emit(
        emitter, "memory_region_dump_begin",
        f"memory: dumping {plugin} regions to {tmpdir}",
        {"path": path, "plugin": plugin, "tmpdir": tmpdir},
    )
    try:
        await ssh.run_command(integration, dump_cmd, timeout_seconds=900.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("%s --dump failed: %s", plugin, exc)
        await safe_emit(
            emitter, "memory_region_dump_failed",
            f"memory: {plugin} --dump failed — {exc}",
            {"plugin": plugin, "error": str(exc)[:300]},
        )
        await _run_quiet(ssh, integration, cleanup_cmd)
        return []

    try:
        listing = await ssh.run_command(integration, list_cmd, timeout_seconds=30.0)
    except (OSError, TimeoutError, RuntimeError, AILAError):
        listing = ""
    files = [ln.strip() for ln in listing.splitlines() if ln.strip()]
    artifacts: list[dict[str, Any]] = []

    # Regex for classic vol3 malfind filename:
    # pid.<pid>.vad.<start>-<end>.dmp  (or similar)
    fn_re = re.compile(r"pid\.(?P<pid>\d+)\.vad\.(?P<start>[0-9a-fx]+)-(?P<end>[0-9a-fx]+)\.dmp", re.I)

    pulled = 0
    for remote in files:
        if pulled >= _MAX_DUMPED_REGIONS:
            break
        try:
            b64 = await _read_file_base64(ssh, integration, remote, analyzer_os, _MAX_REGION_BYTES)
        except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
            _log.debug("region readback %s failed: %s", remote, exc)
            continue
        if not b64:
            continue
        raw = base64.b64decode(b64)
        if len(raw) > _MAX_REGION_BYTES:
            raw = raw[:_MAX_REGION_BYTES]
        sha = hashlib.sha256(raw).hexdigest()
        basename = Path(remote.replace("\\", "/")).name
        meta = fn_re.search(basename) or {}
        mz = raw[:2] == b"MZ"
        artifacts.append({
            "family":      "malware",
            "type":        "memory_dumped_region",
            "source_tool": "volatility3",
            "data": {
                "source_plugin": plugin,
                "remote_path":   remote,
                "filename":      basename,
                "size":          len(raw),
                "sha256":        sha,
                "pid":           int(meta.group("pid")) if isinstance(meta, re.Match) else None,
                "vad_start":     meta.group("start") if isinstance(meta, re.Match) else "",
                "vad_end":       meta.group("end")   if isinstance(meta, re.Match) else "",
                "has_mz_header": mz,
                "content_b64":   b64,
            },
        })
        pulled += 1

    await _run_quiet(ssh, integration, cleanup_cmd)
    await safe_emit(
        emitter, "memory_region_dump_done",
        f"memory: pulled {len(artifacts)} region(s) from {plugin}",
        {"plugin": plugin, "region_count": len(artifacts)},
    )
    return artifacts


async def _read_file_base64(
    ssh: Any, integration: dict, remote: str, analyzer_os: str, max_bytes: int,
) -> str:
    if analyzer_os == "windows":
        cmd = (
            f'powershell -NoProfile -Command "'
            f'$fs=[System.IO.File]::OpenRead(\'{remote}\'); '
            f'$buf=New-Object byte[] {max_bytes}; '
            f'$n=$fs.Read($buf,0,$buf.Length); $fs.Close(); '
            f'[Convert]::ToBase64String($buf,0,$n)"'
        )
    else:
        cmd = f"head -c {max_bytes} {sq(remote, analyzer_os)} | base64 -w 0"
    out = await ssh.run_command(integration, cmd, timeout_seconds=120.0)
    return out.strip()


async def _run_quiet(ssh: Any, integration: dict, cmd: str) -> None:
    try:
        await ssh.run_command(integration, cmd, timeout_seconds=30.0)
    except (OSError, TimeoutError, RuntimeError, AILAError):
        pass


# --- IOC string triage (Tier 2) -----------------------------------------------

_IOC_WORDLIST_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "memory_ioc_wordlist.txt"


def _load_ioc_wordlist() -> list[str]:
    try:
        text = _IOC_WORDLIST_PATH.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


async def _run_ioc_strings_pass(
    ssh: Any, integration: dict, path: str, dump_os: str, emitter: Any,
) -> list[dict[str, Any]]:
    """Scan the memory image for a curated IOC wordlist.

    Rather than running ``windows.strings.Strings`` (which needs a
    pre-generated strings file) we run a simple byte-scan on the
    analyzer that grabs the first N occurrences of each wordlist term.
    That gives us PID-less but fast IOC presence rows — enough to drive
    a "this dump contains PowerShell Empire strings" triage signal.
    """
    if dump_os != "windows":
        return []
    wordlist = _load_ioc_wordlist()
    if not wordlist:
        await safe_emit(
            emitter, "memory_ioc_wordlist_missing",
            f"memory: IOC wordlist not found at {_IOC_WORDLIST_PATH}",
            {"path": str(_IOC_WORDLIST_PATH)},
        )
        return []

    # Build an alternation regex. Escape each literal, cap total length —
    # overlong patterns choke PowerShell's -match engine.
    escaped = [re.escape(w) for w in wordlist[:120]]
    pattern = "|".join(escaped)

    win_path = path.replace("\\", "\\\\")
    cmd = (
        f'powershell -NoProfile -Command "'
        f'$fs=[System.IO.File]::OpenRead(\'{win_path}\'); '
        f'$buf=New-Object byte[] (512*1024*1024); '
        f'$n=$fs.Read($buf,0,$buf.Length); $fs.Close(); '
        f'$txt=[System.Text.Encoding]::ASCII.GetString($buf,0,$n); '
        f'[regex]::Matches($txt,\'{pattern}\') | '
        f'Select-Object -First {_MAX_IOC_HITS} | ForEach-Object {{ '
        f'\\"$($_.Index)`t$($_.Value)\\" }}"'
    )

    try:
        await safe_emit(
            emitter, "memory_ioc_scan_begin",
            f"memory: IOC string scan ({len(wordlist)} terms, first 512 MB)",
            {"term_count": len(wordlist), "window_mb": 512},
        )
        output = await ssh.run_command(integration, cmd, timeout_seconds=240.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("IOC scan failed: %s", exc)
        await safe_emit(
            emitter, "memory_ioc_scan_failed",
            f"memory: IOC scan failed — {exc}",
            {"error": str(exc)[:300]},
        )
        return []

    hits: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" in line:
            offset, term = line.split("\t", 1)
        else:
            offset, term = "", line
        hits.append({"offset": offset, "term": term})

    if not hits:
        await safe_emit(
            emitter, "memory_ioc_scan_empty",
            "memory: IOC scan produced no hits",
            {},
        )
        return []

    # Aggregate per-term counts so the UI can surface the loudest signals.
    counts: dict[str, int] = {}
    for h in hits:
        counts[h["term"]] = counts.get(h["term"], 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:50]

    await safe_emit(
        emitter, "memory_ioc_scan_done",
        f"memory: IOC scan → {len(hits)} hit(s) across {len(counts)} term(s)",
        {"hit_count": len(hits), "unique_terms": len(counts)},
    )

    return [{
        "family":      "ioc",
        "type":        "memory_ioc_hits",
        "source_tool": "memory_strings",
        "data": {
            "records":     hits,
            "term_counts": [{"term": t, "count": c} for t, c in top],
            "window_mb":   512,
            "wordlist_size": len(wordlist),
        },
    }]


# --- main entry ---------------------------------------------------------------

async def collect_memory_artifacts(
    ssh: Any,
    integration: dict,
    path: str,
    analyzer_os: str = "linux",
    emitter: Any = None,
    on_artifact: Any = None,
    project_id: str | None = None,
) -> list[dict[str, Any]]:
    """Detect memory profile, run vol3 plugins, and derive cross-plugin artifacts.

    Returns the list of raw-plugin + derived artifacts produced. Each
    artifact is also passed through ``on_artifact`` as it's produced so
    the dispatcher can persist incrementally.
    """
    from aila.modules.forensics.tools.vol_symbols import (
        ensure_volatility_symbols,
        warmup_windows_pdb_cache,
    )

    esink = err_sink(analyzer_os)

    if analyzer_os in ("windows", "linux", "macos"):
        await ensure_volatility_symbols(ssh, integration, analyzer_os, analyzer_os, emitter=emitter)

    dump_os = await _detect_memory_profile(ssh, integration, path, analyzer_os, emitter=emitter)
    plugins = list(_PLUGINS_BY_OS.get(dump_os, _LINUX_MEMORY_PLUGINS))

    if dump_os != analyzer_os:
        await ensure_volatility_symbols(ssh, integration, dump_os, analyzer_os, emitter=emitter)

    # Windows dumps often require a kernel PDB not shipped in the generic
    # upstream windows.zip pack. Force vol3 to fetch+convert it once up
    # front so subsequent plugins hit the user-scope ISF cache instantly
    # instead of each one triggering a silent 10+ minute symbol fetch.
    if dump_os == "windows":
        await warmup_windows_pdb_cache(ssh, integration, path, analyzer_os, emitter=emitter)

    # Tier 3 — credential plugins, directive-gated.
    creds_allowed, creds_reason = await _credential_directive_allows(project_id)
    if creds_allowed and dump_os == "windows":
        plugins.extend(_WINDOWS_CREDENTIAL_PLUGINS)
        await safe_emit(
            emitter, "memory_credentials_allowed",
            f"memory: credential plugins enabled — {creds_reason}",
            {"reason": creds_reason, "added": len(_WINDOWS_CREDENTIAL_PLUGINS)},
        )
    else:
        await safe_emit(
            emitter, "memory_credentials_skipped",
            f"memory: credential plugins disabled — {creds_reason}",
            {"reason": creds_reason},
        )

    _log.info("Memory dump %s detected as %s — running %d plugins", path, dump_os, len(plugins))
    await safe_emit(
        emitter, "memory_plugins_begin",
        f"memory: {len(plugins)} vol plugins on {path}",
        {"path": path, "plugin_count": len(plugins), "dump_os": dump_os,
         "credentials_allowed": creds_allowed},
    )

    artifacts: list[dict[str, Any]] = []
    qpath = sq(path, analyzer_os)

    for plugin, family in plugins:
        # Leave stderr on the channel (no ``esink`` suffix) so that when a
        # plugin exits non-zero paramiko hands us the real Volatility
        # traceback in ``error_output`` — without it the user sees a bare
        # ``exit code 1:`` with no cause, which happens on known upstream
        # hive-layout failures (volatility3 issues #590, #1472, #1944).
        cmd = f"{vol_cmd(analyzer_os)} -f {qpath} -r json {plugin}"
        start_ts = _time.monotonic()
        await safe_emit(
            emitter, "ssh_exec",
            f"memory[{plugin}]: running (600s timeout)",
            {"path": path, "plugin": plugin, "command": cmd, "timeout_s": 600},
        )
        try:
            output = await ssh.run_command(integration, cmd, timeout_seconds=600.0)
        except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
            elapsed = _time.monotonic() - start_ts
            _log.debug("vol %s failed for %s: %s", plugin, path, exc, exc_info=True)
            err_text = str(exc)
            await safe_emit(
                emitter, "plugin_failed",
                f"memory[{plugin}] failed after {elapsed:.1f}s: {err_text[:300]}",
                {"path": path, "plugin": plugin, "command": cmd,
                 "elapsed_s": round(elapsed, 1), "error": err_text[:2000]},
            )
            continue

        elapsed = _time.monotonic() - start_ts
        if not output.strip() or "unsatisfied" in output.lower():
            await safe_emit(
                emitter, "plugin_empty",
                f"memory[{plugin}]: no data in {elapsed:.1f}s",
                {"path": path, "plugin": plugin, "elapsed_s": round(elapsed, 1)},
            )
            continue

        records = _parse_vol_json(output)
        head_sample = "\n".join(output.strip().splitlines()[:5])[:500]
        art: dict[str, Any] = {
            "family":      family,
            "type":        plugin.replace(".", "_"),
            "source_tool": "volatility3",
            "data": {
                "plugin":         plugin,
                "dump_os":        dump_os,
                "evidence_path":  path,
                "records":        records,
                "record_count":   len(records),
                "raw_output_sample": truncate(output, 4000),
            },
        }
        if family == "credentials":
            art["data"]["sensitive"] = True
        artifacts.append(art)
        if on_artifact:
            await on_artifact(art)
        await safe_emit(
            emitter, "artifact_added",
            f"memory[{plugin}]: ok in {elapsed:.1f}s — {len(records)} row(s), {len(output):,} bytes",
            {
                "path": path, "plugin": plugin, "type": family,
                "elapsed_s":   round(elapsed, 1),
                "bytes":       len(output),
                "record_count": len(records),
                "output_head": head_sample,
            },
        )

    # Tier 2a — region dump (malfind --dump → binary bytes as artifacts).
    if dump_os in _DUMP_PLUGINS:
        region_arts = await _dump_malfind_regions(
            ssh, integration, path, analyzer_os, dump_os, esink, emitter,
        )
        for art in region_arts:
            artifacts.append(art)
            if on_artifact:
                await on_artifact(art)

    # Tier 2b — IOC string triage.
    ioc_arts = await _run_ioc_strings_pass(
        ssh, integration, path, dump_os, emitter,
    )
    for art in ioc_arts:
        artifacts.append(art)
        if on_artifact:
            await on_artifact(art)

    # Tier 1 — cross-plugin derivations. Pure-Python over the rows we
    # just collected; no extra SSH.
    await derive_all(artifacts, on_artifact, emitter=emitter)

    return artifacts
