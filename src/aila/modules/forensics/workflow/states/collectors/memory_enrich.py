"""Cross-plugin memory enrichment -- no SSH, pure data crunching.

The Volatility 3 sweep in ``memory.py`` produces one artifact per plugin
with ``data.records`` populated from ``vol -r json``. This module joins
those rows across plugins and emits higher-level artifacts that are
impossible to get from any single plugin:

- ``process_tree`` -- pslist × cmdline × getsids × privileges, PPID linkage
- ``injection_candidates`` -- malfind ∪ ldrmodules (RWX + no-file + MZ)
- ``network_by_process`` -- netscan × pslist, per-connection with owner image
- ``handle_anomalies`` -- handles × pslist, Section-to-remote-PID + physical memory
- ``rootkit_candidates`` -- psscan \\ pslist, psxview mismatches
- ``registry_exec_history`` -- userassist ∪ shimcachemem ∪ amcache, normalized

Every deriver is a pure function over the row arrays gathered during
the sweep. Timestamps are emitted in ISO-8601 so the timeline miner
that already walks ``data.records[]`` picks them up automatically.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "derive_all",
    "DERIVER_NAMES",
]

_log = logging.getLogger(__name__)

DERIVER_NAMES = (
    "process_tree",
    "injection_candidates",
    "network_by_process",
    "handle_anomalies",
    "rootkit_candidates",
    "registry_exec_history",
)

# --- normalisation helpers ----------------------------------------------------

_WINDOWS_SYSTEM_IMAGES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "spoolsv.exe",
    "svchost.exe", "explorer.exe", "taskhostw.exe", "dwm.exe",
    "conhost.exe", "fontdrvhost.exe", "searchindexer.exe", "runtimebroker.exe",
    "sihost.exe", "ctfmon.exe", "audiodg.exe",
}

# Images that, when seen as a child of a non-LOLBIN parent, are an injection
# or lateral-movement smell. Consumers use this as a scoring signal, not a
# hard fact.
_LOLBIN_IMAGES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
    "installutil.exe", "msbuild.exe", "cscript.exe", "wscript.exe",
    "forfiles.exe", "conhost.exe",
}

_SUSPICIOUS_CMDLINE_PATTERNS = [
    re.compile(r"\-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"\biex\b.+\bdownloadstring\b", re.I),
    re.compile(r"\bfromBase64String\b", re.I),
    re.compile(r"\bInvoke-WebRequest\b", re.I),
    re.compile(r"\bbitsadmin\s+/transfer\b", re.I),
    re.compile(r"\bregsvr32\s+/s\s+/i:\s*http", re.I),
    re.compile(r"\bmshta\s+http", re.I),
    re.compile(r"\bjavascript:\b", re.I),
    re.compile(r"\brundll32\s+.*,(?:DllRegisterServer|#\d+)", re.I),
    re.compile(r"\bcertutil\s+-(?:urlcache|decode)\b", re.I),
]


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        s = str(value).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _to_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_private_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%", maxsplit=1)[0]).is_private
    except (ValueError, TypeError):
        return False


def _image_basename(path: str) -> str:
    if not path:
        return ""
    for sep in ("\\", "/"):
        if sep in path:
            path = path.rsplit(sep, 1)[-1]
    return path.lower()


def _rows_for(artifacts: list[dict[str, Any]], plugin_key: str) -> list[dict[str, Any]]:
    """Return the records[] for the first artifact whose type matches ``plugin_key``.

    ``plugin_key`` is the ``vol.plugin.Name`` with dots replaced by underscores
    (that's what ``memory.py`` stores in ``artifact["type"]``). Accepts a
    trailing wildcard fragment via substring match for convenience.
    """
    for a in artifacts:
        t = a.get("type", "")
        if t == plugin_key or plugin_key in t:
            data = a.get("data") or {}
            recs = data.get("records")
            if isinstance(recs, list):
                return recs
    return []


# --- derivers -----------------------------------------------------------------

def _derive_process_tree(artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    pslist = _rows_for(artifacts, "windows_pslist") or _rows_for(artifacts, "linux_pslist") or _rows_for(artifacts, "mac_pslist")
    if not pslist:
        return None
    cmdline = _rows_for(artifacts, "windows_cmdline")
    getsids = _rows_for(artifacts, "windows_getsids")
    privileges = _rows_for(artifacts, "windows_privileges")

    cmdline_by_pid: dict[int, str] = {}
    for r in cmdline:
        pid = _to_int(r.get("PID"))
        if pid is not None:
            cmdline_by_pid[pid] = _to_str(r.get("Args") or r.get("CommandLine") or r.get("Cmd") or "")

    sids_by_pid: dict[int, list[str]] = {}
    for r in getsids:
        pid = _to_int(r.get("PID"))
        if pid is not None:
            sid = _to_str(r.get("SID") or r.get("Sid") or "")
            sids_by_pid.setdefault(pid, []).append(sid)

    privs_by_pid: dict[int, list[str]] = {}
    for r in privileges:
        pid = _to_int(r.get("PID"))
        if pid is not None:
            name = _to_str(r.get("Privilege") or r.get("Name") or "")
            if name:
                privs_by_pid.setdefault(pid, []).append(name)

    records: list[dict[str, Any]] = []
    for r in pslist:
        pid = _to_int(r.get("PID"))
        ppid = _to_int(r.get("PPID") or r.get("Parent") or r.get("PPid"))
        image = _to_str(r.get("ImageFileName") or r.get("COMM") or r.get("Name") or "")
        image_base = _image_basename(image)
        cmd = cmdline_by_pid.get(pid or -1, "")
        sids = sids_by_pid.get(pid or -1, [])
        privs = privs_by_pid.get(pid or -1, [])
        reasons: list[str] = []

        for pat in _SUSPICIOUS_CMDLINE_PATTERNS:
            if pat.search(cmd):
                reasons.append(f"cmdline_suspicious:{pat.pattern[:30]}")
                break

        if image_base in _LOLBIN_IMAGES:
            reasons.append(f"lolbin_image:{image_base}")

        if any(sid.startswith("S-1-5-18") for sid in sids) and image_base not in _WINDOWS_SYSTEM_IMAGES:
            reasons.append("system_sid_on_nonsystem_image")

        if "SeDebugPrivilege" in privs and image_base not in {"lsass.exe", "services.exe", "wininit.exe"}:
            reasons.append("sedebug_on_nonsystem")

        rec = {
            "PID": pid,
            "PPID": ppid,
            "Image": image,
            "Cmdline": cmd,
            "SIDs": sids,
            "Privileges": privs,
            "CreateTime": _to_str(r.get("CreateTime") or r.get("StartTime") or r.get("Started")),
            "ExitTime": _to_str(r.get("ExitTime") or ""),
            "Threads": _to_int(r.get("Threads")),
            "Handles": _to_int(r.get("Handles")),
            "suspicious_reasons": reasons,
        }
        if reasons:
            rec["severity"] = "high" if len(reasons) >= 2 else "medium"
        records.append(rec)

    return {
        "family": "memory",
        "type": "memory_process_tree",
        "source_tool": "memory_enrich",
        "data": {
            "derived_at": _iso_now(),
            "source_plugins": ["pslist", "cmdline", "getsids", "privileges"],
            "records": records,
        },
    }


_MZ_HEADER = "MZ"
_RWX_FLAGS = ("PAGE_EXECUTE_READWRITE", "rwx", "EXECUTE_READWRITE")


def _derive_injection_candidates(artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    malfind = _rows_for(artifacts, "windows_malfind") or _rows_for(artifacts, "mac_malfind")
    ldrmods = _rows_for(artifacts, "windows_ldrmodules")
    pslist = _rows_for(artifacts, "windows_pslist") or _rows_for(artifacts, "linux_pslist") or _rows_for(artifacts, "mac_pslist")

    if not (malfind or ldrmods):
        return None

    image_by_pid: dict[int, str] = {}
    for r in pslist:
        pid = _to_int(r.get("PID"))
        if pid is not None:
            image_by_pid[pid] = _to_str(r.get("ImageFileName") or r.get("COMM") or r.get("Name") or "")

    records: list[dict[str, Any]] = []
    for r in malfind:
        pid = _to_int(r.get("PID"))
        header = _to_str(r.get("Hexdump") or r.get("Disasm") or "")[:200]
        protection = _to_str(r.get("Protection") or "")
        tag = _to_str(r.get("Tag") or "")
        start = _to_str(r.get("Start VPN") or r.get("Start") or "")
        end = _to_str(r.get("End VPN") or r.get("End") or "")
        reasons = ["malfind_hit"]
        if any(flag in protection for flag in _RWX_FLAGS):
            reasons.append("rwx_protection")
        if _MZ_HEADER in header:
            reasons.append("mz_header_in_rwx_region")
        records.append({
            "source_plugin": "malfind",
            "PID": pid,
            "Image": image_by_pid.get(pid or -1, ""),
            "Start": start,
            "End": end,
            "Protection": protection,
            "Tag": tag,
            "reasons": reasons,
            "severity": "high" if "mz_header_in_rwx_region" in reasons else "medium",
        })

    for r in ldrmods:
        pid = _to_int(r.get("PID"))
        in_load = bool(r.get("InLoad"))
        in_init = bool(r.get("InInit"))
        in_mem = bool(r.get("InMem"))
        mapped = _to_str(r.get("MappedPath") or "")
        # classic unlink -- present in VAD but delinked from one or more PEB lists
        if not (in_load and in_init and in_mem):
            reasons = ["unlinked_module"]
            if not in_load:
                reasons.append("not_in_load")
            if not in_init:
                reasons.append("not_in_init")
            if not in_mem:
                reasons.append("not_in_mem")
            if not mapped:
                reasons.append("no_mapped_path")
            records.append({
                "source_plugin": "ldrmodules",
                "PID": pid,
                "Image": image_by_pid.get(pid or -1, ""),
                "MappedPath": mapped,
                "InLoad": in_load,
                "InInit": in_init,
                "InMem": in_mem,
                "reasons": reasons,
                "severity": "high" if not mapped else "medium",
            })

    if not records:
        return None
    return {
        "family": "malware",
        "type": "memory_injection_candidates",
        "source_tool": "memory_enrich",
        "data": {
            "derived_at": _iso_now(),
            "source_plugins": ["malfind", "ldrmodules"],
            "records": records,
        },
    }


def _derive_network_by_process(artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    netscan = (
        _rows_for(artifacts, "windows_netscan")
        or _rows_for(artifacts, "linux_sockstat")
        or _rows_for(artifacts, "mac_netstat")
    )
    pslist = _rows_for(artifacts, "windows_pslist") or _rows_for(artifacts, "linux_pslist") or _rows_for(artifacts, "mac_pslist")
    if not netscan:
        return None

    image_by_pid: dict[int, str] = {}
    for r in pslist:
        pid = _to_int(r.get("PID"))
        if pid is not None:
            image_by_pid[pid] = _to_str(r.get("ImageFileName") or r.get("COMM") or r.get("Name") or "")

    records: list[dict[str, Any]] = []
    for r in netscan:
        pid = _to_int(r.get("PID") or r.get("Owner"))
        foreign_addr = _to_str(r.get("ForeignAddr") or r.get("RemoteAddr") or "")
        local_addr = _to_str(r.get("LocalAddr") or "")
        local_port = _to_int(r.get("LocalPort"))
        foreign_port = _to_int(r.get("ForeignPort") or r.get("RemotePort"))
        proto = _to_str(r.get("Proto") or r.get("Protocol") or "")
        state = _to_str(r.get("State") or "")
        created = _to_str(r.get("Created") or r.get("CreateTime") or "")
        image = image_by_pid.get(pid or -1, "") or _to_str(r.get("Owner") or "")
        reasons: list[str] = []
        if foreign_addr and foreign_addr not in ("0.0.0.0", "::", "*") and not _is_private_ip(foreign_addr):
            reasons.append("external_remote")
        if state == "LISTENING" and _image_basename(image) not in _WINDOWS_SYSTEM_IMAGES and local_port and local_port > 1024:
            reasons.append("unexpected_listener")
        if _image_basename(image) in _LOLBIN_IMAGES:
            reasons.append("lolbin_network_io")
        records.append({
            "PID": pid,
            "Image": image,
            "Proto": proto,
            "LocalAddr": local_addr,
            "LocalPort": local_port,
            "ForeignAddr": foreign_addr,
            "ForeignPort": foreign_port,
            "State": state,
            "Created": created,
            "reasons": reasons,
            "severity": "high" if len(reasons) >= 2 else ("medium" if reasons else "low"),
        })

    return {
        "family": "network",
        "type": "memory_network_by_process",
        "source_tool": "memory_enrich",
        "data": {
            "derived_at": _iso_now(),
            "source_plugins": ["netscan", "pslist"],
            "records": records,
        },
    }


def _derive_handle_anomalies(artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    handles = _rows_for(artifacts, "windows_handles")
    pslist = _rows_for(artifacts, "windows_pslist")
    if not handles:
        return None

    image_by_pid: dict[int, str] = {}
    for r in pslist:
        pid = _to_int(r.get("PID"))
        if pid is not None:
            image_by_pid[pid] = _to_str(r.get("ImageFileName") or "")

    records: list[dict[str, Any]] = []
    for r in handles:
        pid = _to_int(r.get("PID"))
        htype = _to_str(r.get("Type") or "")
        name = _to_str(r.get("Name") or "")
        reasons: list[str] = []
        if name and "\\Device\\PhysicalMemory" in name:
            reasons.append("physical_memory_handle")
        if htype == "Section" and name and "\\Device\\PhysicalMemory" in name:
            reasons.append("section_to_physical_memory")
        if htype == "Process" and name:
            # handle to another process -- potential injection plumbing
            reasons.append("process_handle")
        if not reasons:
            continue
        records.append({
            "PID": pid,
            "Image": image_by_pid.get(pid or -1, ""),
            "Type": htype,
            "Name": name,
            "GrantedAccess": _to_str(r.get("GrantedAccess") or ""),
            "reasons": reasons,
            "severity": "high" if "physical_memory_handle" in reasons else "medium",
        })

    if not records:
        return None
    return {
        "family": "malware",
        "type": "memory_handle_anomalies",
        "source_tool": "memory_enrich",
        "data": {
            "derived_at": _iso_now(),
            "source_plugins": ["handles", "pslist"],
            "records": records,
        },
    }


def _derive_rootkit_candidates(artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    pslist = _rows_for(artifacts, "windows_pslist")
    psscan = _rows_for(artifacts, "windows_psscan")
    psxview = _rows_for(artifacts, "windows_psxview")
    if not (psscan or psxview):
        return None

    pslist_pids = {_to_int(r.get("PID")) for r in pslist}
    pslist_pids.discard(None)

    records: list[dict[str, Any]] = []
    for r in psscan:
        pid = _to_int(r.get("PID"))
        if pid is None or pid in pslist_pids:
            continue
        records.append({
            "source_plugin": "psscan",
            "PID": pid,
            "Image": _to_str(r.get("ImageFileName") or ""),
            "Offset": _to_str(r.get("Offset(V)") or r.get("Offset") or ""),
            "CreateTime": _to_str(r.get("CreateTime") or ""),
            "ExitTime": _to_str(r.get("ExitTime") or ""),
            "reasons": ["unlinked_from_pslist"],
            "severity": "high",
        })

    for r in psxview:
        pid = _to_int(r.get("PID"))
        views = {k: r.get(k) for k in r if k not in ("PID", "Image", "ImageFileName")}
        booleans = {k: v for k, v in views.items() if isinstance(v, bool)}
        if booleans and not all(booleans.values()) and any(booleans.values()):
            missing = [k for k, v in booleans.items() if not v]
            records.append({
                "source_plugin": "psxview",
                "PID": pid,
                "Image": _to_str(r.get("ImageFileName") or r.get("Image") or ""),
                "missing_from": missing,
                "reasons": ["psxview_disagreement"],
                "severity": "medium",
            })

    if not records:
        return None
    return {
        "family": "malware",
        "type": "memory_rootkit_candidates",
        "source_tool": "memory_enrich",
        "data": {
            "derived_at": _iso_now(),
            "source_plugins": ["pslist", "psscan", "psxview"],
            "records": records,
        },
    }


def _derive_registry_exec_history(artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    userassist = _rows_for(artifacts, "windows_registry_userassist")
    shimcache = _rows_for(artifacts, "windows_registry_shimcachemem") or _rows_for(artifacts, "windows_shimcachemem")
    amcache = _rows_for(artifacts, "windows_amcache") or _rows_for(artifacts, "windows_registry_amcache")

    records: list[dict[str, Any]] = []
    for r in userassist:
        records.append({
            "source_plugin": "userassist",
            "Path": _to_str(r.get("Name") or r.get("Path") or ""),
            "LastModified": _to_str(r.get("LastModified") or r.get("Last Modified") or r.get("LastUpdated") or ""),
            "Count": _to_int(r.get("Count") or r.get("Count of executions")),
            "User": _to_str(r.get("User") or ""),
        })
    for r in shimcache:
        records.append({
            "source_plugin": "shimcachemem",
            "Path": _to_str(r.get("Path") or r.get("Name") or ""),
            "LastModified": _to_str(r.get("LastModified") or r.get("LastUpdate") or ""),
            "Executed": r.get("Executed"),
            "Order": _to_int(r.get("Order")),
        })
    for r in amcache:
        records.append({
            "source_plugin": "amcache",
            "Path": _to_str(r.get("Path") or r.get("FilePath") or ""),
            "LastModified": _to_str(r.get("LastModified") or r.get("LastUpdated") or r.get("InstallTime") or ""),
            "SHA1": _to_str(r.get("SHA1") or r.get("FileHash") or ""),
            "Product": _to_str(r.get("Product") or ""),
            "Company": _to_str(r.get("Company") or ""),
        })

    if not records:
        return None
    return {
        "family": "execution",
        "type": "memory_registry_exec_history",
        "source_tool": "memory_enrich",
        "data": {
            "derived_at": _iso_now(),
            "source_plugins": ["userassist", "shimcachemem", "amcache"],
            "records": records,
        },
    }


# --- public entry -------------------------------------------------------------

async def derive_all(
    artifacts: list[dict[str, Any]],
    on_artifact: Callable[[dict[str, Any]], Awaitable[None]] | None,
    emitter: Any = None,
) -> list[dict[str, Any]]:
    """Run every deriver; emit + persist each non-empty result.

    Returns the list of derived artifacts for the caller's tally.
    """
    from ._helpers import safe_emit

    await safe_emit(
        emitter, "memory_derive_begin",
        f"memory: running {len(DERIVER_NAMES)} cross-plugin derivers",
        {"derivers": list(DERIVER_NAMES)},
    )

    derivers = (
        ("process_tree",        _derive_process_tree),
        ("injection_candidates", _derive_injection_candidates),
        ("network_by_process",   _derive_network_by_process),
        ("handle_anomalies",     _derive_handle_anomalies),
        ("rootkit_candidates",   _derive_rootkit_candidates),
        ("registry_exec_history", _derive_registry_exec_history),
    )

    derived: list[dict[str, Any]] = []
    for name, fn in derivers:
        try:
            art = fn(artifacts)
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            _log.debug("memory deriver %s failed: %s", name, exc, exc_info=True)
            await safe_emit(
                emitter, "memory_derive_failed",
                f"memory: deriver {name} failed -- {exc}",
                {"deriver": name, "error": str(exc)[:300]},
            )
            continue
        if art is None:
            await safe_emit(
                emitter, "memory_derive_empty",
                f"memory: deriver {name} produced no rows (source plugins missing)",
                {"deriver": name},
            )
            continue
        row_count = len(art.get("data", {}).get("records", []))
        derived.append(art)
        if on_artifact is not None:
            await on_artifact(art)
        await safe_emit(
            emitter, "memory_derive_done",
            f"memory: deriver {name} → {row_count} row(s)",
            {"deriver": name, "row_count": row_count, "type": art.get("type")},
        )

    await safe_emit(
        emitter, "memory_derive_complete",
        f"memory: derivation complete -- {len(derived)} derived artifact(s)",
        {"derived_count": len(derived)},
    )
    return derived
