"""Bootstrap Volatility 3 symbol tables on the analyzer machine.

Volatility 3 plugins fail with ``Symbols not found`` / ``unsatisfied
requirement`` when no matching debug symbols are installed for the
kernel build in the dump. Upstream ships three prebuilt symbol packs
at ``https://downloads.volatilityfoundation.org/volatility3/symbols/``
(linux, mac, windows). On first use vol3 will auto-fetch them from
that URL -- but only if the analyzer has outbound internet to that host
AND the fetch hasn't already been attempted and failed. Air-gapped or
proxy-restricted analyzers never get symbols, and every plugin run
returns 0.3s of empty output.

This module ensures the correct pack is present BEFORE the collector
runs its plugins. It is idempotent: a marker file inside the pack
directory short-circuits subsequent invocations. On analyzer hosts
where symbols are already there (vol's own auto-fetch worked, or the
sysadmin unpacked them manually) the first check exits after a single
directory listing.

Symbol packs live in
``<volatility3 install>/volatility3/symbols/<os>/`` -- we resolve the
install path by asking python on the analyzer, then unzip into place.

References:
- https://github.com/volatilityfoundation/volatility3  (upstream)
- https://downloads.volatilityfoundation.org/volatility3/symbols/
"""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.exceptions import AILAError

from ..workflow.states.collectors._helpers import err_sink, safe_emit

__all__ = [
    "ensure_volatility_symbols",
    "warmup_windows_pdb_cache",
    "VOLATILITY_SYMBOL_URLS",
]

_log = logging.getLogger(__name__)

VOLATILITY_SYMBOL_URLS: dict[str, str] = {
    "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
    "linux":   "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip",
    "macos":   "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
}
# Upstream packs the mac tree under ``mac/`` (not ``macos/``).
_PACK_DIRNAME: dict[str, str] = {
    "windows": "windows",
    "linux":   "linux",
    "macos":   "mac",
}

# Process-local cache so we don't re-probe the analyzer for every plugin
# in the same collector run. Key: (analyzer_host, dump_os) -> bool.
_bootstrapped: dict[tuple[str, str], bool] = {}


def _cmd_resolve_symbols_dir(analyzer_os: str) -> str:
    """Return a shell command that prints the vol3 symbols directory path."""
    py_expr = (
        "import os,volatility3;"
        "p=os.path.join(os.path.dirname(volatility3.__file__),'symbols');"
        "os.makedirs(p, exist_ok=True);"
        "print(p)"
    )
    if analyzer_os == "windows":
        return f'python -c "{py_expr}"'
    return f"python3 -c '{py_expr}'"


def _cmd_check_pack(symbols_dir: str, dump_os: str, analyzer_os: str) -> str:
    """Return a shell command that exits 0 iff the pack for ``dump_os`` is installed."""
    pack = _PACK_DIRNAME[dump_os]
    if analyzer_os == "windows":
        # Any .json.xz file inside the pack dir -> installed.
        return (
            f'powershell -NoProfile -Command "'
            f'if (Test-Path \'{symbols_dir}\\{pack}\') {{ '
            f'$n = (Get-ChildItem -Recurse -Filter *.json.xz \'{symbols_dir}\\{pack}\' '
            f'-ErrorAction SilentlyContinue | Measure-Object).Count; '
            f'if ($n -gt 0) {{ exit 0 }} else {{ exit 1 }} '
            f'}} else {{ exit 1 }}"'
        )
    return (
        f"test -d {symbols_dir}/{pack} && "
        f"find {symbols_dir}/{pack} -name '*.json.xz' -print -quit | grep -q ."
    )


def _cmd_download_and_extract(
    symbols_dir: str, dump_os: str, url: str, analyzer_os: str,
) -> str:
    """Return a shell command that downloads ``url`` and unzips it into ``symbols_dir``."""
    if analyzer_os == "windows":
        # Use python since it's already required (vol3 is a python package)
        # and avoids dependence on PowerShell web cmdlets being available.
        py = (
            "import urllib.request,zipfile,io,os;"
            f"r=urllib.request.urlopen({url!r}, timeout=600);"
            "data=r.read();"
            f"z=zipfile.ZipFile(io.BytesIO(data));"
            f"z.extractall({symbols_dir!r});"
            "print('OK',len(data))"
        )
        return f'python -c "{py}"'
    return (
        f"mkdir -p {symbols_dir} && "
        f"cd {symbols_dir} && "
        f"(curl -fsSL -o /tmp/vol3_{dump_os}.zip {url} || "
        f"wget -q -O /tmp/vol3_{dump_os}.zip {url}) && "
        f"unzip -q -o /tmp/vol3_{dump_os}.zip -d {symbols_dir} && "
        f"rm -f /tmp/vol3_{dump_os}.zip && echo OK"
    )


async def ensure_volatility_symbols(
    ssh: Any,
    integration: dict,
    dump_os: str,
    analyzer_os: str,
    emitter: Any = None,
) -> bool:
    """Ensure vol3's ``<dump_os>`` symbol pack is installed on the analyzer.

    Idempotent. Returns True when the pack is present at the end of the
    call (whether it was already there or just fetched), False when the
    download failed. Callers that get False should still run their
    plugins -- vol3 may have locally cached symbols for this specific
    kernel build in its user-scope cache, which lives outside the pack
    directory -- but should treat the outcome as low-confidence.

    The first successful check for a given (analyzer, dump_os) is
    cached in-process so repeated calls (one per plugin) cost a single
    SSH round-trip only the first time.
    """
    if dump_os not in VOLATILITY_SYMBOL_URLS:
        return True  # nothing to bootstrap

    host = str(integration.get("host") or integration.get("hostname") or "?")
    cache_key = (host, dump_os)
    if _bootstrapped.get(cache_key):
        return True

    esink = err_sink(analyzer_os)

    # 1. Resolve where vol3 keeps its symbols on this analyzer.
    try:
        symbols_dir = (await ssh.run_command(
            integration,
            f"{_cmd_resolve_symbols_dir(analyzer_os)} {esink}",
            timeout_seconds=30.0,
        )).strip().splitlines()[-1].strip()
    except (OSError, TimeoutError, RuntimeError, AILAError, IndexError) as exc:
        _log.debug("cannot resolve vol3 symbols dir on %s: %s", host, exc)
        await safe_emit(
            emitter, "memory_symbols_resolve_failed",
            f"memory: could not resolve vol3 symbols path on {host} ({exc})",
            {"host": host, "error": str(exc)[:300]},
        )
        return False
    if not symbols_dir:
        await safe_emit(
            emitter, "memory_symbols_resolve_failed",
            f"memory: vol3 symbols path probe returned empty on {host}",
            {"host": host},
        )
        return False

    # 2. Already installed? Short-circuit.
    try:
        await ssh.run_command(
            integration,
            _cmd_check_pack(symbols_dir, dump_os, analyzer_os),
            timeout_seconds=30.0,
        )
        _bootstrapped[cache_key] = True
        await safe_emit(
            emitter, "memory_symbols_present",
            f"memory: vol3 {dump_os} symbols already present on {host}",
            {"host": host, "dump_os": dump_os, "symbols_dir": symbols_dir},
        )
        return True
    except (OSError, TimeoutError, RuntimeError, AILAError):
        pass  # pack missing -- proceed to download

    # 3. Download and unzip. One pack ≈ 100-250 MB, so allow a long
    #    timeout -- but cap it so a hanging proxy doesn't stall the
    #    whole collector.
    url = VOLATILITY_SYMBOL_URLS[dump_os]
    await safe_emit(
        emitter, "memory_symbols_downloading",
        f"memory: fetching vol3 {dump_os} symbols from {url} onto {host}",
        {"host": host, "dump_os": dump_os, "url": url, "symbols_dir": symbols_dir},
    )
    try:
        await ssh.run_command(
            integration,
            _cmd_download_and_extract(symbols_dir, dump_os, url, analyzer_os),
            timeout_seconds=900.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.warning("vol3 symbol download failed on %s: %s", host, exc)
        await safe_emit(
            emitter, "memory_symbols_download_failed",
            f"memory: vol3 {dump_os} symbol download failed on {host}: {exc}",
            {"host": host, "dump_os": dump_os, "error": str(exc)[:500]},
        )
        return False

    # 4. Re-check.
    try:
        await ssh.run_command(
            integration,
            _cmd_check_pack(symbols_dir, dump_os, analyzer_os),
            timeout_seconds=30.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.warning("vol3 symbol pack missing after download on %s: %s", host, exc)
        await safe_emit(
            emitter, "memory_symbols_verify_failed",
            f"memory: vol3 {dump_os} symbols not found after install on {host}",
            {"host": host, "dump_os": dump_os, "error": str(exc)[:300]},
        )
        return False

    _bootstrapped[cache_key] = True
    await safe_emit(
        emitter, "memory_symbols_installed",
        f"memory: vol3 {dump_os} symbols installed on {host} at {symbols_dir}",
        {"host": host, "dump_os": dump_os, "symbols_dir": symbols_dir},
    )
    return True


# Process-local cache so we only warm the Windows PDB cache once per
# (analyzer_host, dump_path) pair. Two memory plugins against the same
# dump share the same converted ISF inside vol3's user-scope cache, so
# the second call is effectively free.
_pdb_warmed: dict[tuple[str, str], bool] = {}


async def warmup_windows_pdb_cache(
    ssh: Any,
    integration: dict,
    path: str,
    analyzer_os: str,
    emitter: Any = None,
) -> bool:
    """Force vol3 to fetch+convert the dump's exact ntoskrnl PDB once.

    The upstream ``windows.zip`` symbol pack only ships ISFs for a
    curated list of kernel builds. Any dump whose ``ntoskrnl.exe`` PDB
    GUID+Age isn't in that pack triggers an on-demand fetch from
    Microsoft's symbol server (``msdl.microsoft.com``), followed by a
    local PDB→ISF conversion. That chain runs **inside the first plugin
    call** (typically ``windows.info`` or ``windows.pslist``), which is
    what manifests as the silent "SSH idle >600s" hang we saw on
    FOR-1500 WS1/FILE RAM.

    This helper runs ``windows.info`` once with a generous 20-minute
    timeout so the fetch+convert cost is paid exactly once, up front,
    and every subsequent plugin reads the converted ISF from the
    user-scope cache instantly. The resolved kernel identity is logged
    as a progress event for observability.

    Returns True on success (cache populated, output non-empty),
    False otherwise. The caller should still run plugins on False --
    the dump may still be analysable via fallback code paths -- but
    should log the warmup failure as a reduced-confidence signal.
    """
    from ..workflow.states.collectors._helpers import vol_cmd

    host = str(integration.get("host") or integration.get("hostname") or "?")
    cache_key = (host, path)
    if _pdb_warmed.get(cache_key):
        return True

    if analyzer_os == "windows":
        qpath = f'"{path}"'
    else:
        import shlex
        qpath = shlex.quote(path)

    cmd = f"{vol_cmd(analyzer_os)} -f {qpath} windows.info"
    await safe_emit(
        emitter, "memory_pdb_warmup_start",
        f"memory: warming vol3 PDB cache on {host} (fetches ntoskrnl PDB from msdl.microsoft.com)",
        {"host": host, "path": path, "command": cmd, "timeout_s": 1200},
    )
    try:
        output = await ssh.run_command(integration, cmd, timeout_seconds=1200.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.warning("vol3 Windows PDB warmup failed on %s: %s", host, exc)
        await safe_emit(
            emitter, "memory_pdb_warmup_failed",
            f"memory: PDB warmup failed on {host}: {str(exc)[:300]}",
            {"host": host, "path": path, "error": str(exc)[:2000]},
        )
        return False

    if not output.strip() or "unsatisfied" in output.lower():
        await safe_emit(
            emitter, "memory_pdb_warmup_empty",
            f"memory: PDB warmup produced no kernel info on {host}",
            {"host": host, "path": path, "output_len": len(output)},
        )
        return False

    # Pull the identity line (Kernel Base / DTB / Symbols) for observability.
    kernel_line = ""
    for line in output.splitlines():
        low = line.lower()
        if "symbols" in low or "kernel base" in low or "ntoskrnl" in low:
            kernel_line = line.strip()
            break

    _pdb_warmed[cache_key] = True
    await safe_emit(
        emitter, "memory_pdb_warmup_done",
        f"memory: PDB cache warmed on {host} -- {kernel_line or 'kernel symbols resolved'}",
        {"host": host, "path": path, "kernel_identity": kernel_line[:500]},
    )
    return True
