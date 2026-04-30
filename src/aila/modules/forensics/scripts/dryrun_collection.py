"""End-to-end dry run of the forensics disk collector against a local disk image.

Runs every dissect query in the module's query list, pipes output through the
same JSONL parse + aggregation + enrichment logic that the SSH-based collector
uses, and reports per-query health: record count, truncation, suspicious hits,
parse errors, wall time. No SSH, no task queue, no UI — just the local
dissect CLI + our pipeline.

Designed to be the fast-feedback loop so the Live SSE path doesn't have to be
the only way bugs are discovered.

Usage:
    python -m aila.modules.forensics.scripts.dryrun_collection \\
        H:/case-001/windows_disk.raw.001
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from aila.modules.forensics.workflow.states.collectors.disk import (
    _COMMON_QUERIES, _LINUX_QUERIES, _MACOS_QUERIES, _WINDOWS_QUERIES,
    _mark_suspicious,
)


def _run_dissect_query(disk_path: str, qfunc: str) -> tuple[str, float, int]:
    """Invoke `python -m dissect.target.tools.query -j -f <qfunc> <disk>` locally
    and capture output via tempfile (same mechanism as the SSH path)."""
    fd, outfile = tempfile.mkstemp(prefix="aila_dry_", suffix=".out")
    os.close(fd)
    start = time.monotonic()
    try:
        subprocess.run(
            [sys.executable, "-m", "dissect.target.tools.query",
             "-j", "-f", qfunc, disk_path],
            stdout=open(outfile, "w", encoding="utf-8", errors="ignore"),
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
        elapsed = time.monotonic() - start
        with open(outfile, encoding="utf-8", errors="ignore") as f:
            data = f.read()
        return data, elapsed, len(data)
    finally:
        try:
            os.unlink(outfile)
        except OSError:
            pass


def _parse_and_enrich(qfunc: str, output: str) -> dict[str, Any]:
    """Replay the orchestrator's parse+aggregate+enrich logic on raw output."""
    MAX_RECORDS = 1000
    parsed: list[dict[str, Any]] = []
    parse_errors = 0
    total = 0
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            parse_errors += 1

    if not parsed and output.strip():
        import re
        clean = re.sub(r"^<Target [^>]+>\s*", "", output.strip(), count=1)
        parsed = [{"query": qfunc, "value": clean[:4000]}]
        total = 1
        parse_errors = 0

    records: list[dict[str, Any]]
    if qfunc == "prefetch":
        by_exe: dict[str, dict[str, Any]] = {}
        for rec in parsed:
            exe = (rec.get("filename") or rec.get("name") or rec.get("executable") or "<?>")
            if isinstance(exe, dict):
                exe = exe.get("executable", "<?>")
            slot = by_exe.setdefault(str(exe), {"executable": str(exe), "files_accessed_count": 0})
            slot["files_accessed_count"] += 1
        records = list(by_exe.values())[:MAX_RECORDS]
    elif qfunc == "shellbags":
        by_path: dict[str, dict[str, Any]] = {}
        for rec in parsed:
            p = rec.get("path") or rec.get("full_path") or "<?>"
            slot = by_path.setdefault(str(p), {"path": str(p), "access_count": 0})
            slot["access_count"] += 1
        records = list(by_path.values())[:MAX_RECORDS]
    elif qfunc in ("runkeys", "services", "startupinfo", "tasks",
                   "mru.recentdocs", "powershell_history", "recyclebin"):
        for rec in parsed:
            _mark_suspicious(rec, candidate_fields=(
                "command", "path", "executable", "image_path", "name", "servicedll",
            ))
        records = parsed[:MAX_RECORDS]
    else:
        records = parsed[:MAX_RECORDS]

    suspicious = sum(1 for r in records if r.get("suspicious_reasons"))
    return {
        "record_count": total,
        "records_stored": len(records),
        "truncated": total > len(records),
        "parse_errors": parse_errors,
        "suspicious_count": suspicious,
        "first_record_keys": sorted(records[0].keys()) if records else [],
    }


def main(disk_path: str) -> int:
    print(f"Dry-run against {disk_path}\n")

    # Detect OS first (same as collector).
    info_cmd = [sys.executable, "-m", "dissect.target.tools.info", disk_path]
    info_out = subprocess.run(info_cmd, capture_output=True, text=True, timeout=120).stdout
    image_os = "windows" if "windows" in info_out.lower() else (
        "macos" if "darwin" in info_out.lower() or "macos" in info_out.lower() else "linux"
    )
    print(f"Detected image OS: {image_os}\n")

    os_pack = {"windows": _WINDOWS_QUERIES, "linux": _LINUX_QUERIES, "macos": _MACOS_QUERIES}[image_os]
    queries = _COMMON_QUERIES + os_pack

    results: list[dict[str, Any]] = []
    fails: list[dict[str, Any]] = []

    for qfunc, family in queries:
        print(f"  [{qfunc:30s}] ", end="", flush=True)
        try:
            raw, elapsed, nbytes = _run_dissect_query(disk_path, qfunc)
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT after 180s")
            fails.append({"query": qfunc, "error": "timeout"})
            continue

        help_markers = ("usage: query.py", "error: ", "unrecognized arguments")
        if any(m in raw for m in help_markers) and "{" not in raw[:500]:
            print(f"  FAIL DISSECT REJECTED NAME ({nbytes}B, {elapsed:.1f}s)")
            fails.append({"query": qfunc, "error": "dissect-rejected-name",
                          "sample": raw[:200]})
            continue

        summary = _parse_and_enrich(qfunc, raw)
        summary.update({"query": qfunc, "family": family,
                        "elapsed_s": round(elapsed, 1), "bytes": nbytes})
        results.append(summary)
        sus = f"  ! {summary['suspicious_count']} suspicious" if summary["suspicious_count"] else ""
        trunc = "  (truncated)" if summary["truncated"] else ""
        print(f"  OK {summary['records_stored']:5d} rec  "
              f"{summary['elapsed_s']:5.1f}s  {nbytes:>9d}B{trunc}{sus}")

    print(f"\n{'=' * 60}")
    print(f"Summary: {len(results)} queries succeeded, {len(fails)} failed")
    for f in fails:
        print(f"  FAIL {f['query']}: {f['error']}")
        if "sample" in f:
            print(f"    sample: {f['sample'][:150]}")
    return 0 if not fails else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <disk-image-path>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
