"""AFL++ scraper -- tails ``out/default/fuzzer_stats`` + ``crashes/``.

AFL++'s output dir layout:

  <out>/default/
    fuzzer_stats        -- k=v lines, rewritten every ~30 s
    queue/              -- corpus
    crashes/            -- id:NNNNNN,sig:NNN,src:NNNNNN,op:OOO,...
                          one file per unique crash (AFL dedups by edge)

``fuzzer_stats`` keys we care about:
  start_time, last_update, run_time, fuzzer_pid,
  execs_done, execs_per_sec, paths_total, unique_crashes, bitmap_cvg
"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

from ..base import CrashRecord, Sample

_log = logging.getLogger("aila_fuzz_reporter.afl++")

__all__ = ["AflPlusPlusScraper"]

# bitmap_cvg looks like "32.45%" in AFL++ stats.
_PCT_RE = re.compile(r"([0-9.]+)%?")


class AflPlusPlusScraper:
    """Reader for one ``afl-fuzz -o <out_dir>`` directory."""

    name = "afl++"

    def __init__(self, out_dir: str | Path) -> None:
        # Accept either the parent (passed --out) or the per-instance
        # subdir AFL writes into ("default" by default).
        root = Path(out_dir)
        if (root / "default").is_dir():
            root = root / "default"
        self.root = root

    def poll(self) -> Sample | None:
        stats_path = self.root / "fuzzer_stats"
        if not stats_path.exists():
            return None
        kv = self._read_kv(stats_path)
        if not kv:
            return None
        return Sample(
            execs_per_sec=_as_float(kv.get("execs_per_sec")),
            total_execs=_as_int(kv.get("execs_done")),
            corpus_size=_as_int(kv.get("paths_total") or kv.get("corpus_count")),
            coverage_pct=_as_pct(kv.get("bitmap_cvg")),
            crashes_found=_as_int(kv.get("unique_crashes") or kv.get("saved_crashes")),
        )

    def discover_crashes(self) -> list[CrashRecord]:
        crash_dir = self.root / "crashes"
        if not crash_dir.is_dir():
            return []
        out: list[CrashRecord] = []
        for path in sorted(crash_dir.iterdir()):
            if not path.is_file() or path.name.startswith("README"):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            # AFL++ filenames carry the dedup signature in the "sig:"
            # field. Use the whole filename for the stack hash so the
            # same crash from the same edge tuple collapses.
            stack_hash = hashlib.sha256(path.name.encode("utf-8")).hexdigest()
            out.append(CrashRecord(
                stack_hash=stack_hash,
                crash_type=_infer_crash_type(path.name),
                crash_signature=path.name,
                severity="unknown",
                reproducer_path=str(path),
                reproducer_size_bytes=stat.st_size,
                stack_trace=None,
                extra={
                    "engine": "afl++",
                    "filename": path.name,
                },
            ))
        return out

    @staticmethod
    def _read_kv(path: Path) -> dict[str, str]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            _log.debug("afl++ stats read failed: %s", exc)
            return {}
        kv: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            kv[k.strip()] = v.strip()
        return kv


def _as_int(v: str | None) -> int | None:
    if v is None:
        return None
    try:
        return int(float(v.split()[0]))
    except (ValueError, AttributeError):
        return None


def _as_float(v: str | None) -> float | None:
    if v is None:
        return None
    try:
        return float(v.split()[0])
    except (ValueError, AttributeError):
        return None


def _as_pct(v: str | None) -> float | None:
    if v is None:
        return None
    m = _PCT_RE.search(v)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _infer_crash_type(filename: str) -> str | None:
    """AFL++ doesn't classify; surface the op field when present."""
    parts = dict(
        kv.split(":", 1) for kv in filename.split(",") if ":" in kv
    )
    op = parts.get("op")
    if op:
        return f"afl++_op_{op}"
    return None
