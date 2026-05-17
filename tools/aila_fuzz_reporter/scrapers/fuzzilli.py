"""Fuzzilli scraper — tails ``--storagePath`` for stats + crashes.

Fuzzilli's storage layout (matches Apple's reference impl):

  <storagePath>/
    stats.json          — periodically rewritten by fuzzilli
    corpus/             — programs in the active corpus
    crashes/            — minimised crash reproducers, one file each
                          (some Fuzzilli builds use 'distinct_crashes')

This scraper polls stats.json for the campaign-level scalars and
scans crashes/ for new files. Each crash file's contents are read as
the reproducer payload; a stable stack hash is derived from the
file name (Fuzzilli embeds a signature in the filename).
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from ..base import CrashRecord, Sample

_log = logging.getLogger("aila_fuzz_reporter.fuzzilli")

__all__ = ["FuzzilliScraper"]


class FuzzilliScraper:
    """Reader for one Fuzzilli ``--storagePath`` directory."""

    name = "fuzzilli"

    def __init__(self, storage_path: str | Path) -> None:
        self.root = Path(storage_path)

    def poll(self) -> Sample | None:
        stats_path = self.root / "stats.json"
        if not stats_path.exists():
            return None
        try:
            data = json.loads(stats_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _log.debug("fuzzilli stats.json read failed: %s", exc)
            return None
        # Field names vary across Fuzzilli versions; map the common
        # ones with a fallback chain.
        execs = (
            data.get("totalExecs")
            or data.get("execs")
            or data.get("execCount")
        )
        eps = (
            data.get("execsPerSecond")
            or data.get("execsPerSec")
            or data.get("execRate")
        )
        cov = (
            data.get("coverage")
            or data.get("edgeCoverage")
        )
        # Fuzzilli reports coverage as a fraction (0..1) — convert to %.
        if isinstance(cov, (int, float)) and 0 <= cov <= 1:
            cov = float(cov) * 100.0
        corpus = data.get("corpusSize") or data.get("corpus")
        crashes = (
            data.get("crashes")
            or data.get("crashCount")
            or self._count_crash_files()
        )
        return Sample(
            execs_per_sec=float(eps) if isinstance(eps, (int, float)) else None,
            total_execs=int(execs) if isinstance(execs, (int, float)) else None,
            corpus_size=int(corpus) if isinstance(corpus, (int, float)) else None,
            coverage_pct=float(cov) if isinstance(cov, (int, float)) else None,
            crashes_found=int(crashes) if isinstance(crashes, (int, float)) else None,
        )

    def discover_crashes(self) -> list[CrashRecord]:
        # Fuzzilli writes to 'crashes/' or 'distinct_crashes/' depending
        # on profile; check both.
        candidates: list[Path] = []
        for sub in ("crashes", "distinct_crashes"):
            d = self.root / sub
            if d.is_dir():
                candidates.extend(p for p in d.iterdir() if p.is_file())
        out: list[CrashRecord] = []
        for path in candidates:
            try:
                stat = path.stat()
            except OSError:
                continue
            payload = path.read_bytes() if stat.st_size <= 64 * 1024 else b""
            # Fuzzilli filenames look like "crash-<signature>.js" or
            # similar — use SHA-256 of the filename as the stack hash
            # so reruns of the same minimised crash dedup.
            stack_hash = hashlib.sha256(path.name.encode("utf-8")).hexdigest()
            out.append(CrashRecord(
                stack_hash=stack_hash,
                crash_type=None,  # fuzzilli doesn't classify
                crash_signature=path.name,
                severity="unknown",
                reproducer_path=str(path),
                reproducer_size_bytes=stat.st_size,
                stack_trace=None,
                extra={
                    "engine": "fuzzilli",
                    "filename": path.name,
                    "payload_preview": payload[:512].decode(
                        "utf-8", errors="replace",
                    ),
                },
            ))
        return out

    def _count_crash_files(self) -> int:
        total = 0
        for sub in ("crashes", "distinct_crashes"):
            d = self.root / sub
            if d.is_dir():
                total += sum(1 for p in d.iterdir() if p.is_file())
        return total
