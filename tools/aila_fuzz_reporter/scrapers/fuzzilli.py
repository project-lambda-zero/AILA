"""Fuzzilli scraper -- tails ``--storagePath`` for stats + crashes.

Fuzzilli's storage layout (matches Apple's reference impl):

  <storagePath>/
    stats.json          -- periodically rewritten by fuzzilli
    corpus/             -- programs in the active corpus
    crashes/            -- minimised crash reproducers, one file each
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
import os
import stat as _stat
from pathlib import Path
from typing import Final

from ..base import CrashRecord, Sample

_log = logging.getLogger("aila_fuzz_reporter.fuzzilli")

__all__ = ["FuzzilliScraper"]

_MAX_REPRODUCER_BYTES: Final[int] = 64 * 1024
# Absurdly large files are refused outright, far above the read cap.
_MAX_REPRODUCER_HARD_CAP: Final[int] = _MAX_REPRODUCER_BYTES * 16


def _safe_crash_files(directory: Path) -> list[Path]:
    """Return regular, non-symlink files in a crash dir, rejecting unsafe entries.

    A fuzz output directory is untrusted input. A symlink planted there would
    otherwise be dereferenced and its target's bytes read into a crash record
    (an exfiltration path). Reject symlinks (lstat, no follow), non-regular
    entries, and files above the hard size cap.
    """
    if not directory.is_dir():
        return []
    safe: list[Path] = []
    for entry in directory.iterdir():
        try:
            lst = entry.lstat()
        except OSError:
            _log.warning("fuzz_scrape_reject path=%s reason=lstat_error", entry)
            continue
        if _stat.S_ISLNK(lst.st_mode):
            _log.warning("fuzz_scrape_reject path=%s reason=symlink", entry)
            continue
        if not _stat.S_ISREG(lst.st_mode):
            _log.warning("fuzz_scrape_reject path=%s reason=not_regular", entry)
            continue
        if lst.st_size > _MAX_REPRODUCER_HARD_CAP:
            _log.warning(
                "fuzz_scrape_reject path=%s reason=too_large size=%d", entry, lst.st_size
            )
            continue
        safe.append(entry)
    return safe


def _read_reproducer(path: Path) -> tuple[bytes, int]:
    """Read up to the cap with O_NOFOLLOW so a symlink swapped in after lstat is refused."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb", closefd=True) as fh:
        size = os.fstat(fh.fileno()).st_size
        payload = fh.read(_MAX_REPRODUCER_BYTES)
    return payload, size


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
        # Fuzzilli reports coverage as a fraction (0..1) -- convert to %.
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
            candidates.extend(_safe_crash_files(self.root / sub))
        out: list[CrashRecord] = []
        for path in candidates:
            try:
                payload, size = _read_reproducer(path)
            except OSError as exc:
                _log.warning("fuzz_scrape_reject path=%s reason=open_error err=%s", path, exc)
                continue
            # Fuzzilli filenames look like "crash-<signature>.js" or
            # similar -- use SHA-256 of the filename as the stack hash
            # so reruns of the same minimised crash dedup.
            stack_hash = hashlib.sha256(path.name.encode("utf-8")).hexdigest()
            out.append(CrashRecord(
                stack_hash=stack_hash,
                crash_type=None,  # fuzzilli doesn't classify
                crash_signature=path.name,
                severity="unknown",
                reproducer_path=str(path),
                reproducer_size_bytes=size,
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
        return sum(
            len(_safe_crash_files(self.root / sub))
            for sub in ("crashes", "distinct_crashes")
        )
