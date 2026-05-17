"""libFuzzer scraper — tails the run log for stats + scans the
``-artifact_prefix`` directory for ``crash-*`` / ``leak-*`` / ``oom-*``
artifact files.

libFuzzer doesn't write a structured stats file. The status format
is the stderr line:

  #NNNNNN  NEW    cov: COV ft: FT corp: CORP/SIZE exec/s: EPS rss: RSS Mb

The launcher writes that stream to ``<workdir>/fuzzer.log`` (see
``fuzz_launcher.LaunchCommand``) so this scraper tails it from disk.
"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

from ..base import CrashRecord, Sample

_log = logging.getLogger("aila_fuzz_reporter.libfuzzer")

__all__ = ["LibFuzzerScraper"]

# Matches both NEW and pulse lines.
_STATS_RE = re.compile(
    r"#(?P<execs>\d+)\s+\S+\s+cov:\s+(?P<cov>\d+)\s+ft:\s+\S+\s+"
    r"corp:\s+(?P<corp>\d+).*?exec/s:\s+(?P<eps>\d+)",
)
# crash-<sha1>, leak-<sha1>, oom-<sha1>, timeout-<sha1>
_ARTIFACT_RE = re.compile(r"^(crash|leak|oom|timeout)-[0-9a-fA-F]+$")


class LibFuzzerScraper:
    """Reader for one libFuzzer run (log file + artifacts dir)."""

    name = "libfuzzer"

    def __init__(
        self,
        log_path: str | Path,
        artifacts_dir: str | Path,
    ) -> None:
        self.log_path = Path(log_path)
        self.artifacts_dir = Path(artifacts_dir)

    def poll(self) -> Sample | None:
        if not self.log_path.exists():
            return None
        # Read the last ~32 KB of the log to find the most recent
        # stats line. Reading the whole log every poll would scale
        # poorly on long campaigns.
        try:
            with self.log_path.open("rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 32_768))
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError as exc:
            _log.debug("libfuzzer log read failed: %s", exc)
            return None
        last: re.Match[str] | None = None
        for m in _STATS_RE.finditer(tail):
            last = m
        if last is None:
            return None
        # libFuzzer doesn't report coverage as a percentage; report
        # the raw edge count via `extra` once the contract supports
        # custom fields. For now: leave coverage_pct=None.
        return Sample(
            execs_per_sec=float(last.group("eps")),
            total_execs=int(last.group("execs")),
            corpus_size=int(last.group("corp")),
            coverage_pct=None,
            crashes_found=self._count_artifacts(),
        )

    def discover_crashes(self) -> list[CrashRecord]:
        if not self.artifacts_dir.is_dir():
            return []
        out: list[CrashRecord] = []
        for path in sorted(self.artifacts_dir.iterdir()):
            if not path.is_file():
                continue
            if not _ARTIFACT_RE.match(path.name):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            kind = path.name.split("-", 1)[0]
            stack_hash = hashlib.sha256(path.name.encode("utf-8")).hexdigest()
            out.append(CrashRecord(
                stack_hash=stack_hash,
                crash_type=f"libfuzzer_{kind}",
                crash_signature=path.name,
                severity="medium" if kind == "crash" else "low",
                reproducer_path=str(path),
                reproducer_size_bytes=stat.st_size,
                stack_trace=None,
                extra={
                    "engine": "libfuzzer",
                    "artifact_kind": kind,
                },
            ))
        return out

    def _count_artifacts(self) -> int:
        if not self.artifacts_dir.is_dir():
            return 0
        return sum(
            1 for p in self.artifacts_dir.iterdir()
            if p.is_file() and _ARTIFACT_RE.match(p.name)
        )
