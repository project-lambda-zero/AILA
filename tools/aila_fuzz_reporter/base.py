"""Shared client + scraper protocol for the AILA fuzz reporter sidecar.

The ``AilaClient`` is a thin HTTP wrapper around the existing AILA
fuzz endpoints (PATCH /vr/fuzz/campaigns/:id, POST /vr/fuzz/crashes,
POST /vr/fuzz/campaigns/:id/telemetry). It handles auth via API key,
retries transient failures with exponential backoff, and never raises
into the scrape loop -- failures log + return False so the loop keeps
running.

Each per-engine scraper implements ``Scraper.poll()`` and
``Scraper.discover_crashes()``. The CLI in ``__main__.py`` loops at
the configured interval, calls those methods, and pushes the results
through the client.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "AilaClient",
    "CrashRecord",
    "Sample",
    "Scraper",
]

_log = logging.getLogger("aila_fuzz_reporter")


@dataclass
class Sample:
    """One telemetry measurement emitted by Scraper.poll()."""

    execs_per_sec: float | None = None
    total_execs: int | None = None
    corpus_size: int | None = None
    coverage_pct: float | None = None
    crashes_found: int | None = None


@dataclass
class CrashRecord:
    """One crash discovered by Scraper.discover_crashes()."""

    stack_hash: str
    crash_type: str | None = None
    crash_signature: str | None = None
    severity: str = "unknown"
    reproducer_path: str | None = None
    reproducer_size_bytes: int | None = None
    stack_trace: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Scraper(Protocol):
    """Per-engine reader. Stateless beyond the fuzzer output dir."""

    name: str

    def poll(self) -> Sample | None:
        """Return the latest telemetry sample or None when nothing to report.

        Called every ``--interval`` seconds. Returning None tells the
        runner "no change since last poll" -- runner skips the PATCH.
        """
        ...

    def discover_crashes(self) -> list[CrashRecord]:
        """Return every crash currently visible in the fuzzer's crash dir.

        Runner deduplicates against its local seen-set (keyed by
        stack_hash) so the same crash is only POSTed once per process.
        """
        ...


@dataclass
class AilaClient:
    """HTTP client targeting one AILA instance + one campaign."""

    base_url: str
    api_key: str
    campaign_id: str
    request_timeout: float = 15.0
    max_retries: int = 4

    def patch_campaign(self, sample: Sample) -> bool:
        """PATCH /vr/fuzz/campaigns/:id with the new scalar metrics.

        Body skips fields that are None so the backend snapshot logic
        (see fuzz_service._record_telemetry_snapshot) only fires for
        the metrics that actually moved.
        """
        body: dict[str, Any] = {
            k: v for k, v in {
                "execs_per_sec": sample.execs_per_sec,
                "total_execs": sample.total_execs,
                "corpus_size": sample.corpus_size,
                "coverage_pct": sample.coverage_pct,
                "crashes_found": sample.crashes_found,
            }.items() if v is not None
        }
        if not body:
            return True
        return self._request(
            "PATCH",
            f"/api/vr/fuzz/campaigns/{self.campaign_id}",
            body=body,
        )

    def post_telemetry(self, sample: Sample) -> bool:
        """POST /vr/fuzz/campaigns/:id/telemetry -- explicit time-series sample.

        Use this in addition to patch_campaign when you want to write
        a row even though no scalar moved (e.g. periodic heartbeat).
        """
        body = {
            "execs_per_sec": sample.execs_per_sec,
            "total_execs": sample.total_execs,
            "corpus_size": sample.corpus_size,
            "coverage_pct": sample.coverage_pct,
            "crashes_found": sample.crashes_found,
        }
        return self._request(
            "POST",
            f"/api/vr/fuzz/campaigns/{self.campaign_id}/telemetry",
            body=body,
        )

    def post_crash(self, crash: CrashRecord) -> bool:
        """POST /vr/fuzz/crashes -- register one crash for this campaign."""
        body = {
            "campaign_id": self.campaign_id,
            "stack_hash": crash.stack_hash,
            "crash_type": crash.crash_type,
            "crash_signature": crash.crash_signature,
            "severity": crash.severity,
            "reproducer_path": crash.reproducer_path,
            "reproducer_size_bytes": crash.reproducer_size_bytes,
            "stack_trace": crash.stack_trace,
            "extra": crash.extra or {},
        }
        return self._request(
            "POST",
            "/api/vr/fuzz/crashes",
            body=body,
        )

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> bool:
        """Send an HTTP request with retries. Returns True on 2xx."""
        url = self.base_url.rstrip("/") + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        delay = 1.0
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("X-API-Key", self.api_key)
            req.add_header("Authorization", f"Bearer {self.api_key}")
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                    if 200 <= resp.status < 300:
                        return True
                    _log.warning(
                        "AILA %s %s → HTTP %d (attempt %d)",
                        method, path, resp.status, attempt + 1,
                    )
            except urllib.error.HTTPError as exc:
                # 4xx is non-retryable (auth, validation, dup).
                if 400 <= exc.code < 500:
                    body_text = ""
                    try:
                        body_text = exc.read().decode("utf-8", errors="replace")[:512]
                    except (OSError, AttributeError):
                        pass
                    _log.error(
                        "AILA %s %s → HTTP %d (no retry): %s",
                        method, path, exc.code, body_text,
                    )
                    return False
                _log.warning(
                    "AILA %s %s → HTTP %d (attempt %d): %s",
                    method, path, exc.code, attempt + 1, exc,
                )
            except (OSError, TimeoutError) as exc:
                _log.warning(
                    "AILA %s %s connection error (attempt %d): %s",
                    method, path, attempt + 1, exc,
                )
            if attempt < self.max_retries:
                time.sleep(delay)
                delay = min(delay * 2.0, 30.0)
        _log.error(
            "AILA %s %s gave up after %d attempts",
            method, path, self.max_retries + 1,
        )
        return False


def stack_hash_of(stack_trace: str) -> str:
    """Compute the AILA-canonical stack hash -- SHA-256 of the top frames.

    Matches the platform's expectation in fuzz_service.register_crash
    which dedupes by ``(campaign_id, stack_hash)``. The function names
    in the top-5 frames make the canonical signature; the file:line
    are excluded so the same bug across builds collapses.
    """
    if not stack_trace:
        return hashlib.sha256(b"").hexdigest()
    frames: list[str] = []
    for raw in stack_trace.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Best-effort function name extraction. Each engine formats
        # differently; the heuristic picks anything between "in" and
        # the first "(" or whitespace, falling back to the whole line.
        token = line
        if " in " in line:
            token = line.split(" in ", 1)[1]
        if "(" in token:
            token = token.split("(", 1)[0]
        token = token.strip()
        if token:
            frames.append(token)
        if len(frames) >= 5:
            break
    canonical = "\n".join(frames).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def file_head(path: Path, limit: int = 4096) -> bytes:
    """Read up to ``limit`` bytes from ``path``. Returns b'' on error."""
    try:
        with path.open("rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""
