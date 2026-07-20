"""FastAPI router for the forensics module.

Mounted at ``/forensics`` by ``ForensicsModule.route_specs()``.
Every endpoint uses ``DataEnvelope[T]`` response models, platform auth,
and rate limiting per MODULE_STANDARD and MODULE_AI_CONTEXT rules.

All list/get endpoints enforce team_id scoping via ``_team_filter`` to
prevent cross-tenant data leaks (aligned with cost/automation routers).
"""
from __future__ import annotations

import json
import logging
import math
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import delete as sa_delete
from sqlalchemy import func as sa_func
from sqlmodel import select

from aila.api.schemas.common import PaginatedResponse
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.contracts.auth import AuthContext, require_auth
from aila.platform.services.redis_pool import pool_available
from aila.platform.tasks.progress import ProgressStream
from aila.platform.uow import UnitOfWork

from .contracts import (
    AnswerCandidate,
    EvidenceItem,
    InvestigationRequest,
    MachineReadinessResult,
    NormalizedArtifact,
    ProjectCreate,
    ProjectSummary,
    PromotedLead,
    ReasoningGraphDiffResult,
    ReasoningGraphSnapshot,
    WriteUp,
 )
from .contracts.directive import AnalystDirective, AnalystDirectiveCreate
from .contracts.finding_suppression import FindingSuppression, FindingSuppressionRequest
from .contracts.investigation import AgentStep
from .contracts.retrieve import FetchRawRequest, RetrieveFileRequest
from .contracts.solid_evidence import SolidEvidence, TagInvestigationRequest
from .contracts.status import InvestigationStatus, ProjectStatus

_log = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)

__all__ = ["create_forensics_router"]


def _finding_fingerprint(f: dict[str, Any]) -> str:
    """Stable 64-char hash of a finding's identity tuple.

    Mirrors the dedup ``_key`` used inside ``list_findings`` so the same
    row on re-run produces the same fingerprint. Persisted in
    ``forensics_finding_suppressions.fingerprint`` to hide rows the
    analyst has marked false-positive.
    """
    import hashlib as _hashlib

    exe = f.get("executable")
    exe_key = exe if not isinstance(exe, (dict, list)) else json.dumps(exe, sort_keys=True)
    parts = [
        str(f.get("artifact_type") or ""),
        str(exe_key or ""),
        str(f.get("path") or ""),
        str(f.get("name") or ""),
        str(f.get("user") or ""),
    ]
    payload = "\x1f".join(parts).encode("utf-8", errors="replace")
    return _hashlib.sha256(payload).hexdigest()


def _agent_step_from_record(s: Any) -> AgentStep:
    """Project a persisted ``AgentStepRecord`` to the API contract.

    The honest investigator stores its case-model snapshot (contract,
    hypotheses, rejected, observables, provenance, expected_observation,
    submitted) as a JSON blob inside the ``reasoning`` column. We parse
    it here so the frontend can render structured panels. If parsing
    fails we fall back to treating ``reasoning`` as free text -- older
    rows written by earlier agents remain readable.
    """
    contract = None
    hypotheses: list[dict] = []
    rejected: list[dict] = []
    observables = None
    provenance = None
    expected_observation: str | None = None
    submitted = False
    reasoning_text = s.reasoning or ""
    if reasoning_text.lstrip().startswith("{"):
        try:
            blob = json.loads(reasoning_text)
        except (ValueError, TypeError):
            blob = None
        if isinstance(blob, dict):
            if isinstance(blob.get("reasoning"), str):
                reasoning_text = blob["reasoning"]
            if isinstance(blob.get("contract"), dict) and blob["contract"]:
                contract = blob["contract"]
            if isinstance(blob.get("hypotheses"), list):
                hypotheses = [h for h in blob["hypotheses"] if isinstance(h, dict)]
            if isinstance(blob.get("rejected"), list):
                rejected = [r for r in blob["rejected"] if isinstance(r, dict)]
            if isinstance(blob.get("observables"), dict) and blob["observables"]:
                observables = blob["observables"]
            if isinstance(blob.get("provenance"), dict) and blob["provenance"]:
                provenance = blob["provenance"]
            if isinstance(blob.get("expected_observation"), str) and blob["expected_observation"]:
                expected_observation = blob["expected_observation"]
            submitted = bool(blob.get("submitted", False))
    return AgentStep(
        id=s.id, step_number=s.step_number, action=s.action,
        script_content=s.script_content, command=s.command,
        stdout=s.stdout, stderr=s.stderr, exit_code=s.exit_code,
        reasoning=reasoning_text, created_at=s.created_at,
        contract=contract, hypotheses=hypotheses, rejected=rejected,
        observables=observables, provenance=provenance,
        expected_observation=expected_observation, submitted=submitted,
    )


_INV_TERMINAL_STATUSES = frozenset({"completed", "failed", "exhausted", "cancelled"})
# Only states that mean the worker CANNOT succeed from here count as
# reap-worthy. ``done`` is explicitly excluded: a worker that exits
# cleanly has either already flipped the investigation via the terminal
# ``response_emit`` state (and we're reading a stale session), or is
# about to in the next commit. Reaping on ``done`` turns benign races
# into user-visible failures like
# "Investigation auto-reaped -- worker task settled as done." which is
# a lie -- the worker succeeded.
_TASK_DEAD_STATUSES = frozenset({"failed", "dead", "cancelled"})


async def _zombie_reap_reason(session: Any, inv: Any) -> str | None:
    """Return a human-readable reason for reaping ``inv``, or ``None``.

    Read-only. Inspects the worker ``TaskRecord`` and decides whether
    the investigation row is stuck behind a worker that can no longer
    finish it. Does NOT mutate ``inv`` or write to the session -- see
    :func:`_apply_zombie_reap` for the mutation.

    Reaping is conservative:

    - ``TaskRecord`` is missing              -> reap (worker disappeared)
    - ``TaskRecord.status`` is failed/dead/cancelled -> reap
    - ``TaskRecord.status`` is ``done``      -> DO NOT reap. The worker
      finished successfully; ``response_emit`` may not have committed yet
      or this session is stale. The next GET will observe the correct
      state.
    - anything else (``queued``, ``in_progress``, ``retrying``) -> leave
      it alone; the platform reaper owns staleness via
      ``REAPER_ZOMBIE_THRESHOLD_S``.
    """
    if inv.status in _INV_TERMINAL_STATUSES:
        return None
    if inv.status not in ("pending", "running"):
        return None
    if not inv.task_id:
        return None

    from aila.platform.tasks.models import TaskRecord

    task = (await session.exec(
        select(TaskRecord).where(TaskRecord.id == inv.task_id)
    )).first()

    if task is None:
        return f"task {inv.task_id} no longer exists"
    if task.status in _TASK_DEAD_STATUSES:
        return f"worker task settled as {task.status}"
    return None


def _apply_zombie_reap(session: Any, inv: Any, reason: str) -> None:
    """Mutate ``inv`` into the auto-reaped state. Caller commits.

    Fix §49 -- split out of the old ``_reconcile_investigation_if_zombie``
    so HTTP GET handlers can advertise ``needs_reap`` without mutating
    the row inside a safe method. The mutation now happens only on the
    POST endpoint (``/reap``) the operator UI calls explicitly.
    """
    inv.status = "failed"
    if not inv.final_answer:
        inv.final_answer = f"Investigation auto-reaped -- {reason}."
    session.add(inv)
    _log.warning(
        "investigation auto-reaped inv_id=%s reason=%s", inv.id, reason,
    )


class InvestigationSummary(BaseModel):
    """Summary of an investigation run for list endpoints."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    question: str
    status: str
    attempts_used: int
    max_attempts: int | None = None
    final_answer: str | None = None
    confidence: str | None = None
    task_id: str | None = None
    parent_investigation_id: str | None = None
    # fix §49 -- GET handlers no longer mutate. When the row's worker
    # task has settled as failed/dead/cancelled (or vanished), the
    # GET surfaces ``needs_reap=True`` so the UI can show the stuck
    # state and offer a 'Reap' action that POSTs to ``/reap``. The
    # actual flip to ``failed`` happens only in the POST handler.
    needs_reap: bool = False
    needs_reap_reason: str | None = None


class RerunInvestigationRequest(BaseModel):
    """Request to rerun an investigation, carrying prior findings forward."""

    model_config = ConfigDict(extra="forbid")

    max_attempts: int | None = Field(default=None, ge=1, le=50)
    question_override: str | None = None


class InvestigationDetail(BaseModel):
    """Full investigation detail with all agent steps."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    question: str
    status: str
    attempts_used: int
    max_attempts: int
    final_answer: str | None = None
    confidence: str | None = None
    parent_investigation_id: str | None = None
    steps: list[AgentStep] = Field(default_factory=list)
    # fix §49 -- see InvestigationSummary above. Detail handler is a
    # safe GET; reap mutation lives on POST ``/reap``.
    needs_reap: bool = False
    needs_reap_reason: str | None = None


class NetworkAnalysis(BaseModel):
    """Structured PCAP analysis -- parsed rows + optional LLM commentary.

    Every field is a concrete list of typed dicts that the frontend renders
    directly. ``commentary`` is a list of ``{subject, narrative, severity}``
    objects produced by the forensics-freeflow LLM task when enabled.
    """

    model_config = ConfigDict(extra="forbid")

    stats: dict[str, Any] = Field(default_factory=dict)
    protocol_hierarchy: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    sessions: list[dict[str, Any]] = Field(default_factory=list)
    dns: list[dict[str, Any]] = Field(default_factory=list)
    suspicious_dns: list[dict[str, Any]] = Field(default_factory=list)
    http_requests: list[dict[str, Any]] = Field(default_factory=list)
    http_responses: list[dict[str, Any]] = Field(default_factory=list)
    tls_client_hellos: list[dict[str, Any]] = Field(default_factory=list)
    unusual_ports: list[dict[str, Any]] = Field(default_factory=list)
    user_agents: list[dict[str, Any]] = Field(default_factory=list)
    credentials: list[dict[str, Any]] = Field(default_factory=list)
    beacons: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    commentary: list[dict[str, Any]] = Field(default_factory=list)


class RegistryAnalysis(BaseModel):
    """Windows registry analysis result."""

    model_config = ConfigDict(extra="forbid")

    autoruns: list[dict[str, Any]] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    installed_software: list[dict[str, Any]] = Field(default_factory=list)
    user_accounts: list[dict[str, Any]] = Field(default_factory=list)
    usb_history: list[dict[str, Any]] = Field(default_factory=list)
    recent_docs: list[dict[str, Any]] = Field(default_factory=list)
    network_interfaces: list[dict[str, Any]] = Field(default_factory=list)
    shellbags: list[dict[str, Any]] = Field(default_factory=list)
    amcache: list[dict[str, Any]] = Field(default_factory=list)
    shimcache: list[dict[str, Any]] = Field(default_factory=list)
    bam: list[dict[str, Any]] = Field(default_factory=list)
    security_packages: list[dict[str, Any]] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    """A single timeline event."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    source: str
    event_type: str
    description: str
    artifact_id: str | None = None
    source_investigation_id: str | None = None
    timestamp_origin: str = "data"  # "data:<k>" | "observable:<k>"
    data: dict[str, Any] = Field(default_factory=dict)


class Occurrence(BaseModel):
    """A confident finding with no event-time.

    Same gating as ``TimelineEntry`` but for rows whose data carried no
    parseable timestamp. Surfaced separately so analysts can see "what
    we know" alongside "when it happened."
    """

    model_config = ConfigDict(extra="forbid")

    source: str
    event_type: str
    description: str
    artifact_id: str | None = None
    source_investigation_id: str | None = None
    recorded_at: str  # AILA's record-time, used only for stable sort
    data: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# Shared timestamp / suspicion helpers used by both the /timeline and
# /occurrences endpoints. Kept module-private so the two endpoints stay
# in lock-step on what counts as a "confident, suspicious finding."
# --------------------------------------------------------------------------
_TS_TIME_KEY_PATTERNS = [
    __import__("re").compile(r"(^|_)(timestamp|time|date|datetime)$"),
    __import__("re").compile(r"_(at|on|when|stamp)$"),
    __import__("re").compile(
        r"^(first|last|seen|modified|created|accessed|"
        r"started|ended|finished|written|installed|"
        r"executed|launched|deleted|run|runs)_"
    ),
    __import__("re").compile(
        r"_(modified|created|accessed|seen|written|"
        r"installed|executed|launched|deleted|"
        r"started|ended|finished|run|runs|time_epoch)$"
    ),
    __import__("re").compile(
        r"^(lnk|prefetch|registry|file|process|user|"
        r"event|log|task|service|conn|dns|http)_"
        r"(time|date|modified|created|accessed|seen|run|runs)$"
    ),
]
# Evidence-native short keys used by dissect/zeek/tshark outputs that
# don't follow the `_suffix` convention. Match them exactly (lowercase).
_TS_EXACT_KEYS = {
    "ts", "mtime", "atime", "ctime", "btime",
    "last_run", "previous_runs", "first_seen", "last_seen",
    "eventtime", "event_time", "timecreated", "time_created",
    "systemtime", "creation_time", "last_written",
    "frame_time_epoch", "frame.time_epoch",
}
_TS_LIKE = __import__("re").compile(
    r"^\s*\d{4}[-/]\d{1,2}[-/]\d{1,2}"
    r"([T\s]\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?"
    r"(Z|[+-]\d{2}:?\d{2})?)?\s*$"
)
# Accept bare UNIX epoch seconds (int or float) -- tshark's
# frame.time_epoch, dissect's raw windows FILETIME ticks after division,
# any "seconds since 1970" field. Range guard: 2001-01-01 to 2099-12-31
# so we don't mistake an arbitrary integer for a timestamp.
_TS_EPOCH_MIN = 978307200        # 2001-01-01T00:00:00Z
_TS_EPOCH_MAX = 4102444800       # 2100-01-01T00:00:00Z
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d",
    "%Y/%m/%d %H:%M:%S",
)
_TYPED_INV_ROWS = {
    "trigger_artifact", "lnk_dropper", "capa_findings",
    "process_injection", "ioc_observation", "persistence_finding",
}
_CONFIDENCE_RANK: dict[Any, int] = {
    "confirmed": 3, "high": 2, "medium": 1, "low": 0,
    "caveated": 0, "unknown": 0, "": 0, None: 0,
}
_SEVERITY_RANK: dict[Any, int] = {
    "critical": 3, "high": 2, "medium": 1, "low": 0,
    "info": 0, "informational": 0, "": 0, None: 0,
}
_BAR_LEVELS = {"low": 0, "medium": 1, "high": 2}


def _parse_ts(raw: object) -> str | None:
    from datetime import datetime
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or not _TS_LIKE.match(s):
        return None
    iso_try = s.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(iso_try)
        return s
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            datetime.strptime(s, fmt)
            return s
        except ValueError:
            continue
    return None


def _looks_time_key(k: str) -> bool:
    kl = k.lower()
    if kl in _TS_EXACT_KEYS:
        return True
    return any(p.search(kl) for p in _TS_TIME_KEY_PATTERNS)


def _parse_epoch(raw: object) -> str | None:
    """Accept UNIX epoch seconds (int or float) in a sane forensic range."""
    try:
        n = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not (_TS_EPOCH_MIN <= n <= _TS_EPOCH_MAX):
        return None
    from datetime import UTC, datetime
    return datetime.fromtimestamp(n, tz=UTC).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _coerce_event_time(raw: object) -> str | None:
    """Parse either an ISO string or a bare UNIX epoch value."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return _parse_epoch(raw)
    s = str(raw).strip()
    if not s:
        return None
    iso = _parse_ts(s)
    if iso:
        return iso
    # numeric string -> epoch fallback
    return _parse_epoch(s)


def _scan_scope(
    scope: dict[str, Any], prefix: str, out: list[tuple[str, str]]
) -> None:
    for k, v in scope.items():
        if not _looks_time_key(k):
            continue
        # Scalar case
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            ts = _coerce_event_time(v)
            if ts:
                out.append((ts, f"{prefix}{k}"))
            continue
        # List case -- e.g. prefetch's `previous_runs: [ts, ts, ts, ...]`
        if isinstance(v, list):
            for item in v:
                ts = _coerce_event_time(item)
                if ts:
                    out.append((ts, f"{prefix}{k}[]"))


def _mine_all_timestamps(payload: dict[str, Any]) -> list[tuple[str, str]]:
    """Enumerate every evidence-native event time in a single artifact row.

    The current timeline failure mode was that artifacts look like
    ``{"records": [{ts, mtime, last_run, ...}, ...]}``: all the real
    event times live **inside** ``records[]``, not at the top level.
    This walker yields one (timestamp, origin) tuple per time-bearing
    field it finds -- across ``payload`` itself, ``payload.observables``,
    and **every item in ``payload.records``**. Bare UNIX epoch ints/
    floats (e.g. ``frame.time_epoch``, dissect FILETIME→epoch) are
    normalised to ISO UTC so the timeline can sort them against
    ISO-string event times from other sources.
    """
    out: list[tuple[str, str]] = []

    # 1. Canonical top-level keys ------------------------------------------
    for k in ("timestamp", "time", "created"):
        v = payload.get(k)
        if v is None:
            continue
        ts = _coerce_event_time(v)
        if ts:
            out.append((ts, f"data:{k}"))

    # 2. Top-level heuristic keys ------------------------------------------
    _scan_scope(payload, "observable:", out)

    # 3. Nested `observables` (investigation-emitted rows) -----------------
    inner = payload.get("observables")
    if isinstance(inner, dict):
        _scan_scope(inner, "observable:observables.", out)

    # 4. `records[]` -- the big one. Every collector (prefetch, shellbags,
    #    evtx, mft, usnjrnl, runkeys, tasks, services, dns, http, ...)
    #    stores its evidence-native rows here. Each row contributes its
    #    own event-time entry (or several, when it carries created /
    #    modified / accessed separately).
    records = payload.get("records")
    if isinstance(records, list):
        for i, rec in enumerate(records):
            if isinstance(rec, dict):
                _scan_scope(rec, f"record[{i}]:", out)

    # Dedup identical (ts, origin) tuples preserving order
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for tup in out:
        if tup in seen:
            continue
        seen.add(tup)
        unique.append(tup)
    return unique


def _passes_bar(row: Any, payload: dict[str, Any], bar: int) -> bool:
    """Confidence/suspicion gate shared by /timeline and /occurrences.

    ``bar`` is an index into [low, medium, high].

    - ``low`` (0): everything goes -- the analyst wants the full
      evidence-time story (prefetch runs, shellbag opens, evtx events,
      MFT touches). Only pure dumps (``observables_snapshot``) stay
      excluded.
    - ``medium`` (1): default. Admit any collector row that carries at
      least one suspicious record (``suspicious_reasons`` marked by the
      dissect collectors) OR an explicit severity/confidence/lead
      signal; admit typed investigation rows always.
    - ``high`` (2): only confirmed agent findings + rows with explicit
      ``severity=high|critical`` / ``confidence=high|confirmed`` /
      ``lead_score ≥ 5``.
    """
    atype = row.artifact_type
    if atype == "observables_snapshot":
        return False  # pure dumps never belong on the timeline

    if row.source_investigation_id:
        if atype in _TYPED_INV_ROWS:
            return True
        if atype == "investigation_summary":
            conf = (payload.get("confidence") or "").lower()
            return _CONFIDENCE_RANK.get(conf, 0) >= bar
        return False

    # --- collector rows ---------------------------------------------------
    if bar == 0:
        return True  # "show me the whole evidence-time story"

    # Explicit signals at the artifact level
    if (row.lead_score or 0) >= (1.0 if bar == 1 else 5.0):
        return True
    sev = str(payload.get("severity") or "").lower()
    if _SEVERITY_RANK.get(sev, 0) >= max(1, bar):
        return True
    conf = str(payload.get("confidence") or "").lower()
    if _CONFIDENCE_RANK.get(conf, 0) >= max(1, bar):
        return True
    if payload.get("suspicious") is True or payload.get("malicious") is True:
        return True

    # Medium bar: also let through any collector artifact that flagged
    # at least one of its records as suspicious. Dissect's disk
    # collectors attach a ``suspicious_reasons`` list to prefetch /
    # shellbag / runkey / service / task rows when a cheap regex fires.
    # That's our "low-cost evidence story" admission path.
    if bar == 1:
        records = payload.get("records")
        if isinstance(records, list):
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                if rec.get("suspicious_reasons"):
                    return True
                if rec.get("suspicious") is True or rec.get("malicious") is True:
                    return True
    return False


_DESC_PRIORITY_KEYS: tuple[str, ...] = (
    "description",      # already humanised by the collector
    "executable",       # prefetch
    "image_path",       # services / autoruns
    "command",          # runkeys / tasks
    "path", "file_path", "full_path", "filename", "linkedfile",
    "qname",            # dns
    "host", "uri",      # http
    "sni",              # tls
    "name",             # generic
    "event_id",         # evtx
    "provider",         # evtx
    "key",              # registry
)


def _humanise_scalars(rec: dict[str, Any], limit: int = 4) -> str:
    """Join the first `limit` scalar key=value pairs as ``k=v · k=v``.

    Used as a last-resort humaniser so an analyst sees real evidence keys
    (e.g. ``ip=10.0.0.5 · bytes=41234 · dport=445``) instead of the
    Python ``dict.__repr__`` that used to leak into the timeline UI.
    """
    parts: list[str] = []
    for k, v in rec.items():
        if k in ("observables", "records", "raw_output_sample",
                 "summary_prompt", "data"):
            continue
        if v is None or v == "":
            continue
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if not s or s == "<unknown>":
                continue
            parts.append(f"{k}={s[:60]}")
            if len(parts) >= limit:
                break
    return " · ".join(parts) if parts else "(no scalar fields)"


# Per-artefact-type humaniser: maps ``artifact_type`` to a function that
# renders ``data`` into a single compact, evidence-first line. Nothing
# here dumps a raw dict.
def _desc_network_capture_stats(data: dict[str, Any]) -> str:
    s = data.get("stats") or {}
    pkts = s.get("packet_count") or s.get("packets")
    dur = s.get("duration_s") or s.get("duration")
    byt = s.get("total_bytes") or s.get("bytes")
    return f"capture -- pkts={pkts or '?'} bytes={byt or '?'} duration={dur or '?'}s"


def _desc_network_hosts(data: dict[str, Any]) -> str:
    rows = data.get("rows") or []
    return f"network hosts -- {len(rows)} unique endpoint(s)"


def _desc_network_dns(data: dict[str, Any]) -> str:
    rows = data.get("rows") or []
    return f"DNS -- {len(rows)} unique name(s)"


def _desc_network_http_requests(data: dict[str, Any]) -> str:
    rows = data.get("rows") or []
    return f"HTTP requests -- {len(rows)} record(s)"


def _desc_network_commentary(data: dict[str, Any]) -> str:
    rows = data.get("rows") or []
    return f"network commentary -- {len(rows)} bullet(s)"


def _desc_memory_table(data: dict[str, Any]) -> str:
    plugin = data.get("plugin") or data.get("type") or "memory"
    n = data.get("record_count") or len(data.get("records") or [])
    return f"{plugin} -- {n} row(s)"


def _desc_investigation_summary(data: dict[str, Any]) -> str:
    q = data.get("question") or data.get("prompt") or ""
    a = data.get("answer") or ""
    if q and a:
        return f"Q: {str(q)[:80]} -> A: {str(a)[:80]}"
    if a:
        return f"answer: {str(a)[:160]}"
    return "investigation summary"


_ROW_DESC_HUMANISERS: dict[str, Any] = {
    "capture_stats":         _desc_network_capture_stats,
    "hosts":                 _desc_network_hosts,
    "sessions":              lambda d: f"network sessions -- {len(d.get('rows') or [])} flow(s)",
    "dns":                   _desc_network_dns,
    "suspicious_dns":        lambda d: f"suspicious DNS -- {len(d.get('rows') or [])} name(s)",
    "http_requests":         _desc_network_http_requests,
    "http_responses":        lambda d: f"HTTP responses -- {len(d.get('rows') or [])} record(s)",
    "tls_client_hellos":     lambda d: f"TLS Client Hellos -- {len(d.get('rows') or [])} record(s)",
    "unusual_ports":         lambda d: f"unusual ports -- {len(d.get('rows') or [])} hit(s)",
    "user_agents":           lambda d: f"user agents -- {len(d.get('rows') or [])} unique",
    "credentials":           lambda d: f"credential frames -- {len(d.get('rows') or [])} hit(s)",
    "beacons":               lambda d: f"beacon candidates -- {len(d.get('rows') or [])} flow(s)",
    "anomalies":             lambda d: f"network anomalies -- {len(d.get('rows') or [])} kind(s)",
    "commentary":            _desc_network_commentary,
    "protocol_hierarchy":    lambda d: f"protocol hierarchy -- {len(d.get('rows') or [])} protocol(s)",
    "investigation_summary": _desc_investigation_summary,
}


def _row_description(data: dict[str, Any]) -> str:
    """Human-readable single-line description for an artefact-level event.

    Tries, in order:
      1. A type-specific humaniser (see ``_ROW_DESC_HUMANISERS``).
      2. The canonical fields used by collectors (``description``,
         ``answer``, ``value``, ``path``).
      3. Falls back to a compact scalar-only key=value join -- never the
         raw ``dict.__repr__`` that the old implementation leaked into
         the UI.
    """
    atype = data.get("type") or data.get("artifact_type") or ""
    fn = _ROW_DESC_HUMANISERS.get(str(atype))
    if fn is not None:
        try:
            out = fn(data)
            if out:
                return str(out)[:200]
        except (KeyError, TypeError, ValueError):
            pass

    for k in ("description", "info", "answer", "value", "path"):
        v = data.get(k)
        if v:
            s = str(v).strip()
            if s and s != "<unknown>":
                return s[:200]

    return _humanise_scalars(data)[:200]


def _record_description(rec: dict[str, Any]) -> str:
    """Pull the most informative identifier from a single evidence record.

    Each collector stores slightly different keys on its rows: prefetch
    has ``executable`` + ``path``, shellbags has ``path``, evtx has
    ``event_id`` + ``provider``, runkeys has ``name`` + ``command``,
    MFT has ``file_path`` + ``name``. We check the common ones in
    priority order, then fall back to a compact k=v summary rather than
    the Python dict repr the old implementation used.
    """
    for k in _DESC_PRIORITY_KEYS:
        v = rec.get(k)
        if v:
            s = str(v).strip()
            if s and s != "<unknown>":
                return s[:200]
    return _humanise_scalars(rec)[:200]


def create_forensics_router() -> APIRouter:
    """Construct and return the forensics module APIRouter."""
    router = APIRouter(tags=["forensics"])

    def _team_filter(stmt: Any, model: Any, auth: AuthContext) -> Any:
        """Apply team_id WHERE clause when the caller has a team context."""
        if auth.team_id is not None:
            stmt = stmt.where(model.team_id == auth.team_id)
        return stmt

    def _require_project_ownership(project: Any, auth: AuthContext) -> None:
        """Raise 403 if the project belongs to a different team."""
        record_team = getattr(project, "team_id", None)
        if auth.team_id is not None and record_team != auth.team_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Project is not owned by your team.",
            )

    @router.post(
        "/projects",
        response_model=DataEnvelope[ProjectSummary],
        summary="Create a new forensics project.",
        status_code=status.HTTP_201_CREATED,
    )
    @limiter.limit("30/minute")
    async def create_project(
        request: Request,
        body: ProjectCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[ProjectSummary]:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            sys_stmt = select(ManagedSystemRecord).where(ManagedSystemRecord.id == body.system_id)
            if auth.team_id is not None:
                sys_stmt = sys_stmt.where(ManagedSystemRecord.team_id == auth.team_id)
            system = (await uow.session.exec(sys_stmt)).first()
            if system is None:
                raise HTTPException(status_code=404, detail=f"System {body.system_id} not found.")

            record = ForensicsProjectRecord(
                name=body.name,
                description=body.description,
                system_id=body.system_id,
                evidence_directory=body.evidence_directory,
                analyzer_os=body.analyzer_os.value,
                project_kind=body.project_kind.value,
                status=ProjectStatus.CREATED.value,
                team_id=auth.team_id,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

        return DataEnvelope(data=ProjectSummary(
            id=record.id,
            name=record.name,
            description=record.description,
            system_id=record.system_id,
            system_name=system.name,
            evidence_directory=record.evidence_directory,
            analyzer_os=record.analyzer_os,
            project_kind=record.project_kind,
            status=record.status,
            created_at=record.created_at,
            updated_at=record.updated_at,
        ))

    @router.get(
        "/projects",
        response_model=DataEnvelope[PaginatedResponse[ProjectSummary]],
        summary="List forensics projects.",
    )
    @limiter.limit("60/minute")
    async def list_projects(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ) -> DataEnvelope[PaginatedResponse[ProjectSummary]]:
        del request

        from aila.modules.forensics.db_models import (
            ArtifactRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
            LeadRecord,
            ProjectEvidenceRecord,
        )
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            count_stmt = _team_filter(
                select(sa_func.count()).select_from(ForensicsProjectRecord),
                ForensicsProjectRecord,
                auth,
            )
            total = (await uow.session.exec(count_stmt)).one()

            query = _team_filter(
                select(ForensicsProjectRecord),
                ForensicsProjectRecord,
                auth,
            ).order_by(
                ForensicsProjectRecord.created_at.desc()
            ).offset((page - 1) * page_size).limit(page_size)
            rows = (await uow.session.exec(query)).all()

            project_ids = [r.id for r in rows]
            system_ids = [r.system_id for r in rows if r.system_id is not None]

            # One aggregated GROUP BY query per related table -- avoids the
            # N+1 trap that left the list page showing zeros for every
            # count. Each result is a dict {project_id: count} and is
            # empty when the page itself is empty.
            async def _counts_by_project(model: Any) -> dict[str, int]:
                if not project_ids:
                    return {}
                result = await uow.session.exec(
                    select(model.project_id, sa_func.count())
                    .where(model.project_id.in_(project_ids))
                    .group_by(model.project_id)
                )
                return {pid: int(n) for pid, n in result.all()}

            evidence_by_pid = await _counts_by_project(ProjectEvidenceRecord)
            artifact_by_pid = await _counts_by_project(ArtifactRecord)
            lead_by_pid = await _counts_by_project(LeadRecord)
            inv_by_pid = await _counts_by_project(InvestigationRunRecord)

            systems_by_id: dict[int, str] = {}
            if system_ids:
                system_rows = (await uow.session.exec(
                    select(ManagedSystemRecord).where(
                        ManagedSystemRecord.id.in_(system_ids)
                    )
                )).all()
                systems_by_id = {s.id: s.name for s in system_rows}

        items = [
            ProjectSummary(
                id=r.id,
                name=r.name,
                description=r.description,
                system_id=r.system_id,
                system_name=systems_by_id.get(r.system_id),
                evidence_directory=r.evidence_directory,
                analyzer_os=r.analyzer_os,
                project_kind=r.project_kind,
                status=r.status,
                evidence_count=evidence_by_pid.get(r.id, 0),
                artifact_count=artifact_by_pid.get(r.id, 0),
                lead_count=lead_by_pid.get(r.id, 0),
                investigation_count=inv_by_pid.get(r.id, 0),
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            for r in rows
        ]
        return DataEnvelope(data=PaginatedResponse(
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
            items=items,
        ))

    @router.get(
        "/projects/{project_id}",
        response_model=DataEnvelope[ProjectSummary],
        summary="Get forensics project details.",
    )
    @limiter.limit("60/minute")
    async def get_project(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[ProjectSummary]:
        del request

        from aila.modules.forensics.db_models import (
            ArtifactRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
            LeadRecord,
            ProjectEvidenceRecord,
        )
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()

            evidence_count = (await uow.session.exec(
                select(sa_func.count()).select_from(ProjectEvidenceRecord).where(
                    ProjectEvidenceRecord.project_id == project_id
                )
            )).one()
            artifact_count = (await uow.session.exec(
                select(sa_func.count()).select_from(ArtifactRecord).where(
                    ArtifactRecord.project_id == project_id
                )
            )).one()
            lead_count = (await uow.session.exec(
                select(sa_func.count()).select_from(LeadRecord).where(
                    LeadRecord.project_id == project_id
                )
            )).one()
            inv_count = (await uow.session.exec(
                select(sa_func.count()).select_from(InvestigationRunRecord).where(
                    InvestigationRunRecord.project_id == project_id
                )
            )).one()

        return DataEnvelope(data=ProjectSummary(
            id=project.id,
            name=project.name,
            description=project.description,
            system_id=project.system_id,
            system_name=system.name if system else None,
            evidence_directory=project.evidence_directory,
            analyzer_os=project.analyzer_os,
            project_kind=project.project_kind,
            status=project.status,
            evidence_count=evidence_count,
            artifact_count=artifact_count,
            lead_count=lead_count,
            investigation_count=inv_count,
            created_at=project.created_at,
            updated_at=project.updated_at,
        ))

    @router.post(
        "/projects/{project_id}/full-analysis",
        response_model=DataEnvelope[dict[str, str]],
        summary="Trigger a pre-investigation full-analysis scan of the project.",
    )
    @limiter.limit("5/minute")
    async def trigger_full_analysis(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict[str, str]]:
        """Kick off the full intake → collection → deep_analysis → ... pipeline
        so artifacts are pre-cached in the DB. Subsequent freeflow-mode
        investigations consume those artifacts instead of re-scanning."""
        from aila.api.deps import get_task_queue
        from aila.modules.forensics.db_models import ForensicsProjectRecord
        from aila.modules.forensics.workflow.task import run_forensics_analysis
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)
            if project.project_kind == "raw_directory":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Full analysis is not supported for raw_directory projects. "
                        "Ask questions via the free-flow investigator instead."
                    ),
                )
            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(status_code=404, detail="System not found.")

        integration = {
            "name": system.name, "host": system.host, "username": system.username,
            "port": system.port, "private_key_path": system.private_key_path,
            "password_secret_id": system.password_secret_id,
            "known_hosts_path": system.known_hosts_path,
            "host_key_fingerprint": system.host_key_fingerprint,
        }

        task_queue = get_task_queue("forensics", request)
        handle = await task_queue.submit(
            track="forensics",
            fn=run_forensics_analysis,
            kwargs={
                "project_id": project_id,
                "mode": "full_analysis",
                "integration": integration,
                "analyzer_os": project.analyzer_os,
                "evidence_directory": project.evidence_directory,
            },
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(data={"task_id": handle.task_id, "status": "queued"})

    @router.delete(
        "/projects/{project_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Delete a forensics project and all its data.",
    )
    @limiter.limit("10/minute")
    async def delete_project(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        del request

        from aila.modules.forensics.db_models import (
            AgentStepRecord,
            AnalystDirectiveRecord,
            AnswerCandidateRecord,
            ArtifactRecord,
            FindingSuppressionRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
            LeadRecord,
            ProjectEvidenceRecord,
            SolidEvidenceRecord,
            WriteUpRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            # Delete in dependency order to respect FK constraints.
            # select(Model.id) yields scalar strings, not record objects.
            inv_ids = list((await uow.session.exec(
                select(InvestigationRunRecord.id)
                .where(InvestigationRunRecord.project_id == project_id)
            )).all())
            for inv_id in inv_ids:
                await uow.session.exec(
                    sa_delete(AgentStepRecord).where(AgentStepRecord.investigation_id == inv_id)
                )
                await uow.session.exec(
                    sa_delete(AnswerCandidateRecord).where(
                        AnswerCandidateRecord.investigation_id == inv_id
                    )
                )
            await uow.session.exec(
                sa_delete(InvestigationRunRecord).where(InvestigationRunRecord.project_id == project_id)
            )
            await uow.session.exec(
                sa_delete(WriteUpRecord).where(WriteUpRecord.project_id == project_id)
            )
            await uow.session.exec(
                sa_delete(ArtifactRecord).where(ArtifactRecord.project_id == project_id)
            )
            await uow.session.exec(
                sa_delete(LeadRecord).where(LeadRecord.project_id == project_id)
            )
            await uow.session.exec(
                sa_delete(ProjectEvidenceRecord).where(ProjectEvidenceRecord.project_id == project_id)
            )
            # Project-scoped children whose FK is project_id -- previously
            # orphaned on delete. AnswerCandidate can be linked by project_id
            # without an investigation, so it is swept here as well.
            await uow.session.exec(
                sa_delete(AnswerCandidateRecord).where(
                    AnswerCandidateRecord.project_id == project_id
                )
            )
            await uow.session.exec(
                sa_delete(AnalystDirectiveRecord).where(
                    AnalystDirectiveRecord.project_id == project_id
                )
            )
            await uow.session.exec(
                sa_delete(FindingSuppressionRecord).where(
                    FindingSuppressionRecord.project_id == project_id
                )
            )
            await uow.session.exec(
                sa_delete(SolidEvidenceRecord).where(
                    SolidEvidenceRecord.project_id == project_id
                )
            )
            await uow.session.delete(project)
            await uow.commit()

    @router.post(
        "/projects/{project_id}/readiness-check",
        response_model=DataEnvelope[MachineReadinessResult],
        summary="Check analyzer machine readiness.",
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit("10/minute")
    async def check_readiness(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[MachineReadinessResult]:
        from aila.api.deps import get_task_queue
        from aila.modules.forensics.db_models import ForensicsProjectRecord
        from aila.modules.forensics.services.machine_readiness import MachineReadinessService
        from aila.modules.forensics.workflow.task import run_forensics_analysis
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(status_code=404, detail=f"System {project.system_id} not found.")

        from aila.config import get_settings
        service = MachineReadinessService(get_settings())
        integration = {
            "name": system.name,
            "host": system.host,
            "username": system.username,
            "port": system.port,
            "private_key_path": system.private_key_path,
            "password_secret_id": system.password_secret_id,
            "known_hosts_path": system.known_hosts_path,
            "host_key_fingerprint": system.host_key_fingerprint,
        }

        async def _log_progress(event: dict[str, Any]) -> None:
            _log.debug("Readiness check progress: %s -- %s", event.get("tool", "system"), event.get("message"))

        result = await service.check_readiness(
            integration=integration,
            system_id=system.id,
            system_name=system.name,
            analyzer_os=project.analyzer_os,
            progress_cb=_log_progress,
        )

        if result.ready:
            task_queue = get_task_queue("forensics", request)
            async with UnitOfWork() as uow:
                proj = (await uow.session.exec(
                    select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
                )).first()
                if proj and proj.status == ProjectStatus.CREATED.value:
                    proj.status = ProjectStatus.READY.value
                    uow.session.add(proj)
                    await uow.session.commit()

                    enqueue_mode = (
                        "raw_directory" if project.project_kind == "raw_directory" else "full_analysis"
                    )
                    await task_queue.submit(
                        track="forensics",
                        fn=run_forensics_analysis,
                        kwargs={
                            "project_id": project_id,
                            "mode": enqueue_mode,
                            "integration": integration,
                            "analyzer_os": project.analyzer_os,
                            "evidence_directory": project.evidence_directory,
                            "project_kind": project.project_kind,
                        },
                        user_id=auth.user_id,
                        group_id=auth.role,
                        team_id=auth.team_id,
                    )
                    _log.info(
                        "Auto-enqueued %s for project %s",
                        enqueue_mode, project_id,
                    )

        return DataEnvelope(data=result)


    @router.get(
        "/projects/{project_id}/readiness-check/stream",
        summary="Stream readiness check progress via SSE.",
        response_class=StreamingResponse,
        responses={
            200: {
                "description": "SSE stream of per-tool readiness check progress",
                "content": {"text/event-stream": {"schema": {"type": "string"}}},
            }
        },
    )
    @limiter.limit("10/minute")
    async def stream_readiness_check(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        """Run the readiness check and stream per-tool progress as SSE.

        Each event is a JSON object with fields:
        - ``stage``: ``"start"`` | ``"checking"`` | ``"installing"`` | ``"tool_done"`` | ``"done"``
        - ``tool``: tool name (absent on start/done events)
        - ``status``: ``"installed"`` | ``"missing"`` | ``"skipped"`` (on tool_done)
        - ``message``: human-readable description
        - ``total``: total tool count (on start/done)
        - ``installed_count`` / ``missing_count``: tallies (on done)
        - ``ready``: bool (on done)
        """
        from aila.api.deps import get_task_queue
        from aila.modules.forensics.db_models import ForensicsProjectRecord
        from aila.modules.forensics.services.machine_readiness import MachineReadinessService
        from aila.storage.db_models import ManagedSystemRecord
        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(status_code=404, detail=f"System {project.system_id} not found.")

        integration = {
            "name": system.name,
            "host": system.host,
            "username": system.username,
            "port": system.port,
            "private_key_path": system.private_key_path,
            "password_secret_id": system.password_secret_id,
            "known_hosts_path": system.known_hosts_path,
            "host_key_fingerprint": system.host_key_fingerprint,
        }

        # Count total tools to include in start event
        import json as _json
        from pathlib import Path

        from aila.config import get_settings
        from aila.platform.sse import stream_from_worker
        _data_path = Path(__file__).parent / "data" / "tool_requirements.json"
        _reqs = _json.loads(_data_path.read_text(encoding="utf-8"))
        total_tools = sum(len(v) for v in _reqs.values())

        async def _worker(progress_cb: Any) -> None:
            svc = MachineReadinessService(get_settings())
            result = await svc.check_readiness(
                integration=integration,
                system_id=system.id,
                system_name=system.name,
                analyzer_os=project.analyzer_os,
                progress_cb=progress_cb,
            )
            if result.ready:
                task_queue = get_task_queue("forensics", request)
                async with UnitOfWork() as _uow:
                    proj = (await _uow.session.exec(
                        select(ForensicsProjectRecord).where(
                            ForensicsProjectRecord.id == project_id
                        )
                    )).first()
                    if proj and proj.status == ProjectStatus.CREATED.value:
                        proj.status = ProjectStatus.READY.value
                        _uow.session.add(proj)
                        await _uow.session.commit()

                        from aila.modules.forensics.workflow.task import run_forensics_analysis
                        enqueue_mode = (
                            "raw_directory"
                            if project.project_kind == "raw_directory"
                            else "full_analysis"
                        )
                        await task_queue.submit(
                            track="forensics",
                            fn=run_forensics_analysis,
                            kwargs={
                                "project_id": project_id,
                                "mode": enqueue_mode,
                                "integration": integration,
                                "analyzer_os": project.analyzer_os,
                                "evidence_directory": project.evidence_directory,
                                "project_kind": project.project_kind,
                            },
                            user_id=auth.user_id,
                            group_id=auth.role,
                            team_id=auth.team_id,
                        )

            await progress_cb({
                "stage": "done",
                "ready": result.ready,
                "installed_count": sum(1 for t in result.tools if t.status == "installed"),
                "missing_count": sum(1 for t in result.tools if t.status == "missing"),
                "total": len(result.tools),
                "message": result.message,
            })

        return StreamingResponse(
            stream_from_worker(
                _worker,
                start_event={
                    "stage": "start",
                    "total": total_tools,
                    "os": project.analyzer_os,
                    "message": f"Starting readiness check on {system.name} ({project.analyzer_os})",
                },
            ),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @router.get(
        "/projects/{project_id}/evidence",
        response_model=DataEnvelope[list[EvidenceItem]],
        summary="List evidence files for a project.",
    )
    @limiter.limit("60/minute")
    async def list_evidence(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[EvidenceItem]]:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, ProjectEvidenceRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(ProjectEvidenceRecord).where(ProjectEvidenceRecord.project_id == project_id)
            )).all()

        items = [
            EvidenceItem(
                id=r.id,
                file_path=r.file_path,
                evidence_type=r.evidence_type,
                file_hash_sha256=r.file_hash_sha256,
                size_bytes=r.size_bytes,
            )
            for r in rows
        ]
        return DataEnvelope(data=items)

    @router.get(
        "/projects/{project_id}/findings",
        response_model=DataEnvelope[list[dict[str, Any]]],
        summary="Flat list of concrete suspicious findings extracted from artifacts.",
    )
    @limiter.limit("60/minute")
    async def list_findings(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[dict[str, Any]]]:
        """Walk every artifact's ``records[]``, pull rows tagged
        ``suspicious_reasons``, return them as a flat table the UI can render
        as the auto-findings view."""
        from aila.modules.forensics.db_models import (
            ArtifactRecord,
            FindingSuppressionRecord,
            ForensicsProjectRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)
            arts = (await uow.session.exec(
                select(ArtifactRecord).where(ArtifactRecord.project_id == project_id)
            )).all()
            suppressed_fps = set((await uow.session.exec(
                select(FindingSuppressionRecord.fingerprint).where(
                    FindingSuppressionRecord.project_id == project_id,
                )
            )).all())

        findings: list[dict[str, Any]] = []
        for art in arts:
            try:
                data = json.loads(art.data_json) if art.data_json else {}
            except (json.JSONDecodeError, TypeError):
                continue
            records = data.get("records") if isinstance(data, dict) else None
            if not isinstance(records, list):
                continue
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                sus = rec.get("suspicious_reasons")
                if not sus:
                    continue
                executable = rec.get("executable") or rec.get("command") or rec.get("image_path")
                if isinstance(executable, dict):
                    executable = executable.get("executable")
                path = rec.get("path") or rec.get("file_path")
                name = rec.get("name")
                findings.append({
                    "artifact_type": art.artifact_type,
                    "artifact_family": art.artifact_family,
                    "source_tool": art.source_tool,
                    "suspicious_reasons": sus if isinstance(sus, list) else [str(sus)],
                    "executable": executable,
                    "path": path,
                    "name": name,
                    "last_run": rec.get("last_run") or rec.get("ts"),
                    "run_count": rec.get("run_count"),
                    "user": rec.get("username") or rec.get("user_id"),
                    "raw_record": rec,
                })

        # Dedup: collapse identical findings that come from running the same
        # collector against multiple disks (or the same disk's re-runs). The
        # identity key is the artifact type + the concrete evidence fields --
        # two runkey rows pointing at the same cmd.exe with the same user are
        # the same finding, not two findings.
        seen: dict[str, dict[str, Any]] = {}
        for f in findings:
            fp = _finding_fingerprint(f)
            f["fingerprint"] = fp
            existing = seen.get(fp)
            if existing is None:
                f["occurrences"] = 1
                seen[fp] = f
            else:
                existing["occurrences"] = existing.get("occurrences", 1) + 1
                # Merge suspicious_reasons from duplicates (union).
                existing_reasons = set(existing["suspicious_reasons"])
                for r in f["suspicious_reasons"]:
                    if r not in existing_reasons:
                        existing["suspicious_reasons"].append(r)
                        existing_reasons.add(r)

        deduped = [f for fp, f in seen.items() if fp not in suppressed_fps]
        deduped.sort(key=lambda f: -len(f["suspicious_reasons"]))
        return DataEnvelope(data=deduped)

    @router.get(
        "/projects/{project_id}/artifacts",
        response_model=DataEnvelope[PaginatedResponse[NormalizedArtifact]],
        summary="Query normalized artifacts for a project.",
    )
    @limiter.limit("60/minute")
    async def list_artifacts(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        artifact_family: str | None = Query(default=None),
        artifact_type: str | None = Query(default=None),
        source: str | None = Query(
            default=None,
            description=(
                "Provenance filter. One of: 'investigations' (rows the agent "
                "wrote on answer submit), 'collectors' (intake + full-analysis), "
                "or omit for all rows."
            ),
        ),
        investigation_id: str | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=250),
    ) -> DataEnvelope[PaginatedResponse[NormalizedArtifact]]:
        del request

        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            where_clause = ArtifactRecord.project_id == project_id
            base_where = select(ArtifactRecord).where(where_clause)
            count_base = select(sa_func.count()).select_from(ArtifactRecord).where(where_clause)
            if artifact_family:
                base_where = base_where.where(ArtifactRecord.artifact_family == artifact_family)
                count_base = count_base.where(ArtifactRecord.artifact_family == artifact_family)
            if artifact_type:
                base_where = base_where.where(ArtifactRecord.artifact_type == artifact_type)
                count_base = count_base.where(ArtifactRecord.artifact_type == artifact_type)
            if source == "investigations":
                base_where = base_where.where(ArtifactRecord.source_investigation_id.is_not(None))  # type: ignore[union-attr]
                count_base = count_base.where(ArtifactRecord.source_investigation_id.is_not(None))  # type: ignore[union-attr]
            elif source == "collectors":
                base_where = base_where.where(ArtifactRecord.source_investigation_id.is_(None))  # type: ignore[union-attr]
                count_base = count_base.where(ArtifactRecord.source_investigation_id.is_(None))  # type: ignore[union-attr]
            if investigation_id:
                base_where = base_where.where(ArtifactRecord.source_investigation_id == investigation_id)
                count_base = count_base.where(ArtifactRecord.source_investigation_id == investigation_id)

            total = (await uow.session.exec(count_base)).one()
            rows = (await uow.session.exec(
                base_where.offset((page - 1) * page_size).limit(page_size)
            )).all()

        items = [
            NormalizedArtifact(
                id=r.id,
                project_id=r.project_id,
                artifact_family=r.artifact_family,
                artifact_type=r.artifact_type,
                source_tool=r.source_tool,
                source_evidence_id=r.source_evidence_id,
                source_investigation_id=r.source_investigation_id,
                data=json.loads(r.data_json),
                lead_score=r.lead_score,
            )
            for r in rows
        ]
        return DataEnvelope(data=PaginatedResponse(
            total=total, page=page, page_size=page_size,
            pages=max(1, math.ceil(total / page_size)), items=items,
        ))

    @router.get(
        "/projects/{project_id}/leads",
        response_model=DataEnvelope[list[PromotedLead]],
        summary="Get top promoted leads for a project.",
    )
    @limiter.limit("60/minute")
    async def list_leads(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        limit: int = Query(default=20, ge=1, le=100),
    ) -> DataEnvelope[list[PromotedLead]]:
        del request

        from aila.modules.forensics.contracts.artifact import LeadEvidence
        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord, LeadRecord
        from aila.modules.forensics.workflow.states.promotion import _build_reason

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(LeadRecord)
                .where(LeadRecord.project_id == project_id)
                .order_by(LeadRecord.score.desc())
                .limit(limit)
            )).all()

            # Recompute reason + evidence live from the backing artifact so
            # stale DB rows (from promotion runs that predate the evidence
            # extractor) still surface concrete context to the UI.
            artifact_ids = [r.artifact_id for r in rows]
            artifacts_by_id: dict[str, ArtifactRecord] = {}
            if artifact_ids:
                arts = (await uow.session.exec(
                    select(ArtifactRecord).where(ArtifactRecord.id.in_(artifact_ids))  # type: ignore[attr-defined]
                )).all()
                artifacts_by_id = {a.id: a for a in arts}

        items: list[PromotedLead] = []
        for r in rows:
            art = artifacts_by_id.get(r.artifact_id)
            if art is not None:
                live_reason, live_evidence = _build_reason(art, r.score)
                evidence_models = [
                    LeadEvidence(keyword=e["keyword"], path=e["path"], excerpt=e["excerpt"])
                    for e in live_evidence
                ]
                artifact_type = art.artifact_type
                source_tool = art.source_tool
            else:
                live_reason = r.reason
                evidence_models = []
                artifact_type = ""
                source_tool = None

            items.append(PromotedLead(
                id=r.id,
                project_id=r.project_id,
                artifact_id=r.artifact_id,
                score=r.score,
                reason=live_reason,
                artifact_family=r.artifact_family,
                artifact_type=artifact_type,
                source_tool=source_tool,
                evidence=evidence_models,
                related_artifact_ids=json.loads(r.related_artifact_ids_json),
                question_families=json.loads(r.question_families_json),
            ))
        return DataEnvelope(data=items)

    @router.post(
        "/projects/{project_id}/investigate",
        response_model=DataEnvelope[InvestigationSummary],
        summary="Start a free-flow investigation.",
        status_code=status.HTTP_202_ACCEPTED,
    )
    @limiter.limit("10/minute")
    async def start_investigation(
        request: Request,
        project_id: str,
        body: InvestigationRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[InvestigationSummary]:

        from aila.api.deps import get_task_queue
        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
        from aila.modules.forensics.workflow.task import run_forensics_investigation
        from aila.storage.db_models import ManagedSystemRecord

        task_queue = get_task_queue("forensics", request)

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(
                    status_code=status.HTTP_424_FAILED_DEPENDENCY,
                    detail=f"Analyzer system {project.system_id} no longer exists.",
                )

            record = InvestigationRunRecord(
                project_id=project_id,
                question=body.question,
                status="pending",
                max_attempts=body.max_attempts,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

            integration = {
                "name": system.name,
                "host": system.host,
                "username": system.username,
                "port": system.port,
                "private_key_path": system.private_key_path,
                "password_secret_id": system.password_secret_id,
                "known_hosts_path": system.known_hosts_path,
                "host_key_fingerprint": system.host_key_fingerprint,
            }

        try:
            handle = await task_queue.submit(
                track="forensics",
                fn=run_forensics_investigation,
                kwargs={
                    "investigation_id": record.id,
                    "project_id": project_id,
                    "question": body.question,
                    "max_attempts": body.max_attempts,
                    "integration": integration,
                    "analyzer_os": project.analyzer_os,
                    "evidence_directory": project.evidence_directory,
                    # The dispatcher's mode_selection uses this to pick
                    # FORENSICS_FREEFLOW_V1 (agentic plan-and-execute Q&A)
                    # instead of FORENSICS_FULL_ANALYSIS_V1 (scheduled-scan
                    # pipeline). An investigation has a question, so the
                    # freeflow agent is what should run.
                    "mode": "freeflow",
                },
                user_id=auth.user_id,
                group_id=auth.role,
                team_id=auth.team_id,
            )
            async with UnitOfWork() as uow:
                inv = (await uow.session.exec(
                    select(InvestigationRunRecord).where(InvestigationRunRecord.id == record.id)
                )).first()
                if inv is not None:
                    inv.task_id = handle.task_id
                    uow.session.add(inv)
                    await uow.session.commit()
                    await uow.session.refresh(inv)
                    record = inv
        except (RuntimeError, OSError, ValueError) as exc:
            _log.exception(
                "Failed to enqueue investigation %s: %s",
                record.id, exc,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to enqueue investigation task. Try again later.",
            )

        return DataEnvelope(data=InvestigationSummary(
            id=record.id,
            project_id=record.project_id,
            question=record.question,
            status=record.status,
            attempts_used=record.attempts_used,
            max_attempts=record.max_attempts,
            task_id=record.task_id,
            parent_investigation_id=record.parent_investigation_id,
        ))

    @router.post(
        "/projects/{project_id}/investigations/{investigation_id}/rerun",
        response_model=DataEnvelope[InvestigationSummary],
        summary="Rerun an investigation, carrying prior findings forward.",
        status_code=status.HTTP_201_CREATED,
    )
    @limiter.limit("20/minute")
    async def rerun_investigation(
        request: Request,
        project_id: str,
        investigation_id: str,
        body: RerunInvestigationRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[InvestigationSummary]:
        """Start a new investigation enriched with the parent attempt.

        The new run carries forward the parent's per-step persisted
        observables and gets a one-shot prompt block summarising the
        prior outcome. The parent's submitted answer (if any) is treated
        as a hypothesis the agent must verify, not as ground truth.
        """
        from aila.api.deps import get_task_queue
        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            InvestigationRunRecord,
        )
        from aila.modules.forensics.workflow.task import run_forensics_investigation
        from aila.storage.db_models import ManagedSystemRecord

        task_queue = get_task_queue("forensics", request)

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            parent = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == investigation_id,
                    InvestigationRunRecord.project_id == project_id,
                )
            )).first()
            if parent is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Investigation {investigation_id} not found in project.",
                )
            if parent.status in {"pending", "running"}:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Cannot rerun while parent attempt is still in flight "
                        f"(status={parent.status}). Wait for it to complete or stop it."
                    ),
                )

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(
                    status_code=status.HTTP_424_FAILED_DEPENDENCY,
                    detail=f"Analyzer system {project.system_id} no longer exists.",
                )

            new_question = (body.question_override or parent.question).strip()
            if not new_question:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot rerun: question is empty and no override provided.",
                )
            new_max = body.max_attempts or parent.max_attempts

            record = InvestigationRunRecord(
                project_id=project_id,
                question=new_question,
                status="pending",
                max_attempts=new_max,
                parent_investigation_id=parent.id,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

            integration = {
                "name": system.name,
                "host": system.host,
                "username": system.username,
                "port": system.port,
                "private_key_path": system.private_key_path,
                "password_secret_id": system.password_secret_id,
                "known_hosts_path": system.known_hosts_path,
                "host_key_fingerprint": system.host_key_fingerprint,
            }

        try:
            handle = await task_queue.submit(
                track="forensics",
                fn=run_forensics_investigation,
                kwargs={
                    "investigation_id": record.id,
                    "project_id": project_id,
                    "question": new_question,
                    "max_attempts": new_max,
                    "integration": integration,
                    "analyzer_os": project.analyzer_os,
                    "evidence_directory": project.evidence_directory,
                    "mode": "freeflow",
                    "parent_investigation_id": parent.id,
                },
                user_id=auth.user_id,
                group_id=auth.role,
                team_id=auth.team_id,
            )
            async with UnitOfWork() as uow2:
                inv = (await uow2.session.exec(
                    select(InvestigationRunRecord).where(InvestigationRunRecord.id == record.id)
                )).first()
                if inv is not None:
                    inv.task_id = handle.task_id
                    uow2.session.add(inv)
                    await uow2.session.commit()
                    await uow2.session.refresh(inv)
                    record = inv
        except (RuntimeError, OSError, ValueError) as exc:
            _log.exception("Failed to enqueue rerun for parent %s: %s", parent.id, exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to enqueue rerun task. Try again later.",
            ) from exc

        return DataEnvelope(data=InvestigationSummary(
            id=record.id,
            project_id=record.project_id,
            question=record.question,
            status=record.status,
            attempts_used=record.attempts_used,
            max_attempts=record.max_attempts,
            task_id=record.task_id,
            parent_investigation_id=record.parent_investigation_id,
        ))

    @router.get(
        "/projects/{project_id}/investigations",
        response_model=DataEnvelope[list[InvestigationSummary]],
        summary="List investigation runs for a project.",
    )
    @limiter.limit("60/minute")
    async def list_investigations(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[InvestigationSummary]]:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = list((await uow.session.exec(
                select(InvestigationRunRecord)
                .where(InvestigationRunRecord.project_id == project_id)
                .order_by(InvestigationRunRecord.created_at.desc())
            )).all())

            # fix §49 -- GET no longer mutates. Build per-row needs_reap
            # flags read-only; the operator UI calls POST /reap to
            # trigger the actual status flip.
            reap_reasons: dict[str, str] = {}
            for inv in rows:
                reason = await _zombie_reap_reason(uow.session, inv)
                if reason is not None:
                    reap_reasons[inv.id] = reason

        return DataEnvelope(data=[
            InvestigationSummary(
                id=r.id, project_id=r.project_id, question=r.question,
                status=r.status, attempts_used=r.attempts_used,
                max_attempts=r.max_attempts,
                final_answer=r.final_answer, confidence=r.confidence,
                parent_investigation_id=r.parent_investigation_id,
                needs_reap=r.id in reap_reasons,
                needs_reap_reason=reap_reasons.get(r.id),
            )
            for r in rows
        ])

    @router.get(
        "/projects/{project_id}/investigations/{investigation_id}",
        response_model=DataEnvelope[InvestigationDetail],
        summary="Get investigation detail with agent steps.",
    )
    @limiter.limit("60/minute")
    async def get_investigation(
        request: Request,
        project_id: str,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[InvestigationDetail]:
        del request

        from aila.modules.forensics.db_models import (
            AgentStepRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
            )).first()
            if inv is None or inv.project_id != project_id:
                raise HTTPException(status_code=404, detail="Investigation not found.")

            # fix §49 -- read-only zombie check; mutation now lives on
            # POST /reap so this GET stays a safe method.
            reap_reason = await _zombie_reap_reason(uow.session, inv)

            step_rows = (await uow.session.exec(
                select(AgentStepRecord)
                .where(AgentStepRecord.investigation_id == investigation_id)
                .order_by(AgentStepRecord.step_number)
            )).all()

        steps = [_agent_step_from_record(s) for s in step_rows]
        return DataEnvelope(data=InvestigationDetail(
            id=inv.id, project_id=inv.project_id, question=inv.question,
            status=inv.status, attempts_used=inv.attempts_used,
            max_attempts=inv.max_attempts, final_answer=inv.final_answer,
            confidence=inv.confidence,
            parent_investigation_id=inv.parent_investigation_id,
            steps=steps,
            needs_reap=reap_reason is not None,
            needs_reap_reason=reap_reason,
        ))

    @router.post(
        "/projects/{project_id}/investigations/{investigation_id}/reap",
        response_model=DataEnvelope[InvestigationSummary],
        summary="Force-flip a zombie investigation to ``failed``.",
    )
    @limiter.limit("30/minute")
    async def reap_investigation(
        request: Request,
        project_id: str,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[InvestigationSummary]:
        """Operator-initiated zombie reap (§49).

        The GET handlers expose ``needs_reap`` read-only. When the
        operator confirms the row is stuck the UI POSTs here, which
        re-checks the same conservative predicate as the GETs and,
        only if the predicate still holds, flips ``inv.status`` to
        ``failed`` and writes an audit-friendly ``final_answer``.

        Replaces the auto-reap-on-GET behavior that violated the HTTP
        safe-method contract. A platform-level cron sweeper is still
        responsible for stale rows whose UI never gets visited.
        """
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
            )).first()
            if inv is None or inv.project_id != project_id:
                raise HTTPException(status_code=404, detail="Investigation not found.")

            reason = await _zombie_reap_reason(uow.session, inv)
            if reason is None:
                # Not a zombie. Return 409 -- the client's view was
                # stale, the row is fine.
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Investigation is not in a reapable state. "
                        "Refresh and check needs_reap."
                    ),
                )
            _apply_zombie_reap(uow.session, inv, reason)
            await uow.commit()
            await uow.session.refresh(inv)

        return DataEnvelope(data=InvestigationSummary(
            id=inv.id, project_id=inv.project_id, question=inv.question,
            status=inv.status, attempts_used=inv.attempts_used,
            max_attempts=inv.max_attempts,
            final_answer=inv.final_answer, confidence=inv.confidence,
            task_id=inv.task_id,
            parent_investigation_id=inv.parent_investigation_id,
            needs_reap=False,
            needs_reap_reason=None,
        ))

    @router.get(
        "/projects/{project_id}/investigations/{investigation_id}/reasoning-graphs",
        response_model=DataEnvelope[list[ReasoningGraphSnapshot]],
        summary="List durable reasoning graph snapshots for an investigation.",
    )
    @limiter.limit("60/minute")
    async def list_reasoning_graphs(
        request: Request,
        project_id: str,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[ReasoningGraphSnapshot]]:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
        from aila.platform.services.factory import ServiceFactory

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
            )).first()
            if inv is None or inv.project_id != project_id:
                raise HTTPException(status_code=404, detail="Investigation not found.")

        rows = await ServiceFactory().reasoning_graphs.list_snapshots(
            module_id="forensics",
            subject_kind="investigation",
            subject_id=investigation_id,
        )
        return DataEnvelope(data=[
            ReasoningGraphSnapshot(
                id=row.id,
                run_id=row.run_id,
                module_id=row.module_id,
                subject_kind=row.subject_kind,
                subject_id=row.subject_id,
                step_number=row.step_number,
                strategy_family=row.strategy_family,
                graph=row.graph_json,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        ])

    @router.get(
        "/projects/{project_id}/investigations/{investigation_id}/reasoning-graphs/diff",
        response_model=DataEnvelope[ReasoningGraphDiffResult],
        summary="Diff two reasoning graph snapshots for an investigation.",
    )
    @limiter.limit("60/minute")
    async def diff_reasoning_graphs(
        request: Request,
        project_id: str,
        investigation_id: str,
        from_step: int = Query(..., ge=1),
        to_step: int = Query(..., ge=1),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[ReasoningGraphDiffResult]:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
        from aila.platform.services.factory import ServiceFactory

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
            )).first()
            if inv is None or inv.project_id != project_id:
                raise HTTPException(status_code=404, detail="Investigation not found.")

        diff = await ServiceFactory().reasoning_graphs.diff_snapshots(
            module_id="forensics",
            subject_kind="investigation",
            subject_id=investigation_id,
            from_step=from_step,
            to_step=to_step,
        )
        return DataEnvelope(
            data=ReasoningGraphDiffResult(
                investigation_id=investigation_id,
                diff=diff,
            )
        )


    @router.get(
        "/projects/{project_id}/investigations/{investigation_id}/events",
        summary="Stream investigation progress via SSE.",
        response_class=StreamingResponse,
        responses={
            200: {
                "description": "SSE event stream with investigation progress updates",
                "content": {
                    "text/event-stream": {
                        "schema": {"type": "string"},
                    },
                },
            },
        },
    )
    @limiter.limit("30/minute")
    async def stream_investigation_events(
        request: Request,
        project_id: str,
        investigation_id: str,
        last_id: str = Query(default="0"),
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        """Stream investigation agent progress via Server-Sent Events.

        Replays past events on connect, then streams live updates until
        the investigation reaches a terminal state (completed / failed).
        """
        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
            )).first()
            if inv is None or inv.project_id != project_id:
                raise HTTPException(status_code=404, detail="Investigation not found.")

        task_id = inv.task_id

        if not pool_available() or not task_id:
            async def _no_stream() -> AsyncGenerator[str, None]:
                msg = json.dumps(
                    {"message": "No progress stream available -- Redis not configured or task not yet queued"}
                )
                yield f"data: {msg}\n\n"

            return StreamingResponse(
                _no_stream(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        _INV_TERMINAL = frozenset({"completed", "failed"})

        async def _fetch_inv_status() -> str | None:
            async with UnitOfWork() as _uow:
                r = (await _uow.session.exec(
                    select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
                )).first()
                return r.status if r else None

        async def _inv_sse_generator() -> AsyncGenerator[str, None]:
            stream = ProgressStream()

            yield f"data: {json.dumps({'stage': 'stream', 'message': 'Connected', 'percent': 0})}\n\n"

            resume_from = last_id
            latest_stage = "queued"
            try:
                catchup_events = await stream.catchup(task_id, last_id)
                for event in catchup_events:
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("stage"):
                        latest_stage = event["stage"]
                resume_from = "$"
            except (RuntimeError, OSError, TimeoutError, ConnectionError) as exc:
                _log.warning("Investigation SSE catchup failed for %s: %s", task_id, exc)

            current_status = await _fetch_inv_status()
            if current_status in _INV_TERMINAL:
                yield f"event: done\ndata: {json.dumps({'status': current_status})}\n\n"
                return

            async for event in stream.stream_events(task_id, resume_from):
                if event.get("type") == "ping":
                    current_status = await _fetch_inv_status()
                    if current_status in _INV_TERMINAL:
                        yield f"event: done\ndata: {json.dumps({'status': current_status})}\n\n"
                        return
                    yield f"data: {json.dumps({'stage': 'heartbeat', 'message': f'Investigation running (stage={latest_stage})', 'percent': None})}\n\n"
                    continue

                yield f"data: {json.dumps(event)}\n\n"
                if event.get("stage"):
                    latest_stage = event["stage"]
                if event.get("stage") in _INV_TERMINAL:
                    yield f"event: done\ndata: {json.dumps({'status': event['stage']})}\n\n"
                    return

        return StreamingResponse(
            _inv_sse_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @router.get(
        "/projects/{project_id}/answers",
        response_model=DataEnvelope[list[AnswerCandidate]],
        summary="List all answered questions for a project.",
    )
    @limiter.limit("60/minute")
    async def list_answers(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[AnswerCandidate]]:
        del request

        from aila.modules.forensics.db_models import AnswerCandidateRecord, ForensicsProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(AnswerCandidateRecord)
                .where(AnswerCandidateRecord.project_id == project_id)
                .order_by(AnswerCandidateRecord.created_at.desc())
            )).all()

        return DataEnvelope(data=[
            AnswerCandidate(
                id=r.id, project_id=r.project_id,
                investigation_id=r.investigation_id,
                question_text=r.question_text, answer_text=r.answer_text,
                confidence=r.confidence, primary_artifact_id=r.primary_artifact_id,
                corroboration=json.loads(r.corroboration_json),
                format_hint=r.format_hint, created_at=r.created_at,
            )
            for r in rows
        ])

    @router.get(
        "/projects/{project_id}/writeups",
        response_model=DataEnvelope[list[WriteUp]],
        summary="List write-ups for a project.",
    )
    @limiter.limit("60/minute")
    async def list_writeups(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[WriteUp]]:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, WriteUpRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(WriteUpRecord)
                .where(WriteUpRecord.project_id == project_id)
                .order_by(WriteUpRecord.created_at.desc())
            )).all()

        return DataEnvelope(data=[
            WriteUp(
                id=r.id, project_id=r.project_id,
                investigation_id=r.investigation_id,
                title=r.title, content_markdown=r.content_markdown,
                methodology=r.methodology,
                artifacts_referenced=json.loads(r.artifacts_referenced_json),
                created_at=r.created_at,
            )
            for r in rows
        ])

    def _slugify(text: str, max_len: int = 48) -> str:
        import re as _re
        s = _re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip()).strip("-")
        return (s[:max_len] or "untitled").lower()

    def _writeup_markdown(
        writeup,
        project,
        question: str | None,
    ) -> str:
        stamp = (
            writeup.created_at.strftime("%Y-%m-%d %H:%M UTC")
            if writeup.created_at else "unknown"
        )
        lines: list[str] = [
            f"# {writeup.title}",
            "",
            f"**Project:** {project.name}  ",
            f"**Project ID:** `{project.id}`  ",
        ]
        if writeup.investigation_id:
            lines.append(f"**Investigation ID:** `{writeup.investigation_id}`  ")
        if question:
            lines.append(f"**Question:** {question}  ")
        lines.extend([
            f"**Generated:** {stamp}  ",
            "",
            "---",
            "",
        ])
        if writeup.methodology:
            lines.extend(["## Methodology", "", writeup.methodology, "", "---", ""])
        lines.append(writeup.content_markdown or "_(empty)_")
        refs = json.loads(writeup.artifacts_referenced_json or "[]")
        if refs:
            lines.extend(["", "---", "", "## Referenced Artifacts", ""])
            for a in refs:
                lines.append(f"- `{a}`")
        return "\n".join(lines) + "\n"

    @router.get(
        "/projects/{project_id}/writeups/{writeup_id}.md",
        response_class=StreamingResponse,
        summary="Download a single write-up as a Markdown file.",
    )
    @limiter.limit("60/minute")
    async def download_writeup(
        request: Request,
        project_id: str,
        writeup_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        del request

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            InvestigationRunRecord,
            WriteUpRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            writeup = (await uow.session.exec(
                select(WriteUpRecord).where(
                    WriteUpRecord.project_id == project_id,
                    WriteUpRecord.id == writeup_id,
                )
            )).first()
            if writeup is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Write-up {writeup_id} not found on project {project_id}.",
                )

            question: str | None = None
            if writeup.investigation_id:
                inv = (await uow.session.exec(
                    select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == writeup.investigation_id
                    )
                )).first()
                if inv is not None:
                    question = inv.question

            md = _writeup_markdown(writeup, project, question)

        fname = f"{_slugify(project.name)}-{_slugify(writeup.title)}.md"
        return StreamingResponse(
            iter([md.encode("utf-8")]),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @router.get(
        "/projects/{project_id}/writeups.md",
        response_class=StreamingResponse,
        summary="Download all write-ups for the project as a single Markdown bundle.",
    )
    @limiter.limit("30/minute")
    async def download_writeups_bundle(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        del request

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            InvestigationRunRecord,
            WriteUpRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(WriteUpRecord)
                .where(WriteUpRecord.project_id == project_id)
                .order_by(WriteUpRecord.created_at.asc())
            )).all()

            inv_ids = {r.investigation_id for r in rows if r.investigation_id}
            questions: dict[str, str] = {}
            if inv_ids:
                inv_rows = (await uow.session.exec(
                    select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id.in_(list(inv_ids))  # type: ignore[union-attr]
                    )
                )).all()
                questions = {i.id: i.question for i in inv_rows}

        chunks: list[str] = [
            f"# {project.name} -- Forensics Write-ups",
            "",
            f"**Project ID:** `{project.id}`  ",
            f"**Write-up count:** {len(rows)}  ",
            "",
            "---",
            "",
        ]
        if not rows:
            chunks.append("_No write-ups produced yet._")
        else:
            for idx, r in enumerate(rows, 1):
                chunks.append(
                    _writeup_markdown(r, project, questions.get(r.investigation_id or ""))
                )
                if idx < len(rows):
                    chunks.append("\n\n---\n\n")
        md = "\n".join(chunks) + "\n"

        fname = f"{_slugify(project.name)}-writeups.md"
        return StreamingResponse(
            iter([md.encode("utf-8")]),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @router.get(
        "/projects/{project_id}/pcap/carved/{sha256}",
        response_class=StreamingResponse,
        summary="Download a file carved from a pcap by the Zeek stage.",
    )
    @limiter.limit("30/minute")
    async def download_carved_file(
        request: Request,
        project_id: str,
        sha256: str,
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        del request

        from aila.config import get_settings
        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord
        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        sha_norm = (sha256 or "").lower().strip()
        if not sha_norm or len(sha_norm) not in (40, 64):
            raise HTTPException(status_code=400, detail="Invalid sha256.")

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.project_id == project_id,
                    ArtifactRecord.artifact_type == "carved_file",
                )
            )).all()

        match: dict[str, Any] | None = None
        for r in rows:
            try:
                d = json.loads(r.data_json or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            if str(d.get("sha256") or "").lower() == sha_norm:
                match = d
                break
        if match is None:
            raise HTTPException(
                status_code=404,
                detail=f"No carved file with sha256={sha_norm} on project {project_id}.",
            )

        remote_path = match.get("carved_path")
        if not remote_path or not isinstance(remote_path, str):
            raise HTTPException(status_code=410, detail="Carved file has no on-disk path.")

        import tempfile
        from pathlib import Path as _Path

        settings = get_settings()
        ssh = await get_ssh_service(settings)
        system_id = project.system_id
        from aila.storage.db_models import ManagedSystemRecord
        async with UnitOfWork() as uow:
            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == system_id)
            )).first()
        if system is None:
            raise HTTPException(status_code=410, detail="Analyzer system record missing.")

        # Resolve the integration dict the same way the collectors do.
        integration = {
            "host": system.host,
            "port": system.port,
            "username": system.username,
            "private_key_path": getattr(system, "private_key_path", None),
            "known_hosts_path": getattr(system, "known_hosts_path", None),
            "secret_key": getattr(system, "secret_key", None),
        }

        fd = tempfile.NamedTemporaryFile(delete=False, suffix=".carved")
        fd.close()
        local_tmp = _Path(fd.name)
        try:
            await ssh.download_file(integration, remote_path, local_tmp, timeout_seconds=600.0)
        except (OSError, TimeoutError, ConnectionError, RuntimeError) as exc:
            try:
                local_tmp.unlink()
            except OSError:
                pass
            raise HTTPException(
                status_code=410,
                detail=(
                    f"Carved file {sha_norm} no longer available on the analyzer "
                    f"(original path {remote_path}): {exc}"
                ),
            ) from exc

        filename_guess = (
            str(match.get("filename_guess") or f"carved_{sha_norm[:12]}.bin")
            .replace("/", "_").replace("\\", "_").replace("\"", "_")
        )

        def _stream():
            with local_tmp.open("rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    yield chunk
            try:
                local_tmp.unlink()
            except OSError:
                pass

        headers = {
            "Content-Disposition": f'attachment; filename="{filename_guess}"',
            "X-Carved-Sha256": sha_norm,
        }
        mime = str(match.get("mime_type") or "application/octet-stream")
        return StreamingResponse(_stream(), media_type=mime, headers=headers)

    @router.delete(
        "/projects/{project_id}/writeups/{writeup_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Permanently delete a write-up.",
    )
    @limiter.limit("30/minute")
    async def delete_writeup(
        request: Request,
        project_id: str,
        writeup_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request

        from aila.modules.forensics.db_models import ForensicsProjectRecord, WriteUpRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            writeup = (await uow.session.exec(
                select(WriteUpRecord).where(
                    WriteUpRecord.project_id == project_id,
                    WriteUpRecord.id == writeup_id,
                )
            )).first()
            if writeup is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Write-up {writeup_id} not found on project {project_id}.",
                )

            await uow.session.delete(writeup)
            await uow.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get(
        "/projects/{project_id}/directives.md",
        response_class=StreamingResponse,
        summary="Download all analyst directives for the project as a Markdown file.",
    )
    @limiter.limit("30/minute")
    async def download_directives(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        investigation_id: str | None = Query(default=None),
        include_inactive: bool = Query(default=False),
    ) -> StreamingResponse:
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            stmt = select(AnalystDirectiveRecord).where(
                AnalystDirectiveRecord.project_id == project_id
            )
            if investigation_id is not None:
                stmt = stmt.where(
                    (AnalystDirectiveRecord.investigation_id.is_(None))  # type: ignore[union-attr]
                    | (AnalystDirectiveRecord.investigation_id == investigation_id)
                )
            if not include_inactive:
                stmt = stmt.where(AnalystDirectiveRecord.active.is_(True))  # type: ignore[union-attr]
            directives = (await uow.session.exec(stmt)).all()

            # Resolve investigation titles for the per-investigation section.
            inv_ids = {d.investigation_id for d in directives if d.investigation_id}
            questions: dict[str, str] = {}
            if inv_ids:
                inv_rows = (await uow.session.exec(
                    select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id.in_(list(inv_ids))  # type: ignore[union-attr]
                    )
                )).all()
                questions = {i.id: i.question for i in inv_rows}

        project_wide = [d for d in directives if d.investigation_id is None]
        by_inv: dict[str, list[AnalystDirectiveRecord]] = {}
        for d in directives:
            if d.investigation_id is not None:
                by_inv.setdefault(d.investigation_id, []).append(d)

        def _fmt(d) -> str:
            stamp = d.created_at.strftime("%Y-%m-%d %H:%M UTC") if d.created_at else "unknown"
            status_flag = "" if d.active else " _(inactive)_"
            verdict = f" · verdict: **{d.verdict}**" if d.verdict else ""
            strategy = f" · strategy: `{d.strategy_family}`" if d.strategy_family else ""
            artifact = f" · required_artifact: `{d.required_artifact}`" if d.required_artifact else ""
            author = f" · by {d.created_by}" if d.created_by else ""
            body = (d.text or "").strip().replace("\n", "\n  ")
            return f"- [{stamp}]{status_flag}{verdict}{strategy}{artifact}{author}\n  {body}"

        lines: list[str] = [
            f"# {project.name} -- Analyst Directives",
            "",
            f"**Project ID:** `{project.id}`  ",
            f"**Total directives:** {len(directives)}  ",
            "",
            "---",
            "",
            "## Project-wide directives",
            "",
        ]
        if project_wide:
            lines.extend(_fmt(d) for d in sorted(project_wide, key=lambda r: r.created_at or ""))
        else:
            lines.append("_None._")

        if by_inv:
            lines.extend(["", "## Per-investigation directives", ""])
            for inv_id, items in by_inv.items():
                q = questions.get(inv_id, "(no question on record)")
                lines.extend([
                    f"### Investigation `{inv_id}`",
                    "",
                    f"**Question:** {q}",
                    "",
                ])
                lines.extend(_fmt(d) for d in sorted(items, key=lambda r: r.created_at or ""))
                lines.append("")

        md = "\n".join(lines) + "\n"
        fname = f"{_slugify(project.name)}-directives.md"
        return StreamingResponse(
            iter([md.encode("utf-8")]),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @router.get(
        "/projects/{project_id}/network-analysis",
        response_model=DataEnvelope[NetworkAnalysis],
        summary="Get NetworkMiner-style PCAP analysis.",
    )
    @limiter.limit("30/minute")
    async def get_network_analysis(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[NetworkAnalysis]:
        del request

        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.project_id == project_id,
                    ArtifactRecord.artifact_family == "network",
                )
            )).all()

        # Each network artifact stores its rows under data["rows"] (or
        # data["stats"] for the single-row capture summary). Collapse
        # duplicate types produced across multiple pcap files by
        # concatenating their row lists.
        stats: dict[str, Any] = {}
        collected: dict[str, list[dict[str, Any]]] = {
            "protocol_hierarchy": [], "hosts": [], "sessions": [],
            "dns": [], "suspicious_dns": [], "http_requests": [],
            "http_responses": [], "tls_client_hellos": [],
            "unusual_ports": [], "user_agents": [], "credentials": [],
            "beacons": [], "anomalies": [], "commentary": [],
        }

        for row in rows:
            data = json.loads(row.data_json)
            atype = row.artifact_type
            if atype == "capture_stats":
                s = data.get("stats") or {}
                # Aggregate across multi-pcap projects: sum counts and take
                # the longest duration observed.
                stats["packet_count"] = (
                    stats.get("packet_count", 0) + int(s.get("packet_count") or 0)
                )
                stats["byte_count"] = (
                    stats.get("byte_count", 0) + int(s.get("byte_count") or 0)
                )
                stats["duration_s"] = max(
                    float(stats.get("duration_s") or 0.0),
                    float(s.get("duration_s") or 0.0),
                )
                continue
            if atype in collected:
                rows_list = data.get("rows") or []
                if isinstance(rows_list, list):
                    collected[atype].extend(rows_list)

        return DataEnvelope(data=NetworkAnalysis(
            stats=stats,
            protocol_hierarchy=collected["protocol_hierarchy"],
            hosts=collected["hosts"],
            sessions=collected["sessions"],
            dns=collected["dns"],
            suspicious_dns=collected["suspicious_dns"],
            http_requests=collected["http_requests"],
            http_responses=collected["http_responses"],
            tls_client_hellos=collected["tls_client_hellos"],
            unusual_ports=collected["unusual_ports"],
            user_agents=collected["user_agents"],
            credentials=collected["credentials"],
            beacons=collected["beacons"],
            anomalies=collected["anomalies"],
            commentary=collected["commentary"],
        ))

    @router.get(
        "/projects/{project_id}/registry-analysis",
        response_model=DataEnvelope[RegistryAnalysis],
        summary="Get Windows Registry analysis.",
    )
    @limiter.limit("30/minute")
    async def get_registry_analysis(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[RegistryAnalysis]:
        del request

        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            from sqlmodel import or_

            rows = (await uow.session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.project_id == project_id,
                    or_(
                        ArtifactRecord.artifact_family == "registry",
                        ArtifactRecord.artifact_family == "filesystem",
                        ArtifactRecord.artifact_family == "execution",
                    ),
                )
            )).all()

        _REG_TYPE_TO_BUCKET: dict[str, str] = {
            "runkeys": "autoruns",
            "startup": "autoruns",
            "services": "services",
            "apps_installed": "installed_software",
            "users": "user_accounts",
            "usb": "usb_history",
            "recentfiles": "recent_docs",
            "shellbags": "shellbags",
            "registry_hivelist": "autoruns",
            "shell_history_powershell": "autoruns",
            "prefetch": "shimcache",
            "tasks": "services",
        }

        buckets: dict[str, list[dict[str, Any]]] = {
            "autoruns": [], "services": [], "installed_software": [],
            "user_accounts": [], "usb_history": [], "recent_docs": [],
            "network_interfaces": [], "shellbags": [], "amcache": [],
            "shimcache": [], "bam": [], "security_packages": [],
        }

        for row in rows:
            data = json.loads(row.data_json)
            data["_artifact_type"] = row.artifact_type
            data["_artifact_family"] = row.artifact_family
            bucket_name = _REG_TYPE_TO_BUCKET.get(row.artifact_type)
            if bucket_name and bucket_name in buckets:
                buckets[bucket_name].append(data)

        return DataEnvelope(data=RegistryAnalysis(
            autoruns=buckets["autoruns"],
            services=buckets["services"],
            installed_software=buckets["installed_software"],
            user_accounts=buckets["user_accounts"],
            usb_history=buckets["usb_history"],
            recent_docs=buckets["recent_docs"],
            network_interfaces=buckets["network_interfaces"],
            shellbags=buckets["shellbags"],
            amcache=buckets["amcache"],
            shimcache=buckets["shimcache"],
            bam=buckets["bam"],
            security_packages=buckets["security_packages"],
        ))

    @router.get(
        "/projects/{project_id}/timeline",
        response_model=DataEnvelope[list[TimelineEntry]],
        summary="Get forensic timeline events.",
    )
    @limiter.limit("30/minute")
    async def get_timeline(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        limit: int = Query(default=2000, ge=1, le=10000),
        min_confidence: str = Query(
            default="medium",
            pattern="^(low|medium|high)$",
            description=(
                "Minimum confidence/suspicion bar a finding must clear "
                "to appear on the timeline. 'low' includes anything with "
                "a real event-time; 'medium' is the default forensic "
                "view (typed agent findings + scored collector rows); "
                "'high' includes only confirmed agent answers + critical "
                "severity collector rows."
            ),
        ),
    ) -> DataEnvelope[list[TimelineEntry]]:
        """Build an event-time correlation timeline.

        ONLY entries with a real event-time (not the AILA record-time)
        are returned. The endpoint mines timestamps from:

          1. Canonical fields: ``data.timestamp / time / created``.
          2. Time-bearing observable keys (``lnk_modified``,
             ``first_seen``, ``last_executed``, ``*_at`` …) whose value
             parses as ISO-8601 / common log time. A single row may
             yield multiple entries when several time fields are
             present (e.g. an LNK with created/modified/accessed all
             becomes three timeline rows).

        Rows that have no event-time are dropped -- record-time fallback
        produces useless "all 73 events happened in the last hour"
        clusters that hide real chronology.

        A confidence/suspicion gate filters out the noise floor:
          - ``observables_snapshot`` is always excluded (it's a dump).
          - Investigation-emitted typed rows
            (``trigger_artifact``, ``lnk_dropper``, ``capa_findings``,
            ``process_injection``, ``ioc_observation``,
            ``persistence_finding``) carry confirmed agent observables
            and pass at any level.
          - ``investigation_summary`` rows pass when the answer's
            confidence meets the bar.
          - Collector rows pass when they are flagged ``suspicious``
            / ``severity ∈ {medium,high,critical}`` /
            ``confidence ∈ {high,medium}`` / ``lead_score > 0`` for
            the requested bar.
        """
        del request

        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord

        bar = _BAR_LEVELS[min_confidence]

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(ArtifactRecord)
                .where(ArtifactRecord.project_id == project_id)
                .limit(limit)
            )).all()

        # Hard cap per artifact so one noisy MFT/evtx artifact can't
        # monopolise the response. The overall page is still bounded by
        # the top-level `limit`.
        _PER_ARTIFACT_CAP = 250

        import re as _re_local
        _RECORD_ORIGIN_RE = _re_local.compile(r"^record\[(\d+)\]:(.+)$")

        entries: list[TimelineEntry] = []
        for row in rows:
            try:
                data = json.loads(row.data_json or "{}")
            except (TypeError, ValueError):
                data = {}
            if not isinstance(data, dict):
                data = {"raw": data}

            if not _passes_bar(row, data, bar):
                continue

            timestamps = _mine_all_timestamps(data)
            if not timestamps:
                continue  # no event time -> belongs to /occurrences

            records = data.get("records") if isinstance(data.get("records"), list) else []
            artifact_desc = _row_description(data)

            emitted = 0
            for ts, origin in timestamps:
                if emitted >= _PER_ARTIFACT_CAP:
                    break

                # Pick the description that matches WHERE the timestamp
                # came from. Entries mined from record[i] describe that
                # specific row; entries mined from the artifact root use
                # the artifact summary.
                m = _RECORD_ORIGIN_RE.match(origin)
                if m and records:
                    idx = int(m.group(1))
                    field = m.group(2).rstrip("[]")
                    if 0 <= idx < len(records) and isinstance(records[idx], dict):
                        base = _record_description(records[idx])
                        desc = f"{base} [{field}]"
                    else:
                        desc = f"{artifact_desc} [{field}]"
                else:
                    origin_label = origin.split(":", 1)[-1]
                    desc = (
                        f"{artifact_desc} [{origin_label}]"
                        if len(timestamps) > 1
                        else artifact_desc
                    )

                # The per-entry ``data`` payload used to be the full
                # artifact dict -- fine for small rows, heavy (and
                # misleading) when the artifact carries 500 records of
                # which only one relates to this timestamp. Narrow to
                # the specific record when we have one.
                entry_data: dict[str, Any]
                if m and records:
                    idx = int(m.group(1))
                    if 0 <= idx < len(records) and isinstance(records[idx], dict):
                        entry_data = {
                            "record": records[idx],
                            "artifact_type": row.artifact_type,
                            "artifact_family": row.artifact_family,
                            "source_tool": row.source_tool,
                        }
                    else:
                        entry_data = data
                else:
                    entry_data = data

                entries.append(TimelineEntry(
                    timestamp=str(ts),
                    source=row.source_tool or "unknown",
                    event_type=row.artifact_type,
                    description=desc[:300],
                    artifact_id=row.id,
                    source_investigation_id=row.source_investigation_id,
                    timestamp_origin=origin,
                    data=entry_data,
                ))
                emitted += 1

        entries.sort(key=lambda e: e.timestamp)
        return DataEnvelope(data=entries)

    @router.get(
        "/projects/{project_id}/occurrences",
        response_model=DataEnvelope[list[Occurrence]],
        summary="Confident findings without an event-time.",
    )
    @limiter.limit("30/minute")
    async def get_occurrences(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        limit: int = Query(default=2000, ge=1, le=10000),
        min_confidence: str = Query(
            default="medium",
            pattern="^(low|medium|high)$",
        ),
    ) -> DataEnvelope[list[Occurrence]]:
        """Sibling of ``/timeline`` for findings that have no event-time.

        Same gating as ``/timeline`` (suspicious/confident only,
        observable_snapshot excluded), but returns rows whose payload
        carried no parseable timestamp. Sorted by AILA's record-time as
        a stable secondary order -- that's metadata about the report,
        not a claim about when the event happened.
        """
        del request

        from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord

        bar = _BAR_LEVELS[min_confidence]

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(ArtifactRecord)
                .where(ArtifactRecord.project_id == project_id)
                .limit(limit)
            )).all()

        out: list[Occurrence] = []
        for row in rows:
            try:
                data = json.loads(row.data_json or "{}")
            except (TypeError, ValueError):
                data = {}
            if not isinstance(data, dict):
                data = {"raw": data}

            if not _passes_bar(row, data, bar):
                continue
            if _mine_all_timestamps(data):
                continue  # has an event time -> belongs to /timeline

            out.append(Occurrence(
                source=row.source_tool or "unknown",
                event_type=row.artifact_type,
                description=_row_description(data)[:300],
                artifact_id=row.id,
                source_investigation_id=row.source_investigation_id,
                recorded_at=row.created_at.isoformat() if row.created_at else "",
                data=data,
            ))

        out.sort(key=lambda o: o.recorded_at, reverse=True)
        return DataEnvelope(data=out)

    @router.get(
        "/projects/{project_id}/directives",
        response_model=DataEnvelope[list[AnalystDirective]],
        summary="List analyst directives for a project (and optionally one investigation).",
    )
    @limiter.limit("60/minute")
    async def list_directives(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        investigation_id: str | None = Query(default=None),
        include_inactive: bool = Query(default=False),
    ) -> DataEnvelope[list[AnalystDirective]]:
        """Return active directives for ``project_id``.

        When ``investigation_id`` is provided, returns project-wide
        directives (where ``investigation_id IS NULL``) plus directives
        scoped to that investigation. Project-wide entries are returned
        first so the analyst sees the standing rules before the
        per-investigation overrides.
        """
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            ForensicsProjectRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            stmt = select(AnalystDirectiveRecord).where(
                AnalystDirectiveRecord.project_id == project_id
            )
            if investigation_id is not None:
                stmt = stmt.where(
                    (AnalystDirectiveRecord.investigation_id.is_(None))  # type: ignore[union-attr]
                    | (AnalystDirectiveRecord.investigation_id == investigation_id)
                )
            else:
                stmt = stmt.where(AnalystDirectiveRecord.investigation_id.is_(None))  # type: ignore[union-attr]
            if not include_inactive:
                stmt = stmt.where(AnalystDirectiveRecord.active.is_(True))  # type: ignore[union-attr]
            rows = (await uow.session.exec(stmt)).all()

        items = sorted(
            (AnalystDirective(
                id=r.id,
                project_id=r.project_id,
                investigation_id=r.investigation_id,
                text=r.text,
                created_by=r.created_by,
                created_at=r.created_at,
                resolved_at=r.resolved_at,
                active=r.active,
                verdict=r.verdict,
                strategy_family=r.strategy_family,
                required_artifact=r.required_artifact,
                source_investigation_id=r.source_investigation_id,
                source_answer_id=r.source_answer_id,
            ) for r in rows),
            key=lambda d: (d.investigation_id is not None, d.created_at),
        )
        return DataEnvelope(data=items)

    @router.post(
        "/projects/{project_id}/directives",
        response_model=DataEnvelope[AnalystDirective],
        status_code=status.HTTP_201_CREATED,
        summary="Create a new analyst directive.",
    )
    @limiter.limit("30/minute")
    async def create_directive(
        request: Request,
        project_id: str,
        body: AnalystDirectiveCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[AnalystDirective]:
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            if body.investigation_id is not None:
                inv = (await uow.session.exec(
                    select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == body.investigation_id
                    )
                )).first()
                if inv is None or inv.project_id != project_id:
                    raise HTTPException(
                        status_code=404,
                        detail=(
                            f"Investigation {body.investigation_id} not found on "
                            f"project {project_id}."
                        ),
                    )

            record = AnalystDirectiveRecord(
                project_id=project_id,
                investigation_id=body.investigation_id,
                text=body.text.strip(),
                created_by=auth.user_id,
                strategy_family=(body.strategy_family or "").strip() or None,
                required_artifact=(body.required_artifact or "").strip() or None,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

        return DataEnvelope(data=AnalystDirective(
            id=record.id,
            project_id=record.project_id,
            investigation_id=record.investigation_id,
            text=record.text,
            created_by=record.created_by,
            created_at=record.created_at,
            resolved_at=record.resolved_at,
            active=record.active,
            verdict=record.verdict,
            strategy_family=record.strategy_family,
            required_artifact=record.required_artifact,
            source_investigation_id=record.source_investigation_id,
            source_answer_id=record.source_answer_id,
        ))

    @router.delete(
        "/projects/{project_id}/directives/{directive_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Soft-delete (deactivate) an analyst directive.",
    )
    @limiter.limit("30/minute")
    async def delete_directive(
        request: Request,
        project_id: str,
        directive_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            ForensicsProjectRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            record = (await uow.session.exec(
                select(AnalystDirectiveRecord).where(
                    AnalystDirectiveRecord.id == directive_id,
                    AnalystDirectiveRecord.project_id == project_id,
                )
            )).first()
            if record is None:
                raise HTTPException(status_code=404, detail=f"Directive {directive_id} not found.")
            record.active = False
            from aila.platform.contracts._common import utc_now
            record.resolved_at = utc_now()
            uow.session.add(record)
            await uow.commit()

    @router.post(
        "/projects/{project_id}/retrieve-file",
        summary="Extract an arbitrary file from a project's disk image and stream it back.",
        response_class=StreamingResponse,
        responses={
            200: {
                "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}},
                "description": "Raw file bytes",
            },
        },
    )
    @limiter.limit("10/minute")
    async def retrieve_file(
        request: Request,
        project_id: str,
        body: RetrieveFileRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        """Pull a single artefact out of the project's disk image.

        Runs a dissect.target extraction on the analyzer, SFTPs the
        result back to the API host, and streams the bytes to the
        browser with ``Content-Disposition: attachment`` so the file
        is saved directly. The temp file on the API host is deleted
        via a background task after the response completes.
        """
        from starlette.background import BackgroundTask as _BackgroundTask

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            ProjectEvidenceRecord,
        )
        from aila.modules.forensics.services.file_retriever import (
            FileRetrievalError,
            retrieve_file_from_image,
        )
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)
            if project.project_kind == "raw_directory":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "This project is a raw directory -- there is no disk image "
                        "to extract from. Use /projects/{id}/fetch-raw instead."
                    ),
                )

            # Pick the disk image: by ``evidence_id`` when supplied,
            # otherwise the sole disk_image evidence row (reject when
            # ambiguous).
            ev_stmt = select(ProjectEvidenceRecord).where(
                ProjectEvidenceRecord.project_id == project_id,
                ProjectEvidenceRecord.evidence_type == "disk_image",
            )
            if body.evidence_id:
                ev_stmt = ev_stmt.where(ProjectEvidenceRecord.id == body.evidence_id)
            evidences = (await uow.session.exec(ev_stmt)).all()

            if not evidences:
                raise HTTPException(
                    status_code=404,
                    detail="No disk image evidence found on this project.",
                )
            if body.evidence_id is None and len(evidences) > 1:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Project has multiple disk images; "
                        "specify evidence_id to pick one."
                    ),
                )
            evidence = evidences[0]

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(status_code=404, detail="System not found.")

        integration = {
            "name": system.name, "host": system.host, "username": system.username,
            "port": system.port, "private_key_path": system.private_key_path,
            "password_secret_id": system.password_secret_id,
            "known_hosts_path": system.known_hosts_path,
            "host_key_fingerprint": system.host_key_fingerprint,
        }

        platform = getattr(request.app.state, "platform", None)
        settings = getattr(getattr(platform, "runtime", None), "settings", None) if platform else None
        if settings is None:
            from aila.config import get_settings
            settings = get_settings()

        try:
            local_path, size, sha256_hex, filename, kind = await retrieve_file_from_image(
                settings=settings,
                integration=integration,
                analyzer_os=project.analyzer_os,
                disk_image_path=evidence.file_path,
                virtual_path=body.virtual_path,
            )
        except FileRetrievalError as exc:
            msg = str(exc)
            if "not found" in msg.lower():
                raise HTTPException(status_code=404, detail=msg) from exc
            if "exceeds size limit" in msg.lower():
                raise HTTPException(status_code=413, detail=msg) from exc
            raise HTTPException(status_code=500, detail=msg) from exc

        def _iter_bytes() -> Any:
            with open(local_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    yield chunk

        def _cleanup() -> None:
            try:
                local_path.unlink(missing_ok=True)
            except OSError:
                _log.warning("failed to delete retrieval temp %s", local_path)

        _log.info(
            "retrieved %s kind=%s (%d bytes, sha256=%s) from project %s",
            filename, kind, size, sha256_hex, project_id,
        )

        # Safe ASCII filename for the header; quote any non-ASCII bytes
        # per RFC 5987 fallback.
        safe_name = filename.encode("ascii", "replace").decode("ascii")
        media_type = "application/zip" if kind == "dir" else "application/octet-stream"
        return StreamingResponse(
            _iter_bytes(),
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}"',
                "Content-Length": str(size),
                "X-File-Sha256": sha256_hex,
                "X-File-Size": str(size),
                "X-Retrieve-Kind": kind,
            },
            background=_BackgroundTask(_cleanup),
        )

    @router.post(
        "/projects/{project_id}/fetch-raw",
        summary="Fetch a file or directory from a raw_directory project's evidence.",
        response_class=StreamingResponse,
        responses={
            200: {
                "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}},
                "description": "Raw file or archive bytes",
            },
        },
    )
    @limiter.limit("10/minute")
    async def fetch_raw(
        request: Request,
        project_id: str,
        body: FetchRawRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        """Ship a single evidence row off the analyzer filesystem.

        Unlike ``retrieve-file`` this never touches dissect -- the evidence
        path is a real filesystem location (the raw_directory project
        kind stores loose files and subdirectories as-is). Directories
        are zipped on the analyzer; single files are streamed verbatim.
        """
        from starlette.background import BackgroundTask as _BackgroundTask

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            ProjectEvidenceRecord,
        )
        from aila.modules.forensics.services.file_retriever import (
            FileRetrievalError,
            retrieve_from_raw_directory,
        )
        from aila.storage.db_models import ManagedSystemRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)
            if project.project_kind != "raw_directory":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "fetch-raw is only valid for raw_directory projects. "
                        "Use /projects/{id}/retrieve-file for disk-evidence projects."
                    ),
                )

            evidence = (await uow.session.exec(
                select(ProjectEvidenceRecord).where(
                    ProjectEvidenceRecord.project_id == project_id,
                    ProjectEvidenceRecord.id == body.evidence_id,
                )
            )).first()
            if evidence is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Evidence {body.evidence_id} not found on this project.",
                )

            system = (await uow.session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
            )).first()
            if system is None:
                raise HTTPException(status_code=404, detail="System not found.")

        integration = {
            "name": system.name, "host": system.host, "username": system.username,
            "port": system.port, "private_key_path": system.private_key_path,
            "password_secret_id": system.password_secret_id,
            "known_hosts_path": system.known_hosts_path,
            "host_key_fingerprint": system.host_key_fingerprint,
        }

        platform = getattr(request.app.state, "platform", None)
        settings = getattr(getattr(platform, "runtime", None), "settings", None) if platform else None
        if settings is None:
            from aila.config import get_settings
            settings = get_settings()

        try:
            local_path, size, sha256_hex, filename, kind = await retrieve_from_raw_directory(
                settings=settings,
                integration=integration,
                analyzer_os=project.analyzer_os,
                target_path=evidence.file_path,
            )
        except FileRetrievalError as exc:
            msg = str(exc)
            if "not found" in msg.lower():
                raise HTTPException(status_code=404, detail=msg) from exc
            if "exceeds size limit" in msg.lower():
                raise HTTPException(status_code=413, detail=msg) from exc
            raise HTTPException(status_code=500, detail=msg) from exc

        def _iter_bytes_raw() -> Any:
            with open(local_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    yield chunk

        def _cleanup_raw() -> None:
            try:
                local_path.unlink(missing_ok=True)
            except OSError:
                _log.warning("failed to delete raw-retrieval temp %s", local_path)

        _log.info(
            "fetch_raw: shipped %s kind=%s (%d bytes, sha256=%s) from project %s",
            filename, kind, size, sha256_hex, project_id,
        )

        safe_name = filename.encode("ascii", "replace").decode("ascii")
        media_type = "application/zip" if kind == "dir" else "application/octet-stream"
        return StreamingResponse(
            _iter_bytes_raw(),
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}"',
                "Content-Length": str(size),
                "X-File-Sha256": sha256_hex,
                "X-File-Size": str(size),
                "X-Retrieve-Kind": kind,
            },
            background=_BackgroundTask(_cleanup_raw),
        )

    # ---------------------------------------------------------------
    # Investigation control & analyst tagging
    # ---------------------------------------------------------------

    @router.post(
        "/projects/{project_id}/investigations/{investigation_id}/cancel",
        response_model=DataEnvelope[dict],
        summary="Cancel a running investigation (hard stop).",
    )
    @limiter.limit("30/minute")
    async def cancel_investigation(
        request: Request,
        project_id: str,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        """Stop an in-flight investigation immediately.

        Flips ``InvestigationRunRecord.status`` to ``cancelled`` and
        (if there is an active task) asks the task framework to mark
        the worker task cancelled. The investigator polls its record's
        status at every loop iteration and exits cleanly when it sees
        the cancelled flag.
        """
        del request

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            InvestigationRunRecord,
        )
        from aila.platform.tasks.storage import TaskRepository

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == investigation_id,
                    InvestigationRunRecord.project_id == project_id,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Investigation {investigation_id} not found on project {project_id}.",
                )

            if inv.status in _INV_TERMINAL_STATUSES:
                return DataEnvelope(data={
                    "investigation_id": inv.id,
                    "status": inv.status,
                    "already_terminal": True,
                })

            task_cancelled = False
            if inv.task_id:
                try:
                    task_cancelled = await TaskRepository.set_cancelled(
                        uow.session, inv.task_id, auth,
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    _log.warning(
                        "cancel_investigation: task cancel failed inv=%s task=%s err=%s",
                        inv.id, inv.task_id, exc,
                    )

            inv.status = InvestigationStatus.CANCELLED.value
            if not inv.final_answer:
                inv.final_answer = "Cancelled by analyst."
            uow.session.add(inv)
            await uow.commit()

        return DataEnvelope(data={
            "investigation_id": investigation_id,
            "status": InvestigationStatus.CANCELLED.value,
            "task_cancelled": task_cancelled,
        })

    @router.post(
        "/projects/{project_id}/investigations/{investigation_id}/tag",
        response_model=DataEnvelope[SolidEvidence],
        status_code=status.HTTP_201_CREATED,
        summary="Tag a completed investigation as TRUE or FALSE finding.",
    )
    @limiter.limit("30/minute")
    async def tag_investigation(
        request: Request,
        project_id: str,
        investigation_id: str,
        body: TagInvestigationRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[SolidEvidence]:
        """Persist a solid-evidence row + a verdict-flagged directive.

        The verdict-flagged directive is project-scoped (not investigation-
        scoped) so every *future* investigation under the project sees the
        settled fact or disproved hypothesis in its system prompt.
        """
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            AnswerCandidateRecord,
            ForensicsProjectRecord,
            InvestigationRunRecord,
            SolidEvidenceRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == investigation_id,
                    InvestigationRunRecord.project_id == project_id,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Investigation {investigation_id} not found on project {project_id}.",
                )
            if inv.status not in _INV_TERMINAL_STATUSES:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Investigation is still {inv.status!r}; wait for it to "
                        "finish before tagging."
                    ),
                )

            # Pick the source: explicit answer candidate or the investigation's
            # final_answer.
            question_text = inv.question
            answer_text: str
            confidence: str
            primary_artifact: str | None = None
            corroboration_json: str = "[]"
            source_answer_id: str | None = None
            if body.answer_id:
                ans = (await uow.session.exec(
                    select(AnswerCandidateRecord).where(
                        AnswerCandidateRecord.id == body.answer_id,
                        AnswerCandidateRecord.project_id == project_id,
                    )
                )).first()
                if ans is None:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Answer {body.answer_id} not found on project {project_id}.",
                    )
                question_text = ans.question_text or inv.question
                answer_text = ans.answer_text or ""
                confidence = ans.confidence or "unknown"
                primary_artifact = ans.primary_artifact_id
                corroboration_json = ans.corroboration_json or "[]"
                source_answer_id = ans.id
            else:
                answer_text = inv.final_answer or ""
                confidence = inv.confidence or "unknown"

            if not answer_text.strip():
                raise HTTPException(
                    status_code=422,
                    detail="Investigation has no answer to tag.",
                )

            # Create the verdict-flagged project-wide directive.
            if body.verdict == "true":
                directive_text = (
                    f"CONFIRMED FINDING (analyst-verified). "
                    f"Q: {question_text.strip()} -> A: {answer_text.strip()}"
                )
            else:
                directive_text = (
                    f"DISPROVED HYPOTHESIS (analyst-rejected -- do not re-pursue). "
                    f"Q: {question_text.strip()} -> A: {answer_text.strip()}"
                )
            if body.notes.strip():
                directive_text += f" Notes: {body.notes.strip()}"

            directive = AnalystDirectiveRecord(
                project_id=project_id,
                investigation_id=None,  # project-wide so it propagates
                text=directive_text,
                created_by=auth.user_id,
                verdict=body.verdict,
                source_investigation_id=investigation_id,
                source_answer_id=source_answer_id,
            )
            uow.session.add(directive)
            await uow.session.flush()

            evidence = SolidEvidenceRecord(
                project_id=project_id,
                question=question_text,
                answer=answer_text,
                verdict=body.verdict,
                confidence=confidence,
                source_investigation_id=investigation_id,
                source_answer_id=source_answer_id,
                source_directive_id=directive.id,
                primary_artifact=primary_artifact,
                corroboration_json=corroboration_json,
                tagged_by=auth.user_id,
                notes=body.notes.strip(),
            )
            uow.session.add(evidence)
            await uow.commit()
            await uow.session.refresh(evidence)

        try:
            corroboration = json.loads(evidence.corroboration_json or "[]")
            if not isinstance(corroboration, list):
                corroboration = []
        except (ValueError, TypeError):
            corroboration = []

        return DataEnvelope(data=SolidEvidence(
            id=evidence.id,
            project_id=evidence.project_id,
            question=evidence.question,
            answer=evidence.answer,
            verdict=evidence.verdict,  # type: ignore[arg-type]
            confidence=evidence.confidence,
            source_investigation_id=evidence.source_investigation_id,
            source_answer_id=evidence.source_answer_id,
            source_directive_id=evidence.source_directive_id,
            primary_artifact=evidence.primary_artifact,
            corroboration=[str(x) for x in corroboration],
            tagged_by=evidence.tagged_by,
            tagged_at=evidence.tagged_at,
            notes=evidence.notes,
        ))

    @router.get(
        "/projects/{project_id}/solid-evidence",
        response_model=DataEnvelope[list[SolidEvidence]],
        summary="List analyst-tagged solid-evidence rows for a project.",
    )
    @limiter.limit("60/minute")
    async def list_solid_evidence(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        verdict: str | None = Query(default=None, description="Filter by 'true' or 'false'."),
    ) -> DataEnvelope[list[SolidEvidence]]:
        del request

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            SolidEvidenceRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            stmt = select(SolidEvidenceRecord).where(
                SolidEvidenceRecord.project_id == project_id,
            )
            if verdict in ("true", "false"):
                stmt = stmt.where(SolidEvidenceRecord.verdict == verdict)
            rows = (await uow.session.exec(stmt)).all()

        items: list[SolidEvidence] = []
        for r in rows:
            try:
                corroboration = json.loads(r.corroboration_json or "[]")
                if not isinstance(corroboration, list):
                    corroboration = []
            except (ValueError, TypeError):
                corroboration = []
            items.append(SolidEvidence(
                id=r.id,
                project_id=r.project_id,
                question=r.question,
                answer=r.answer,
                verdict=r.verdict,  # type: ignore[arg-type]
                confidence=r.confidence,
                source_investigation_id=r.source_investigation_id,
                source_answer_id=r.source_answer_id,
                source_directive_id=r.source_directive_id,
                primary_artifact=r.primary_artifact,
                corroboration=[str(x) for x in corroboration],
                tagged_by=r.tagged_by,
                tagged_at=r.tagged_at,
                notes=r.notes,
            ))
        items.sort(key=lambda e: e.tagged_at, reverse=True)
        return DataEnvelope(data=items)

    @router.delete(
        "/projects/{project_id}/solid-evidence/{evidence_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Remove an analyst-tagged solid-evidence row (also deactivates its directive).",
    )
    @limiter.limit("30/minute")
    async def delete_solid_evidence(
        request: Request,
        project_id: str,
        evidence_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            ForensicsProjectRecord,
            SolidEvidenceRecord,
        )
        from aila.platform.contracts._common import utc_now

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            evidence = (await uow.session.exec(
                select(SolidEvidenceRecord).where(
                    SolidEvidenceRecord.id == evidence_id,
                    SolidEvidenceRecord.project_id == project_id,
                )
            )).first()
            if evidence is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Solid evidence {evidence_id} not found on project {project_id}.",
                )

            # Deactivate the linked directive if any.
            if evidence.source_directive_id:
                directive = (await uow.session.exec(
                    select(AnalystDirectiveRecord).where(
                        AnalystDirectiveRecord.id == evidence.source_directive_id,
                    )
                )).first()
                if directive is not None and directive.active:
                    directive.active = False
                    directive.resolved_at = utc_now()
                    uow.session.add(directive)

            await uow.session.delete(evidence)
            await uow.commit()

    @router.post(
        "/projects/{project_id}/findings/suppress",
        response_model=DataEnvelope[FindingSuppression],
        status_code=status.HTTP_201_CREATED,
        summary="Mark an auto-finding as false positive (hides it + drops a directive).",
    )
    @limiter.limit("30/minute")
    async def suppress_finding(
        request: Request,
        project_id: str,
        body: FindingSuppressionRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[FindingSuppression]:
        """Persist a false-positive mark on a heuristic finding.

        The row is keyed on the fingerprint computed by
        ``_finding_fingerprint()``; subsequent calls to
        ``GET /findings`` will filter out matching rows. A project-wide
        ``AnalystDirective`` with ``verdict="false"`` is also dropped so
        the investigator's next run sees "analyst cleared this as benign"
        in its DISPROVED HYPOTHESES block.
        """
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            FindingSuppressionRecord,
            ForensicsProjectRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            # Idempotent upsert: same (project, fingerprint) ⇒ return existing.
            existing = (await uow.session.exec(
                select(FindingSuppressionRecord).where(
                    FindingSuppressionRecord.project_id == project_id,
                    FindingSuppressionRecord.fingerprint == body.fingerprint,
                )
            )).first()
            if existing is not None:
                try:
                    reasons = json.loads(existing.reasons_json or "[]")
                    if not isinstance(reasons, list):
                        reasons = []
                except (ValueError, TypeError):
                    reasons = []
                return DataEnvelope(data=FindingSuppression(
                    id=existing.id,
                    project_id=existing.project_id,
                    fingerprint=existing.fingerprint,
                    artifact_type=existing.artifact_type,
                    executable=existing.executable,
                    path=existing.path,
                    name=existing.name,
                    finding_user=existing.finding_user,
                    reasons=[str(x) for x in reasons],
                    notes=existing.notes,
                    source_directive_id=existing.source_directive_id,
                    suppressed_by=existing.suppressed_by,
                    suppressed_at=existing.suppressed_at,
                ))

            # Build a short, prompt-friendly directive text.
            subject_parts = []
            if body.artifact_type:
                subject_parts.append(body.artifact_type)
            if body.executable:
                subject_parts.append(f"executable={body.executable}")
            if body.path:
                subject_parts.append(f"path={body.path}")
            if body.name:
                subject_parts.append(f"name={body.name}")
            if body.finding_user:
                subject_parts.append(f"user={body.finding_user}")
            subject = " ".join(subject_parts) or f"fingerprint={body.fingerprint[:16]}"
            reason_hint = ", ".join(body.reasons[:6]) if body.reasons else "(no reasons recorded)"
            directive_text = (
                f"FALSE POSITIVE (analyst-cleared auto-finding -- treat as benign). "
                f"{subject}. Heuristic reasons: {reason_hint}."
            )
            if body.notes.strip():
                directive_text += f" Notes: {body.notes.strip()}"

            directive = AnalystDirectiveRecord(
                project_id=project_id,
                investigation_id=None,
                text=directive_text,
                created_by=auth.user_id,
                verdict="false",
                source_investigation_id=None,
                source_answer_id=None,
            )
            uow.session.add(directive)
            await uow.session.flush()

            record = FindingSuppressionRecord(
                project_id=project_id,
                fingerprint=body.fingerprint,
                artifact_type=body.artifact_type,
                executable=body.executable,
                path=body.path,
                name=body.name,
                finding_user=body.finding_user,
                reasons_json=json.dumps(body.reasons),
                notes=body.notes.strip(),
                source_directive_id=directive.id,
                suppressed_by=auth.user_id,
            )
            uow.session.add(record)
            await uow.commit()
            await uow.session.refresh(record)

        return DataEnvelope(data=FindingSuppression(
            id=record.id,
            project_id=record.project_id,
            fingerprint=record.fingerprint,
            artifact_type=record.artifact_type,
            executable=record.executable,
            path=record.path,
            name=record.name,
            finding_user=record.finding_user,
            reasons=body.reasons,
            notes=record.notes,
            source_directive_id=record.source_directive_id,
            suppressed_by=record.suppressed_by,
            suppressed_at=record.suppressed_at,
        ))

    @router.get(
        "/projects/{project_id}/findings/suppressions",
        response_model=DataEnvelope[list[FindingSuppression]],
        summary="List analyst-suppressed auto-findings.",
    )
    @limiter.limit("60/minute")
    async def list_finding_suppressions(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[FindingSuppression]]:
        del request

        from aila.modules.forensics.db_models import (
            FindingSuppressionRecord,
            ForensicsProjectRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            rows = (await uow.session.exec(
                select(FindingSuppressionRecord).where(
                    FindingSuppressionRecord.project_id == project_id,
                )
            )).all()

        items: list[FindingSuppression] = []
        for r in rows:
            try:
                reasons = json.loads(r.reasons_json or "[]")
                if not isinstance(reasons, list):
                    reasons = []
            except (ValueError, TypeError):
                reasons = []
            items.append(FindingSuppression(
                id=r.id,
                project_id=r.project_id,
                fingerprint=r.fingerprint,
                artifact_type=r.artifact_type,
                executable=r.executable,
                path=r.path,
                name=r.name,
                finding_user=r.finding_user,
                reasons=[str(x) for x in reasons],
                notes=r.notes,
                source_directive_id=r.source_directive_id,
                suppressed_by=r.suppressed_by,
                suppressed_at=r.suppressed_at,
            ))
        items.sort(key=lambda s: s.suppressed_at, reverse=True)
        return DataEnvelope(data=items)

    @router.delete(
        "/projects/{project_id}/findings/suppressions/{suppression_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Remove a false-positive suppression (row re-appears + directive deactivated).",
    )
    @limiter.limit("30/minute")
    async def delete_finding_suppression(
        request: Request,
        project_id: str,
        suppression_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        del request

        from aila.modules.forensics.db_models import (
            AnalystDirectiveRecord,
            FindingSuppressionRecord,
            ForensicsProjectRecord,
        )
        from aila.platform.contracts._common import utc_now

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found.")
            _require_project_ownership(project, auth)

            record = (await uow.session.exec(
                select(FindingSuppressionRecord).where(
                    FindingSuppressionRecord.id == suppression_id,
                    FindingSuppressionRecord.project_id == project_id,
                )
            )).first()
            if record is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Suppression {suppression_id} not found on project {project_id}.",
                )
            if record.source_directive_id:
                directive = (await uow.session.exec(
                    select(AnalystDirectiveRecord).where(
                        AnalystDirectiveRecord.id == record.source_directive_id,
                    )
                )).first()
                if directive is not None and directive.active:
                    directive.active = False
                    directive.resolved_at = utc_now()
                    uow.session.add(directive)

            await uow.session.delete(record)
            await uow.commit()

    return router
