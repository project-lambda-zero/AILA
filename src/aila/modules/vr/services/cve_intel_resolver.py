"""Resolve CVE intel for an investigation in a way the reasoning loop
can consume honestly.

When an operator asks "look at CVE-2026-42945 variants", the agent
needs to know whether NVD actually has data for that CVE — without
that signal it invents details ("recent/future RCE") instead of
admitting it doesn't know. This helper:

  1. Extracts CVE-NNNN-NNNN tokens from a free-form question.
  2. Resolves each via the vulnerability module's registered
     ``IntelService`` — the same aggregator the
     ``GET /vulnerability/cves/{id}`` endpoint uses. That service
     already orchestrates NVD + EPSS + KEV with caching + graceful
     fallback.
  3. Catches every exception (transport error, NVD 404, module
     not registered) and produces a structured ``CVEResolution``
     entry with an explicit ``status``.
  4. Returns the list. ``investigation_setup`` writes it into the
     workflow state input; ``vuln_researcher.build_prompt`` renders
     it as a "## External CVE intel" prompt section so the agent
     can branch on ``status='not_found'`` instead of confabulating.

We deliberately reach into the vulnerability module's already-wired
runtime instead of constructing our own IntelService. That gives
us the EPSS + KEV + cache + per-provider fallback the operator
already configured, and we don't duplicate provider wiring.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

__all__ = [
    "CVEResolution",
    "extract_cve_ids",
    "resolve_cve_intel",
]

_log = logging.getLogger(__name__)

# Permissive CVE pattern — catches CVE-2024-1 (1-digit historical) through
# CVE-2026-100000000 (8+ digits, increasingly common in 2024+). The IntelService
# backend returns not_found for invalid ids, so the regex stays loose.
# fix §187 — was \d{4,7}; 1-digit and 8+-digit serials were silently dropped.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


@dataclass
class CVEResolution:
    """One resolved (or unresolved) CVE.

    ``status`` is the discriminator the agent must read — values are a
    discriminated union:
      - ``found``           → real intel; consume description / CWE /
                              CVSS / EPSS / KEV.
      - ``not_found``       → NVD definitively has no record (HTTP 404
                              from the aggregator). Do not invent details.
      - ``transport_error`` → NVD/IntelService unreachable (timeout,
                              network error) OR returned an inconclusive
                              fallback. Distinct from ``not_found``: agent
                              MUST treat as "unknown — retry may resolve",
                              NOT as "CVE doesn't exist".
      - ``error``           → other unhandled failure (parser, internal);
                              treat as 'unknown'.

    fix §189 — added ``transport_error`` so the agent can distinguish
    "NVD says no record" from "we couldn't reach NVD". Conflating the
    two caused the agent to drop CVE context whenever NVD was down.

    EPSS + KEV signals are what distinguish "this CVE matters in
    the wild" from "the agent invented it":
      - kev_listed=True → CISA flagged as actively exploited
      - epss_percentile > 90 → near-top probability of exploitation
    """

    cve_id: str
    status: str
    description: str = ""
    cvss_score: float | None = None
    base_severity: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_listed: bool = False
    kev_date_added: str | None = None
    attack_vector: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    nvd_url: str | None = None
    published_at: str | None = None
    notes: list[str] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cve_id": self.cve_id,
            "status": self.status,
        }
        if self.description:
            out["description"] = self.description
        if self.cvss_score is not None:
            out["cvss_score"] = self.cvss_score
        if self.base_severity:
            out["base_severity"] = self.base_severity
        if self.epss_score is not None:
            out["epss_score"] = self.epss_score
        if self.epss_percentile is not None:
            out["epss_percentile"] = self.epss_percentile
        if self.kev_listed:
            out["kev_listed"] = True
            if self.kev_date_added:
                out["kev_date_added"] = self.kev_date_added
        if self.attack_vector:
            out["attack_vector"] = self.attack_vector
        if self.privileges_required:
            out["privileges_required"] = self.privileges_required
        if self.user_interaction:
            out["user_interaction"] = self.user_interaction
        if self.nvd_url:
            out["nvd_url"] = self.nvd_url
        if self.published_at:
            out["published_at"] = self.published_at
        if self.notes:
            out["notes"] = list(self.notes)
        if self.error:
            out["error"] = self.error
        return out


def extract_cve_ids(text: str | None) -> list[str]:
    """Return every distinct CVE id (uppercased) found in ``text``."""
    if not text:
        return []
    seen: list[str] = []
    for match in _CVE_RE.findall(text):
        normalized = match.upper()
        if normalized not in seen:
            seen.append(normalized)
    return seen


async def _get_intel_service() -> Any | None:
    """Pull the vulnerability module's registered ``IntelService``.

    Uses the worker-process platform singleton; returns ``None`` when
    the vulnerability module isn't registered (e.g. running with
    --modules vr only) so the resolver collapses to status=error
    instead of raising.
    """
    try:
        from aila.platform.runtime.orchestrator import (  # noqa: PLC0415
            get_worker_platform,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("cve_intel: worker platform import failed: %s", exc)
        return None
    try:
        platform = await get_worker_platform()
    except Exception as exc:  # noqa: BLE001
        _log.warning("cve_intel: get_worker_platform raised: %s", exc)
        return None
    try:
        vuln_runtime = platform.runtime.require_module("vulnerability")
    except KeyError:
        _log.info("cve_intel: vulnerability module not registered")
        return None
    intel = getattr(vuln_runtime, "intel", None)
    if intel is None:
        _log.info(
            "cve_intel: vulnerability runtime exposes no .intel attribute "
            "(runtime type: %s)", type(vuln_runtime).__name__,
        )
        return None
    return intel


async def resolve_cve_intel(cve_ids: list[str]) -> list[CVEResolution]:
    """Resolve each CVE via the vulnerability module's IntelService.

    Defensive: every exception path collapses to a ``CVEResolution``
    with a descriptive status. The investigation never fails because
    NVD is down or returned a 404.
    """
    if not cve_ids:
        return []
    svc = await _get_intel_service()
    if svc is None:
        # fix §190 — upgrade from silent-WARN to operator-visible ERROR
        # so a misconfigured worker (--modules vr without vulnerability)
        # surfaces in log destinations and dashboards. Per the spec a
        # refuse-to-start is too aggressive (a VR module audit run may
        # legitimately ship without CVE intel); the right balance is
        # visibility + degradation. The platform has no generic ops-event
        # bus reachable from this call site (events.emitter is per-state
        # WorkflowServices), so the log channel IS the alerting surface.
        # Use a distinctive marker `cve_intel.module_missing` that log
        # destinations / Grafana / Loki can grep on.
        _log.error(
            "cve_intel.module_missing — vulnerability module not registered "
            "or runtime not initialized; CVE intel unavailable for %d id(s): %s. "
            "Agent will see status=error entries and treat the CVEs as unknown. "
            "Check worker `--modules` argument or platform module registry.",
            len(cve_ids), ", ".join(cve_ids[:10]) + ("…" if len(cve_ids) > 10 else ""),
        )
        return [
            CVEResolution(
                cve_id=cid,
                status="error",
                error=(
                    "IntelService unavailable — vulnerability module not "
                    "registered or runtime not initialized. Cannot enrich CVE "
                    "context; agent must treat the id as 'unknown'. Operator "
                    "alert raised via cve_intel.module_missing log marker."
                ),
            )
            for cid in cve_ids
        ]

    out: list[CVEResolution] = []
    for cve_id in cve_ids:
        try:
            knowledge = await svc.fetch_cve_intel(cve_id)
        except Exception as exc:  # noqa: BLE001  defensive — classify by type then collapse
            # fix §188 — classify error type by exception class instead of
            # string-matching the message. A genuine NVD 404 reaches us as
            # httpx.HTTPStatusError(.response.status_code==404); transport
            # failures arrive as httpx.TimeoutException / httpx.NetworkError.
            # Anything else is bucket "error" with the exception class name
            # in the payload so the operator can debug from logs.
            if (
                isinstance(exc, httpx.HTTPStatusError)
                and exc.response is not None
                and exc.response.status_code == 404
            ):
                out.append(CVEResolution(
                    cve_id=cve_id,
                    status="not_found",
                    error=(
                        "NVD returned 404 for this CVE id (invalid / "
                        "future-dated / rescinded). Do not invent "
                        "details — surface that the intel lookup "
                        "failed and ask the operator for context if "
                        "the CVE id is critical to the investigation."
                    ),
                ))
            elif isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
                out.append(CVEResolution(
                    cve_id=cve_id,
                    status="transport_error",
                    error=(
                        f"{type(exc).__name__}: NVD/IntelService unreachable "
                        f"({str(exc)[:200]}). Treat the CVE id as unknown for "
                        f"this turn — a retry on the next investigation step "
                        f"may resolve."
                    ),
                ))
            else:
                out.append(CVEResolution(
                    cve_id=cve_id,
                    status="error",
                    error=f"{type(exc).__name__}: {str(exc)[:240]}",
                ))
            continue
        if knowledge is None:
            # fix §189 — fetch_cve_intel returns None for BOTH
            # "NVD definitively absent" AND "NVD lookup produced a
            # fallback-only record because the network failed". We
            # cannot distinguish from this layer; route to
            # transport_error so the agent treats it as "unknown,
            # retry may resolve" instead of "CVE doesn't exist".
            # Distinguishing requires IntelService to expose the
            # fallback_reason path (separate work).
            out.append(CVEResolution(
                cve_id=cve_id,
                status="transport_error",
                error=(
                    "IntelService returned no record after cache + NVD "
                    "lookup. Could be NVD-doesn't-have-it OR NVD-was-"
                    "down — distinguishing requires IntelService API "
                    "extension. Agent must treat as unknown; do not "
                    "invent details and consider re-asking on next turn."
                ),
            ))
            continue
        out.append(CVEResolution(
            cve_id=cve_id,
            status="found",
            description=knowledge.description or "",
            cvss_score=knowledge.cvss_score,
            base_severity=knowledge.base_severity,
            epss_score=knowledge.epss_score,
            epss_percentile=knowledge.epss_percentile,
            kev_listed=bool(knowledge.kev_listed),
            kev_date_added=knowledge.kev_date_added,
            attack_vector=knowledge.attack_vector,
            privileges_required=knowledge.privileges_required,
            user_interaction=knowledge.user_interaction,
            nvd_url=knowledge.nvd_url,
            published_at=knowledge.published_at,
            notes=list(knowledge.notes or []),
        ))
    return out
