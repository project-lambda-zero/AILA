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

__all__ = [
    "CVEResolution",
    "extract_cve_ids",
    "resolve_cve_intel",
]

_log = logging.getLogger(__name__)

# Permissive CVE pattern — catches CVE-2024-1, CVE-2024-1234567, etc.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class CVEResolution:
    """One resolved (or unresolved) CVE.

    ``status`` is the field the agent must read:
      - ``found``     → real intel; consume description / CWE / CVSS /
                        EPSS / KEV
      - ``not_found`` → no aggregator has a record for this CVE id;
                        do not invent details
      - ``error``     → transport / parser failure; treat as 'unknown'

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
        return [
            CVEResolution(
                cve_id=cid,
                status="error",
                error=(
                    "IntelService unavailable — vulnerability module not "
                    "registered or runtime not initialized. Cannot enrich CVE "
                    "context; agent must treat the id as 'unknown'."
                ),
            )
            for cid in cve_ids
        ]

    out: list[CVEResolution] = []
    for cve_id in cve_ids:
        try:
            knowledge = await svc.fetch_cve_intel(cve_id)
        except Exception as exc:  # noqa: BLE001  defensive — collapse NVD/transport to status
            text = str(exc)
            if "404" in text or "Not Found" in text:
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
            else:
                out.append(CVEResolution(
                    cve_id=cve_id,
                    status="error",
                    error=f"{type(exc).__name__}: {text[:240]}",
                ))
            continue
        if knowledge is None:
            out.append(CVEResolution(
                cve_id=cve_id,
                status="not_found",
                error=(
                    "IntelService returned no record after cache + NVD "
                    "lookup. Agent must treat as unknown; do not invent."
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
