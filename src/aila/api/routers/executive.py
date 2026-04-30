"""Executive reporting router for AILA REST API.

Provides fleet-wide executive PDF export, per-system compliance evidence ZIP,
and a health/posture summary endpoint.

Requirements: EXEC-01, EXEC-03 (Phase 147).

Security notes:
  - All endpoints require reader+ auth via require_user_or_api_key.
  - ZIP filenames are constructed from hardcoded strings + sanitised system name
    (never from user-controlled path input).
  - SMTP config is loaded from ConfigRegistry only; never from request body.
  - PDF generation runs in asyncio.to_thread() to avoid blocking the event loop.
"""
from __future__ import annotations

import asyncio
import io
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import ExecutiveHealthResponse
from aila.api.schemas.envelope import DataEnvelope
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/executive", tags=["executive"], dependencies=[Depends(require_user_or_api_key)])

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_HTML_RISK_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>AILA Executive Risk Summary</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: Arial, Helvetica, sans-serif;
  background: #ffffff;
  color: #1a1a2e;
  padding: 40px 48px;
}}
.header {{
  border-bottom: 3px solid #0f3460;
  padding-bottom: 16px;
  margin-bottom: 28px;
}}
.header h1 {{
  font-size: 22px;
  color: #0f3460;
  letter-spacing: 0.04em;
}}
.header .meta {{
  font-size: 11px;
  color: #555;
  margin-top: 4px;
}}
.posture-grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 32px;
}}
.posture-card {{
  border: 1px solid #ddd;
  border-radius: 6px;
  padding: 16px 12px;
  text-align: center;
  background: #f9f9fc;
}}
.posture-card .count {{
  font-size: 2.4em;
  font-weight: 700;
  line-height: 1;
  margin-bottom: 4px;
}}
.posture-card .label {{
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #555;
}}
.immediate {{ color: #c0392b; }}
.high {{ color: #e67e22; }}
.moderate {{ color: #b8860b; }}
.planned {{ color: #27ae60; }}
h2 {{
  font-size: 14px;
  color: #0f3460;
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}}
.severity-bar-wrap {{
  margin-bottom: 28px;
}}
.bar-row {{
  display: flex;
  align-items: center;
  margin-bottom: 6px;
  font-size: 12px;
}}
.bar-label {{ width: 80px; color: #444; }}
.bar-track {{
  flex: 1;
  height: 14px;
  background: #eee;
  border-radius: 3px;
  overflow: hidden;
  margin: 0 8px;
}}
.bar-fill {{ height: 100%; border-radius: 3px; }}
.bar-count {{ width: 32px; text-align: right; color: #444; font-size: 11px; }}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 10.5px;
  margin-top: 8px;
}}
th {{
  background: #0f3460;
  color: #fff;
  padding: 6px 8px;
  text-align: left;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
td {{
  padding: 5px 8px;
  border-bottom: 1px solid #eee;
  vertical-align: top;
  word-break: break-word;
}}
tr:nth-child(even) td {{ background: #f9f9fc; }}
.crit-immediate {{ color: #c0392b; font-weight: 700; }}
.crit-high {{ color: #e67e22; font-weight: 700; }}
.crit-moderate {{ color: #b8860b; }}
.crit-planned {{ color: #27ae60; }}
.footer {{
  margin-top: 36px;
  font-size: 9px;
  color: #888;
  border-top: 1px solid #eee;
  padding-top: 8px;
  text-align: center;
}}
</style>
</head>
<body>
<div class="header">
  <h1>AILA Executive Risk Summary</h1>
  <div class="meta">Generated: {generated_at} &nbsp;|&nbsp; Findings reflect current scan state</div>
</div>

<div class="posture-grid">
  <div class="posture-card">
    <div class="count immediate">{immediate}</div>
    <div class="label">Critical / Immediate</div>
  </div>
  <div class="posture-card">
    <div class="count high">{high}</div>
    <div class="label">High</div>
  </div>
  <div class="posture-card">
    <div class="count moderate">{moderate}</div>
    <div class="label">Moderate</div>
  </div>
  <div class="posture-card">
    <div class="count planned">{planned}</div>
    <div class="label">Planned</div>
  </div>
</div>

<h2>Severity Distribution</h2>
<div class="severity-bar-wrap">
{severity_bars}
</div>

<h2>Top Findings by Severity</h2>
<table>
  <thead>
    <tr>
      <th>System</th>
      <th>Package</th>
      <th>CVE</th>
      <th>Severity</th>
      <th>Score</th>
      <th>Fixed Version</th>
      <th>KEV</th>
    </tr>
  </thead>
  <tbody>
{finding_rows}
  </tbody>
</table>

<div class="footer">
  Generated by AILA &mdash; AI Lab Assistant &nbsp;|&nbsp;
  Total: {total_findings} findings across {systems_count} system(s) &nbsp;|&nbsp;
  Trend data based on current scan state &mdash; no historical time series available.
</div>
</body>
</html>
"""

_CRITICALITY_ORDER = {"Immediate": 0, "High": 1, "Moderate": 2, "Planned": 3}
_CRITICALITY_CSS = {
    "immediate": "crit-immediate",
    "high": "crit-high",
    "moderate": "crit-moderate",
    "planned": "crit-planned",
}


def _build_severity_bars(breakdown: dict[str, int], total: int) -> str:
    """Render horizontal CSS severity bars as HTML rows."""
    colors = {
        "Immediate": "#c0392b",
        "High": "#e67e22",
        "Moderate": "#b8860b",
        "Planned": "#27ae60",
    }
    lines: list[str] = []
    for label in ("Immediate", "High", "Moderate", "Planned"):
        count = breakdown.get(label, 0)
        pct = round((count / total) * 100) if total > 0 else 0
        color = colors.get(label, "#999")
        lines.append(
            f'  <div class="bar-row">'
            f'<span class="bar-label">{label}</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'
            f'<span class="bar-count">{count}</span>'
            f"</div>"
        )
    return "\n".join(lines)


def _build_finding_rows_html(findings: list[dict]) -> str:
    """Render top findings as HTML table rows."""
    rows: list[str] = []
    sorted_findings = sorted(
        findings,
        key=lambda r: _CRITICALITY_ORDER.get(r.get("criticality") or "", 99),
    )[:25]

    for f in sorted_findings:
        crit = (f.get("criticality") or "").capitalize()
        css = _CRITICALITY_CSS.get(crit.lower(), "")
        cve = f.get("cve_id") or "—"
        score = f.get("score")
        score_str = f"{score:.1f}" if score is not None else "—"
        fixed = f.get("fixed_version") or "—"
        kev = "Yes" if f.get("is_kev") else "No"
        pkg = f.get("package_name") or "—"
        sys_name = f.get("system_name") or "—"

        rows.append(
            f"    <tr>"
            f"<td>{sys_name}</td>"
            f"<td>{pkg}</td>"
            f"<td>{cve}</td>"
            f'<td class="{css}">{crit}</td>'
            f"<td>{score_str}</td>"
            f"<td>{fixed}</td>"
            f"<td>{kev}</td>"
            f"</tr>"
        )

    return "\n".join(rows) if rows else "    <tr><td colspan='7'>No findings available.</td></tr>"


async def _fetch_all_findings(module: object) -> list[dict]:
    """Fetch all latest vulnerability findings via the module boundary."""
    async with async_session_scope() as session:
        return await module.latest_findings(session)


async def _fetch_system_findings(module: object, system_id: int) -> list[dict]:
    """Fetch latest vulnerability findings for one system via the module boundary."""
    async with async_session_scope() as session:
        return await module.latest_findings(session, system_id=system_id)


def _build_severity_breakdown(findings: list[dict]) -> dict[str, int]:
    """Compute severity breakdown counts from a findings list."""
    breakdown: dict[str, int] = {"Immediate": 0, "High": 0, "Moderate": 0, "Planned": 0}
    for f in findings:
        key = (f.get("criticality") or "").capitalize()
        if key in breakdown:
            breakdown[key] += 1
    return breakdown


def _generate_risk_pdf_bytes(module: object, findings: list[dict]) -> bytes:
    """Render executive risk summary PDF through the vulnerability module boundary."""
    return module.build_risk_pdf_bytes(findings)


def _build_evidence_zip(module: object, system_id: int, findings: list[dict]) -> bytes:
    """Build a compliance evidence ZIP through the vulnerability module boundary."""
    return module.build_evidence_zip(system_id, findings)


def _sanitise_filename_component(value: str) -> str:
    """Replace non-alphanumeric chars with underscores for safe filenames."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in value)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=DataEnvelope[ExecutiveHealthResponse],
    summary="Executive reporting health / posture summary",
)
@limiter.limit("60/minute")
async def executive_health(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[ExecutiveHealthResponse]:
    """Return fleet-wide risk posture summary from LatestFindingRecord.

    Used by the frontend executive dashboard to populate severity summary cards
    without requiring a full PDF download.
    """
    module = request.app.state.platform.runtime.module_registry.require("vulnerability")
    findings = await _fetch_all_findings(module)
    breakdown = _build_severity_breakdown(findings)

    # Determine last_scanned_at from the maximum last_scanned_at across all findings
    last_scanned_at: str | None = None
    for f in findings:
        val = f.get("last_scanned_at")
        if val:
            if last_scanned_at is None or val > last_scanned_at:
                last_scanned_at = str(val)

    systems_with_findings = len({f.get("system_id") for f in findings if f.get("system_id") is not None})

    return DataEnvelope(
        data=ExecutiveHealthResponse(
            total_findings=len(findings),
            severity_breakdown=breakdown,
            last_scanned_at=last_scanned_at,
            systems_with_findings=systems_with_findings,
        )
    )


@router.get(
    "/risk-summary-pdf",
    summary="Download executive risk summary PDF (EXEC-01)",
)
@limiter.limit("10/minute")
async def download_risk_summary_pdf(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> StreamingResponse:
    """Generate and stream a fleet-wide executive risk summary PDF.

    Queries all LatestFindingRecord rows (no run_id filter — fleet-wide posture).
    Renders HTML with severity breakdown cards and top-25 findings table.
    Converts to PDF via weasyprint in a thread pool (asyncio.to_thread).

    Filename: aila-risk-summary-YYYYMMDD.pdf
    Requires: weasyprint (aila[pdf] extras).
    """
    module = request.app.state.platform.runtime.module_registry.require("vulnerability")
    findings = await _fetch_all_findings(module)

    try:
        pdf_bytes = await asyncio.to_thread(_generate_risk_pdf_bytes, module, findings)
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF generation requires the aila[pdf] extras (weasyprint). Install with: pip install aila[pdf]",
        )
    except Exception as exc:
        _log.error("Risk summary PDF generation failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF generation failed. Check server logs for details.",
        )

    date_str = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"aila-risk-summary-{date_str}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/systems/{system_id}/evidence-package",
    summary="Download compliance evidence ZIP for a system (EXEC-03)",
)
@limiter.limit("10/minute")
async def download_evidence_package(
    request: Request,
    system_id: int,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> StreamingResponse:
    """Generate and stream a compliance evidence ZIP archive for a specific system.

    ZIP contains:
      findings.json       — all findings for the system
      findings.csv        — same in CSV (VulnerabilityReportBuilder column order)
      compliance_tags.json — NIST/PCI compliance tags per finding
      scan_metadata.json  — system metadata and severity breakdown

    Returns 404 if no findings exist for the given system_id.
    """
    module = request.app.state.platform.runtime.module_registry.require("vulnerability")
    findings = await _fetch_system_findings(module, system_id)
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No findings found for system_id={system_id}. Either the system does not exist or has no scan data.",
        )

    zip_bytes = await asyncio.to_thread(_build_evidence_zip, module, system_id, findings)

    system_name_raw = findings[0].get("system_name", "system") if findings else "system"
    safe_name = _sanitise_filename_component(system_name_raw[:40])
    date_str = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"evidence-{safe_name}-{date_str}.zip"

    return StreamingResponse(
        io.BytesIO(zip_bytes),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
