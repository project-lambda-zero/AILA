"""Advisory builder -- CVSS scoring, CWE mapping, vendor-ready formatting.

Loads CVSS templates and CWE mappings from the VR module's data files,
applies caller-supplied overrides, and computes CVSS 3.1 base scores using
the official FIRST formula. ``format_advisory`` renders a VRAdvisory-shaped
dict suitable for downstream serialization.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from aila.platform.tools import Tool

__all__ = ["AdvisoryBuilderTool"]


_DEFAULT_REMEDIATION = (
    "Upgrade to the patched version. Apply vendor-supplied mitigations "
    "if an upgrade is not immediately feasible."
)
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_CVSS_PATH = _DATA_DIR / "cvss_templates.json"
_CWE_PATH = _DATA_DIR / "cwe_mappings.json"

# CVSS 3.1 metric value table (FIRST specification §7.4).
_AV: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_U: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

def _roundup(x: float) -> float:
    """CVSS 3.1 roundup (spec §7.1): ceil to nearest 0.1 via integer math."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _severity(score: float) -> str:
    """CVSS qualitative severity rating (NONE/LOW/MEDIUM/HIGH/CRITICAL)."""
    for threshold, label in ((0.0, "NONE"), (4.0, "LOW"), (7.0, "MEDIUM"), (9.0, "HIGH")):
        if score < threshold or (threshold == 0.0 and score <= 0.0):
            return label
    return "CRITICAL"


def _compute_base_score(metrics: dict[str, str]) -> float:
    """Apply the CVSS 3.1 base-score formula (FIRST spec §7.1)."""
    av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
    scope = metrics["S"]
    pr = (_PR_C if scope == "C" else _PR_U)[metrics["PR"]]
    c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    raw = (impact + 8.22 * av * ac * pr * ui) * (1.08 if scope == "C" else 1.0)
    return _roundup(min(raw, 10.0))


def _vector_string(metrics: dict[str, str]) -> str:
    parts = [f"{k}:{metrics[k]}" for k in _METRIC_ORDER]
    return "CVSS:3.1/" + "/".join(parts)


class AdvisoryBuilderTool(Tool):
    """Compute CVSS, map CWE, format vendor-ready advisories."""

    name = "vr.advisory_builder"
    description = (
        "Generate vulnerability advisories with CVSS scoring, CWE mapping, and "
        "vendor-ready formatting. Actions: compute_cvss, map_cwe, format_advisory."
    )
    inputs = {"action": {"type": "string", "description": "compute_cvss | map_cwe | format_advisory"}}
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(self, cvss_path: Path | None = None, cwe_path: Path | None = None) -> None:
        with (cvss_path or _CVSS_PATH).open("r", encoding="utf-8") as fh:
            self._cvss_templates = json.load(fh)
        with (cwe_path or _CWE_PATH).open("r", encoding="utf-8") as fh:
            self._cwe_mappings = json.load(fh)

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        if action == "compute_cvss":
            return self.compute_cvss(crash_type=kwargs.get("crash_type", ""), overrides=kwargs.get("overrides") or {})
        if action == "map_cwe":
            return self.map_cwe(crash_type=kwargs.get("crash_type", ""))
        if action == "format_advisory":
            return self.format_advisory(finding=kwargs.get("finding") or {})
        return {"status": "error", "error": f"Unknown action: {action!r}. Expected compute_cvss, map_cwe, or format_advisory."}

    def compute_cvss(self, crash_type: str, overrides: dict[str, str] | None = None) -> dict:
        """Compute a CVSS 3.1 base score from a crash-type template."""
        if not crash_type or crash_type not in self._cvss_templates:
            return {"status": "error", "error": f"No CVSS template for crash_type {crash_type!r}."}
        template = self._cvss_templates[crash_type]
        metrics = {k: template[k] for k in _METRIC_ORDER}
        for key, value in (overrides or {}).items():
            if key in _METRIC_ORDER and isinstance(value, str):
                metrics[key] = value
        try:
            score = _compute_base_score(metrics)
        except KeyError as exc:
            return {"status": "error", "error": f"Invalid CVSS metric value: {exc!s}"}
        return {
            "status": "ready",
            "vector_string": _vector_string(metrics),
            "base_score": score,
            "severity": _severity(score),
            "metrics": metrics,
            "notes": template.get("notes", ""),
        }

    def map_cwe(self, crash_type: str) -> dict:
        """Look up the canonical CWE for a crash type."""
        entry = self._cwe_mappings.get(crash_type)
        if not entry:
            return {"status": "error", "error": f"No CWE mapping for crash_type {crash_type!r}."}
        return {
            "status": "ready",
            "cwe_id": entry["cwe_id"],
            "name": entry.get("name", ""),
            "description": entry.get("description", ""),
        }

    def format_advisory(self, finding: dict[str, Any]) -> dict:
        """Render a VRAdvisory-shaped dict from a finding payload.

        The caller supplies a flattened dict (crash_type, root_cause,
        cvss, cwe, poc_reliability, affected_versions, ...). Output
        matches the ``VRAdvisory`` contract field-by-field.
        """
        crash_type = str(finding.get("crash_type") or "")
        root_cause = str(finding.get("root_cause") or "")
        fn = str(finding.get("vulnerable_function") or "")
        finding_id = str(finding.get("finding_id") or finding.get("id") or "")
        poc_reliability = finding.get("poc_reliability")

        cvss_payload = finding.get("cvss") or (self.compute_cvss(crash_type=crash_type) if crash_type else {})
        cwe_payload = finding.get("cwe") or (self.map_cwe(crash_type=crash_type) if crash_type else None)
        score = float(cvss_payload.get("base_score") or 0.0)
        sev = str(cvss_payload.get("severity") or "")
        crash_label = crash_type.replace("_", " ").title() if crash_type else "Vulnerability"
        kind = crash_type.replace("_", " ") if crash_type else "vulnerability"
        location = f" in {fn}" if fn else ""

        title = f"{crash_label} in {fn}" if fn else crash_label
        summary = (
            f"A {sev.lower()}-severity {kind} (CVSS {score}){location} allows an attacker to subvert the affected component."
            if sev else f"A {kind}{location} affects the targeted component."
        )
        tech_parts: list[str] = []
        if root_cause:
            tech_parts.append(root_cause)
        if fn:
            tech_parts.append(f"Vulnerable function: {fn}.")
        sig = finding.get("crash_signature") or {}
        if isinstance(sig, dict) and sig.get("signature_hash"):
            tech_parts.append(f"Crash signature: {sig['signature_hash'][:16]}...")
        impact_parts: list[str] = []
        if sev:
            impact_parts.append(f"CVSS 3.1 base score: {score} ({sev}).")
        if poc_reliability is not None:
            impact_parts.append(f"Proof-of-concept reliability: {poc_reliability}.")

        cwe_mapping = None
        if cwe_payload and cwe_payload.get("cwe_id"):
            cwe_mapping = {
                "cwe_id": cwe_payload.get("cwe_id", ""),
                "name": cwe_payload.get("name", ""),
                "description": cwe_payload.get("description", ""),
            }

        advisory = {
            "id": None,
            "finding_id": finding_id,
            "cve_id": finding.get("cve_id"),
            "title": title,
            "summary": summary,
            "technical_details": "\n\n".join(tech_parts),
            "impact": " ".join(impact_parts),
            "affected_versions": list(finding.get("affected_versions") or []),
            "remediation": str(finding.get("remediation") or _DEFAULT_REMEDIATION),
            "cvss": {
                "vector_string": str(cvss_payload.get("vector_string") or ""),
                "base_score": score,
                "severity": sev,
            },
            "cwe": cwe_mapping,
            "references": list(finding.get("references") or []),
        }
        return {"status": "ready", "advisory": advisory}
