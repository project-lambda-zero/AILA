"""Advisory state — score, classify, format, and persist a finding.

Pipeline:
1. Pull crash_type from research / poc parsed_asan; fall back to
   ``info_disclosure`` when nothing concrete is available.
2. Compute a CVSS 3.1 base score and severity for that crash_type.
3. Map the crash_type to its canonical CWE.
4. Ask the LLM for narrative sections (summary, technical_details, impact,
   remediation). The LLM is allowed to fail; the formatter falls back to a
   deterministic skeleton derived from research + CVSS data.
5. Render the VRAdvisory-shaped dict with AdvisoryBuilderTool.
6. Persist a VRFindingRecord row with the advisory JSON, CVSS metrics,
   crash signature, and PoC metadata.

DB write failures are logged and swallowed so the workflow still emits a
response — the operator can re-derive the advisory from the workflow
output even if persistence flapped.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from aila.modules.vr.contracts.finding import CrashType
from aila.modules.vr.db_models import VRFindingRecord
from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["state_advisory"]

_log = logging.getLogger(__name__)

_NARRATIVE_SYSTEM = """You are writing a coordinated-disclosure advisory \
for a confirmed N-day vulnerability. Return ONE JSON object exactly:
{
  "summary": "2-3 sentence non-technical description",
  "technical_details": "deep technical explanation of root cause and trigger",
  "impact": "what an attacker gains; bounded by the crash primitive",
  "remediation": "concrete upgrade / mitigation guidance"
}
Do not invent CVE numbers. Do not include CVSS strings; the harness \
computes those separately."""


def _resolve_crash_type(
    research: dict[str, Any], poc: dict[str, Any] | None,
) -> str:
    poc = poc or {}
    parsed = poc.get("parsed_asan") or {}
    candidates = [
        parsed.get("crash_type"),
        research.get("crash_type"),
    ]
    valid = {item.value for item in CrashType}
    for candidate in candidates:
        text = (candidate or "").strip().lower()
        if text in valid:
            return text
    return CrashType.INFO_DISCLOSURE.value


async def _llm_narrative(
    services: Any, research: dict[str, Any], poc: dict[str, Any] | None,
    crash_type: str, cvss: dict[str, Any], cwe: dict[str, Any] | None,
) -> dict[str, str]:
    """Best-effort narrative generation; falls back to a deterministic skeleton."""
    user = json.dumps({
        "research": research,
        "crash_type": crash_type,
        "cvss": {k: cvss.get(k) for k in ("vector_string", "base_score", "severity")},
        "cwe": cwe,
        "poc_status": (poc or {}).get("status"),
        "poc_reliability": (poc or {}).get("reliability"),
    })
    try:
        response = await services.llm_client.chat(
            task_type="vulnerability_research",
            messages=[
                {"role": "system", "content": _NARRATIVE_SYSTEM},
                {"role": "user", "content": user},
            ],
            run_id=services.run_id,
        )
        if response.disabled:
            raise RuntimeError("LLM disabled")
        raw = response.content or "{}"
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end < 0:
            raise ValueError("no JSON object in LLM response")
        parsed = json.loads(raw[start : end + 1])
        return {
            "summary": str(parsed.get("summary") or ""),
            "technical_details": str(parsed.get("technical_details") or ""),
            "impact": str(parsed.get("impact") or ""),
            "remediation": str(parsed.get("remediation") or ""),
        }
    except (RuntimeError, ValueError, OSError, TimeoutError) as exc:
        _log.warning("advisory narrative LLM error: %s — using fallback", exc)
        fn = research.get("vulnerable_function") or "the affected function"
        return {
            "summary": (
                f"A {crash_type.replace('_', ' ')} in {fn} affects the targeted component."
            ),
            "technical_details": str(research.get("root_cause") or ""),
            "impact": (
                f"CVSS {cvss.get('base_score')} ({cvss.get('severity')}). "
                f"Crash primitive: {crash_type}."
            ),
            "remediation": "Apply the vendor patch identified by the differential analysis.",
        }


async def _persist_finding(
    project_id: str, advisory: dict[str, Any], poc: dict[str, Any] | None,
    crash_type: str, research: dict[str, Any], cvss: dict[str, Any],
    cwe: dict[str, Any] | None,
) -> str | None:
    poc = poc or {}
    signature_block = poc.get("crash_signature") or {}
    record = VRFindingRecord(
        project_id=project_id,
        crash_type=crash_type,
        crash_signature=signature_block.get("signature_hash"),
        root_cause=str(research.get("root_cause") or ""),
        vulnerable_function=research.get("vulnerable_function") or None,
        poc_code=poc.get("code") or None,
        poc_language=poc.get("language") or None,
        poc_reliability=poc.get("reliability"),
        asan_report=poc.get("asan_report") or None,
        cvss_vector=cvss.get("vector_string"),
        cvss_score=cvss.get("base_score"),
        cwe_id=(cwe or {}).get("cwe_id"),
        advisory_json=json.dumps(advisory),
    )
    try:
        async with UnitOfWork() as uow:
            uow.session.add(record)
            await uow.commit()
            return record.id
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning("advisory persistence failed: %s", exc)
        return None


async def state_advisory(input: dict[str, Any], services: Any) -> StateResult:
    """Compute CVSS / CWE, build the advisory, and persist a VRFindingRecord."""
    project_id = str(input.get("project_id") or "")
    research = input.get("research") or {}
    poc = input.get("poc") or {}
    crash_type = _resolve_crash_type(research, poc)

    cvss_result = services.advisory_builder.forward(
        action="compute_cvss", crash_type=crash_type,
    )
    cvss_block: dict[str, Any] = {}
    if cvss_result.get("status") == "ready":
        cvss_block = {
            "vector_string": cvss_result.get("vector_string"),
            "base_score": cvss_result.get("base_score"),
            "severity": cvss_result.get("severity"),
        }

    cwe_result = services.advisory_builder.forward(
        action="map_cwe", crash_type=crash_type,
    )
    cwe_block = cwe_result if cwe_result.get("status") == "ready" else None

    narrative = await _llm_narrative(
        services, research, poc, crash_type, cvss_block, cwe_block,
    )

    finding_payload = {
        "crash_type": crash_type,
        "root_cause": research.get("root_cause") or "",
        "vulnerable_function": research.get("vulnerable_function") or "",
        "cve_id": input.get("cve_id"),
        "poc_reliability": poc.get("reliability"),
        "crash_signature": poc.get("crash_signature"),
        "cvss": cvss_block,
        "cwe": cwe_block,
        "summary_override": narrative["summary"],
        "technical_details_override": narrative["technical_details"],
        "impact_override": narrative["impact"],
        "remediation": narrative["remediation"],
    }
    formatted = services.advisory_builder.forward(
        action="format_advisory", finding=finding_payload,
    )
    advisory = formatted.get("advisory") or {}
    # Apply LLM narrative on top of the formatted skeleton so the DB row
    # captures the richer text the model produced.
    if narrative["summary"]:
        advisory["summary"] = narrative["summary"]
    if narrative["technical_details"]:
        advisory["technical_details"] = narrative["technical_details"]
    if narrative["impact"]:
        advisory["impact"] = narrative["impact"]
    if narrative["remediation"]:
        advisory["remediation"] = narrative["remediation"]

    finding_id = await _persist_finding(
        project_id, advisory, poc, crash_type, research, cvss_block, cwe_block,
    )
    if finding_id:
        advisory["finding_id"] = finding_id

    return StateResult(
        next_state="response_emit",
        output={
            **input,
            "advisory": advisory,
            "finding_id": finding_id,
            "crash_type": crash_type,
        },
    )
