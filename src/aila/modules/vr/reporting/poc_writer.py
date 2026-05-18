"""Exploit / Proof-of-Concept writer agent.

Takes a confirmed vulnerability finding (root cause + affected
function + reproduction conditions) and produces a runnable PoC
that demonstrates the bug. Output is a strict typed schema so the
downstream renderer + VRFindingRecord.poc_code can store it
directly.

PoC discipline (same rules as ReportWriter):

- DO NOT invent code paths or function signatures not present in
  the supplied finding facts. If the finding lacks information
  needed to produce a runnable PoC, the writer emits a
  ``can_run = false`` PoC with a skeleton + explicit notes saying
  what's missing. Better an honest stub than a fabricated exploit.
- Pick the right language for the target: source-repo C/C++ →
  Python scripted request (curl/requests/socket); kernel target →
  C; JS engine → JS; web app → curl or python requests.
- Default to least-harmful payload that demonstrates the bug
  (crash / OOB read), NOT weaponized code. Caveat in the payload
  description that operator hardens the PoC for their context.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from aila.platform.services.factory import ServiceFactory

__all__ = [
    "PocDraft",
    "PocWriter",
]

_log = logging.getLogger(__name__)


class PocDraft(BaseModel):
    """Structured exploit / PoC draft for a vulnerability finding.

    Schema is intentionally close to VRFindingRecord.poc_code so the
    dispatcher can persist it without re-massaging. The
    ``can_run`` flag tells the operator whether this PoC is ready
    to execute or whether it's a skeleton awaiting their hardening.
    """

    title: str = Field(description="Short PoC title — what it demonstrates.")
    language: str = Field(
        description=(
            "PoC source language: 'python', 'c', 'cpp', 'bash', "
            "'javascript', 'go', 'rust'. Pick what's natural for "
            "exercising this target."
        ),
    )
    code: str = Field(
        description=(
            "Full PoC source. Self-contained when possible. Include "
            "shebang for scripts. No external dependencies beyond "
            "stdlib + one well-known library (requests / curl)."
        ),
    )
    build_command: str = Field(
        default="",
        description=(
            "Shell command to build the PoC. Empty for interpreted "
            "languages. Example: 'gcc -fno-stack-protector -z "
            "execstack poc.c -o poc'."
        ),
    )
    run_command: str = Field(
        description=(
            "Shell command(s) to actually fire the PoC against a "
            "running target. Include any required environment setup."
        ),
    )
    target_setup: str = Field(
        default="",
        description=(
            "How to stand up the vulnerable target so the PoC has "
            "something to hit. Example nginx config snippet, docker "
            "run line, build flags."
        ),
    )
    expected_outcome: str = Field(
        description=(
            "What success looks like: 'worker process crashes with "
            "SIGSEGV in ngx_http_script_copy_capture_code'; "
            "'ASAN heap-buffer-overflow report at 0x...'; "
            "'service returns 502 then restarts'. Concrete signals "
            "the operator can verify."
        ),
    )
    can_run: bool = Field(
        description=(
            "True when this PoC is runnable as-is. False when key "
            "information was missing from the finding and the PoC "
            "is a skeleton awaiting operator completion."
        ),
    )
    missing_inputs: list[str] = Field(
        default_factory=list,
        description=(
            "When can_run is False, list what's needed to make the "
            "PoC runnable. Empty when can_run is True."
        ),
    )
    caveats: list[str] = Field(
        default_factory=list,
        description=(
            "Important caveats: ASLR / NX / stack canary assumptions, "
            "version-specific behavior, sandbox escape preconditions, "
            "rate-limiting concerns. Operator-facing warnings."
        ),
    )
    safety_notes: str = Field(
        default="",
        description=(
            "Safety guidance: target only owned infrastructure, "
            "any cleanup steps needed after running, denial-of-"
            "service caveats."
        ),
    )


class PocWriter:
    """LLM-backed PoC writer. Construction takes a ServiceFactory.

    Stateless — one instance produces many PoCs concurrently. The
    ``write`` method is the only public entry point.
    """

    _TASK_TYPE = "vulnerability_research.poc_writer"

    def __init__(self, services: ServiceFactory | None = None) -> None:
        self._services = services or ServiceFactory()

    async def write(self, facts: dict[str, Any]) -> PocDraft:
        """Generate a PocDraft from a structured facts dict.

        ``facts`` shape mirrors what ReportWriter accepts so the same
        collector can feed both writers, plus a few PoC-specific
        fields:

          - vulnerability_class: str (e.g. 'heap_buffer_overflow')
          - vulnerable_function: str
          - affected_components: list[str]   ('file:line function')
          - reproduction_conditions: str     (preconditions text)
          - target_kind: 'source_repo' | 'binary_upload' | etc.
          - target_repo: str | None
          - root_cause_summary: str
          - final_answer: str                (the agent's submit text)
        """
        response = await self._services.llm_client.chat_structured(
            task_type=self._TASK_TYPE,
            messages=[
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": self._render_facts(facts)},
            ],
            model_class=PocDraft,
        )
        if response.disabled:
            raise RuntimeError("LLM kill-switch active — cannot draft PoC")
        return PocDraft.model_validate(json.loads(response.content))

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are a senior exploit developer. Your job: convert a "
            "confirmed vulnerability finding into a runnable proof of "
            "concept that demonstrates the bug.\n\n"
            "Hard rules:\n"
            "- ONLY use facts present in the input. Do NOT invent "
            "function signatures, file paths, struct layouts, or "
            "configuration directives that weren't established by "
            "the investigation.\n"
            "- If the finding is missing critical information for a "
            "real PoC (exact memory layout, calling convention, "
            "target version), produce a SKELETON PoC with "
            "``can_run=False`` and list the missing inputs. Better "
            "an honest stub than a fabricated exploit.\n"
            "- Default to LEAST-HARMFUL payload that demonstrates "
            "the bug. A crash / OOB read is enough for proof. Do "
            "not author working RCE shellcode unless the finding "
            "explicitly establishes the primitive.\n"
            "- For source-repo C/C++ targets, prefer a Python "
            "scripted request (requests / socket / curl) that "
            "triggers the bug remotely. Include the target setup "
            "(config snippet, build flags) so the operator can "
            "stand up the vulnerable instance.\n"
            "- For binary targets, write C that exercises the "
            "vulnerable primitive directly.\n"
            "- ``expected_outcome`` MUST be a concrete signal the "
            "operator can verify: a specific crash type, an ASAN "
            "report line, an HTTP error code, a particular log "
            "message. 'It works' is not an acceptable expected "
            "outcome.\n"
            "- Output MUST be valid JSON matching the PocDraft "
            "schema. No prose outside the JSON object."
        )

    @staticmethod
    def _render_facts(facts: dict[str, Any]) -> str:
        out: list[str] = ["# Vulnerability finding\n"]

        if facts.get("investigation_title"):
            out.append(f"Title: {facts['investigation_title']}")
        if facts.get("cve_id"):
            out.append(f"CVE: {facts['cve_id']}")
        if facts.get("vulnerability_class"):
            out.append(f"Class: {facts['vulnerability_class']}")
        if facts.get("vulnerable_function"):
            out.append(f"Vulnerable function: {facts['vulnerable_function']}")
        out.append(f"Target kind: {facts.get('target_kind') or 'unknown'}")
        if facts.get("target_repo"):
            out.append(f"Target repo: {facts['target_repo']}")
        if facts.get("target_ref"):
            out.append(f"Target ref: {facts['target_ref']}")
        out.append("")

        if facts.get("affected_components"):
            out.append("# Affected components")
            for c in facts["affected_components"]:
                out.append(f"- {c}")
            out.append("")

        if facts.get("reproduction_conditions"):
            out.append("# Reproduction conditions")
            out.append(str(facts["reproduction_conditions"])[:2000])
            out.append("")

        if facts.get("root_cause_summary"):
            out.append("# Root cause (summary)")
            out.append(str(facts["root_cause_summary"])[:2000])
            out.append("")

        if facts.get("final_answer"):
            out.append("# Full finding (authoritative)")
            out.append(str(facts["final_answer"])[:6000])
            out.append("")

        out.append(
            "# Instruction\n\n"
            "Produce a PocDraft JSON object per the schema. Pick the "
            "most natural language for this target. Make the PoC "
            "self-contained and runnable. If critical information is "
            "missing, set can_run=False and list the gaps in "
            "missing_inputs — do not fabricate."
        )
        return "\n".join(out)
