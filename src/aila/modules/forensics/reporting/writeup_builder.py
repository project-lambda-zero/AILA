"""Professional forensic write-up generator.

Builds structured, publication-quality DFIR / CTF malware-analysis
reports from investigation steps, artefacts, Ghidra pre-analysis,
memory-enrichment derivers, and network summaries. The prompt is
deliberately opinionated — the LLM is handed a 15-section contract
with hard rules and a tool-stack reference so that output quality is
bounded by the evidence, not by the model's default verbosity style.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from aila.platform.services.factory import ServiceFactory

__all__ = ["build_writeup"]

_log = logging.getLogger(__name__)

# Cap the user-message bundle so we do not blow the context window on
# disk-image cases that produced thousands of artefacts. 32 KB is enough
# to carry inventory, step log, and the pre-computed Ghidra + memory +
# network summaries without swamping the model.
_USER_BUNDLE_CHAR_CAP = 32_000
_PER_SECTION_CAP = 6_000
_STEP_STDOUT_CAP = 400
_STEP_REASONING_CAP = 400


_WRITEUP_SYSTEM_PROMPT = """You are a senior DFIR / malware-analysis engineer writing an incident-response report for a client SOC. The report is graded by a staff-level reviewer AND a CTF organiser; it MUST NOT read like generic LLM output. Every factual claim MUST be traceable to evidence you cite inline by one of: artifact_id, absolute file path, function address (`<function_name>@<0xADDR>`), or a tool-stdout excerpt tagged with the step number that produced it.

# OUTPUT CONTRACT

Write a single Markdown document using EXACTLY the section numbering and headings below. Every section is mandatory. If a section has no findings, write `*No findings in this layer — see <evidence reference> for why.*` instead of omitting it. Do not add sections the contract does not list. Do not collapse sections into each other.

## 1. Executive Summary
Three sentences maximum. Who, what, when, where, impact. Cite the primary artefact.

## 2. Investigation Question and Answer
- **Question** (verbatim from the input).
- **Answer** (verbatim, matching the answer_format from the contract).
- **Confidence**: one of `exact`, `strong`, `medium`, `caveated`.
- **Primary artefact**: artifact_id or absolute path.

## 3. Evidence Inventory
Markdown table with columns: `name | libmagic type | sha256 | size | path | notes`. One row per evidence file listed in the case bundle.

## 4. File Identification
Sub-section per binary-like artefact, each with:
- libmagic description + MIME
- architecture / bits / endianness
- MD5 / SHA1 / SHA256 (and imphash when PE)
- compile timestamp (only when trustworthy)
- signature state (signed y/n, signer CN if known)

## 5. Strings Analysis
Filtered, never dumped. Use Markdown tables titled:
- URLs / domains / IPs / bare hostnames
- Absolute file paths
- Registry paths
- Mutex / event / named-pipe names
- Crypto references (`AES`, `RC4`, `XOR`, `SHA256`, key literals)
- Shell / LOLBIN fragments

Each row MUST cite the tool (`strings`, `FLOSS`, `Ghidra`) and either the offset or the function address (`<name>@<0xADDR>`). Cap at 60 rows per table — include only the most evidence-bearing ones.

## 6. Binary Structure
- **PE**: machine, sections with entropy flags, top imports grouped by intent, exports, TLS callbacks, overlay presence.
- **ELF**: class, machine, dynamic symbols, notable sections.
- **Go binaries**: build-id, module path, stripped y/n.

## 7. Obfuscation & Anti-Analysis
- Packer (`UPX`, `MPRESS`, `Themida`, `Enigma`, `VMProtect`, `garble`, or `none`).
- String obfuscation (`XOR`, `base64`, `RC4`, `custom`).
- Control-flow flattening evidence.
- Anti-debug / anti-VM primitives — reference Ghidra's `intent_map.anti_debug` function addresses when the bundle has them.

## 8. Disassembly & Decompilation Highlights
Work from the pre-collected `ghidra_functions` and `ghidra_decompilation` artefacts in the bundle. List every call-graph root that touches network / crypto / filesystem / process-creation as `<name>@<0xADDR>` with a one-sentence intent. Include 3–8 short pseudocode snippets that directly implement the malicious behaviour; NEVER paste more than 40 lines per snippet.

## 9. Cryptography
Algorithms identified, keys / IVs / salts extracted, ciphertext path + entropy, plaintext when decoded. Cite the Ghidra function + address for every primitive.

## 10. C2 / Network
Markdown table: `URL | IP | port | proto | user-agent | JA3 | beacon interval | source_step_or_artifact`. Include encoded C2 keys, XOR campaign obfuscation, and protocol format (HTTP / gRPC / protobuf / custom). Source rows from pcap artefacts AND/OR extracted strings — cite which.

## 11. MITRE ATT&CK Mapping
Markdown table: `Tactic | Technique | ID | Evidence`. Include ONLY entries you can cite. Do not pad with speculative techniques.

## 12. Indicators of Compromise
Fenced code block formatted so an analyst can drop it straight into `iocs.txt`:
```
hashes:
  <artifact>: md5=... sha1=... sha256=...
network:
  ip: ...
  domain: ...
  url: ...
filesystem:
  /path/...
registry:
  HKLM\\...\\Value = ...
names:
  mutex: ...
  pipe: ...
  service: ...
  task: ...
```

## 13. CTF Hypothesis Q&A
6–12 Q/A pairs predicting likely CTF questions. For each pair:
- **Q**: short natural-language question.
- **A**: exact expected answer string (matching typical CTF flag / value formats).
- **Source**: artifact_id / path / `<function>@<0xADDR>`.

Aim for breadth across the 9 phases, not depth on one finding.

## 14. Timeline of Investigator Actions
Markdown table: `# | action | tool | intent | outcome`. Chronological. One row per investigation step.

## 15. Conclusions & Confidence
Final verdict, residual unknowns, recommended follow-ups (static-only, offline).

# HARD RULES

- Every claim MUST cite a piece of evidence from the bundle below — artifact_id, absolute file path, `<function>@<0xADDR>`, or `step #N`. No citation, no claim.
- Do NOT reference any tool, capability, or workflow that is not listed under TOOL STACK. If something is absent from the bundle, say so plainly under Gaps; do NOT fill the gap with speculation.
- Do NOT write hedging filler: "typical malware might...", "this is commonly observed", "it is worth noting", "interestingly", "notably". Either cite or omit.
- Do NOT paste more than 40 lines of code, 60 table rows, or 80 raw strings per section.
- Use fenced code blocks for commands, pseudocode, hex, and IOC blocks. Use Markdown tables for every list-of-rows section.
- Pick American OR British English and stay consistent. No emojis. No marketing language.
- Normalise timestamps to ISO-8601 UTC with second resolution.
- When you reference a step from the investigator's timeline, cite it as `step #N`.

# TOOL STACK AVAILABLE TO THE INVESTIGATOR

You may reference these in the methodology section; do NOT claim the investigator used a tool whose output is not present in the step log or the artefact bundle:

- dissect.target, dissect.executable, dissect.ntfs, dissect.regf
- Volatility 3 (`windows.*`, `linux.*`, `mac.*`) with memory-enrichment derivers
- tshark / Zeek (pcap)
- Sysinternals strings, FLOSS, capa
- pefile, python-magic, yara-python, pylnk3
- Ghidra headless (pre-run by the `binary_analysis` collection lane) emitting `ghidra_functions` and `ghidra_decompilation` artefacts
- 7-Zip, dnSpyEx, PyInstaller Extractor, signtool

Return ONLY the Markdown report. No prose before or after. No meta-commentary about your own process."""


async def build_writeup(
    project_id: str,
    investigation_id: str | None,
    steps: list[dict[str, Any]],
    input_context: dict[str, Any],
) -> dict[str, Any]:
    """Generate a professional write-up from investigation data.

    Args:
        project_id: The forensics project ID (included in result context).
        investigation_id: Optional investigation run ID (included in result context).
        steps: List of agent step dicts.
        input_context: Full workflow input context.

    Returns:
        Dict with 'title', 'content', 'methodology', 'artifacts_json'.
    """
    _log.debug("Building writeup for project=%s investigation=%s", project_id, investigation_id)
    question = input_context.get("question", "Full evidence analysis")
    answer = input_context.get("answer")
    confidence = input_context.get("confidence", "")
    observables = input_context.get("observables") or {}
    contract = input_context.get("contract") or {}
    hypotheses = input_context.get("hypotheses") or []
    rejected = input_context.get("rejected") or []

    tools_used = _derive_tools_used(steps)
    methodology = (
        f"Tools used: {', '.join(sorted(tools_used)) or 'N/A'}. "
        f"Total investigation steps: {len(steps)}."
    )

    content = await _generate_writeup_content(
        project_id=project_id,
        investigation_id=investigation_id,
        question=question,
        answer=answer,
        confidence=confidence,
        steps=steps,
        tools_used=sorted(tools_used),
        observables=observables,
        contract=contract,
        hypotheses=hypotheses,
        rejected=rejected,
    )

    artifacts_referenced = [s.get("primary_artifact_id") for s in steps if s.get("primary_artifact_id")]

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = f"Investigation: {question[:80]}" if question else f"Analysis Report — {timestamp}"

    return {
        "title": title,
        "content": content,
        "methodology": methodology,
        "artifacts_json": json.dumps(artifacts_referenced),
    }


# ---------------------------------------------------------------------------
# Tool-stack attribution
# ---------------------------------------------------------------------------

def _derive_tools_used(steps: list[dict[str, Any]]) -> set[str]:
    """Infer the tool stack from the investigator's step log."""
    tools_used: set[str] = set()
    for step in steps:
        action = step.get("action", "reasoning")
        cmd = (step.get("command") or "").lower()
        if action == "script_execute":
            tools_used.add("Python script (custom)")
        if "dissect" in cmd:
            tools_used.add("dissect.target")
        if "vol.py" in cmd or "volatility" in cmd or "vol3" in cmd:
            tools_used.add("Volatility 3")
        if "tshark" in cmd:
            tools_used.add("tshark (Wireshark)")
        if "zeek" in cmd:
            tools_used.add("Zeek")
        if "strings" in cmd:
            tools_used.add("Sysinternals strings / GNU strings")
        if "floss" in cmd:
            tools_used.add("FLOSS")
        if "capa" in cmd:
            tools_used.add("capa")
        if "magic.from_file" in cmd or "python-magic" in cmd:
            tools_used.add("python-magic")
        if "pefile" in cmd:
            tools_used.add("pefile")
        if "pylnk3" in cmd:
            tools_used.add("pylnk3")
        if "analyzeheadless" in cmd or "ghidra" in cmd:
            tools_used.add("Ghidra headless")
        if "yara" in cmd:
            tools_used.add("yara-python")
        if action == "tool_run" and cmd and not tools_used.intersection({"dissect.target", "Volatility 3"}):
            first = cmd.split()[0] if cmd.strip() else ""
            if first and not any(t.split()[0].lower() in first for t in tools_used):
                tools_used.add(f"CLI: {first}")
    return tools_used


# ---------------------------------------------------------------------------
# User-message bundle construction
# ---------------------------------------------------------------------------

async def _generate_writeup_content(
    project_id: str,
    investigation_id: str | None,
    question: str,
    answer: str | None,
    confidence: str,
    steps: list[dict[str, Any]],
    tools_used: list[str],
    observables: dict[str, Any],
    contract: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
) -> str:
    """Generate write-up content via LLM; fall back to template on failure."""
    # Assemble the case bundle the model will reason over. Everything
    # downstream of here is deterministic summarisation of what the
    # investigator actually produced — no prose, no guesswork.
    bundle_parts: list[str] = []

    bundle_parts.append(_section_case_header(
        project_id=project_id,
        investigation_id=investigation_id,
        question=question,
        answer=answer,
        confidence=confidence,
        contract=contract,
        tools_used=tools_used,
        step_count=len(steps),
    ))

    # Pull artefacts snapshot from the project database so the model
    # sees the evidence universe, not just the last 10 steps.
    artefacts_by_family = await _load_artefacts_by_family(project_id)
    bundle_parts.append(_section_evidence_inventory(artefacts_by_family))
    bundle_parts.append(_section_artefact_families(artefacts_by_family))

    bundle_parts.append(_section_ghidra_summary(artefacts_by_family))
    bundle_parts.append(_section_memory_enrich_summary(artefacts_by_family))
    bundle_parts.append(_section_network_summary(artefacts_by_family))

    bundle_parts.append(_section_observables(observables))
    bundle_parts.append(_section_hypotheses(hypotheses, rejected))
    bundle_parts.append(_section_step_log(steps))

    user_bundle = _cap_bundle("\n\n".join(bundle_parts), _USER_BUNDLE_CHAR_CAP)

    client = ServiceFactory().llm_client
    resp = await client.chat(
        task_type="forensics_writeup",
        messages=[
            {"role": "system", "content": _WRITEUP_SYSTEM_PROMPT},
            {"role": "user", "content": user_bundle},
        ],
    )
    if resp.disabled:
        raise RuntimeError("LLM kill-switch active")
    return resp.content


# ---------------------------------------------------------------------------
# Bundle sections
# ---------------------------------------------------------------------------

def _section_case_header(
    project_id: str,
    investigation_id: str | None,
    question: str,
    answer: str | None,
    confidence: str,
    contract: dict[str, Any],
    tools_used: list[str],
    step_count: int,
) -> str:
    lines = ["# CASE"]
    lines.append(f"project_id: {project_id}")
    lines.append(f"investigation_id: {investigation_id or '-'}")
    lines.append(f"question: {question}")
    lines.append(f"answer: {answer or '-'}")
    lines.append(f"confidence: {confidence or '-'}")
    if contract:
        lines.append(f"answer_type: {contract.get('answer_type','-')}")
        lines.append(f"answer_format: {contract.get('answer_format','-')}")
        lines.append(f"evidence_domain: {contract.get('evidence_domain','-')}")
    lines.append(f"tools_used: {', '.join(tools_used) or '-'}")
    lines.append(f"step_count: {step_count}")
    lines.append(f"report_generated_utc: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    return "\n".join(lines)


async def _load_artefacts_by_family(project_id: str) -> dict[str, list[dict[str, Any]]]:
    """Pull every artefact record for the project, grouped by family."""
    if not project_id:
        return {}
    try:
        from sqlmodel import select

        from aila.modules.forensics.db_models import ArtifactRecord
        from aila.platform.uow import UnitOfWork

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(ArtifactRecord).where(ArtifactRecord.project_id == project_id)
            )).all()
        for r in rows:
            family = getattr(r, "family", "unknown") or "unknown"
            payload = getattr(r, "data", None)
            if isinstance(payload, str):
                try:
                    payload_obj = json.loads(payload)
                except json.JSONDecodeError:
                    payload_obj = {}
            elif isinstance(payload, dict):
                payload_obj = payload
            else:
                payload_obj = {}
            grouped[family].append({
                "id": getattr(r, "id", ""),
                "type": getattr(r, "type", ""),
                "source_tool": getattr(r, "source_tool", ""),
                "data": payload_obj,
            })
        return dict(grouped)
    except Exception:
        _log.warning("Failed to load artefacts_by_family for %s", project_id, exc_info=True)
        return {}


def _section_evidence_inventory(artefacts_by_family: dict[str, list[dict[str, Any]]]) -> str:
    """Inventory of the evidence files on disk, mined from binary_analysis."""
    rows: list[str] = ["# EVIDENCE INVENTORY"]
    bin_rows = artefacts_by_family.get("malware", []) + artefacts_by_family.get("binary", [])
    seen: set[str] = set()
    rows.append("name | libmagic | sha256 | size | path")
    for a in bin_rows:
        data = a.get("data") or {}
        sha = str(data.get("sha256") or "")
        if not sha or sha in seen:
            continue
        seen.add(sha)
        rows.append(
            f"{data.get('basename','?')} | "
            f"{data.get('filetype_desc', data.get('filetype','?'))} | "
            f"{sha[:16]}… | {data.get('size','?')} | "
            f"{data.get('evidence_path', data.get('path',''))}"
        )
    if len(rows) == 2:
        rows.append("(no binary-family artefacts in snapshot)")
    return _cap_section("\n".join(rows))


def _section_artefact_families(artefacts_by_family: dict[str, list[dict[str, Any]]]) -> str:
    """High-level summary of every artefact family present."""
    lines = ["# ARTEFACT FAMILIES"]
    for family, rows in sorted(artefacts_by_family.items()):
        types = defaultdict(int)
        for r in rows:
            types[r.get("type", "unknown")] += 1
        parts = ", ".join(f"{t}:{n}" for t, n in sorted(types.items(), key=lambda kv: -kv[1]))
        lines.append(f"- {family} ({len(rows)} total) — {parts}")
    if len(lines) == 1:
        lines.append("(empty snapshot)")
    return "\n".join(lines)


def _section_ghidra_summary(artefacts_by_family: dict[str, list[dict[str, Any]]]) -> str:
    """Hoist the Ghidra pre-analysis summary into the bundle."""
    lines = ["# GHIDRA PRE-ANALYSIS"]
    found = False
    for family_rows in artefacts_by_family.values():
        for a in family_rows:
            if a.get("type") != "ghidra_decompilation":
                continue
            found = True
            data = a.get("data") or {}
            summary = data.get("summary") or {}
            lines.append(f"## artifact {a.get('id','?')[:8]} — {data.get('basename','?')}")
            lines.append(f"sha256: {data.get('sha256','?')}")
            lines.append(f"total_functions: {summary.get('total_functions','?')}")
            lines.append(f"functions_with_c_source: {summary.get('functions_with_c_source','?')}")
            top = summary.get("top_functions_by_size") or []
            if top:
                lines.append("top_functions_by_size (first 20):")
                for row in top[:20]:
                    lines.append(f"  - {row.get('address','?')} {row.get('name','?')} size={row.get('size','?')}")
            intent = summary.get("intent_map") or {}
            if intent:
                lines.append("intent_map:")
                for bucket, entries in intent.items():
                    if not entries:
                        continue
                    clipped = entries[:40]
                    lines.append(f"  {bucket}: {', '.join(str(e) for e in clipped)}")
            counts = summary.get("intent_bucket_counts") or {}
            if counts:
                lines.append(f"intent_bucket_counts: {counts}")
    if not found:
        lines.append("(no ghidra_decompilation artefacts — binaries were skipped, oversize, signed, or not PE/ELF)")
    return _cap_section("\n".join(lines))


def _section_memory_enrich_summary(artefacts_by_family: dict[str, list[dict[str, Any]]]) -> str:
    """Hoist the six memory-enrichment derivers into the bundle."""
    lines = ["# MEMORY ENRICHMENT"]
    mem_rows = artefacts_by_family.get("memory", [])
    derivers = {
        "process_tree",
        "injection_candidates",
        "network_by_process",
        "handle_anomalies",
        "rootkit_candidates",
        "registry_exec_history",
    }
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in mem_rows:
        if a.get("type") in derivers:
            by_type[a["type"]].append(a)
    if not by_type:
        lines.append("(no memory enrichment artefacts — project has no memory image or collection failed)")
        return _cap_section("\n".join(lines))
    for t, rows in sorted(by_type.items()):
        lines.append(f"## {t} ({len(rows)} artefact(s))")
        for a in rows[:3]:
            data = a.get("data") or {}
            records = data.get("records") or []
            lines.append(f"  - records: {len(records)}  (preview next {min(5, len(records))})")
            for rec in records[:5]:
                lines.append(f"    * {json.dumps(rec, default=str)[:240]}")
    return _cap_section("\n".join(lines))


def _section_network_summary(artefacts_by_family: dict[str, list[dict[str, Any]]]) -> str:
    """Summarise the pcap / network lane."""
    lines = ["# NETWORK SUMMARY"]
    net_rows = artefacts_by_family.get("network", [])
    if not net_rows:
        lines.append("(no network artefacts)")
        return _cap_section("\n".join(lines))
    grouped: dict[str, int] = defaultdict(int)
    hosts: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()
    for a in net_rows:
        grouped[a.get("type", "?")] += 1
        data = a.get("data") or {}
        for rec in (data.get("records") or [])[:200]:
            if not isinstance(rec, dict):
                continue
            for key in ("ip", "dst", "src", "host", "server", "client"):
                val = rec.get(key)
                if isinstance(val, str) and val:
                    hosts.add(val[:64])
            d = rec.get("domain") or rec.get("query_name")
            if isinstance(d, str) and d:
                domains.add(d[:128])
            u = rec.get("url") or rec.get("uri")
            if isinstance(u, str) and u:
                urls.add(u[:256])
    lines.append(f"types: {dict(grouped)}")
    if hosts:
        lines.append(f"hosts ({len(hosts)} unique, first 30): {sorted(hosts)[:30]}")
    if domains:
        lines.append(f"domains ({len(domains)} unique, first 30): {sorted(domains)[:30]}")
    if urls:
        lines.append(f"urls ({len(urls)} unique, first 20): {sorted(urls)[:20]}")
    return _cap_section("\n".join(lines))


def _section_observables(observables: dict[str, Any]) -> str:
    """Dump the final observables dict — the audit trail the investigator left."""
    lines = ["# OBSERVABLES (investigator audit trail)"]
    if not observables:
        lines.append("(empty)")
        return "\n".join(lines)
    try:
        blob = json.dumps(observables, indent=2, default=str, sort_keys=True)
    except (TypeError, ValueError):
        blob = str(observables)
    return _cap_section(lines[0] + "\n```json\n" + blob + "\n```")


def _section_hypotheses(
    hypotheses: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
) -> str:
    lines = ["# HYPOTHESES"]
    if hypotheses:
        lines.append("## open")
        for h in hypotheses:
            lines.append(f"- {h.get('id','?')}: {h.get('claim','?')} — kill: {h.get('kill_criterion','?')}")
    if rejected:
        lines.append("## rejected")
        for h in rejected:
            lines.append(f"- {h.get('id','?')}: {h.get('claim','?')} — reason: {h.get('reason','?')}")
    if len(lines) == 1:
        lines.append("(none)")
    return "\n".join(lines)


def _section_step_log(steps: list[dict[str, Any]]) -> str:
    lines = ["# STEP LOG"]
    for s in steps:
        n = s.get("step_number", "?")
        action = s.get("action", "?")
        cmd = (s.get("command") or "")[:200]
        reasoning = (s.get("reasoning") or "")[:_STEP_REASONING_CAP]
        stdout = (s.get("stdout") or "")[:_STEP_STDOUT_CAP]
        stderr = (s.get("stderr") or "")[:200]
        lines.append(f"## step {n} — {action}")
        if cmd:
            lines.append(f"command: {cmd}")
        if reasoning:
            lines.append(f"reasoning: {reasoning}")
        if stdout:
            lines.append(f"stdout_head: {stdout}")
        if stderr:
            lines.append(f"stderr_head: {stderr}")
    if len(lines) == 1:
        lines.append("(no steps)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Budget / fallbacks
# ---------------------------------------------------------------------------

def _cap_section(text: str) -> str:
    if len(text) <= _PER_SECTION_CAP:
        return text
    return text[:_PER_SECTION_CAP] + "\n…[section truncated]…"


def _cap_bundle(text: str, cap: int) -> str:
    if len(text) <= cap:
        return text
    return text[:cap] + "\n…[bundle truncated to protect context window]…"


def _build_template_writeup(
    question: str,
    answer: str | None,
    confidence: str,
    steps: list[dict[str, Any]],
    tools_used: list[str],
    observables: dict[str, Any],
    artefacts_by_family: dict[str, list[dict[str, Any]]],
) -> str:
    """Fallback structured template when the LLM is unavailable.

    The template deliberately mirrors the 15-section contract so that a
    kill-switched / offline write-up still carries the same shape an
    analyst can complete by hand.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out: list[str] = []
    out.append("# Forensic Investigation Report")
    out.append(f"*Generated {timestamp} — LLM unavailable, template fallback.*")
    out.append("")
    out.append("## 1. Executive Summary")
    out.append(
        f"Investigation of *{question}* completed across {len(steps)} step(s) "
        f"using: {', '.join(tools_used) or 'n/a'}."
    )
    out.append("")
    out.append("## 2. Investigation Question and Answer")
    out.append(f"- **Question**: {question}")
    out.append(f"- **Answer**: {answer or '_No definitive answer within budget._'}")
    out.append(f"- **Confidence**: {confidence or '-'}")
    out.append("")

    out.append("## 3. Evidence Inventory")
    out.append("| name | libmagic | sha256 | size | path |")
    out.append("| --- | --- | --- | --- | --- |")
    seen: set[str] = set()
    for a in artefacts_by_family.get("malware", []) + artefacts_by_family.get("binary", []):
        d = a.get("data") or {}
        sha = str(d.get("sha256") or "")
        if not sha or sha in seen:
            continue
        seen.add(sha)
        out.append(
            f"| {d.get('basename','?')} | {d.get('filetype_desc', d.get('filetype','?'))} | "
            f"{sha[:16]}… | {d.get('size','?')} | {d.get('evidence_path', d.get('path',''))} |"
        )
    if not seen:
        out.append("| _none_ | | | | |")
    out.append("")

    for heading in (
        "4. File Identification",
        "5. Strings Analysis",
        "6. Binary Structure",
        "7. Obfuscation & Anti-Analysis",
        "8. Disassembly & Decompilation Highlights",
        "9. Cryptography",
        "10. C2 / Network",
        "11. MITRE ATT&CK Mapping",
        "12. Indicators of Compromise",
        "13. CTF Hypothesis Q&A",
    ):
        out.append(f"## {heading}")
        out.append("*No findings in this layer — LLM fallback, template only. See §14 for raw step evidence.*")
        out.append("")

    out.append("## 14. Timeline of Investigator Actions")
    out.append("| # | action | tool | intent | outcome |")
    out.append("| --- | --- | --- | --- | --- |")
    for s in steps:
        n = s.get("step_number", "?")
        act = s.get("action", "?")
        cmd = (s.get("command") or "").split(" ", 1)[0]
        intent = (s.get("reasoning") or "").replace("|", "/")[:120]
        outcome = "ok" if s.get("stdout") else ("err" if s.get("stderr") else "-")
        out.append(f"| {n} | {act} | {cmd} | {intent} | {outcome} |")
    out.append("")

    out.append("## 15. Conclusions & Confidence")
    out.append(f"Confidence: **{confidence or '-'}**. ")
    out.append(f"Observables captured: {list((observables or {}).keys())[:30]}")
    return "\n".join(out)
