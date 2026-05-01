# Vulnerability Research Module — Brainstorm

Working document. Not a spec. Everything here is open to challenge.

---

## What This Is

An automated vulnerability research workbench with a human in the loop. The LLM is not a helper — it's the primary researcher. It generates hypotheses, selects strategies, picks fuzzing targets, writes harnesses, triages crashes, develops exploits, and produces advisories. The human steers, supplies context (published writeups, domain knowledge, hunches), and validates findings.

Two distinct workflows:
1. **Vulnerability Research** — open-ended bug hunting on a target (binary, library, codebase)
2. **N-day PoC Writer** — given a CVE, produce a working exploit

---

## How It Connects to the Platform

Same pattern as forensics:
- SSH into a **research workstation** (Linux lab VM with tools installed)
- Multi-turn **CyberReasoningEngine** loop (hypothesis -> action -> observe -> refine)
- **Operator steering** for human-in-the-loop (confirmed facts, strategy pins, context injection)
- **Evidence graph** tracking what was tried, what worked, what didn't
- **Durable workflow** via DurableStateMachine (survives crashes, retries, resumable)

New:
- **IDA Pro headless MCP** — purpose-built for this module, not the generic one
- **Fuzzing campaign orchestration** — AFL++, libFuzzer, honggfuzz as managed campaigns
- **Exploit development sandbox** — compile, run, test PoCs on the research workstation

---

## The Research Workstation

A Linux VM (or bare metal) the module SSHes into. Must have:

| Tool | Purpose |
|---|---|
| IDA Pro (headless) | Reverse engineering, decompilation, binary analysis |
| Ghidra (headless) | Alternative RE, free, scriptable via Ghidra Bridge |
| AFL++ | Coverage-guided fuzzing |
| libFuzzer | In-process fuzzing (for source-available targets) |
| honggfuzz | Alternative fuzzer, good at feedback-driven mutation |
| GDB + pwndbg/GEF | Crash analysis, exploit development |
| BinDiff / Diaphora | Patch diffing between binary versions |
| Git | Source history archaeology |
| Semgrep | Pattern-based source audit |
| Compiler toolchain | gcc, clang, ASAN/MSAN/UBSAN for building harnesses |
| Python 3 + pwntools | Exploit scripting |
| protobuf/flatbuffers | Protocol-aware fuzzing structure definitions |
| radare2/rizin | Lightweight binary analysis, scripting |

The module should verify tool availability at project creation (like forensics MachineReadinessCheck).

---

## Workflow 1: Vulnerability Research

### Project Lifecycle

```
CREATE PROJECT
  target: binary path, source repo URL, or both
  scope: specific binary, library, protocol handler, parser, etc.
  context: human-supplied notes, published writeups, prior research
  |
  v
RECONNAISSANCE
  - Binary analysis: architecture, protections (ASLR, canary, PIE, NX, RELRO, CFI)
  - Attack surface mapping: parsers, network handlers, file format processors
  - Dependency analysis: what libraries, what versions, known CVEs in deps
  - Source archaeology (if available): dangerous function usage, recent security commits
  |
  v
HYPOTHESIS GENERATION
  LLM proposes: "The TIFF parser in libfoo likely has integer overflow in tile size calculation"
  LLM explains: why plausible, what evidence supports it, what would disprove it
  Human can: confirm, redirect, add hypotheses, supply external intel
  |
  v
STRATEGY SELECTION (per hypothesis)
  Options:
  - Fuzzing campaign (AFL++/libFuzzer with custom harness)
  - Manual code audit (source or decompiler output)
  - Patch diff analysis (compare versions to find silent fixes)
  - Variant analysis (pattern search across codebase)
  - Protocol fuzzing (structure-aware mutation)
  - Git history mining (find bug-introducing commits)
  |
  v
EXECUTION (multi-turn, iterative)
  LLM writes harnesses, scripts, analysis tools
  LLM reads tool output, crash reports, coverage data
  LLM refines strategy based on results
  Human can inject context at any point
  |
  v
TRIAGE
  - Crash dedup and bucketing
  - Root cause analysis (what memory error, where, why)
  - Exploitability assessment (controllable? reachable? mitigations?)
  - Severity estimation (CVSS vector, impact)
  |
  v
EXPLOIT DEVELOPMENT (if exploitable)
  - PoC skeleton generation
  - Mitigation bypass strategy (ASLR leak, stack pivot, ROP chain)
  - PoC testing and reliability assessment
  |
  v
REPORTING
  - Technical advisory (root cause, impact, affected versions, remediation)
  - PoC code (working exploit or crash trigger)
  - Fuzzing campaign summary (corpus size, coverage, crashes found, time)
  - Strategy log (what was tried, what worked, what didn't, why)
  - Evidence graph (full reasoning chain from hypothesis to finding)
```

### What the LLM Decides

The LLM is not executing a checklist. It's making creative research decisions:

- **Where to look.** "This binary has 47 parsers. The MQTT message handler looks most promising because it processes untrusted input with no length validation in the decompiled code."
- **What to fuzz.** "I'll target the `parse_extension()` function because it has a complex state machine with 12 branches and no bounds checking on the `ext_length` field."
- **How to write the harness.** Generates AFL++ harness code that sets up the right state to reach the target function.
- **When to pivot.** "After 6 hours of fuzzing with 0 crashes and 89% edge coverage, this target is likely not fruitful. Pivoting to the TLS handshake parser."
- **How to interpret crashes.** "This crash at `0x41414141` is a controlled write-what-where via the heap metadata corruption. The overflow is 4 bytes past the allocation in `realloc_buffer()`."
- **Whether it's exploitable.** "Controllable heap overflow with 4 bytes of overwrite. Target has partial RELRO and no CFI. Exploitable via tcache poisoning on glibc 2.35+."

### What the Human Supplies

- Published vulnerability writeups ("here's how Project Zero found a similar bug in Chrome's TIFF parser")
- Domain expertise ("this protocol uses length-prefix encoding, fuzz the length fields")
- Strategy overrides ("don't bother with the GUI code, focus on the network daemon")
- External intelligence ("version 2.3.1 had a silent security fix, diff against 2.3.0")
- Go/no-go decisions on exploit development

---

## Workflow 2: N-day PoC Writer

Separate, focused workflow. Input: a CVE ID. Output: a working PoC.

```
INPUT: CVE-2024-XXXXX
  |
  v
RESEARCH
  - Fetch advisory (NVD, vendor, OSV)
  - Find the patch commit (git log, vendor changelog, BinDiff)
  - Identify affected versions and fixed version
  |
  v
ROOT CAUSE ANALYSIS
  - Reverse the patch: what was the bug?
  - Understand the trigger condition
  - Map the vulnerable code path
  |
  v
POC DEVELOPMENT
  - Write minimal trigger (crash PoC)
  - If exploitable: write exploit PoC
  - Test against affected version
  - Verify fix in patched version
  |
  v
OUTPUT
  - PoC code (Python/C)
  - Writeup: root cause, trigger, affected versions, mitigation
  - Reliability notes (deterministic? race condition? heap-dependent?)
```

This is a tighter loop — less open-ended than full research. The LLM has a clear goal (working PoC for a known bug) and a defined success criterion (crash or exploit on vulnerable version, clean on patched).

---

## Fuzzing Campaign Management

The LLM doesn't just "run AFL++". It manages the full campaign lifecycle:

### Target Selection
LLM analyzes the binary and proposes fuzzing targets:
- Parser entry points (file formats, network protocols)
- Deserialization functions (protobuf, JSON, XML)
- State machine handlers (protocol implementations)
- Memory management wrappers (custom allocators, pools)

### Harness Generation
LLM writes the harness code:
```c
// Generated by AILA VR module for target: parse_mqtt_message
#include <stdint.h>
#include <stdlib.h>
#include "mqtt_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mqtt_context_t ctx = {0};
    mqtt_init(&ctx);
    mqtt_parse_message(&ctx, data, size);
    mqtt_cleanup(&ctx);
    return 0;
}
```

### Protocol-Aware Fuzzing
For structured inputs (protobuf, flatbuffers, ASN.1):
- LLM reads the `.proto` / `.fbs` definition
- Generates a protobuf-aware mutator or uses libprotobuf-mutator
- Seeds the corpus with valid protocol messages
- Mutates structure-aware (field values, field presence, nested messages)

### Campaign Monitoring
- Track edge coverage over time (plateau detection)
- Crash dedup (stack hash, ASAN report clustering)
- Timeout and OOM detection
- Corpus minimization
- Decision: continue, pivot, or stop

### Crash Triage Pipeline
```
crash_input.bin
  -> reproduce under ASAN/MSAN
  -> classify (heap-overflow, stack-overflow, use-after-free, null-deref, etc.)
  -> extract stack trace + ASAN report
  -> root cause via GDB (where exactly, what memory, controllable?)
  -> exploitability assessment
  -> dedup against known crashes
```

---

## IDA Pro Headless MCP

Purpose-built MCP server for VR workflows. Distinct from the general-purpose IDA MCP.

**Core operations:**
- Load binary, auto-analyze
- Decompile function by name/address -> pseudocode
- List functions with size, complexity metrics
- Find xrefs to/from a function
- Search for patterns in decompiled output (dangerous functions, unchecked lengths)
- Diff two binaries (patch diff)
- Annotate findings (rename functions, add comments for the researcher)
- Export call graph for a function cluster
- Find string references and their consumers
- Identify crypto constants, magic numbers, protocol signatures

**Batch operations (for LLM-driven analysis):**
- "Decompile all functions that call `memcpy` and check if any have unchecked size parameters"
- "Find all functions that process user input (xrefs from recv/read/fread) and rank by cyclomatic complexity"
- "Compare function X between binary v2.3.0 and v2.3.1 and explain the patch"

---

## Evidence Graph

Same structure as forensics but with VR-specific node/edge kinds:

**Node kinds:**
- `hypothesis` — "integer overflow in tile_size calculation"
- `target` — specific function or code region being investigated
- `fuzzing_campaign` — AFL++ run with config, corpus, duration
- `crash` — unique crash with stack trace and classification
- `exploit` — PoC code with reliability assessment
- `patch_diff` — diff between versions identifying the fix
- `advisory` — final writeup
- `strategy` — research approach tried (fuzzing, code audit, diffing)
- `human_context` — operator-supplied knowledge

**Edge kinds:**
- `targets` — hypothesis targets a code region
- `found_by` — crash found by fuzzing campaign
- `exploits` — exploit demonstrates a crash
- `disproves` — evidence disproves a hypothesis
- `confirms` — evidence confirms a hypothesis
- `derived_from` — advisory derived from confirmed exploit
- `informed_by` — strategy informed by human context

---

## Module Structure (Projected)

```
src/aila/modules/vr/
  module.py
  runtime.py
  capabilities.py
  tool_keys.py
  contracts/
    project.py          # VRProject, VRTarget, VRScope
    campaign.py         # FuzzingCampaign, CrashReport, CoverageSnapshot
    exploit.py          # PoC, ExploitAssessment, Reliability
    advisory.py         # VulnerabilityAdvisory, CVSSVector
  tools/
    ida_headless.py     # IDA Pro MCP bridge
    fuzzer.py           # AFL++/libFuzzer/honggfuzz orchestration
    crash_triage.py     # ASAN report parser, crash classification
    patch_differ.py     # BinDiff/Diaphora/manual diff
    source_auditor.py   # Semgrep, git log mining, pattern search
    exploit_runner.py   # Compile + execute PoC on research workstation
    harness_builder.py  # Generate fuzzing harness from target analysis
  services/
    campaign_manager.py # Fuzzing campaign lifecycle
    triage_service.py   # Crash dedup, classification, exploitability
    advisory_builder.py # Generate technical advisory from findings
  workflow/
    definitions.py      # VR_RESEARCH_V1, VR_NDAY_POC_V1
    services.py         # VRWorkflowServices
    states/
      recon.py          # Binary analysis, attack surface mapping
      hypothesis.py     # Hypothesis generation and refinement
      fuzzing.py        # Campaign setup, monitoring, triage
      exploitation.py   # PoC development and testing
      reporting.py      # Advisory and campaign summary generation
      nday_research.py  # CVE -> patch -> root cause -> PoC
  reporting/
    advisory_report.py  # Formatted vulnerability advisory
    campaign_report.py  # Fuzzing campaign summary
  frontend/
    spec.ts
    pages/
    components/
  db_models/
    records.py          # VR projects, campaigns, crashes, PoCs
```

---

## Open Questions

1. **Scope boundary.** Where does VR module end and forensics module begin? Forensics analyzes evidence of past compromise. VR actively searches for new vulnerabilities. Clear separation, but what about "analyze this malware binary for exploitable bugs in its C2 protocol" — that's both.

2. **Ethical guardrails.** The module generates working exploits. What controls prevent misuse? Options: audit trail (every action logged), scope pinning (can only target binaries in the project), no exfiltration (results stay on the research workstation).

3. **Fuzzing duration.** Campaigns can run for hours/days. How does this interact with the workflow engine's timeouts? Option: fuzzing state handler launches the campaign and polls, with a configurable max duration. The state handler re-enters on each poll cycle.

4. **Multi-binary targets.** A product might have 10 binaries. Does the module research one at a time, or manage a portfolio of targets with cross-binary analysis (e.g., "this library is used by 3 binaries, fuzz it once")?

5. **Source vs binary.** Some targets have source code (open source, leaked, decompiled). Some are pure binary. The module needs to handle both, and the strategy selection changes dramatically between them.

6. **IDA Pro licensing.** Headless IDA requires a license. Should the module fall back to Ghidra when IDA is unavailable? Or require IDA as a prerequisite?

7. **Collaboration.** Multiple researchers working on the same target? Shared evidence graph? Or single-researcher per project?

8. **Integration with existing vulnerability module.** When VR finds a new bug, does it feed back into the vulnerability scanner's database? "CVE-2024-XXXXX was found by internal research, affects these fleet systems."

---

## What the Domain Profile Already Supports

The CyberReasoningEngine already has `vulnerability_research` registered:

```python
"vulnerability_research": ReasoningDomainProfile(
    domain_id="vulnerability_research",
    task_type="vulnerability_research",
    description="Exploitability, advisories, versions, and remediation reasoning.",
    allowed_strategies=["vulnerability_research", "generic"],
    default_strategy="vulnerability_research",
)
```

This needs expansion. New strategy families for VR:
- `binary_analysis` — RE, decompilation, pattern search
- `fuzzing` — harness generation, campaign management, crash triage
- `patch_diffing` — version comparison, silent fix detection
- `exploit_development` — PoC writing, mitigation bypass
- `source_audit` — git mining, semgrep, variant analysis
- `protocol_analysis` — protocol RE, structure-aware fuzzing

---

## First Deliverable

What should v0.1 of this module do? Candidates:

**Option A: N-day PoC writer first.** Tightest scope. Input: CVE + binary. Output: PoC. Uses IDA headless + patch diffing + exploit scaffolding. Proves the toolchain works.

**Option B: Single-binary fuzzer first.** Input: binary + entry point hint. Output: crashes + triage. Uses AFL++ harness generation + campaign management + crash triage. Proves the fuzzing orchestration works.

**Option C: Full recon first.** Input: binary. Output: attack surface map + hypotheses + ranked targets. Uses IDA headless + decompiler analysis + LLM reasoning. Proves the research reasoning works.

My recommendation: **Option A** (N-day PoC writer). It has the clearest success criterion ("does the PoC crash the vulnerable version?"), exercises the core toolchain (IDA, diffing, exploit writing), and delivers immediate value. The full research workflow builds on top of it.
