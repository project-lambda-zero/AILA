# VR Module v0.1 — N-day PoC Writer Implementation Plan

## What v0.1 does

Given a CVE identifier + a vulnerable binary (or source repo), produce:
1. A working crash PoC (5/5 reliability on vulnerable version, 0/1 on patched)
2. Root cause analysis (what memory error, where, why)
3. Mitigation report (checksec, ASLR, canary, CFI, CET, MTE)
4. Vendor-ready advisory (CVE, CWE, CVSS, affected versions, remediation)
5. Disclosure tracking state

Input: CVE ID + binary path (or source repo URL) + optional patch commit
Output: PoC script + advisory + evidence chain

---

## Gray Area Resolutions (v0.1 scope)

### GA-1: PoC Test Runner Sandboxing

**Decision:** Run PoC as a subprocess on the research workstation via SSH with resource limits. No VMs in v0.1.

Implementation:
- `tools/poc_runner.py` SSHes into the research workstation (same pattern as forensics `ScriptExecutorTool`)
- Wraps execution with: `timeout 30s`, `ulimit -v 2097152` (2GB RAM), `ulimit -f 1048576` (1GB disk)
- On Windows workstations: `Start-Process` with `-NoNewWindow` and job object limits
- Exit semantics:
  - Exit code 139 (SIGSEGV) or 134 (SIGABRT) = crash confirmed
  - Exit code 0 = clean exit (no crash)
  - Exit code 124 = timeout (inconclusive — might be hang or slow crash)
  - ASAN report in stderr = crash confirmed + classified
- Verification model: run PoC against vulnerable binary, then against patched binary. Both on same workstation, sequential.
- If patched binary unavailable: obligation `patched_version_verified` stays unmet, advisory includes "patched version not tested"

### GA-2: Crash Dedup for Stripped/PIE Binaries

**Decision:** Base-relative offset hashing. Normalize before hashing.

Algorithm:
```
1. Parse ASAN report or GDB backtrace
2. For each frame:
   a. If symbols available: use function_name
   b. If stripped: use (module_name, offset_from_module_base)
      - PIE: offset is already relative (works)
      - Non-PIE ASLR (Windows): subtract ImageBase from VA
      - ELF non-PIE: addresses are stable, use raw VA
3. crash_signature = SHA256(crash_type + "|" + top5_normalized_frames)
```

This runs in `tools/crash_triage.py`, not in the DB. Raw ASAN/GDB output stored in `details_json` for manual review.

### GA-3: Disclosure Schema

**Decision:** Implement as fields on `VRFindingRecord`. State machine as a string enum, not a separate table.

```
disclosure_status: undisclosed | reported | acknowledged | patch_pending | patched | public
vendor_contact: str | None
reported_at: datetime | None
embargo_until: datetime | None
cve_id: str | None        # assigned CVE (may differ from input CVE for variants)
patch_version: str | None
```

No enforcement of disclosure policy (organizational concern). The module tracks state so nothing falls through the cracks.

### GA-4: Working Set Curation

**Decision:** Hypothesis-driven curation with IDA bridge queries.

For N-day v0.1, the working set is narrow and predictable:
1. **Patch diff** — decompile the changed functions in both versions (MCP `diff_function`)
2. **Vulnerable function** — decompile the function containing the bug (MCP `decompile`)
3. **Callers** — who calls the vulnerable function (MCP `call_chain`, depth=2)
4. **Data flow** — how does input reach the vulnerable parameter (MCP `trace_dataflow`)
5. **Mitigations** — checksec output (MCP `checksec`)

The evidence pack gets these 5 sections (~4K chars each = ~20K total, well within 60K limit). The LLM can request expansion ("decompile function X") via the `decompile` action.

For v0.3+ (0-day hunting), curation becomes LLM-driven: the LLM picks which functions to decompile based on Trailmark/recon output.

### GA-5: Workstation Readiness Check

**Decision:** Reuse forensics `MachineReadinessService` pattern with VR-specific tool list.

Tool requirements file: `src/aila/modules/vr/data/tool_requirements.json`

Required tools for v0.1:
- `gcc` or `clang` (compile PoC)
- `gdb` (crash analysis)
- `python3` + `pwntools` (PoC scripting)
- `curl` or `wget` (fetch advisory data)
- IDA Headless MCP HTTP reachable (health check via bridge)

Optional tools (v0.3+):
- `afl-fuzz` (fuzzing)
- `semgrep` (source audit)
- `radare2` (lightweight RE)

### GA-6: N-day Benchmark Suite

**Decision:** Curate 20 CVEs as a JSON data file. Run as a pytest parametrized suite.

File: `tests/vr_benchmark/benchmark_cves.json`

Selection criteria:
- Public patch commit exists
- Vulnerable version buildable (or downloadable binary)
- Known working PoC exists (ground truth)
- Mix: 10 Tier 1 (obvious trigger), 7 Tier 2 (needs analysis), 3 Tier 3 (complex)
- Mix: stack overflow, heap overflow, UAF, integer overflow, format string, logic bug

This is a parallel track — curate while building the module, run after v0.1 is feature-complete.

Metrics:
- Detection rate: root cause correctly identified (out of 20)
- PoC rate: working crash PoC produced (out of 20)
- Turn efficiency: mean turns to reach working PoC
- False claims: "exploitable" claimed incorrectly (obligation system should catch)

### GA-7: LLM Cost Tracking

**Decision:** Add `cost_per_turn_usd` to `BudgetConfig`. `BudgetState` computes `estimated_cost_usd` as `turns_used * cost_per_turn_usd`.

One field addition to `budget.py`. No separate cost service. Display in UI alongside turn/time budget.

---

## File Layout

```
src/aila/modules/vr/
├── __init__.py                         # exists
├── module.py                           # ModuleProtocol, create_module()
├── runtime.py                          # picks workflow, validates payload
├── capabilities.py                     # DESCRIPTION, TOOLS, EXAMPLES
├── tool_keys.py                        # tool key constants
├── config_schema.py                    # VR-specific config defaults
├── contracts/
│   ├── __init__.py
│   ├── project.py                      # VRProject, VRTarget, TargetClass
│   ├── finding.py                      # VRFinding, CrashSignature, DisclosureStatus
│   └── advisory.py                     # VRAdvisory, CVSSVector, CWEMapping
├── tools/
│   ├── __init__.py                     # exists
│   ├── ida_bridge.py                   # exists — MCP HTTP bridge
│   ├── poc_runner.py                   # compile + execute PoC via SSH
│   ├── patch_differ.py                 # diff two versions via MCP diff_function
│   ├── crash_triage.py                 # ASAN parser, stack hash dedup
│   └── advisory_builder.py            # CVSS calculator, CWE mapper, advisory formatter
├── services/
│   ├── __init__.py
│   └── machine_readiness.py            # VR workstation tool checker
├── agents/
│   ├── __init__.py
│   └── nday_researcher.py              # CyberReasoningEngine-based N-day agent
├── workflow/
│   ├── __init__.py
│   ├── definitions.py                  # VR_NDAY_V1 workflow definition
│   ├── services.py                     # VRWorkflowServices
│   └── states/
│       ├── __init__.py
│       ├── setup.py                    # readiness check, binary upload, poll until INDEXED
│       ├── research.py                 # patch diff, root cause analysis, hypothesis loop
│       ├── poc_development.py          # write PoC, test, verify reliability
│       ├── advisory.py                 # generate advisory, compute CVSS, map CWE
│       └── response_emit.py           # terminal state
├── reporting/
│   ├── __init__.py
│   └── advisory_report.py             # formatted advisory output
├── db_models/
│   ├── __init__.py
│   ├── project.py                      # VRProjectRecord
│   └── finding.py                      # VRFindingRecord (with disclosure fields)
├── data/
│   ├── tool_requirements.json          # workstation tool checklist
│   ├── cwe_mappings.json               # crash_type -> CWE-ID mapping
│   └── cvss_templates.json             # pre-filled CVSS vectors by bug class
├── api_router.py                       # REST endpoints
└── frontend/                           # v0.1 minimal UI (later)
    ├── spec.ts
    ├── routes.tsx
    ├── nav.ts
    ├── types.ts
    ├── queries.ts
    └── screens/
        └── ProjectPage.tsx
```

---

## Workflow: VR_NDAY_V1

```
setup -> research -> poc_development -> advisory -> response_emit -> __succeeded__
```

### State: setup (timeout: 120s, retries: 2)

1. Verify workstation readiness (SSH + tool check)
2. Upload target binary to MCP via `ida_bridge.upload`
3. Poll `poll_analysis` until state >= READY
4. Run `checksec` — store mitigations in context
5. If patched binary provided: upload that too

**Output:** `binary_id`, `patched_binary_id`, mitigations dict

### State: research (timeout: 7200s, retries: 1)

The core reasoning loop. Uses `CyberReasoningEngine` with VR-specific domain profile.

**Turn budget:** 30 turns (from BudgetState)
**Tool time budget:** 4 hours

**Available actions:**
- `decompile` — decompile a function via MCP
- `diff_versions` — diff vulnerable vs patched via MCP `diff_function`
- `call_chain` — trace callers/callees via MCP
- `trace_dataflow` — trace sink argument backward via MCP
- `search_pattern` — find vuln patterns across binary via MCP
- `xrefs_to` / `xrefs_from` — cross-references via MCP
- `reasoning` — internal reasoning step (no tool call)

**Obligation set (loaded at state entry):**

| ID | Claim | Required Evidence | Severity |
|---|---|---|---|
| `patch_identified` | Patch commit/diff located | Diff output showing the fix | CRITICAL |
| `root_cause_documented` | Bug mechanism understood | Decompiled code + explanation | REQUIRED |
| `vulnerable_function_decompiled` | Vuln function analyzed | Decompiled pseudocode | REQUIRED |
| `crash_type_classified` | Memory error type known | Crash type enum (D-19 vocabulary) | REQUIRED |
| `mitigation_analysis` | Binary protections checked | checksec output | REQUIRED |
| `cvss_vector` | CVSS score computed | CVSS vector string | RECOMMENDED |
| `cwe_mapped` | CWE weakness identified | CWE-ID | RECOMMENDED |
| `affected_versions` | Version range known | Version strings | RECOMMENDED |

**Evidence pack per turn:** bounded to 20 sections / 60K chars. Sections:
- Priority 0: ASAN/crash reports
- Priority 10: Patch diff output
- Priority 20: Decompiled vulnerable function
- Priority 30: Caller/callee context
- Priority 40: Data flow traces
- Priority 50: checksec output
- Priority 80: Other decompiled functions
- Priority 90: Operator context

**Adjudication:** After each turn, `adjudicate()` checks:
- Hedge phrases in reasoning → downgrade
- Claims without evidence → block
- Verdict upgrade without new evidence → block

**Output:** Root cause analysis, crash type, exploitation strategy (if applicable), all evidence refs

### State: poc_development (timeout: 3600s, retries: 2)

1. LLM generates PoC script (Python with pwntools, or C)
2. `poc_runner` uploads script to workstation via SSH
3. Compile (if C): `gcc -o poc poc.c -lpthread`
4. Run against vulnerable binary with resource limits
5. Parse exit code + stderr for crash confirmation
6. If crash: run 4 more times for 5/5 reliability
7. If no crash: LLM adjusts PoC, retry (up to 3 attempts per turn)
8. Run against patched binary: must NOT crash (0/1)

**Obligation set:**

| ID | Severity |
|---|---|
| `poc_crashes_vulnerable` | CRITICAL |
| `poc_5_of_5_reliable` | REQUIRED |
| `patched_version_clean` | CRITICAL (waivable if no patched binary) |
| `asan_report_captured` | REQUIRED |

**Output:** PoC code, crash report, reliability score

### State: advisory (timeout: 600s, retries: 1)

1. Compute CVSS v3.1 vector from collected evidence (deterministic, not LLM-guessed)
   - Attack vector: from target analysis (network/local/physical)
   - Privileges required: from vulnerability context
   - User interaction: from trigger analysis
   - Impact: from crash type + exploitation assessment
2. Map to CWE from `cwe_mappings.json` (crash_type → CWE-ID)
3. LLM generates advisory text sections:
   - Summary (one paragraph)
   - Technical details (root cause, code path)
   - Impact assessment
   - Affected versions
   - Remediation guidance
4. Set `disclosure_status = "undisclosed"`

**Output:** Advisory dict with all fields populated

### State: response_emit (timeout: 60s, retries: 0)

Persist everything to DB, mark project completed, return PlatformResponse.

---

## DB Schema

### VRProjectRecord

```sql
CREATE TABLE vr_projects (
    id              TEXT PRIMARY KEY,
    team_id         TEXT,
    name            TEXT NOT NULL,
    cve_id          TEXT,                           -- CVE-YYYY-NNNNN
    target_class    TEXT NOT NULL DEFAULT 'native',  -- native, jvm, python, etc.
    target_path     TEXT,                           -- original binary/source path
    binary_id       TEXT,                           -- MCP binary_id handle
    patched_path    TEXT,
    patched_binary_id TEXT,
    status          TEXT NOT NULL DEFAULT 'created', -- created, analyzing, completed, failed, stalled
    mitigations_json TEXT DEFAULT '{}',
    budget_json     TEXT DEFAULT '{}',              -- BudgetState snapshot
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);
```

### VRFindingRecord

```sql
CREATE TABLE vr_findings (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES vr_projects(id),
    team_id             TEXT,
    crash_type          TEXT,           -- OVERFLOW_HEAP, UAF, etc. (D-19 vocabulary)
    crash_signature     TEXT,           -- SHA256 stack hash
    root_cause          TEXT,           -- LLM-generated root cause text
    vulnerable_function TEXT,           -- function name or address
    poc_code            TEXT,           -- PoC script content
    poc_language        TEXT,           -- python, c
    poc_reliability     TEXT,           -- "5/5", "3/5"
    asan_report         TEXT,           -- raw ASAN output
    cvss_vector         TEXT,           -- CVSS:3.1/AV:N/AC:L/...
    cvss_score          REAL,
    cwe_id              TEXT,           -- CWE-787
    advisory_json       TEXT DEFAULT '{}',
    -- Disclosure tracking (GA-3)
    disclosure_status   TEXT DEFAULT 'undisclosed',
    vendor_contact      TEXT,
    reported_at         TIMESTAMPTZ,
    embargo_until       TIMESTAMPTZ,
    assigned_cve_id     TEXT,           -- may differ from project.cve_id
    patch_version       TEXT,
    -- Metadata
    evidence_refs_json  TEXT DEFAULT '[]',
    obligations_json    TEXT DEFAULT '{}',  -- ObligationSet snapshot
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);
```

Alembic migration: `src/aila/alembic/versions/028_vr_tables.py`

---

## Build Order

### Phase 1: Contracts + Data (no logic)

| # | File | LOC est | Depends on |
|---|---|---|---|
| 1.1 | `contracts/__init__.py` | 5 | — |
| 1.2 | `contracts/project.py` | 60 | — |
| 1.3 | `contracts/finding.py` | 80 | — |
| 1.4 | `contracts/advisory.py` | 50 | — |
| 1.5 | `tool_keys.py` | 15 | — |
| 1.6 | `capabilities.py` | 30 | 1.5 |
| 1.7 | `config_schema.py` | 40 | — |
| 1.8 | `data/tool_requirements.json` | 50 | — |
| 1.9 | `data/cwe_mappings.json` | 100 | — |
| 1.10 | `data/cvss_templates.json` | 80 | — |

### Phase 2: DB Models + Migration

| # | File | LOC est | Depends on |
|---|---|---|---|
| 2.1 | `db_models/__init__.py` | 10 | 1.x |
| 2.2 | `db_models/project.py` | 50 | 1.2 |
| 2.3 | `db_models/finding.py` | 70 | 1.3 |
| 2.4 | `alembic/versions/028_vr_tables.py` | 80 | 2.2, 2.3 |

### Phase 3: Tools

| # | File | LOC est | Depends on |
|---|---|---|---|
| 3.1 | `tools/poc_runner.py` | 200 | SSH infra |
| 3.2 | `tools/patch_differ.py` | 80 | ida_bridge |
| 3.3 | `tools/crash_triage.py` | 150 | — |
| 3.4 | `tools/advisory_builder.py` | 200 | 1.4, 1.9, 1.10 |

### Phase 4: Agent + Workflow

| # | File | LOC est | Depends on |
|---|---|---|---|
| 4.1 | `agents/nday_researcher.py` | 500 | all tools, obligations, evidence_pack, budget |
| 4.2 | `workflow/services.py` | 80 | 4.1 |
| 4.3 | `workflow/states/setup.py` | 120 | ida_bridge, machine_readiness |
| 4.4 | `workflow/states/research.py` | 200 | 4.1 |
| 4.5 | `workflow/states/poc_development.py` | 200 | poc_runner, crash_triage |
| 4.6 | `workflow/states/advisory.py` | 120 | advisory_builder |
| 4.7 | `workflow/states/response_emit.py` | 60 | — |
| 4.8 | `workflow/definitions.py` | 80 | 4.3-4.7 |
| 4.9 | `services/machine_readiness.py` | 100 | forensics pattern |

### Phase 5: Module Registration

| # | File | LOC est | Depends on |
|---|---|---|---|
| 5.1 | `runtime.py` | 60 | 4.8 |
| 5.2 | `module.py` | 80 | all |
| 5.3 | `api_router.py` | 150 | contracts, db_models |
| 5.4 | Register in `platform/modules/builtin.py` | 3 | 5.2 |
| 5.5 | `reporting/advisory_report.py` | 100 | 1.4 |

### Phase 6: Frontend (minimal)

| # | File | LOC est | Depends on |
|---|---|---|---|
| 6.1 | `frontend/types.ts` | 60 | API |
| 6.2 | `frontend/queries.ts` | 40 | 6.1 |
| 6.3 | `frontend/mutations.ts` | 30 | 6.1 |
| 6.4 | `frontend/screens/ProjectPage.tsx` | 200 | 6.2, 6.3 |
| 6.5 | `frontend/spec.ts, routes.tsx, nav.ts` | 30 | 6.4 |

### Phase 7: Testing + Benchmark

| # | File | LOC est | Depends on |
|---|---|---|---|
| 7.1 | `tests/test_vr_contracts.py` | 100 | 1.x |
| 7.2 | `tests/test_vr_obligations.py` | 80 | obligations |
| 7.3 | `tests/test_vr_crash_triage.py` | 100 | 3.3 |
| 7.4 | `tests/test_vr_advisory_builder.py` | 80 | 3.4 |
| 7.5 | `tests/vr_benchmark/benchmark_cves.json` | parallel | — |
| 7.6 | `tests/vr_benchmark/test_benchmark.py` | 100 | all |

---

## Total Estimate

| Phase | Files | LOC |
|---|---|---|
| 1. Contracts + Data | 10 | ~510 |
| 2. DB + Migration | 4 | ~210 |
| 3. Tools | 4 | ~630 |
| 4. Agent + Workflow | 9 | ~1460 |
| 5. Module Registration | 5 | ~393 |
| 6. Frontend | 5 | ~360 |
| 7. Tests | 6 | ~460 |
| **Total** | **43** | **~4023** |

---

## Verification Checklist

Before marking v0.1 complete:

- [ ] `python -m compileall src/aila/modules/vr -q` — zero errors
- [ ] `python -m ruff check src/aila/modules/vr/` — clean
- [ ] `python -m aila.tools.honesty_audit src/aila/modules/vr` — zero findings
- [ ] `alembic upgrade head` — migration applies cleanly
- [ ] `cd frontend && pnpm -r run type-check` — clean
- [ ] Unit tests pass: contracts, crash triage, advisory builder
- [ ] Integration test: upload binary → research → PoC → advisory (one known CVE)
- [ ] Module starts without errors in platform startup log
- [ ] API endpoints return DataEnvelope responses
- [ ] Obligation system blocks claims without evidence
- [ ] Budget system stops execution at limits
- [ ] PoC runner respects resource limits (no fork bomb crash)
- [ ] Advisory output is vendor-ready (structured, complete, no hallucinated fields)
