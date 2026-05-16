# VR Module — Decisions

Decisions made during brainstorm. These are closed. Don't revisit unless evidence proves them wrong.

---

## Closed Decisions

### D-01: LLM attempts full exploitation autonomously

The LLM is the primary exploit developer, not an assistant. It generates full exploit chains — ROP, heap feng shui, mitigation bypass — and tests them on the research workstation. When it gets stuck (bad gadgets, wrong offsets, unreliable trigger), the human injects context, corrects assumptions, or supplies techniques. The LLM retries with the new information.

The loop is: **LLM attempts -> fails -> human steers -> LLM retries**. Not: human writes exploit, LLM finds gadgets.

Rationale: The CyberReasoningEngine already supports this pattern via operator steering. The forensics module proves multi-turn LLM reasoning with tool execution works. Exploit development is the same shape — hypothesis, attempt, observe, refine.

### D-02: Packed/obfuscated binaries deferred

v0.1 handles clean ELF/PE binaries. UPX, Themida, VMProtect, custom packers are deferred to a later version. The module should detect packed binaries and report "target appears packed, unpacking not yet supported" rather than silently producing garbage analysis.

### D-03: Multiple target classes from day one

The module must distinguish target classes and use different workflows for each:

| Target Class | Examples | Bug Classes | Research Approach | Exploitation |
|---|---|---|---|---|
| **Native userspace** | ELF/PE applications, shared libraries | Memory corruption (heap/stack overflow, UAF, type confusion, integer overflow) | IDA/Ghidra RE, fuzzing, ASAN | ROP, heap feng shui, shellcode |
| **Kernel module/driver** | `.ko`, `.sys`, IOCTL handlers | Same as native + race conditions, TOCTOU, privilege boundary violations | Syzkaller-style fuzzing, KASAN, static analysis | Arbitrary read/write -> privilege escalation. QEMU/KVM testing. |
| **Hypervisor component** | VM escape targets, emulated devices | Paravirt interface bugs, shared memory corruption, device emulation logic | Nested virtualization, device-specific harnesses | Guest-to-host escape. Nested VM testing. |
| **Java/JVM** | Spring Boot, Android apps, Gradle plugins | Deserialization gadget chains, JNDI injection, XXE, EL injection, type juggling | Source audit, gadget chain construction, Jazzer fuzzing | Gadget chain PoC, JNDI/RMI payload |
| **Python** | Django, Flask, ML pipelines, CLI tools | Pickle deserialization, SSTI, command injection, path traversal, unsafe eval/exec | Source audit, Semgrep/Bandit, Atheris fuzzing, input tracing | PoC script exploiting injection vector |
| **JavaScript/Node.js** | Express, Electron, serverless | Prototype pollution, SSRF, ReDoS, template injection, sandbox escape (vm2) | Source audit, CodeQL, jsfuzz, regex analysis | Pollution payload, SSRF chain, sandbox escape PoC |
| **PHP** | WordPress, Laravel, custom CMS | Deserialization POP chains, LFI/RFI, SQLi, type juggling, phar deserialization | Source audit, taint analysis, Psalm/PHPStan | POP chain, phar payload, SQLi PoC |
| **Go** | Cloud infra, CLI tools, network services | Race conditions, slice bounds, unsafe pointer misuse, integer truncation | Staticcheck, go-fuzz, race detector, source audit | PoC triggering race or bounds violation |
| **Rust (unsafe)** | Perf-critical libraries, FFI boundaries | Unsound unsafe blocks, FFI memory management, lifetime bypasses | Miri, cargo-fuzz, unsafe block audit | PoC triggering UB in unsafe code |

**Native vs interpreted:** completely different research approaches. Native = binary RE + memory corruption + shellcode. Interpreted = source audit + logic bugs + payload crafting. The module handles both but the workflow branches hard after target classification.

**Hybrid (Go, Rust):** Memory-safe by default with escape hatches. Focus research on unsafe blocks, cgo, FFI boundaries.

### Fuzzing Instrumentation Matrix

Not just AFL++. The instrumentation depends on target platform, source availability, and OS:

| Fuzzer / Instrumentation | When to use |
|---|---|
| **AFL++** (source) | Linux, source available, compile-time instrumentation. Default choice for C/C++. |
| **AFL++ QEMU mode** | Linux, no source, binary-only. QEMU user-mode emulation for coverage. |
| **WinAFL** | Windows targets. Uses DynamoRIO or Intel PT for coverage. Required for PE binaries that can't run under Linux. |
| **DynamoRIO** | Windows binary instrumentation. Coverage, taint tracking, call tracing. Powers WinAFL and standalone analysis. |
| **Intel PT (Processor Trace)** | Hardware-assisted coverage. Lowest overhead. Works on both Linux (via AFL++ Intel PT mode) and Windows (via WinAFL). Requires compatible CPU. |
| **Frida** | Cross-platform dynamic instrumentation. Inject into running processes. Good for targets that resist static harnesses (anti-debug, integrity checks). Works on Linux, Windows, macOS, Android, iOS. |
| **libFuzzer** | In-process fuzzing for source-available C/C++. Fastest (no fork). Persistent mode. |
| **honggfuzz** | Alternative to AFL++. Good feedback-driven mutation. Supports Intel PT and software coverage. |
| **Syzkaller** | Kernel fuzzing. Generates syscall sequences. Requires QEMU/KVM with KASAN kernel. |
| **Jazzer** | Java/JVM fuzzing via libFuzzer integration. Coverage-guided. |
| **Atheris** | Python fuzzing via libFuzzer integration. |
| **go-fuzz / go test -fuzz** | Go native fuzzing. |
| **cargo-fuzz** | Rust fuzzing via libFuzzer. |
| **jsfuzz** | JavaScript fuzzing. |
| **libprotobuf-mutator** | Structure-aware mutation for protobuf inputs. Layer on top of AFL++/libFuzzer. |
| **Grammar-based (Nautilus, Gramatron)** | Grammar-aware fuzzing for complex input formats (scripting languages, config files, query languages). |
| **Sanitizers** | Not fuzzers but essential companions: |
| -- AddressSanitizer (ASAN) | Heap/stack overflow, UAF, double-free detection |
| -- MemorySanitizer (MSAN) | Uninitialized memory reads |
| -- UBSanitizer (UBSAN) | Integer overflow, null deref, alignment violations |
| -- ThreadSanitizer (TSAN) | Data races, deadlocks |
| -- KASAN | Kernel AddressSanitizer (for kernel fuzzing with syzkaller) |
| -- Miri | Rust undefined behavior detector for unsafe code |

The LLM selects instrumentation based on:
- Target platform (Linux/Windows/cross)
- Source availability (source -> compile-time instrumentation, binary-only -> QEMU/DynamoRIO/Frida/Intel PT)
- Target class (userspace -> AFL++/WinAFL, kernel -> syzkaller, Java -> Jazzer, etc.)
- Anti-analysis presence (integrity checks -> Frida, debug detection -> Intel PT)
- Performance requirements (Intel PT for lowest overhead, Frida for most flexibility)

Each target class has its own:
- Reconnaissance steps (mitigations for native, dependency analysis for interpreted, unsafe block audit for hybrid)
- Bug hunting strategies (fuzzing vs source audit vs gadget chain construction)
- Exploitation model (shellcode vs payload crafting vs injection strings)
- Testing environment (process vs VM vs nested VM vs application server)
- Severity model (RCE vs deserialization vs SSRF -- different impact scales)

The workflow definition branches on target class after initial recon. Not separate modules -- one module with class-aware strategy selection.

### D-04: Disclosure tracking from day one

Every finding has a `disclosure_status` field from v0.1:

```
undisclosed -> reported -> acknowledged -> patch_pending -> patched -> public
```

Fields on the finding record:
- `disclosure_status`: enum above
- `vendor_contact`: who was notified
- `reported_at`: when vendor was notified
- `embargo_until`: coordinated disclosure date
- `cve_id`: assigned CVE (null until reserved)
- `patch_version`: version that contains the fix

The module doesn't enforce disclosure policy (that's organizational). It tracks the state so nothing falls through the cracks.

### D-05: Network fuzzing deferred

v0.1 handles local binary analysis and fuzzing only. Network protocol fuzzing against running services is a complex addition (needs target orchestration, connection management, crash detection via external monitoring, protocol state machines). Deferred to a later version.

The module should identify network-reachable attack surface during recon ("this binary listens on port 8883 for MQTT") but not fuzz it over the network. The researcher can extract the parser function and fuzz it locally via harness.

### D-06: Forensics handoff is NOT to VR

Forensics finds a suspicious binary -> it goes to a **malware analysis module** (future), not VR. The distinction:

| | VR Module | Malware Analysis Module (future) |
|---|---|---|
| **Goal** | Find new vulnerabilities in software | Understand what malware does |
| **Input** | Legitimate software (products, libraries, services) | Suspicious/malicious binaries |
| **Approach** | Offensive (break it) | Defensive (understand it) |
| **Output** | Exploits, advisories, PoCs | IOCs, behavior report, capabilities assessment |
| **Tools** | AFL++, IDA, GDB, exploit frameworks | Sandbox, API monitoring, unpacking, YARA |
| **LLM role** | Creative attacker | Methodical analyst |

Both use IDA Pro and reverse engineering. But the *intent* and *workflow* are different. Combining them would create a god-module that tries to do everything.

The malware analysis module is a separate future module (`src/aila/modules/malware/`). It shares the IDA headless MCP with VR but has its own workflow, contracts, and tools.

---

## Delivery Sequence (Updated)

| Version | Scope | Success Criterion |
|---|---|---|
| **v0.1** | N-day PoC writer + mitigation check + advisory output + disclosure tracking | Given a CVE + binary: produces working crash PoC, checks mitigations, generates vendor-ready advisory, tracks disclosure state |
| **v0.2** | Binary recon + target ranking + target class detection | Given a binary: identifies target class (userspace/kernel/hypervisor), maps attack surface, ranks functions by exploitability, reports mitigations |
| **v0.3** | Fuzzing pipeline (local, single binary) | Given a binary + target function: generates harness, runs AFL++ campaign, triages crashes, assesses exploitability |
| **v0.4** | Full research workflow | Hypothesis-driven, multi-strategy, human-in-the-loop. Combines recon + fuzzing + exploitation + advisory. Project/target hierarchy. |
| **v0.5** | Kernel/hypervisor exploitation workflows | QEMU/KVM test environments, kernel-specific exploitation primitives, VM escape strategies |
| **later** | Network fuzzing, packed binary support, variant analysis, cross-project knowledge |

---

## Module Ecosystem (Current + Planned)

```
src/aila/modules/
  vulnerability/     # SHIPPED — Fleet CVE scanning (SSH inventory -> advisory -> scoring)
  forensics/         # SHIPPED — DFIR investigation (evidence -> analysis -> writeup)
  sbd_nfr/           # SHIPPED — Security by Design NFR assessment (questionnaire -> scoring)
  hello_world/       # SHIPPED — Reference module
  vr/                # PLANNED — Vulnerability research (RE -> fuzzing -> exploitation -> advisory)
  malware/           # FUTURE  — Malware analysis (sandbox -> behavior -> IOCs -> report)
  pentest/           # FUTURE  — Web/infra pentesting (recon -> scan -> exploit -> report)
```

Each module owns its domain. No cross-module imports. Shared infrastructure (IDA headless MCP, SSH, reasoning engine) lives in platform.

---

## v0.1 Decisions (D-07 through D-21)

Answered before N-day PoC writer implementation. These are closed.

### D-07: Hybrid turn + tool-time budget

Turns count reasoning steps. Long-running tools (angr, exploit test runs) run on a separate wall-clock budget.

- Turn budget: 30 turns for N-day (configurable per project)
- Tool time budget: 4 hours for N-day (fuzzing campaigns, angr runs, exploit tests consume from this pool)
- LLM sees both: "Turn 7/30. Tool time: 2h14m remaining."
- Extending: operator can grant +15 turns or +2h tool time at any point

### D-08: Same reasoning loop, trimmed action menu for N-day

One reasoning loop for all workflows. N-day restricts the available action set:

- N-day enabled: `decompile`, `diff_versions`, `search_code`, `run_angr`, `debug`, `write_exploit`, `analyze_crash`, `submit`, `reasoning`
- N-day disabled: `fuzz`, `query_graph`, `write_harness`
- System prompt goal: "Produce a working crash PoC for CVE-XXXX" (not "find vulnerabilities")

No separate state machine. Same evidence graph, same obligation system, fewer action types.

### D-09: IDA MCP backend per-binary

The MCP manages multiple IDA instances internally, one per loaded binary. A project with an ARM blob and an x86 PE gets two backends. Diff commands (`diff_binary`) require both binaries on the same architecture — no cross-backend diff.

### D-10: Operator annotations always win

Annotations carry `source: "llm" | "operator"`. Rules:
- MCP refuses LLM writes that overwrite an operator annotation
- LLM annotations are freely overwritable by both LLM and operator
- System prompt tells LLM: "Operator annotations are authoritative. Note disagreements in reasoning, do not overwrite."

### D-11: 30 turns + 4 hours hard cap for N-day

- 30 LLM turns maximum per N-day task
- 4 hours tool-time maximum
- At budget exhaustion: module submits what it has (partial PoC, analysis, draft advisory) and marks task `stalled`
- Operator can extend (+15 turns, +2h) or close
- Running cost displayed in UI — no silent overruns
- At ~$0.50/turn: $15 max LLM cost per N-day task

### D-12: Always start autonomous, downgrade on failure

No pre-classification of exploit difficulty. The LLM attempts exploitation immediately.

- After 3 consecutive failed exploit attempts: watchdog injects "Exploitation attempts failing. Consider operator assistance or strategy pivot."
- After 5 consecutive failures: auto-downgrade to assist mode (propose strategies, wait for operator confirmation)
- Operator can manually force assist mode at any time

### D-13: 5/5 crash PoC, 3/5 exploit reliability

- Crash PoC: must reproduce 5/5 on vulnerable version, 0/1 on patched version
- Exploit (when developed): 3/5 acceptable for PoC-grade, 5/5 for weapon-grade
- The module runs the reliability sweep automatically after each PoC/exploit modification
- Operator can override threshold per engagement ("3/5 is fine")

### D-14: Operator can waive any obligation

- Waiver recorded as `operator_waiver` evidence node with identity + reason
- Advisory marks findings with waived obligations: "Exploitability assessed with waiver: [reason]"
- CRITICAL obligations require explicit waiver text
- RECOMMENDED obligations auto-waived at 80% turn budget consumed (stop nagging about nice-to-haves)

### D-15: Obligation severity for N-day

| Severity | Obligations |
|---|---|
| CRITICAL (blocks submit) | Patch identified. Vulnerable version crash confirmed. Patched version no-crash confirmed. |
| REQUIRED (blocks advisory) | Root cause documented. ASAN/crash report captured. Mitigation analysis (checksec). PoC reliability 5/5. |
| RECOMMENDED (logged as gap) | CVSS vector computed. CWE mapped. Affected version range. KEV/EPSS checked. |

### D-16: Obligations visible but not prescriptive in prompt

The LLM sees outstanding obligations in the user prompt:
```
Outstanding obligations (3):
  - CRITICAL: patch_diff_exists
  - REQUIRED: mitigation_analysis
  - REQUIRED: poc_reliability_verified
```
It sees WHAT is needed, not HOW to satisfy it. Prevents gaming while giving enough info to plan.

### D-17: One VRNdayTask per (CVE, target_id)

One CVE on three builds = three separate N-day tasks. Each has its own PoC, obligation chain, and advisory. The CVE string is a shared field, not a foreign key. "CVE-level view" is a query aggregation, not a schema change.

### D-18: Crash dedup via symbol-based stack hash

Signature: `SHA256(crash_type + "|" + top5_frame_symbols)`

- Symbols for non-stripped binaries (function names)
- Function+offset for stripped binaries (ASLR-stable)
- Canonicalization runs in crash triage tool, not DB
- Raw ASAN report stored in `details_json` for manual dedup review

### D-19: Closed exploit primitive vocabulary

The LLM must use standardized terms:
```
OVERFLOW_STACK, OVERFLOW_HEAP, UAF, DOUBLE_FREE, TYPE_CONFUSION,
FORMAT_STRING, INTEGER_OVERFLOW, NULL_DEREF, OOB_READ, OOB_WRITE,
ARW, AAR, AAW, RIP_CONTROL,
LEAK_STACK, LEAK_HEAP, LEAK_LIBC, LEAK_PIE,
INFO_DISCLOSURE, CMD_INJECTION, DESER_GADGET, SSTI, SQLI, SSRF
```
Adjudicator rejects free-form descriptions. "Memory corruption" without a specific primitive triggers `primitive_unclassified` obligation.

### D-20: Long-lived workstation for v0.1, VM snapshots for v0.3+

- v0.1: PoC test runner launches target binary as subprocess, feeds trigger input, observes crash (exit code + ASAN). Workstation stays stable.
- v0.3+: Full exploitation (shell, privesc) runs in per-target VM with snapshot/rollback.
- Crash PoCs are safe (they crash the target process, not the host).

### D-21: Benchmark suite of 20 retired CVEs

Curated test suite with known patches and known PoCs:

- 10 Tier 1 (obvious trigger), 7 Tier 2 (needs analysis), 3 Tier 3 (complex)
- Mix: stack overflow, heap overflow, UAF, integer overflow, format string, logic bug
- All CVEs have public patch commits + buildable vulnerable versions

Metrics:
- Detection rate: root cause identified (out of 20)
- PoC rate: working crash PoC produced (out of 20)
- Turn efficiency: turns to reach working PoC
- False claims: "exploitable" claimed incorrectly (obligation system should catch)

Run on every VR module release. Publish results including failures.

---

### D-22: IDA Pro only, no Ghidra fallback

The VR module requires IDA Pro with a valid license. No Ghidra fallback.

- The IDA Headless MCP is the **first deliverable** -- built before the VR module itself
- The module assumes multi-seat IDA licensing (one license per concurrent binary analysis)
- Machine readiness check verifies IDA installation + license validity at project creation
- If IDA is not available, the project fails to create with a clear error: "IDA Pro is required for vulnerability research"
- Ghidra support deferred to v1.0+. Not planned, not promised, not designed for.
- One backend, one decompiler output format, one annotation model. No abstraction layer.
- The IDA MCP is a platform service (`platform/`), not a VR module internal. Future modules (malware analysis) can consume it.

**Build order:**
1. IDA Headless MCP (platform service) -- standalone, testable without VR module
2. VR module N-day PoC writer -- consumes the MCP
3. VR module research workflow -- extends the MCP usage

---

## Decisions for v0.3 fuzzing pipeline (added 2026-05-15)

Detailed milestone plan: `VR_V03_FUZZING_PLAN.md`. Decisions below lock in the architectural choices that plan depends on.

### D-23: Fuzzing lives in the VR module, NOT in audit-mcp

Audit-mcp is a stateless tool surface for code-graph queries. Fuzzing campaigns are durable, multi-hour workloads with workers, persistence, observability, and workflow. AILA already has every piece needed (ARQ task queue, Postgres, workflow engine, SSE, frontend modules); rebuilding inside audit-mcp would be months of work duplicating platform infrastructure.

**Architecture:**
- Fuzzing infrastructure → `src/aila/modules/vr/fuzzing/` (workers, manager, strategies, engines, triage, minimization)
- LLM-facing surface → audit-mcp adds thin `fuzz_*` MCP tools that call AILA's REST API
- Web UI → AILA's `@aila/vr-frontend` module (existing)

Both interfaces share the same Postgres state, workers, and storage.

### D-24: Strategy plugin model (composition first, code upload later)

Strategies have two layers:

1. **Built-in strategies** = Python classes in `vr/fuzzing/strategies/`. Versioned, tested, can do anything. Examples: `mutational`, `differential`, `fuzzilli`, `generative`.
2. **User-defined strategies** = JSON compositions over a registered primitive library. Created via API/UI. Per-team. Stored in `vr_fuzz_strategy_definitions`. Cannot execute arbitrary code.

Plugin upload (drop a `.py` file with a custom `Strategy` subclass) is **deferred** until a real use case justifies the sandboxing work needed to execute untrusted code safely.

Built-in primitive library is the extension point. New primitives ship with the module; user strategies compose them.

### D-25: Engine binding is per-strategy, not global

Each `FuzzStrategy` declares which engines it supports. There is no abstract "engine" that all strategies use. V8 sandbox fuzzing wants `v8_d8_sbx`. Native userspace fuzzing wants `afl++_qemu`. Java fuzzing wants `jazzer`. One-size-fits-all wrapper would force lowest-common-denominator interfaces.

Engines built into v0.3:
- `v8_d8_sbx` — V8 d8 with `--sandbox-testing`
- `pdfium_test_sbx` — PDFium test runner with sandbox-testing JS flags
- `afl++_qemu` — AFL++ QEMU mode for binary-only Linux fuzzing
- `fuzzilli_v8` — FUZZILLI bound to custom V8 build (optional, gated on infrastructure)

Deferred to v0.4: WinAFL+DynamoRIO, Jazzer, Atheris, syzkaller.

### D-26: Crash classification rules are versioned data, not code

Per-engine classification rules live in `vr/fuzzing/triage/rules/<engine>.yaml`. Adding a new crash class for an engine = editing YAML + bumping rule version. No code change, no redeploy. Rules are loaded at startup; reload via admin API.

For V8 sandbox engines, the gold marker `## V8 sandbox violation detected!` (from V8's `testing.cc:1059`) is the single source of truth for "this is a real escape." Everything else classifies as harmless or sandbox-aware.

### D-27: Two-tier storage (worker FS + object storage)

Workers write crashes to local filesystem (fast, ephemeral). Triage worker uploads triaged findings to object storage (durable, queryable). Postgres holds metadata + dedup signatures + time-series stats. This is the same pattern as forensics module evidence storage.

**Backpressure rule:** if worker `crashes/` directory grows above 500MB before triage catches up, workers pause until triage drains the queue. Prevents disk-fill DoS from runaway crash production.

### D-28: Variant hunt is automatic on confirmed bugs

When a finding gets classified `sandbox_violation` (or any CRITICAL severity), the system automatically queues a `variant_hunt_worker` task that mutates the reproducer 10 ways and tests each. New crashes link back to the parent via `parent_finding_id`, building a variant tree per bug.

Variant tree depth capped at 2 levels to prevent exponential explosion. Each parent gets its own variant budget.

This implements the "find all variants" obligation surfaced repeatedly in `VR_STAFF_RESEARCHER_DISCUSSION.md`. A surface crash is never the final answer — the system always asks "what other shapes of this bug exist?"

### D-29: Resolves Open Question 1 — Fuzzing resource management

Per-campaign quota enforced at worker spawn time:
- `cpu_quota_pct` (default 50, max % of one machine's CPU)
- `memory_limit_mb` (default 4096)
- `disk_quota_gb` (default 10)
- `concurrent_workers` (default 4)
- `max_runtime_hours` (default 24, can extend)

When the platform has multiple machines, `services/campaign_scheduler.py` partitions worker assignments per machine. Each machine runs at most `concurrent_workers` total across all campaigns assigned to it. Multi-machine distributed fuzzing (FUZZILLI tree hierarchy) is **deferred to v0.5+** when kernel/hypervisor fuzzing brings broader infrastructure needs.

Defaults pulled from `ConfigRegistry` (per-deployment). Operators can override per-campaign in the create call.

---

## Decisions from 2026-05-15 fuzzing bring-up session

Detailed protocol in `VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md`. These are the actionable decisions that emerged.

### D-30: V8MapInferenceProfile is the v0.3 reference custom strategy

Four CodeGenerators targeting documented 2025-2026 CVE patterns:
- `AliasedArgsAfterWarmupGenerator` — CVE-2025-2135 (Zellic V8CTF). Triggers `InferMapsUnsafe()` missing alias check by calling JIT'd functions with same variable in multiple parameter slots after warmup with distinct objects.
- `PhiTypeMixerGenerator` — CVE-2026-3910 (zero-day, in-the-wild). Builds Phi nodes joining Smi + Object paths to trigger Maglev's incorrect untagging speculation.
- `InferMapsExhaustionGenerator` — CVE-2020-6418 / CVE-2025-2135 family. Forces `InferMapsUnsafe` to walk effect chain past `Array.prototype.X.call(arr)` side effects with aliased receivers.
- `ElementsKindTransitionAliasGenerator` — Cross-product of #1 with explicit `PACKED_SMI` → `PACKED_DOUBLE` → `PACKED_ELEMENTS` transitions via `push()`.

The novelty gap was verified empirically: FUZZILLI's `randomArguments(forCallingFunctionWithParameters:)` source code reads `parameterTypes.map({ randomVariable(forUseAs: $0) })` — each parameter is picked independently, argument aliasing is essentially never produced by stock generators.

### D-31: FUZZILLI is the primary v0.3 fuzz engine; AILA never replicates its generators

The fuzz engine = FUZZILLI subprocess with REPRL. AILA stores strategies as REFERENCES to FUZZILLI profiles + commit pinning. Custom strategies = Swift PRs against a forked FUZZILLI (`project-lambda-zero/fuzzilli`, branch `aila-strategies`). Strategy plugin model from earlier `VR_V03_FUZZING_PLAN.md` GA-9 ("JSON composition of primitives") is REVERSED — Swift CodeGenerators ARE the primitive layer, JSON can't express them.

Strategy JSON schema in AILA:
```json
{
  "id": "mapinf_v8",
  "engine": "v8_d8_std",
  "fuzzilli_profile": "v8MapInference",
  "fuzzilli_commit": "515d05c",
  "cve_targets": ["CVE-2025-2135", "CVE-2026-3910"],
  "novelty_evidence": {
    "pattern": "Argument aliasing after warmup with distinct objects",
    "missing_in": "randomArguments(forCallingFunctionWithParameters:)",
    "cve_caught": "CVE-2025-2135"
  },
  "default_config": {"jobs": 8, "timeout_ms": 5500, "corpus": "markov", "consecutive_mutations": 3},
  "pivot_history": []
}
```

Each new strategy = FUZZILLI rebuild (~4 min) + JSON update. Not Python edit.

### D-32: Campaign storage layout (refined from D-27)

Three distinct directories per campaign on the fuzzing workstation:
- `~/fuzz-storage/<campaign>/` — FUZZILLI's storage (corpus, crashes, settings, stats). `--overwrite` wipes this.
- `~/fuzz-logs/<campaign>/` — Operator-facing logs. DELIBERATELY OUTSIDE storage so `--overwrite` doesn't wipe them. Empirical bug: putting logs inside storage caused FUZZILLI to delete logs on restart.
- Object storage `s3://aila-vr/fuzz/<campaign>/` — durable findings after triage. Synced by triage worker.

Postgres holds metadata + dedup signatures + time-series stats (per D-27).

### D-33: Production = dedicated Linux fuzzing workstations via SSH, NOT WSL2

WSL2 is fine for development/operator-side dev work but production v0.3 deployments use dedicated Linux machines, same execution model as v0.1's `tools/poc_runner.py`. Per-machine state on local SSD, AILA orchestrator connects over SSH.

Rationale:
- Reproducibility: no Windows-host interference, no thermal throttling on laptops
- Isolation: campaign crashes don't kill operator workstation
- Scale: fleet of fungible boxes, campaigns migrate on hardware failure
- Security: untrusted-input processing (attacker-controlled bytes in crashes) needs proper user/cgroup isolation

Provisioning per workstation:
- ≥12 cores, ≥32GB RAM, ≥500GB SSD, Ubuntu 24.04 LTS
- Install depot_tools, Swift 6.2+, FUZZILLI fork (pinned commit), target binaries
- AILA service user (`aila-fuzz`), no shell, cgroup-limited
- Per-orchestrator SSH key with `command=` restriction
- Quarterly key rotation

### D-34: Default minimization stays ON

Initially tested `--minimizationLimit=1.0` (skip minimization) for 5x raw throughput. Reverted because:
- Crash files become 80-instruction programs instead of 20-instruction minimized reproducers
- Triage cost massively higher (operator reads bigger PoCs)
- 30 execs/sec × 72h = 7.8M execs is plenty for our directed CVE-pattern hunt

Quality > raw throughput. Post-hoc minimization helper (`minimize_crash.sh`) exists as fallback. May reconsider when running coverage-discovery campaigns where quantity matters more than triage-readiness.

### D-35: Strategy files include `novelty_evidence` and `pivot_history` blocks

Every strategy JSON in `data/strategies/` must include:
- `novelty_evidence`: pattern definition, source-code citation of why existing tools miss it, CVE caught
- `pivot_history`: log of when this strategy was abandoned/resumed and why

Without `novelty_evidence`, strategy auto-classified as "stock variant" with low priority. Without `pivot_history`, AILA can't tell whether a strategy is fresh or has been tried-and-discarded before — important when revisiting old strategies as CVE landscape shifts.

---

## Decisions from 2026-05-15 hypothesis-engine integration

Detailed protocol in `VR_HYPOTHESIS_ENGINE_INTEGRATION.md`. These build on D-30 through D-35 above.

### D-36: VR uses platform's reasoning engine, not a parallel system

`vulnerability_research` is already a registered `ReasoningStrategyFamily` value in `platform/contracts/reasoning.py:36`. VR's strategy discovery uses the SAME reasoning engine the forensics module uses (`platform/services/reasoning.py`). VR registers its own `ReasoningDomainProfile`, agent (`HonestVulnResearcher`), prompts, and tools. No new platform infrastructure required.

Rationale: the engine already implements the hypothesis lifecycle (propose → dispute → reject/promote → submit) with persistent evidence graph (`ReasoningGraphService`), operator steering (`ReasoningOperatorSteering`), and graph-diff support. Building a parallel system in `vr/` would duplicate ~2000 LOC of working production code.

### D-37: Strategy discovery is hypothesis-driven, not fuzzer-first

Reverses the earlier framing where fuzzing was the workflow entry point. The new entry point is `VR_HYPOTHESIS_INVESTIGATION_V1` — a hypothesis investigation that takes a question + project context + operator steering, runs the reasoning engine loop, and either:
- Emits a fuzzing campaign (via existing `VR_FUZZ_CAMPAIGN_V1`, now PHASE 2)
- Emits an audit memo (no-fuzz outcome with rationale)
- Emits a direct finding entry (variant audit from pure source reading)

Fuzzing is one of three possible OUTCOMES of an investigation, not the default. This matches operator intuition: "let's discuss whether this area is worth fuzzing before we burn compute."

### D-38: Audit memos prevent dead-end re-exploration

When the engine concludes no-fuzz, it MUST emit a `vr_audit_memos` row containing:
- The question that was investigated
- The evidence graph snapshot
- The rejected hypotheses with rationales
- An expiry date (default 90d)
- The trigger conditions that would invalidate the memo (e.g., "new CVE in V8 Maglev within next 90d")

New investigations query memos first via embedding-based similarity over `question + rationale`. If a recent memo covers the area, the engine either trusts the prior conclusion or has to specifically argue why the memo's reasoning no longer holds (new CVE landed, new researcher write-up, etc.).

Defers the "CVE feed → memo invalidation" automation to v0.4.

### D-39: Multi-persona prompting drives hypothesis dispute

The engine's `reasoning` action turns use the 6 personas from `VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md` (Halvar/Maddie/Yuki/Renzo/Noor/Wei) as PROMPT VOICES, not as separate agents. Each rescoring turn runs as a multi-persona dialogue surfacing dispute rather than consensus, then resolves to a `Hypothesis` update.

Rationale: this is the documented technique to reduce LLM sycophancy. A single-voice agent tends to converge prematurely on the first plausible hypothesis. Multi-persona dispute generates explicit refutations as `refutes` edges in the evidence graph.

### D-40: Engine interrupts via `ReasoningOperatorSteering`

The interrupt mechanism from Topic 8 of the discovery discussion maps to existing `ReasoningOperatorSteering`. Operator can inject constraints mid-investigation (e.g., "focus on Maglev only", "drop SpiderMonkey from scope", "this hypothesis is wrong because of X"). The engine's loop checks steering before each turn.

Pivots are logged to BOTH the strategy file's `pivot_history` (per D-35) AND the evidence graph as `refutes` edges from the new operator constraint to any hypotheses it contradicts. This gives traceability in two formats: human-readable diff log AND machine-queryable graph.

### D-41: Reasoning engine supports branching (fork/merge/promote/abandon)

Branching extends the reasoning engine with fork-merge semantics. At any reasoning state, an investigation can fork into N parallel branches; each branch carries its own hypothesis set, evidence subgraph, operator steering, and turn history. Branches can be:
- **active** — currently being explored
- **abandoned** — discarded with rationale; subgraph preserved
- **merged** — evidence promoted into parent without replacing it
- **promoted** — replaced the parent as canonical (siblings auto-abandoned)

Drives 5 use cases in VR:
- Two competing strategies that each could consume the full 72h budget
- Two evidence-gathering paths from different sources
- Operator can't decide between A/B and wants both played out
- Variant hunt — each crash spawns up to 10 mutation-hypothesis branches (per D-28)
- **Multi-persona dispute literally as branches** — each of the 6 personas (Halvar/Maddie/Yuki/Renzo/Noor/Wei from D-39) runs its own dispute loop in a branch, then evidence is merged based on cross-branch corroboration

Schema additions in `platform/contracts/reasoning.py`:
- New `ReasoningBranch` model with id/parent/name/rationale/forked_at/status/cost tracking
- `ReasoningCaseState` gains `branch_id`
- `ReasoningGraphService` snapshots become branch-aware

Two new `ReasoningAction` values: `branch_fork` and `branch_resolve`. Operator can also trigger branching via API.

Default fork policy:
- Fork when initial hypotheses split into >1 mutually-exclusive groups
- Fork when operator steering says "explore both A and B"
- DON'T fork when single hypothesis is overwhelmingly dominant (>80% evidence weight)
- DON'T fork when cost cap is near exhausted

Per-branch budgets default $1.25 (strategy discovery) or $0.20 (variant hunt). Operator can override.

v0.3 ships API-only branching. Frontend tree-visualization UI deferred to v0.4 unless operator demand surfaces sooner.

Platform-level: ~800 LOC. Forensics also benefits (no module-specific changes needed there). VR-specific: ~200 LOC for the `fork_decision` and `branch_resolve` workflow states.

Backward-compatible: investigations that don't fork run on an implicit "main" branch. Existing forensics workflows are unaffected.

---

### D-42: N-day-targeted fuzzing is a parallel mode to discovery fuzzing

Two orthogonal fuzzing modes ship in v0.3:

|Mode|Use case|Engine|Strategy seeds|
|---|---|---|---|
|**Discovery fuzzing** (D-30/D-31)|Hunt novel/0-day bugs in target component|FUZZILLI (grammar-driven)|Custom CodeGenerators (mapinf_v8 etc.)|
|**N-day-targeted fuzzing** (this decision)|Reproduce a known CVE OR find unpatched variants|AFL++ / libFuzzer / WinAFL / syzkaller|Patch diff + advisory PoC + crash report|

Both modes route through the same reasoning engine (D-36). The engine's `submit_decision` now picks from FOUR outcomes instead of three:
1. Direct PoC construction (v0.1 N-day path — hand-written by LLM, no fuzzing)
2. **N-day-targeted fuzz campaign** (new — when advisory is too vague to construct directly, or for variant hunt)
3. Discovery fuzz campaign (existing — novel-bug hunt)
4. Audit memo (no-fuzz outcome)

Module structure splits `vr/fuzzing/` into two peer subpackages:
- `vr/fuzzing/discovery/` — FUZZILLI-driven novel bug hunt (existing v0.3 scope)
- `vr/fuzzing/nday/` — CVE-targeted reproduction + variant hunt (new)

N-day fuzz uses different engines because grammar fuzzers are wrong for CVE reproduction:
- AFL++ / libFuzzer for in-process userspace harnessing
- WinAFL+DynamoRIO for Windows binary fuzzing
- syzkaller for kernel CVE reproduction (full implementation deferred to v0.5)

N-day-specific services:
- `harness_gen/from_patch_diff.py` — auto-generate a fuzz harness from the patched function signature
- `harness_gen/from_advisory.py` — extract harness skeleton from advisory text via LLM
- `harness_gen/from_crash_report.py` — seed corpus from public crash report
- `services/corpus_seeder.py` — build seed corpus from advisory PoC + patch context
- `services/patch_completeness.py` — measure whether fuzz finds variants the patch didn't fix (per the `patch_completeness_assessed` obligation from `VR_STAFF_RESEARCHER_DISCUSSION.md`)

Triggers for picking N-day-targeted over direct construction:
- Advisory text too vague to construct PoC by hand
- Direct construction PoC works BUT operator requested variant analysis
- Patch-completeness assessment requested
- Previous direct construction attempts failed (LLM stuck)

Triggers for picking direct construction over fuzz:
- Advisory is precise (e.g., "OOB read at offset N in function X with input crafted as Y")
- Public PoC exists; just need to wrap and verify
- Single-trigger bug with no variant space to explore
- Budget too tight for fuzz campaign (<2h)

v0.3 ships AFL++ / libFuzzer support. WinAFL and syzkaller are placeholders with documented integration paths; full implementations deferred to v0.4 (Windows) and v0.5 (kernel).

---

### D-43: Conversational investigations, typed outcomes

The reasoning engine is conversational end-to-end. The operator never selects an "intent" from a dropdown or fills a structured form — they just talk, like the 2026-05-15 discovery session ("lets fucking go", "i dont like no minimization", "is this profile enough has novelty tho", "we wont use wsl2 you know it right").

The engine maintains conversation state. Each new operator message:
- Extends the current investigation if it's a refinement ("focus on Maglev only")
- Pivots the current investigation if it changes direction ("forget that, what about Wasm/JS?")
- Demands evidence if it challenges ("how do you KNOW that's underexplored")
- Corrects if the engine got something wrong ("WSL2 is dev only, not production")
- Starts a new investigation only when the topic is genuinely orthogonal

The engine decides which based on conversation context, NOT operator pre-classification.

### What the engine emits (the typed outcome layer)

Internally the engine still produces typed outcomes — those are the SHAPES of work it can produce. But each outcome is INFERRED from where the conversation lands, not pre-declared. When the engine emits an outcome, the chat shows the operator what's being shipped with a confirm button.

|Outcome shape|When the engine emits it|Operator confirmation|
|---|---|---|
|`AssessmentReport`|Conversation explored a target/class survey and reached a ranked view|"Save report?"|
|`StrategyDescriptor`|Conversation converged on a specific strategy to use|"Launch campaign?" / "Save for later?"|
|`ProfileSpecDraft`|Conversation designed a new FUZZILLI profile but operator hasn't asked to launch|"Promote to production strategies?"|
|`ConfigDelta`|Conversation argued over campaign params|"Apply to next launch?"|
|`VariantHuntOrder`|Conversation focused on exploring variants of an existing finding|"Queue variant micro-campaigns?"|
|`PatchAssessmentReport`|Conversation evaluated whether a patch fully closes a bug|"Save assessment?"|
|`AuditMemo`|Conversation concluded no fuzz warranted (often when operator says "this is exhausted, let's move on")|"Save memo (90d expiry)?"|
|`DirectFinding`|Conversation produced a confirmed bug entry from source reading alone|"Promote to vr_findings?"|
|`CrashTriageReport`|Conversation focused on classifying a specific crash|"Save triage / promote to finding?"|
|`CampaignLaunch`|Conversation reached explicit launch authorization (operator said "go" / "do it" / "lets ship it")|Confirmation modal with campaign summary|
|`SubInvestigation`|Engine needs to answer a sub-question to continue|(automatic, doesn't surface)|

The operator never types `"intent": "profile_design"`. They might say "design a profile for V8 Wasm GC bugs but don't launch yet" — the engine parses that as conversation context, runs a reasoning loop appropriate for profile-design work, eventually emits a `ProfileSpecDraft` with a confirm button.

### Conversation-level pivots

Three pivot patterns appeared in the 2026-05-15 session, all natively supported:

|Pattern|Session example|Engine response|
|---|---|---|
|Direction change|"forget that, let's do X" / "no intent selection — should be conversational"|Marks current branch as abandoned (D-41), spawns new branch from a snapshot before the pivot point. Old branch's evidence stays queryable.|
|Constraint addition|"we wont use wsl2", "i dont like no minimization"|Updates `ReasoningOperatorSteering` (D-40), re-evaluates current hypotheses against new constraint. Any hypothesis that depended on the rejected option gets a `refutes` edge from the new constraint.|
|Evidence demand|"how do you KNOW", "no speculation"|Engine pauses any in-flight `submit` action, runs additional `tool_run` actions to gather evidence, then resumes. Updates evidence graph with the new sources.|

### Frontend UX (revised — chat-style, no forms)

The investigation UI is a chat interface. Components:

- Message thread: operator messages + engine messages, like Claude Code or forensics' investigator UI
- Engine messages include action markers: "I'm running `cve_lookup(CVE-2026-3910)`..." / "Hypothesis H4 (concurrent race) abandoned: insufficient evidence per Topic 4 protocol" / "Ready to emit `ProfileSpecDraft` — confirm?"
- Side panel: live evidence graph (reuse forensics' visualization)
- Side panel: branch tree (D-41) — operator can switch branches like switching git branches
- Side panel: current `ReasoningOperatorSteering` constraints (operator can edit inline)
- Top bar: cost meter (current spend / cap), time elapsed
- No "intent picker" anywhere. No form fields per intent. The first message starts the investigation; subsequent messages refine it.

### Engine prompt strategy for conversation parsing

Each operator message gets parsed by the engine into:
- Intent inference (which of the internal intent classes applies — used for routing, never surfaced to operator)
- Constraint extraction (any new operator steering implied by the message)
- Pivot detection (is this a direction change, refinement, or new investigation?)
- Confirmation detection (did the operator approve a pending outcome?)

This parsing happens as the engine's first `reasoning` action turn after receiving the message. Result drives subsequent actions.

The engine's system prompt explicitly says: "Do NOT ask the operator to pre-categorize their request. Infer intent from natural conversation."

### When the engine HAS to ask the operator

The conversational model still leaves room for `request_operator_input` outcomes — but only when:
- The engine genuinely cannot infer intent (rare; ambiguous messages)
- The engine has reached a `submit` outcome that needs operator authorization (campaign launch, memo save, etc.)
- The engine has exhausted its budget without convergence
- An operator-defined constraint is contradictory (e.g., "use FUZZILLI" + "fuzz Windows kernel" — these don't compose)

Even in these cases, the engine doesn't ask "which intent?" — it asks the specific blocking question ("Should I launch the campaign now, or save the strategy for review?" / "Do you want me to drop the Windows constraint or pick a different target?").

### Implementation cost (revised from prior D-43)

Net new beyond D-36 through D-42:

|#|Milestone|LOC est|Notes|
|---|---|---|---|
|M3.3j|Conversation-state model (extends `ReasoningCaseState` with message history + last-pivot snapshot)|~200|Platform-level|
|M3.3k|Intent inference parser (first reasoning turn after each operator message)|~150|Platform-level, used by all conversational agents|
|M3.3l|Pivot detection + branch auto-fork on direction change (uses D-41)|~150|Platform-level|
|M3.3m|Per-outcome system prompts + kill criteria (no per-intent prompts; the agent figures it out)|~300 data|VR-specific|
|M3.3n|Outcome confirmation flow (in-chat confirm buttons for typed emissions)|~250|Frontend chat|
|M3.3o|Sub-investigation support|~250|Platform-level|

Total platform-level: ~750 LOC. VR-specific: ~300 LOC. Frontend ~250 LOC (chat is required for v0.3 launch UX; no separate form-picker frontend needed).

Smaller than prior D-43 (no form-picker frontend, no per-intent forms, no intent registry data files). Aligns with forensics' existing `HonestInvestigator` philosophy: "no hardcoded playbooks, the LLM is the strategist end-to-end."

### Backward compatibility

Operator-issued direct API calls (e.g., POST /api/vr/campaigns with a fully-specified `StrategyDescriptor`) still work — the conversation layer is the default UX, not the only entry point. Power users / automation can bypass.

Forensics' existing investigation UI is already chat-style; VR adopts the same pattern. No frontend forking required.

### D-44: Interactive code IDE + graph visualizations in investigation UI

Pure-text chat is insufficient for VR work. The investigation UI must surface:
- **Specific lines in specific files** when the engine points at code ("vuln pattern here, line N of file X")
- **Callgraphs and taint flow** when the engine reaches a sink or asks "how does data get here?"
- **Decompiled function context** for binary work (IDA output, xrefs)
- **Side-by-side patch view** when analyzing a CVE fix

The chat thread carries reasoning, decisions, and outcomes. The visual panels carry the spatial / structural evidence the chat can't fit inline.

### Panels (layout)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ [Investigation: V8 Maglev typer hunt]   cost: $1.42/$5.00  branches: 2 │
├──────────────────────────────────────────┬──────────────────────────────┤
│                                          │  File Tree (Monaco-style)    │
│  Chat thread                             │  ▾ v8/src/                   │
│  ─────────────                           │    ▾ maglev/                 │
│  operator: what calls FromJSON?          │      maglev-graph-builder.cc │
│  engine: [running call_graph(FromJSON)]  │      maglev-ir.cc            │
│  engine: 3 direct + 14 indirect callers  │      maglev-phi-untagging.cc │
│          [▼ Show graph]                  │    ▾ compiler/               │
│                                          │      ...                     │
│  [GRAPH PANEL INLINE — expandable]       │                              │
│                                          │  ─────────────────────────   │
│  operator: show me line 1247             │  Code Viewer (Monaco)        │
│  engine: [opening maglev-ir.cc:1247]     │  ┌──────────────────────┐    │
│          [▼ See file panel ➜]            │  │ 1245: void Visit(...)│    │
│                                          │  │ 1246:   if (tagged) {│    │
│  engine: This is the Phi untag path the  │  │*1247:     auto val = │    │
│          CVE-2026-3910 patch added a     │  │ 1248:       UntagSm…│    │
│          check to. Compare with...       │  │ 1249:   } else if (…│    │
│                                          │  └──────────────────────┘    │
│                                          │  [highlighted: line 1247]    │
│                                          │  [annotation: engine says…]  │
│                                          │                              │
│                                          │  ─────────────────────────   │
│                                          │  Reasoning evidence graph    │
│                                          │  ▾ Hypotheses (3 active)     │
│                                          │    H1 supports: 5 evidence   │
│                                          │    H2 rejected: 1 refutes    │
│                                          │    H3 active: 0 evidence     │
│                                          │                              │
│                                          │  Branch tree (D-41)          │
│                                          │  ▾ main                      │
│                                          │    ▸ alt_wasm_focus          │
│                                          │                              │
│                                          │  Steering (D-40)             │
│                                          │  • scope: V8 only            │
│                                          │  • no flag-gated features    │
└──────────────────────────────────────────┴──────────────────────────────┘
```

### Engine emits richer message types

The chat doesn't just carry text. Engine messages have typed payloads:

|Message type|Payload|Renders as|
|---|---|---|
|`text`|Markdown string|Normal chat message|
|`tool_call`|Tool name + args|"Running `audit_mcp.callgraph(symbol=FromJSON)`..." with collapsible result|
|`code_pointer`|File path + line range + annotation + reason|Inline preview card + "Open in panel" button. Click → IDE panel jumps to that file/line with highlight|
|`graph_view`|Graph spec (nodes + edges + layout hint)|Embedded React Flow widget, expandable to full-screen|
|`taint_flow`|Source → ... → sink trace with each hop annotated|Animated linear graph showing data progression|
|`xref_view`|List of cross-references with sites|Clickable list, each item opens in IDE panel|
|`patch_diff`|Two file versions side-by-side|GitHub-style split diff with engine commentary|
|`decompiled_function`|IDA pseudocode + assembly + boundary info|Tabbed viewer (decompiled / disasm / hex)|
|`hypothesis_update`|Hypothesis ID + state change|Inline badge: "H1 → supported by 2 new evidence" with click-through to evidence node|
|`outcome_pending`|Pending typed outcome (D-43)|Confirm button + summary of what will be emitted|

Operators can interact with any of these: click a code pointer to open in IDE, click a graph node to expand its neighborhood, click an xref to navigate, etc. Interactions feed back into the engine's context.

### Specific tech choices

|Concern|Choice|Why|
|---|---|---|
|Code editor|**Monaco** (VSCode's editor, npm `@monaco-editor/react`)|Production-grade, syntax highlighting for ~30 languages, inline annotations, search/replace, file tree integration|
|Graph rendering|**React Flow** (`@xyflow/react`)|Already used in similar agentic UIs, supports custom node renderers, edge labels, mini-map, pan/zoom, animated edges (for taint flow)|
|Side-by-side diff|**Monaco Diff Editor** (built into monaco-editor)|Same component family as the main editor; consistent UX|
|File tree|**Custom** built on Monaco + project file index|Don't need a full IDE; just enough to navigate the codebase under investigation|
|Graph data backing|Just the existing `ReasoningEvidenceGraph` from `platform/contracts/reasoning.py`|Already exists. Neo4j would be overkill — investigation graphs are small (<10k nodes) and per-investigation, not cross-investigation queries|
|Code data sources|`audit-mcp` (already in our toolchain) + IDA Headless MCP + file system + git|All existing infrastructure|

### Data flow for "show me a callgraph"

```
operator: "what calls maglev-ir.cc:Visit?"
  ↓
engine reasons: needs callgraph for that symbol
  ↓
engine.tool_run("audit_mcp.callgraph", {symbol: "maglev::Visit", depth: 2})
  ↓
audit-mcp returns: {nodes: [...], edges: [...], hot_paths: [...]}
  ↓
engine emits message {type: "graph_view", payload: {graph, focus: "maglev::Visit"}}
  ↓
chat renders inline graph widget (small) + "Expand" button
  ↓
operator clicks "Expand" → graph fills the right panel, IDE panel hides
  ↓
operator clicks node "TurboFan::Lowering" in graph
  ↓
chat side opens code pointer: turbofan/lowering.cc + relevant function
  ↓
operator: "this is the path I was looking for, hypothesize from here"
  ↓
engine adds graph node + selected callsite as evidence to current hypothesis
```

### Data flow for "look at this line — vuln pattern"

```
engine reasoning concludes: line N of file X exhibits CVE-2025-2135-like alias pattern
  ↓
engine emits message {type: "code_pointer", payload: {
    file: "v8/src/compiler/js-native-context-specialization.cc",
    line_start: 1245, line_end: 1280,
    annotation: "InferMapsUnsafe alias check missing here",
    reason: "Pattern matches CVE-2025-2135 family",
    severity_hint: "high"
}}
  ↓
chat renders preview card with first 5 lines + annotation
  ↓
operator clicks "Open in panel" → IDE panel opens that file, scrolls to 1245-1280,
   highlights region, shows annotation as inline comment
  ↓
operator selects a range, types: "explain what `IsSame` returns here in the
   monomorphic case"
  ↓
selection (file:line_range + selected text) becomes engine context
  ↓
engine responds inline + may add more code_pointers
```

### Persistence

Code pointers and graph views are NOT ephemeral chat ornaments. They get stored as `ReasoningGraphNode` entries with `kind="evidence"`, with the file path / line range / xref list as `attributes`. Subsequent turns can refer back to them via the evidence graph. Investigation export (audit memo, advisory, etc.) embeds the relevant code pointers as anchors.

### Mobile / smaller screens

The 3-panel layout collapses on smaller viewports: chat-only mode, IDE panel as tab, graph as modal overlay. The chat remains the primary surface; visual aids degrade gracefully.

### Backward compatibility

Forensics' existing UI is chat-only with a static evidence graph viewer. D-44's IDE panel + interactive graphs are new surfaces but additive — forensics can opt in. The reasoning engine's message-payload types are agnostic; the chat client decides which to render and how.

### Implementation cost

|#|Milestone|LOC est|Notes|
|---|---|---|---|
|M3.3p|Engine message payload types extended (code_pointer, graph_view, taint_flow, xref_view, patch_diff, decompiled_function, hypothesis_update, outcome_pending)|~250|Platform-level — schemas + serialization|
|M3.3q|`audit-mcp` integration tool — callgraph, xrefs, type-info, taint queries|~400|VR-specific (in `vr/reasoning/tools/`)|
|M3.3r|IDA Headless MCP integration tool — decompile, xrefs (binary work)|~300|VR-specific|
|M3.3s|Frontend chat with rich message renderers|~500|Frontend|
|M3.3t|Monaco-based IDE panel (file tree + viewer + diff editor)|~600|Frontend|
|M3.3u|React Flow graph viewer (with custom nodes for hypothesis/evidence/code/symbol types)|~400|Frontend|
|M3.3v|Interaction wiring — clicks in graph/IDE feed back as engine context|~200|Frontend|

Frontend total: ~1700 LOC. Backend total: ~950 LOC. Net D-44 addition: ~2650 LOC.

Large but high-ROI. Pure chat would force the operator to copy-paste file paths from terminal output, lose graph context across messages, and re-derive callgraphs visually in their head. The IDE + graph viewer pay back the investment quickly.

v0.3 ships core panels (chat + IDE panel + graph viewer). Polish (mobile layout, advanced annotations, multi-file split view) iterates in v0.4.

---

## Open Questions (Remaining)

1. ~~**Fuzzing resource management.**~~ → Resolved by D-29.
2. **Human steering UX richness.** ~~VR needs exploit-specific steering beyond forensics' `ReasoningOperatorSteering`.~~ → Resolved by D-40 (uses existing `ReasoningOperatorSteering` directly).
3. **GDB integration depth.** Surface (run PoC, capture crash) for v0.1, deep (breakpoints, heap inspection) for v0.3.
4. **Multi-model split-roles.** One model vs researcher/implementer/critic split. Experiment in v0.4. (D-39 partially addresses via multi-persona prompting in single model.)
5. **FUZZILLI bring-up cost.** Custom V8 build with REPRL+coverage takes ~25-30min per V8 version (corrected from earlier "~2hrs" estimate based on actual session measurements). Worth automating? Or document and accept the cost?
6. **Differential fuzzing baseline whitelist.** Different V8 tiers produce slightly different output for valid programs (Math precision, GC timing). How big is the false-positive rate without baseline tuning?
7. **Bug bounty intake.** When a real sandbox violation lands, file to Google VRP immediately or internal-validate first? Internal validation costs operator time but reduces public-disclosure risk.
8. **Strategy retirement criteria.** When does a custom strategy get retired? Suggested: 30 days zero new findings OR when stock FUZZILLI catches up to the pattern.
9. **Multi-target prioritization.** With finite fuzzing workstations, how often do we rotate capacity between V8 / SpiderMonkey / JavaScriptCore / etc.? Suggested: 90-day rotations with 2-week overlap.
10. **Researcher onboarding.** D-31 assumes Swift-capable engineers. For solo-operator deployments, path is LLM-drafted generator + automated tests for review.
11. **Hypothesis lifetime across investigations.** When investigation A rejects hypothesis H and investigation B (later) wants to propose H again — does the engine respect A's rejection? Probably yes for 90d (memo expiry) then re-evaluate.
12. **Investigation cost cap.** Forensics uses turn limits. VR hypothesis investigations can be open-ended (web searches, source greps). Suggest 30 min wall-clock OR $5 LLM spend, whichever first.
13. **Audit memo discovery in operator UI.** When operator asks a new question, frontend should surface "we already investigated something similar X days ago, here's the memo." UX work.
14. **CVE feed automation.** D-38 requires memo invalidation when new CVE in the area appears. Need automated feed → memo-invalidation hook. Defer to v0.4.