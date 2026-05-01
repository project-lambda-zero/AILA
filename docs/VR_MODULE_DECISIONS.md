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

## Open Questions (Remaining)

1. **IDA headless MCP architecture.** Purpose-built for VR, or shared with future malware module? Leaning shared.
2. **Fuzzing resource management.** How does the module negotiate resource allocation on the workstation?
3. **Human steering UX richness.** VR needs exploit-specific steering beyond forensics' `ReasoningOperatorSteering`.
4. **GDB integration depth.** Surface (run PoC, capture crash) for v0.1, deep (breakpoints, heap inspection) for v0.3.
5. **Multi-model split-roles.** One model vs researcher/implementer/critic split. Experiment in v0.4.