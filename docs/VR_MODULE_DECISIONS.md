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

## Open Questions (Remaining)

1. **IDA headless MCP architecture.** Purpose-built for VR, or shared with future malware module? Leaning shared — both need decompilation, xrefs, pattern search. The MCP is a platform service; modules consume it.

2. **Exploit testing isolation.** Running a PoC on the research workstation could crash the workstation. Should the module spin up a disposable VM for exploit testing? Or is the researcher responsible for isolation?

3. **Fuzzing resource management.** AFL++ on 16 cores for 8 hours generates heat. How does the module negotiate resource allocation with other work on the research workstation?

4. **Human steering UX.** The forensics module uses `ReasoningOperatorSteering` (confirmed facts, disproved hypotheses, guidance, strategy pins). VR needs the same + exploit-specific steering ("try heap spray at offset 0x40", "the target uses jemalloc not ptmalloc"). How rich does the steering contract need to be?

5. **GDB integration depth.** Surface level (run PoC, capture crash) vs deep (set breakpoints, inspect heap, single-step). Deep GDB integration is a significant tool to build. Defer to v0.3?
