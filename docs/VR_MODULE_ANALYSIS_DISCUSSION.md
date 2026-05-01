# VR Module — Static and Dynamic Analysis Deep Dive

How the module performs static analysis and dynamic analysis, where they overlap, and where the LLM adds value beyond what tools already do.

---

## The Problem

Static analysis tools (Semgrep, CodeQL, IDA, Ghidra) find patterns.
Dynamic analysis tools (fuzzers, debuggers, taint trackers) find behaviors.

Neither alone answers "is this exploitable?" The module needs to:
1. Run both and correlate results
2. Use each to guide the other (static findings -> dynamic confirmation, dynamic crashes -> static root cause)
3. Add reasoning that neither tool provides (context, intent, exploitability judgment)

---

## Static Analysis Layers

### Layer 1: Automated pattern matching (tools do this)

| Tool | Target | What it finds | Limitations |
|---|---|---|---|
| **Semgrep** | Source code (any language) | Known dangerous patterns, injection sinks, unsafe API usage | Rules are pre-written. Misses novel patterns. No data flow. |
| **CodeQL** | Source code (compiled to DB) | Data flow from source to sink, taint propagation, control flow properties | Requires building the target. Slow. Language-specific. |
| **Bandit** | Python source | Unsafe eval, subprocess, pickle, hardcoded secrets | Python-only. Shallow (AST-based, no data flow). |
| **Psalm/PHPStan** | PHP source | Type errors, taint flow, security-sensitive sinks | PHP-only. Requires annotations for best results. |
| **Staticcheck** | Go source | Race conditions, incorrect sync, API misuse | Go-only. Misses unsafe pointer bugs. |
| **IDA/Ghidra** (static) | Binaries | Function boundaries, xrefs, string refs, call graphs, type recovery | No runtime context. Decompiler output is often wrong on types/structs. |
| **BinDiff/Diaphora** | Binary pairs | Changed functions between versions, patch identification | Requires two binaries. Doesn't explain *why* the change matters. |
| **checksec / pwn checksec** | ELF/PE | Mitigations (ASLR, NX, canary, RELRO, CFI, CET, MTE) | Surface-level. Doesn't check if mitigations are actually effective. |
| **YARA** | Binary/memory | Known signatures, crypto constants, packer stubs | Signature-based. Only finds what rules exist for. |

### Layer 2: LLM-guided pattern discovery (the module adds this)

Static tools find what they have rules for. The LLM finds *novel patterns* by reasoning about the code:

**On source code:**
- "This function allocates a buffer of `user_controlled_length` bytes without checking for integer overflow. If `length * sizeof(element)` wraps, the allocation is too small."
- "This deserialization path trusts the `class` field from user input and calls `Class.forName()` without a whitelist."
- "This Go code does `(*C.char)(unsafe.Pointer(&buf[0]))` then passes it to a C function that may write past the buffer length."

**On decompiled binary:**
- "Function at 0x4012A0 reads a 16-bit length field from the input, sign-extends it to 32 bits, then uses it as a memcpy size. A negative 16-bit value becomes a large positive 32-bit value."
- "The custom allocator at 0x401500 doesn't check for double-free. If an object is freed twice, the freelist is corrupted."
- "This function pointer table at 0x605000 is in a writable section. An arbitrary write can redirect control flow."

**On patch diffs:**
- "The patch adds a bounds check on `ext_data_length` before the memcpy. The pre-patch version copies `ext_data_length` bytes without validation — this is the overflow."
- "The patch changes `strcmp` to `strncmp` with a length limit. The original was comparing against a stack buffer — stack overflow via long input string."

### Layer 3: Cross-function and cross-file analysis (LLM-unique)

Static tools analyze function-by-function or follow explicit data flow edges. The LLM can reason about *implicit* relationships:

- "Function A validates input length. Function B processes the same input but is also callable from Function C which *doesn't* call A first. The validation is bypassable."
- "The lock is held in path X but not in path Y. Both paths modify the same shared state. Race condition."
- "This error handler calls `free(buf)` but doesn't null the pointer. The caller continues using `buf` after error recovery. Use-after-free."
- "The configuration parser and the network handler both call `process_extension()` but with different trust contexts. The parser inputs are trusted (from config file), the network inputs are untrusted. The function has no internal trust boundary — it trusts its caller."

---

## Dynamic Analysis Layers

### Layer 1: Black-box execution (tools do this)

| Tool | What it does | Output |
|---|---|---|
| **AFL++/WinAFL** | Mutation-based fuzzing with coverage feedback | Crash inputs, coverage maps, corpus |
| **libFuzzer** | In-process fuzzing | Same, faster, less isolation |
| **ASAN/MSAN/UBSAN** | Runtime error detection | Precise error reports (type, location, stack trace) |
| **Valgrind** | Memory error detection (slower than ASAN) | Uninit reads, leaks, invalid accesses |
| **strace/ltrace** | Syscall/library call tracing | Behavioral profile (what files, what network, what memory ops) |
| **DynamoRIO (drcov)** | Binary coverage collection | Basic block coverage for binary-only targets |
| **Intel PT** | Hardware-assisted tracing | Full execution trace with minimal overhead |
| **Frida** | Dynamic instrumentation (hook any function) | Custom tracing, argument logging, return value modification |
| **Pin** | Intel binary instrumentation | Taint tracking, call graphs, custom analysis passes |
| **GDB/LLDB** | Debugging | Register state, memory inspection, breakpoint-driven analysis |

### Layer 2: LLM-guided dynamic analysis (the module adds this)

The LLM doesn't just run tools. It *designs experiments*:

**Targeted tracing:**
- "I suspect the overflow is triggered when `msg_type == 0x42` and `payload_length > 0x1000`. Let me write a Frida hook on `process_message` that logs only when these conditions are met."
- "The bug requires two specific allocations to be adjacent in memory. Let me write a GDB script that tracks allocations and reports when the target objects are adjacent."

**State manipulation:**
- "I need to trigger the race condition. Let me write a Frida script that adds a `sleep(100ms)` after the lock release in thread A, widening the race window."
- "The bug requires a specific heap layout. Let me write a script that performs allocations in a specific order to shape the heap before triggering the vulnerable path."

**Differential testing:**
- "Does the patched version still crash with this input? Let me run the same input on both versions and compare behavior."
- "The bug exists in the error path. Let me inject faults (make malloc return NULL) and observe the error handling behavior."

**Taint analysis driven by hypothesis:**
- "I believe user input at offset 12 reaches the memcpy size argument. Let me use Intel Pin taint tracking to confirm the data flow: mark bytes 12-15 as tainted and check if they propagate to the third argument of memcpy at 0x4013A0."

### Layer 3: Crash analysis and root cause (LLM-unique)

A crash is not a vulnerability. The module must bridge the gap:

```
Raw crash:
  ASAN: heap-buffer-overflow on address 0x60200000ef54
  WRITE of size 4 at 0x60200000ef54 thread T0
  #0 process_extension+0x1a3 (/target+0x4013a3)
  #1 parse_message+0x87 (/target+0x401287)
  #2 main+0x42 (/target+0x401042)
  0x60200000ef54 is located 4 bytes to the right of 80-byte region

LLM analysis:
  Root cause: process_extension() writes 4 bytes past the allocated buffer.
  The buffer is allocated as ext->data_length bytes (line 12 in decompiled code),
  but the write loop iterates ext->field_count times (line 18). When
  field_count * 4 > data_length, the write exceeds the allocation.
  
  Controllable: yes. data_length and field_count are both read from the input
  at offsets 8 and 12 respectively.
  
  Exploitable: likely. 4-byte controlled write past heap allocation.
  On glibc 2.35+, adjacent chunk metadata can be corrupted for tcache
  poisoning. Target has no heap hardening (no safe-linking detected).
  
  Mitigation bypass needed: partial RELRO (GOT writable), no CFI, PIE enabled
  (need info leak for ASLR bypass).
```

---

## The Interplay: Static Guides Dynamic, Dynamic Confirms Static

This is where the module's reasoning engine adds the most value:

### Static -> Dynamic (hypothesis -> experiment)

```
Static finding:
  "Function parse_header at 0x4012A0 reads a 32-bit size field and passes it
  directly to malloc(). No integer overflow check. If size * element_size wraps
  to a small value, subsequent writes overflow the allocation."

LLM decision:
  "Hypothesis: integer overflow in parse_header leads to heap overflow.
  Experiment: write an AFL++ harness targeting parse_header, seed with valid
  headers where size * element_size approaches UINT32_MAX. Also write a
  targeted input that triggers the exact wrap condition."

Dynamic result:
  "AFL++ found crash in 47 minutes. ASAN confirms heap-buffer-overflow
  4096 bytes past allocation. The wrap occurs when size=0x40000001 and
  element_size=4 (product wraps to 4)."

  Hypothesis CONFIRMED.
```

### Dynamic -> Static (crash -> root cause -> variant search)

```
Dynamic finding:
  "AFL++ found crash in handle_auth(). ASAN: stack-buffer-overflow.
  Stack trace: handle_auth -> validate_token -> base64_decode."

LLM decision:
  "Root cause is in base64_decode. It calculates output length as
  input_length * 3 / 4 but doesn't account for padding characters.
  Stack buffer is allocated for the calculated size; actual decode
  writes more bytes when input has no padding."

  "Variant search: are there other callers of base64_decode that
  allocate based on the same calculation?"

Static analysis:
  "Found 3 other callers of base64_decode:
   - handle_certificate (same pattern, vulnerable)
   - process_cookie (uses heap allocation, still overflows but heap not stack)
   - parse_saml_response (correctly adds +3 to allocation, safe)"

  Variants FOUND: 2 additional vulnerabilities.
```

### Feedback loop (continuous refinement)

```
Turn 1 (static): "200 functions in the binary. Top 5 targets by complexity
  and input reachability: parse_mqtt, handle_tls, process_http, decode_json,
  validate_cert."

Turn 2 (dynamic): "Fuzzed parse_mqtt for 2 hours. 94% edge coverage, 0 crashes.
  Moving to handle_tls."

Turn 3 (dynamic): "handle_tls crashed after 23 minutes. UAF in session resumption
  path when ticket is malformed."

Turn 4 (static): "Root cause: session object freed on parse error at line 47,
  but pointer stored in connection struct is not nulled. Next message reuses
  the stale pointer at line 112."

Turn 5 (static -> dynamic): "Variant search: found same pattern in DTLS handler.
  Writing targeted input to confirm."

Turn 6 (dynamic): "DTLS variant confirmed. Two UAFs from the same root cause."

Turn 7 (exploitation): "UAF gives controlled 64-byte read/write. Target uses
  OpenSSL with custom allocator. Writing exploit targeting SSL_CTX struct overlap."
```

---

## What the Module Actually Orchestrates

### Analysis Session Structure

A single research turn can involve multiple tools in sequence:

```python
# Pseudocode for one analysis turn

async def analysis_turn(hypothesis, target, services):
    # 1. Static check first (fast, no execution needed)
    decomp = await services.ida.decompile(hypothesis.target_function)
    static_findings = await services.reasoning.analyze_code(decomp, hypothesis)
    
    # 2. If static supports hypothesis, design dynamic experiment
    if static_findings.supports_hypothesis:
        experiment = await services.reasoning.design_experiment(
            hypothesis, static_findings, target.instrumentation
        )
        
        # 3. Execute experiment (could be Frida hook, AFL++ run, GDB script)
        if experiment.type == "fuzz":
            harness = await services.reasoning.generate_harness(experiment)
            await services.fuzzer.compile_harness(harness)
            campaign = await services.fuzzer.run(duration=experiment.duration)
            crashes = await services.triage.analyze(campaign.crashes)
        
        elif experiment.type == "trace":
            script = await services.reasoning.generate_frida_script(experiment)
            trace = await services.instrumentation.run_frida(script, target)
            findings = await services.reasoning.interpret_trace(trace, hypothesis)
        
        elif experiment.type == "debug":
            gdb_commands = await services.reasoning.generate_gdb_script(experiment)
            result = await services.debugger.run_script(gdb_commands)
            findings = await services.reasoning.interpret_debug(result, hypothesis)
    
    # 4. Update hypothesis based on results
    return services.reasoning.update_hypothesis(hypothesis, findings)
```

### Tool Composition Patterns

The LLM composes tools in ways no single tool supports:

| Pattern | Tools Combined | What it achieves |
|---|---|---|
| **Coverage-guided target selection** | IDA (call graph) + AFL++ (coverage) | "These 12 functions are unreached by fuzzing. They handle error paths. Increase seed corpus with malformed inputs to reach them." |
| **Taint-guided fuzzing** | Pin/DynamoRIO (taint) + AFL++ (mutator) | "Bytes 12-15 of the input control the branch at 0x4013A0. Tell AFL++ to focus mutations on those bytes." |
| **Crash-to-exploit pipeline** | AFL++ (crash) + ASAN (report) + GDB (heap inspection) + IDA (gadget search) | "Crash found -> root cause identified -> heap layout analyzed -> exploitation strategy designed -> ROP chain built." |
| **Differential binary analysis** | BinDiff (patch) + IDA (decompile both) + LLM (explain) | "The patch adds check X. The pre-patch path allows Y. Trigger condition is Z." |
| **Variant hunting** | Semgrep/CodeQL (pattern) + IDA (binary pattern) + LLM (generalize) | "Found one bug via X pattern. Generalize the pattern. Search entire codebase/binary for variants." |
| **Adaptive harness refinement** | AFL++ (coverage stall) + IDA (uncovered paths) + LLM (harness fix) | "Coverage plateaued at 67%. The uncovered paths require state setup that the harness doesn't provide. Rewrite harness to initialize context object correctly." |

---

## State Management

Static and dynamic analysis produce different artifacts that must be tracked:

### Static artifacts
- Decompiled code (per function, cached, invalidated on re-analysis)
- Call graphs (whole-binary and per-function subgraphs)
- Data flow paths (source-to-sink chains)
- Pattern match results (Semgrep/CodeQL findings)
- Type annotations (recovered struct definitions, function signatures)
- Cross-reference maps (who calls what, who reads what data)

### Dynamic artifacts
- Crash inputs (minimized, with reproduction steps)
- Coverage maps (per-campaign, delta between campaigns)
- Trace logs (Frida output, strace, Intel PT decoded)
- Heap state snapshots (allocation layout at crash point)
- Execution recordings (rr traces for deterministic replay)
- Fuzzing corpus (minimized seeds, coverage-contributing inputs)

### Correlation artifacts
- Hypothesis -> evidence links ("this static finding led to this crash")
- Crash -> root cause mappings ("this crash at 0x4013A3 is caused by the overflow identified in static analysis turn 3")
- Variant chains ("bug A, found dynamically, led to static search that found bugs B and C")

All of these feed the evidence graph. The graph is the module's memory across turns.

---

## Open Questions

1. **How much state does the LLM see per turn?** A full binary has thousands of functions. The LLM can't see all decompiled code at once. It needs a *working set* — the functions relevant to the current hypothesis. How is this working set maintained and updated?

2. **When does static analysis run?** Upfront (full binary recon before any dynamic analysis) or on-demand (decompile only what the current hypothesis needs)? Upfront is expensive for large binaries but gives better target ranking. On-demand is faster but may miss cross-function issues.

3. **How are Frida/GDB scripts validated?** The LLM generates instrumentation code. If it's wrong (bad offsets, wrong types), the script crashes or produces garbage. Does the module validate scripts before running them? Sandbox them?

4. **How does the module handle non-deterministic bugs?** Race conditions, heap-dependent crashes, ASLR-dependent behaviors. Dynamic analysis may not reproduce consistently. The module needs retry logic and confidence scoring on dynamic results.

5. **What about time-bounded analysis?** "Analyze this binary for 4 hours max." The module needs to budget time across static analysis, fuzzing campaigns, and exploitation attempts. Who decides the time split — the LLM or the human?

6. **Multi-architecture targets.** ARM, MIPS, PowerPC firmware. IDA handles disassembly, but dynamic analysis (fuzzing, debugging) requires emulation (QEMU user-mode, QEMU system). How does the module handle cross-architecture targets?

7. **Incremental analysis.** The target gets a new version. Which analysis results can be reused (call graph probably stable), which must be re-run (patch introduced new code paths), and how does the module detect this?
