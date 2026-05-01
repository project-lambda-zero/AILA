# VR Module — Complete Toolchain

Everything the research workstation needs, categorized by research phase. Combines lessons from Metis, Pharos, Trailmark, and 2026-era LLM-assisted VR tooling.

---

## The Stack

```
Layer 5: AILA VR Module (orchestration + reasoning)
  CyberReasoningEngine, evidence obligations, adjudication, workflow engine

Layer 4: LLM-Augmented Analysis
  LLM4Decompile, LATTE (binary taint), HarnessAgent, oss-fuzz-gen

Layer 3: Semantic Analysis
  angr, Trailmark, OOAnalyzer, Z3

Layer 2: Instrumentation + Fuzzing
  AFL++, WinAFL, libFuzzer, Frida, DynamoRIO, Intel PT, sanitizers

Layer 1: Disassembly + Debugging
  IDA Pro, Ghidra, GDB/pwndbg, LLDB, radare2/rizin

Layer 0: Target Environment
  Research workstation (Linux/Windows), QEMU/KVM, compilers, pwntools
```

---

## Tools by Research Phase

### Phase: Reconnaissance

| Tool | What it does | When to use |
|---|---|---|
| **Trailmark** | Source code graph: entrypoints, taint, privilege boundaries, blast radius, complexity hotspots | Source-available targets. First thing to run. |
| **checksec** | Binary mitigations: ASLR, NX, canary, RELRO, CFI, CET, MTE | Every binary target. 5 seconds. Non-negotiable. |
| **IDA Pro** (headless) | Decompilation, function listing, xrefs, string refs, type recovery | Every binary target. |
| **Ghidra** (headless) | Same as IDA, free alternative. Ghidra Bridge for scripting. | When IDA unavailable. |
| **OOAnalyzer** (Pharos, Docker) | C++ class hierarchy, vtable, member layout recovery from binaries | C++ binaries with virtual dispatch. |
| **LLM4Decompile** | LLM-powered decompilation producing more readable C than IDA/Ghidra | Supplementary decompilation for complex functions. |
| **file / binwalk / DIE** | File type identification, packed binary detection, embedded firmware extraction | First-pass triage on unknown binaries. |
| **ssdeep / TLSH** | Fuzzy hashing for function-level binary similarity | Cross-version comparison, library identification. |
| **strings / FLOSS** | String extraction (FLOSS also extracts obfuscated/stacked strings) | Quick indicator extraction from binaries. |

### Phase: Static Analysis

| Tool | What it does | When to use |
|---|---|---|
| **Semgrep** | Pattern-based source audit (1000+ security rules built-in) | Source targets, all languages. Fast, low false-positive. |
| **CodeQL** | Data flow analysis, taint tracking, source-to-sink queries | Source targets when deep flow analysis needed. Requires build. |
| **LATTE** | LLM-powered static binary taint analysis (no manual rules needed) | Binary targets. Automated taint propagation without human-written rules. Found 37 new bugs in firmware. |
| **angr** | Symbolic execution, reaching definitions, control flow graph | Binary targets. Path feasibility. Constraint solving. |
| **BinDiff / Diaphora** | Binary-level patch diffing between two versions | N-day research. Identifying the security fix. |
| **Trailmark diff** | Source-level structural diff between two versions | N-day research on open-source targets. |
| **Tree-sitter** | Language-agnostic AST parsing for scope extraction and call graphs | Lightweight source analysis when CodeQL is too heavy. |
| **Bandit** | Python-specific security linter | Python targets. |
| **Staticcheck** | Go-specific static analysis (races, API misuse) | Go targets. |

### Phase: Dynamic Analysis / Fuzzing

| Tool | What it does | When to use |
|---|---|---|
| **AFL++** | Coverage-guided fuzzing (source instrumentation) | Linux, source available, C/C++. Default choice. |
| **AFL++ QEMU mode** | Coverage-guided fuzzing (binary-only, QEMU emulation) | Linux, no source. |
| **WinAFL + DynamoRIO** | Coverage-guided fuzzing for Windows binaries | Windows PE targets. |
| **Intel PT mode** | Hardware-assisted coverage (lowest overhead) | When available. Both AFL++ and WinAFL support it. |
| **libFuzzer** | In-process persistent fuzzing | Source available, fastest option (no fork). |
| **honggfuzz** | Alternative coverage fuzzer, good feedback-driven mutation | When AFL++ doesn't suit the target. |
| **Syzkaller** | Kernel syscall fuzzing | Kernel modules, drivers. Requires QEMU + KASAN kernel. |
| **Jazzer** | Java/JVM fuzzing via libFuzzer integration | Java targets. |
| **Atheris** | Python fuzzing via libFuzzer integration | Python targets. |
| **go test -fuzz** | Go native fuzzing | Go targets. |
| **cargo-fuzz** | Rust fuzzing via libFuzzer | Rust targets. |
| **libprotobuf-mutator** | Structure-aware protobuf mutation | Protobuf input formats. Layer on AFL++/libFuzzer. |
| **Nautilus / Gramatron** | Grammar-aware fuzzing | Complex input grammars (SQL, config DSLs, query languages). |
| **Fuzz4All** | Universal LLM-guided fuzzing across languages | Compilers, interpreters, language runtimes as targets. |
| **HarnessAgent** | LLM-powered automatic harness generation (87% C, 81% C++) | Automated harness writing. Major time saver. |
| **oss-fuzz-gen** | Google's LLM harness generator for OSS-Fuzz | Open-source C/C++/Java/Python projects. |
| **Frida** | Dynamic instrumentation (hook any function at runtime) | Anti-debug bypass, custom tracing, argument logging. |
| **DynamoRIO** | Binary instrumentation framework | Coverage collection (drcov), taint tracking, WinAFL backend. |
| **rr** | Deterministic record-and-replay debugging | Non-deterministic bugs (races, heap-dependent crashes). |

### Phase: Sanitizers (run alongside fuzzers)

| Tool | What it detects |
|---|---|
| **AddressSanitizer (ASAN)** | Heap/stack overflow, UAF, double-free, global overflow |
| **MemorySanitizer (MSAN)** | Uninitialized memory reads |
| **UBSanitizer (UBSAN)** | Integer overflow, null deref, alignment, signed overflow |
| **ThreadSanitizer (TSAN)** | Data races, deadlocks |
| **LeakSanitizer (LSAN)** | Memory leaks (often combined with ASAN) |
| **KASAN** | Kernel AddressSanitizer (for syzkaller) |
| **KMSAN** | Kernel MemorySanitizer |
| **Miri** | Rust undefined behavior detector for unsafe code |

### Phase: Crash Triage

| Tool | What it does | When to use |
|---|---|---|
| **afl-tmin** | Crash input minimization | Every crash. Reduce to smallest trigger. |
| **afl-cmin** | Corpus minimization | After fuzzing campaign. Remove redundant inputs. |
| **casr** | Crash analysis and severity ranking (ISP RAS) | Automated crash classification and dedup. |
| **exploitable** (GDB plugin) | Exploitability classification (EXPLOITABLE/PROBABLY_EXPLOITABLE/etc.) | Quick exploitability triage on crashes. |
| **GDB + pwndbg** | Heap inspection, register state, breakpoints, single-step | Deep crash analysis and exploit development. |
| **Valgrind** | Memory error detection (slower than ASAN but works on uninstrumented binaries) | When ASAN can't be used (no recompilation). |
| **rr** | Record crash execution for deterministic replay | Reproducing non-deterministic crashes. |
| **ASAN report parser** | Extract crash type, location, stack trace from ASAN output | Every ASAN crash. Feed to LLM for root cause analysis. |

### Phase: Exploit Development

| Tool | What it does | When to use |
|---|---|---|
| **pwntools** | Exploit scripting framework (Python) | Every exploit PoC. Process interaction, payload construction, shellcode. |
| **angr + angrop** | Automatic ROP gadget finding and chain construction | When ROP is needed (NX enabled). |
| **ROPgadget** | ROP gadget search | Simpler gadget finding than angr. |
| **one_gadget** | Find one-shot RCE gadgets in glibc | glibc exploitation shortcuts. |
| **ropper** | ROP/JOP/SOP gadget finder | Alternative to ROPgadget. |
| **Metasploit** | Exploit framework for testing and payload delivery | When PoC needs to demonstrate real impact (reverse shell, etc.). |
| **GEF / pwndbg** | GDB extensions for heap analysis, pattern generation, exploit helpers | Heap exploitation, offset calculation, state inspection. |
| **heaptrace** | Heap operation tracing (malloc/free/realloc with sizes and pointers) | Understanding heap layout for exploitation. |
| **libheap** | GDB plugin for glibc heap inspection (bins, chunks, metadata) | tcache/fastbin/unsorted bin exploitation. |

### Phase: Reporting

| Tool | What it does | When to use |
|---|---|---|
| **AILA advisory builder** | Generate formatted vulnerability advisory | Every confirmed finding. |
| **CVSS calculator** | Compute CVSS v3.1/v4.0 vector from finding attributes | Every advisory. Deterministic, not LLM-guessed. |
| **CWE mapper** | Map finding to CWE weakness type | Every advisory. |
| **SARIF exporter** | Export findings in SARIF format for interop | When feeding findings to other tools or CI. |

---

## Tools We Should Build (Not Available Off-the-Shelf)

| Tool | What it does | Why it doesn't exist |
|---|---|---|
| **IDA Headless MCP v2** | Purpose-built MCP for VR: batch decompile, pattern search across all functions, xref chains, struct recovery, diff two binaries | Existing IDA MCP is interactive, not batch-analysis oriented. |
| **Fuzzing Campaign Manager** | Orchestrate multi-instance AFL++ with corpus sync, coverage tracking, crash dedup, plateau detection, auto-pivot | Individual tools exist but no unified orchestrator that an LLM can drive. |
| **Exploit Test Runner** | Compile PoC, run against target, verify crash/exploit, report result | Manual process today. Needs sandboxing (target might crash the workstation). |
| **Evidence Pack Builder** | Assemble bounded context for LLM turns from IDA output, crash reports, source code, traces | Our Metis-inspired bounded evidence pack concept. No existing tool does this. |
| **Obligation Checker** | Validate LLM claims against collected evidence before accepting conclusions | Our Metis-inspired evidence obligation system. Novel. |

---

## Research Workstation Package List

Minimum install for the research workstation (Debian/Ubuntu):

```bash
# Build tools
apt install build-essential gcc g++ clang llvm cmake ninja-build git

# Fuzzing
apt install afl++ libfuzzer-17-dev honggfuzz

# Analysis
pip install angr trailmark semgrep pwntools ropper

# Debugging
apt install gdb
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Binary tools
apt install binutils file binwalk radare2

# Sanitizers (come with clang/gcc)
# ASAN, MSAN, UBSAN, TSAN built into compiler

# Crash triage
pip install casr  # or build from source

# IDA Pro — licensed, installed separately
# Ghidra — download from ghidra-sre.org
# OOAnalyzer — docker pull ghcr.io/cmu-sei/pharos

# Windows fuzzing (on Windows research workstation)
# WinAFL + DynamoRIO — build from source
# Intel PT — requires compatible CPU + kernel support

# Kernel fuzzing (on QEMU host)
apt install qemu-system-x86
# syzkaller — go install from source
```

---

## What the LLM Selects From

The LLM doesn't use all tools on every target. It selects based on:

```
Target classification:
  native binary + source -> AFL++ + Semgrep + angr + IDA
  native binary only    -> AFL++ QEMU + IDA + angr + LATTE
  Windows PE            -> WinAFL + DynamoRIO + IDA
  Java                  -> Jazzer + Semgrep + Trailmark
  Python                -> Atheris + Bandit + Trailmark
  Go                    -> go-fuzz + Staticcheck + Trailmark
  Rust unsafe           -> cargo-fuzz + Miri + Trailmark
  Kernel module         -> Syzkaller + KASAN + QEMU
  Firmware              -> binwalk + Ghidra + QEMU user-mode
  
N-day research:
  open source -> Trailmark diff + Semgrep + source audit
  binary only -> BinDiff/Diaphora + IDA + angr
  
Exploit development:
  NX enabled  -> angrop/ROPgadget for ROP chain
  glibc heap  -> heaptrace + libheap + one_gadget
  Windows     -> WinDBG patterns + pwntools
```

The evidence obligation system ensures the LLM can't claim "exploitable" without first running checksec, can't claim "path feasible" without angr confirmation, can't claim "tainted from user input" without Trailmark or dynamic trace evidence.
