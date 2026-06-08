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

## What VR actually drives today

AILA's VR module reaches the layers above through three HTTP MCP servers and one in-process retriever, mediated by the module's bridge tools (`src/aila/modules/vr/tools/audit_mcp_bridge.py`, `ida_bridge.py`, `android_mcp_bridge.py`).

| Server | Port | Surface | Owner |
|---|---|---|---|
| **audit-mcp** | 18822 | 58 tools: source graph (Trailmark) + semantic search (semble) + SARIF correlation | source-code targets |
| **ida-headless-mcp** | 18821 | 81 tools: Hex-Rays + miasm + CAPA + symbolic / SMT (binbit) | binary targets |
| **android-mcp** | 18823 | 13 tool wrappers (apktool / jadx / androguard / MobSF / drozer / qark / AndroBugs / LIEF / YARA / apksigner / objection / frida / adb) + 4 composite handlers (`verify_capabilities`, `classify_behavior`, `compute_risk_score`, `find_secrets`) | Android APK targets |
| **semble** | embedded inside audit-mcp | Model2Vec + BM25 + RRF code-chunk retriever | semantic search backend |

The bridges sit between the LLM action layer and the HTTP transport. They are the only places in the VR module that touch the MCP servers. Behaviors that matter for the loop:

- **Schema-driven kwarg validation.** Each bridge fetches `GET /tools` once per process (TTL 300 s), parses every tool's JSON Schema, and rejects calls with unknown kwargs before paying the HTTP round-trip. The agent's "did you mean" error includes the live parameter list.
- **Per-action kwarg synonyms.** Common LLM aliases (`top_k` ↔ `limit` ↔ `max_results`; `max_depth` ↔ `depth`; `function_name` ↔ `name`) are normalized to each tool's canonical kwarg via `_kwarg_alias.py`. Both bridges share the same resolver and a small per-action override map.
- **Pending / poll pattern.** Heavy graph queries (`dead_code`, `unreachable_from_entrypoints`, `scan_and_correlate`) and IDA `analyze_binary` runs return `{status: "pending", task_id: ...}`. The bridge polls every few seconds for up to ~15 minutes. Callers see one synchronous result.
- **Circuit breaker + survey-streak pivot.** Repeated identical-shape failures (3-strike) and survey-tool streaks without a source read (3 consecutive `attack_surface` / `complexity_hotspots` / `fuzzing_targets` / `search_functions` without an intervening `read_function` / `decompile`) inject a hard "pivot" directive into the next prompt.
- **Language-aware tool suppression.** `dead_code` and `unreachable_from_entrypoints` are hidden from the prompt for C++, Java, Kotlin, C#, Swift, Objective-C, and Scala targets where the indexer's reach analysis is unreliable.
- **Lazy pre-warm fan-out.** When `AUDIT_MCP_WORKERS > 1` and a new `index_id` lands its first call, the bridge fires 16 cheap parallel requests so round-robin distribution warms each uvicorn worker's TypeResolver + semble + engine caches once. Skipped on `AUDIT_MCP_WORKERS=1` (the Windows reality).
- **`read_lines` — bridge-side virtual tool.** No upstream MCP endpoint. The bridge resolves `index_id → root_path` via `/tools/list_indexes` and slices the file from disk. Use when an indexer returned a stale or wrong slice (`read_function` returning a file header, `search_constants` returning 0) and you need verbatim source.
- **IDA mutations.** Mutating IDA tools (`rename_function`, `rename_variable`, `set_comment`, `set_function_type`, `patch_bytes`, `patch_cff`, ...) return a `ticket_id` and apply asynchronously; the bridge polls `poll_mutation` for completion.
- **android-mcp bridge — deliberately slim.** No schema-driven kwarg validation, no pre-warm fan-out, no kwarg alias map, no virtual tools. The five ingestion stages (`APK_DECODE` / `JADX_DECOMPILE` / `INDEX_DECOMPILED` / `STATIC_SUMMARY` / `MOBSF_SCAN`) call a small fixed set of actions with known parameters. Transport errors surface as `{"status": "error", "error": "..."}` so callers can branch on one uniform shape. `ANDROID_MCP_TIMEOUT` (default 1800 s) is the absolute network ceiling; the per-stage `StageTracker` timeouts in `services/stage_tracker.py` (APK_DECODE 600 s, JADX_DECOMPILE 900 s, INDEX_DECOMPILED 3600 s, STATIC_SUMMARY 300 s, MOBSF_SCAN 1800 s) are the actual per-stage budgets.

Operators and embedded harnesses can reach audit-mcp's HTTP API directly when they want a one-shot query (e.g. `mcp__audit_mcp_*` MCP tools exposed to outer agent harnesses). Inside AILA, the bridges are the canonical path — they carry the validation, dedup, pre-warm, and survey-streak logic the loop needs.

### Target ingestion stages

VR target onboarding runs through `aila.modules.vr.services.target_analysis.TargetAnalysisService.analyze()`, which routes by `TargetKind` to one of two staged pipelines. Each stage has its own row in the target's `analysis_stages_json` JSON (migration `060_vr_target_analysis_stages`) with `state`, `attempts`, `started_at`, `completed_at`, and `error`. Stages that don't apply to the target's kind are pre-marked `DONE` (skipped) so `roll_up_overall_state` can converge on `READY` without inventing a kind-aware rollup.

**Source-repo / binary pipeline** — every kind except `android_apk`: `source_repo`, `native_binary`, `apk` (legacy native APK kind routed to IDA), `ipa`, `jar`, `dotnet_assembly`, `kernel_image`, `kernel_module`, `hypervisor_image`, plus the descriptor-only kinds (`cve`, `protocol_capture`, `crash_input`, `patch_diff` — these pre-skip `INGESTION` via `_NO_INGEST_KINDS`):

| Stage | What runs |
|---|---|
| `INGESTION` | audit-mcp `clone_repo` + `index_codebase`, or IDA `open_binary`. Polls until ready. |
| `CAPABILITY_PROFILE` | semble warm-up + per-language tool catalog projection; populates the suppression set above |
| `FUNCTION_RANKING` | `fuzzing_targets` ranking with per-language thresholds; persists ranked function index for the agent prompt |

**Android-APK pipeline** — `android_apk` kind only (PRD §C-20):

| Stage | What runs |
|---|---|
| `APK_DECODE` | android-mcp `apktool_decode` — resource + AndroidManifest + smali decode. Persists `mcp_handles_json.android_mcp_decoded_dir`. |
| `JADX_DECOMPILE` | android-mcp `jadx_decompile` — dex-to-Java decompilation. Persists `mcp_handles_json.android_mcp_decompiled_dir`. |
| `INDEX_DECOMPILED` | audit-mcp `index_codebase(path=<decompiled_dir>, language="java")` over the jadx Java tree — polls until READY, then persists `mcp_handles_json.audit_mcp_decompiled_index_id` so VR personas auditing an APK get the same Trailmark / Semble surface (`semantic_search`, `callers_of`, `read_function`) they get against source-repo targets, rooted at the recovered Java methods. Soft-skips with `{"skipped": "no jadx output"}` when JADX_DECOMPILE produced no decompiled dir. |
| `STATIC_SUMMARY` | android-mcp `androguard_summary` — package name, permissions, intent filters, signing certs. Persists `mcp_handles_json.android_mcp_static_summary`; `android_mcp_package_name` surfaces in the target row for the UI's display label. |
| `MOBSF_SCAN` | android-mcp `mobsf_scan` — static-only MobSF scan. Gated on `MOBSF_API_KEY` on the AILA host; when unset the stage records `{"skipped": true}` and transitions `DONE` so the rollup still converges. Persists `mcp_handles_json.android_mcp_mobsf_scan`. |

`aila.modules.vr.services.stage_tracker` owns idempotency, `RUNNING`-timeout reaping (separate `aila.modules.vr.services.target_analysis` reaper), and serialized commits. Operator-driven resume:

```bash
curl -X POST http://localhost:8000/vr/targets/<target_id>/resume-analysis \
     -H "Authorization: Bearer $TOKEN"
```

Re-entrant: it picks up at the first non-`COMPLETED` stage and retries idempotently.

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
