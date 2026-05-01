# VR Module — Lessons from CMU SEI Pharos

What Pharos does, what's relevant to us, and how to integrate its concepts.

---

## What Pharos Actually Is

Pharos is a **static binary analysis framework** from CMU's CERT/CC. Not an LLM tool. Not a fuzzer. Not a vulnerability scanner. It's a set of C++ tools built on top of ROSE (a compiler infrastructure from Lawrence Livermore) that perform deep semantic analysis of x86 binaries.

Key tools:
- **OOAnalyzer** — recovers C++ class hierarchies, vtables, member layouts, inheritance from compiled binaries. Uses Prolog-based logic programming for reasoning about object relationships.
- **APIAnalyzer** — finds sequences of API calls with specific data/control flow relationships (e.g., "opens file, writes to it, closes it")
- **PathAnalyzer** — determines whether a path between two addresses is feasible using Z3 constraint solving
- **FN2Yara** — generates YARA signatures for function matching
- **FN2Hash** — generates function hashes for binary similarity analysis

Core library (`libpharos`) provides:
- Definition-use (def-use) analysis on binary instructions
- Control flow graph construction
- Stack pointer tracking
- Calling convention analysis
- Type detection and propagation
- Abstract interpretation via ROSE instruction semantics

---

## What's Relevant to Us

Pharos solves problems at a layer BELOW what IDA/Ghidra expose. IDA gives you decompiled pseudocode. Pharos gives you semantic understanding of binary behavior — def-use chains, object pointer tracking, path feasibility, API call sequences. These are exactly what the LLM needs but can't derive from pseudocode alone.

### Relevant Capability 1: Object-Oriented Recovery (OOAnalyzer)

**The problem it solves:** A stripped C++ binary. IDA decompiles it, but every object is `void *`, every method call is `call [eax+0x14]`, and you can't tell which functions belong to which class.

**What OOAnalyzer produces:**
- Class member layouts (offset -> type -> name)
- Method-to-class assignments (function X is a method of class Y)
- Virtual function table (vtable) recovery
- Inheritance hierarchy (class A inherits from class B)
- Constructor/destructor identification
- new() and delete() implementation detection

**Why this matters for VR:**
- **UAF detection:** If the module knows which functions are destructors and which free memory, it can identify use-after-free patterns: "object freed by destructor at 0x401200, pointer still used at 0x401350"
- **Type confusion:** Recovered vtables + inheritance reveal when a derived class pointer is cast to the wrong base class type
- **Exploit development:** Recovered object layouts tell you exactly what fields to corrupt for vtable hijacking. "Overwrite 4 bytes at offset +0x18 in a FooBar object to redirect the virtual call at 0x401500"

**How to integrate:**
OOAnalyzer is a standalone C++ tool that produces JSON output. The VR module can:
1. Run OOAnalyzer on the target binary via SSH on the research workstation
2. Parse the JSON into our data model (`VRClassRecovery`, `VRVtable`, `VRInheritance`)
3. Feed the recovered structure to the LLM as context alongside IDA's decompilation
4. The LLM now knows "this is MyClass::processInput(), it accesses member at offset +8 (char* buffer, 64 bytes), and the vtable is at offset +0"

### Relevant Capability 2: API Call Sequence Analysis (APIAnalyzer)

**The problem it solves:** Finding behavioral patterns across multiple API calls. Not just "does this binary call CreateFile" but "does this binary open a file, write attacker-controlled data to it, then execute the file?"

**What APIAnalyzer produces:**
- Sequences of API calls matching a pattern specification
- Data flow relationships between calls (output of call A flows to input of call B)
- Control flow relationships (call A happens before call B on some path)

**Why this matters for VR:**
- **Attack surface identification:** Find all code paths that go from "receive network input" to "write to memory" without validation between
- **Dangerous pattern detection:** "malloc -> user_controlled_memcpy -> no_bounds_check" pattern
- **Windows-specific:** IOCTL dispatch patterns, registry access sequences, privilege escalation paths

**How to integrate:**
Write pattern specifications (Pharos calls them "API signatures") for vulnerability-relevant sequences:
```
# Heap overflow pattern
pattern heap_overflow {
  call1: malloc(size) -> ptr
  call2: memcpy(ptr, src, count) where count > size
  constraint: no bounds check between call1 and call2
}

# TOCTOU file pattern  
pattern toctou_file {
  call1: access(path, mode)
  call2: open(path, flags) 
  constraint: path is same in both calls
  constraint: no atomic operation between check and use
}
```

The LLM doesn't write these patterns from scratch — it selects from a library of known dangerous patterns and adapts them to the target binary's API surface.

### Relevant Capability 3: Path Analysis with Z3 (PathAnalyzer)

**The problem it solves:** "Is the path from point A to point B in the binary actually feasible, or is it dead code behind an infeasible branch?"

**What PathAnalyzer does:**
- Collects branch constraints along a path (e.g., `x > 0 && x < 100 && y == x*2`)
- Feeds constraints to Z3 SMT solver
- Z3 says SAT (path is feasible, here are concrete input values) or UNSAT (path is impossible)

**Why this matters for VR:**
- **Reachability analysis:** "Can attacker-controlled input actually reach this vulnerable memcpy?" Not every code path from recv() to memcpy() is feasible. Branch conditions may make some paths impossible.
- **PoC construction:** Z3 can produce CONCRETE INPUT VALUES that trigger the vulnerable path. "To reach the overflow, send a packet where byte[4] > 0x80 and byte[8] == 0x42." This is the seed for a PoC.
- **Exploit constraint solving:** "What input values cause the heap allocation to be exactly 64 bytes, so the overflow corrupts the adjacent tcache metadata?" Z3 solves this.

**How to integrate:**
This is the most ambitious integration. Options:
1. **Run Pharos PathAnalyzer** on the research workstation (requires Pharos installed + ROSE). Parse output.
2. **Use angr instead** (Python-based, same concept, easier to integrate). angr does symbolic execution with Z3 and is pip-installable.
3. **Use Ghidra's PCode + Z3** via Ghidra Bridge for path constraint collection.

angr is the most practical choice for us — it's Python, it's pip-installable, it has an active community, and it does everything PathAnalyzer does plus more (symbolic execution, constraint solving, automatic exploit generation via its `angrop` module).

### Relevant Capability 4: Definition-Use Analysis

**The problem it solves:** For any instruction, what values does it read (use) and what values does it write (define)? And for any value, where was it defined and where is it used?

**Why this matters for VR:**
- **Taint tracking without execution:** Follow the data flow from input (recv, read, fread) through transformations to dangerous sinks (memcpy, free, function pointer write) without running the program.
- **Root cause from crash:** Given a crash at instruction X reading from address Y, trace backward: what instruction wrote to Y? What instruction computed the address? Where did the size come from?
- **Dead code identification:** Values that are defined but never used (or used but never from user input) can be deprioritized in the analysis.

**How to integrate:**
IDA Pro's decompiler does basic def-use internally, but it's not exposed as a queryable API. Options:
1. **IDA headless MCP extension:** Add a `trace_data_flow(address, direction="backward")` command that uses IDAPython's internal API to follow value definitions/uses
2. **angr's data flow analysis:** `angr.analyses.ReachingDefinitions` provides this on the binary directly
3. **Ghidra's PCode data flow:** Ghidra exposes def-use through its decompiler API

### Relevant Capability 5: Function Hashing and Similarity (FN2Hash, FN2Yara)

**The problem it solves:** "Have I seen this function before? Is this the same function as in the previous version? Is this function similar to a known vulnerable function?"

**Why this matters for VR:**
- **Patch diffing at function level:** Hash functions in v1 and v2, find which functions changed. Changed functions are where the patch is.
- **Known vulnerable function detection:** Build a database of hashed vulnerable functions (e.g., the exact copy of CVE-2024-1234's vulnerable function). Scan new binaries for matches.
- **Library identification:** "This binary statically links OpenSSL 1.1.1k" — identify by matching function hashes against known library builds.
- **Cross-binary variant search:** "This function has the same hash/structure as the vulnerable function in binary A. Binary B might have the same bug."

**How to integrate:**
FN2Hash produces multiple hash types per function (exact hash, mnemonic hash, PIC hash, etc.). We can:
1. Build a function hash database as part of binary recon
2. Compare hashes across binary versions (patch diffing)
3. Compare against a known-vulnerable function database
4. The LLM uses hash matches as evidence: "Function at 0x4012A0 matches the vulnerable function from CVE-2024-5678 with 94% similarity"

---

## What Pharos Does That We Should NOT Replicate

| Pharos Feature | Why we skip it |
|---|---|
| ROSE compiler infrastructure | Massive C++ dependency (months to build). IDA/Ghidra + angr give us equivalent capabilities without ROSE. |
| Prolog-based reasoning (OOAnalyzer) | Interesting academically but we use LLM reasoning instead. The LLM can reason about class hierarchies from decompiled code + OOAnalyzer JSON output without its own Prolog engine. |
| DumpMASM (disassembly listing) | IDA/Ghidra already do this better. |
| Custom build system | 50+ dependencies, Ubuntu-only, hours to compile. Not practical as a runtime dependency. |

---

## Practical Integration Strategy

Don't depend on Pharos directly. Use its **concepts** through tools that are already practical:

| Pharos Concept | Practical Tool | Integration |
|---|---|---|
| OO recovery | OOAnalyzer (run via Docker) or IDA's class recovery + LLM reasoning | SSH run on research workstation, parse JSON output |
| API sequence analysis | IDA xrefs + LLM pattern matching | IDA headless MCP queries, LLM reasons about the sequences |
| Path analysis / constraint solving | **angr** (pip install) | Python library, runs on research workstation, produces concrete inputs |
| Def-use analysis | angr ReachingDefinitions or IDA's internal API | Query via MCP or angr Python API |
| Function hashing | **ssdeep** / **TLSH** / IDA's FLIRT / BinExport | Lightweight tools, pip-installable, compare across versions |
| Binary similarity | **BinDiff** (IDA plugin) / **Diaphora** (IDA plugin) | Already in our tool matrix |

The key insight: **Pharos concepts are valuable. Pharos the tool is impractical as a dependency.** Use angr for symbolic execution + constraint solving, IDA for decompilation + xrefs, and the LLM for the reasoning that Pharos does in Prolog.

---

## What angr Gives Us That Pharos Concepts Need

angr is the practical vehicle for most Pharos-inspired analysis:

| Capability | angr API |
|---|---|
| Symbolic execution | `proj.factory.simulation_manager()` |
| Constraint solving (Z3) | `state.solver.eval()`, `state.solver.constraints` |
| Path feasibility | `simgr.explore(find=target, avoid=bad)` |
| Def-use / reaching definitions | `proj.analyses.ReachingDefinitions` |
| Control flow graph | `proj.analyses.CFG` |
| Call graph | `proj.analyses.CallGraph` |
| Taint analysis | `state.inspect` breakpoints with taint propagation |
| Auto-ROP | `angrop.ROP(proj)` — automatic ROP chain construction |
| Concrete input generation | `state.posix.dumps(0)` — input that reaches a target path |
| Binary loading (ELF/PE/MACH-O) | `angr.Project("binary")` |

angr is pip-installable, pure Python, actively maintained, and covers 90% of what Pharos does at the semantic analysis level. The 10% it misses (OO recovery depth, Prolog reasoning) is where the LLM fills in.

---

## Updated Tool Matrix for VR Module

Combining Metis inspirations + Pharos inspirations + existing plan:

| Layer | Tool | Role |
|---|---|---|
| **Disassembly / Decompilation** | IDA Pro (headless MCP) | Primary RE tool. Decompile, xrefs, type recovery, annotations. |
| | Ghidra (headless) | Fallback RE when IDA unavailable. Scripting via Ghidra Bridge. |
| **Semantic Binary Analysis** | angr | Symbolic execution, constraint solving, path feasibility, reaching definitions, auto-ROP. |
| **OO Recovery** | OOAnalyzer (Docker) | C++ class/vtable/inheritance recovery from binaries. |
| **Function Matching** | BinDiff / Diaphora | Patch diffing between binary versions. |
| | ssdeep / TLSH | Function-level similarity hashing. |
| **Source Analysis** | Tree-sitter | AST parsing for interpreted language targets. |
| | Semgrep / CodeQL | Pattern-based and flow-based source audit. |
| **Fuzzing** | AFL++ / WinAFL / libFuzzer / Jazzer / etc. | Coverage-guided fuzzing (full matrix in DECISIONS.md). |
| **Dynamic Instrumentation** | Frida / DynamoRIO / Intel PT | Runtime hooking, coverage, taint tracking. |
| **Debugging** | GDB + pwndbg / LLDB | Crash analysis, heap inspection, exploit development. |
| **Exploit Assistance** | angr's angrop | Automatic ROP gadget finding and chain construction. |
| | pwntools | Exploit scripting and payload generation. |
| **LLM Reasoning** | CyberReasoningEngine | Hypothesis generation, strategy selection, evidence evaluation, exploit design. |
| **Evidence Gating** | Obligation system (from Metis) | Prevent LLM from claiming things it hasn't proven. |
| **Context Management** | Bounded evidence packs (from Metis) | Limit what the LLM sees per turn, allow expansion on request. |
