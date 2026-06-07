# VR Module — IDA Headless MCP

A purpose-built MCP server for batch binary analysis. Not the interactive IDA MCP. This document explores the design space; it is not a spec.


> **Where this lives in code today.** The headless MCP exists. It ships as the `ida-headless-mcp` service alongside `audit-mcp`, exposes 81 tools over HTTP on port 18821, and is reached from the VR module exclusively through `src/aila/modules/vr/tools/ida_bridge.py`. The sections below remain the design rationale; concrete shape is in the bridge's tool catalogue (fetched via `GET /tools` and cached per process) plus the IDA mutation lifecycle described in §4. Mutating tools (`rename_function`, `rename_variable`, `set_comment`, `set_function_type`, `patch_bytes`, `patch_cff`, ...) return a `ticket_id` and the bridge polls `poll_mutation` until the IDB write has applied.
---

## Why a New MCP

There already is an "IDA MCP." The one shipped in the existing tool ecosystem (and the one most public examples reference) is **interactive**: a human opens a binary in IDA, navigates to a function, asks the assistant to explain it, asks for xrefs, asks to rename a variable. Each call is scoped to "the current function" or "the address the user is looking at," and the workflow assumes a person at the keyboard who already knows what's interesting.

VR doesn't work like that.

The VR loop looks like this:

```
LLM hypothesis: "Length-prefixed parsers in this binary likely have integer overflow bugs"
LLM action:    "Decompile every function that calls memcpy where one argument
                is computed from a length field read by recv/read/fread"
```

That is not an interactive question. It's a batch query against the entire binary, scoped by structural predicates the LLM constructs from its hypothesis. The LLM is **not pointing at a function** — it's asking "show me all functions that match this pattern, and rank them."

The interaction model differs along five axes:

| Axis | Interactive IDA MCP | Headless VR MCP |
|---|---|---|
| Driver | Human at keyboard | LLM in a reasoning loop |
| Scope | "current function" / "selected address" | Whole binary / cross-binary |
| Cardinality | One answer per call | Hundreds of functions per call |
| Lifetime | Session = one IDA window | Session = one project, possibly many binaries, multi-day |
| Side effects | User-visible annotations | Persistent annotations replayed across re-runs, plus outputs the LLM later cites as evidence |

The MCP we need is closer to a **binary database query engine** than an editor assistant. It happens to be backed by IDA's headless mode (`idat -A -S<script>`) but the surface is a structured RPC, not a UI proxy.

A second reason to build a new one: VR's evidence pack and obligation system want **deterministic, reproducible** outputs. The interactive MCP returns whatever IDA's UI happens to render at that moment, including IDA's session-local autoanalysis state. We need calls to be:

- Idempotent — the same call on the same `.i64`/`.idb` returns the same answer.
- Snapshot-friendly — the binary database can be serialized, archived, and reloaded.
- Auditable — every call's inputs and outputs are recordable so the obligation system can verify "function X *was* shown to the LLM at turn N."

The interactive MCP is fine for an analyst exploring a binary. It is the wrong tool for an LLM running 200 batch decompilation calls during a research session.

---

## Architecture (Sketch)

```
                Backend (AILA platform, FastAPI)
                       |
                       | SSH tunnel (existing platform.services.ssh)
                       v
                +-------------------------------+
                |  Research workstation         |
                |                               |
                |  +-------------------------+  |
                |  | ida_headless_mcp.py     |  |
                |  |  (HTTP+JSON or stdio)   |  |
                |  +-----------+-------------+  |
                |              | spawns/manages |
                |              v                |
                |  +-------------------------+  |
                |  | idat -A -S worker.idc   |  |
                |  | (one per active .i64)   |  |
                |  +-------------------------+  |
                |                               |
                |  Project dir: /vr/<proj>/     |
                |    binaries/  -> .bin files   |
                |    idb/       -> .i64 caches  |
                |    cache/     -> decomp cache |
                |    notes/     -> LLM output   |
                +-------------------------------+
```

Two things to settle:

1. **Where does the MCP live?** It is platform-shared (the malware module will also need it — see decision D-06). It belongs in `src/aila/platform/tools/ida_headless/` or as a separate process with the platform owning the client. Putting it inside the VR module would force the malware module to depend on `aila.modules.vulnerability_research`, which violates the ownership rule.

2. **One IDA process or many?** A long-lived IDA process per binary keeps the analysis database hot in RAM. A short-lived process per request is simpler but pays the autoanalysis cost (minutes for large binaries) every time. The realistic answer: one process per `(binary, project)` pair, kept warm for the project's lifetime, reaped on idle timeout.

---

## Command Set

The full API. Names and shapes are starting points, not final.

### Naming convention

Every command takes:

- `binary_id: str` — opaque handle returned by `analyze_binary`. The MCP maps this to an IDA project on disk. The LLM never sees absolute paths.
- `request_id: str` — UUID for tracing. The obligation system stores `(request_id, command, inputs, outputs)` so it can later prove that the LLM was actually shown a piece of evidence it cites.

Outputs are JSON. Large blobs (decompiled C, hex dumps) live as inline strings up to a configurable cap; beyond the cap they spill to `artifact://<id>` and the response carries a reference. The bounded-evidence-pack layer above this MCP is what enforces context limits — the MCP is happy to return 50,000 lines if asked, but the evidence pack builder is what trims and notifies the LLM that things were dropped.

### 1. Analysis commands

#### `analyze_binary(path)`

Loads a binary into IDA, runs full autoanalysis, returns a metadata snapshot. This is the only command that takes a filesystem path. The path is validated against the project root.

Returns:

```jsonc
{
  "binary_id": "b_8a4f...",                // handle for subsequent calls
  "format": "ELF64" | "PE64" | "MachO64" | "raw",
  "arch": "x86_64" | "aarch64" | "arm32" | "mips" | ...,
  "endian": "little" | "big",
  "entry_point": "0x401200",
  "sha256": "...",
  "size_bytes": 18234880,
  "compiler": { "id": "gcc", "version_guess": "11.x", "confidence": 0.7 },
  "linkage": "dynamic" | "static" | "mixed",
  "stripped": true,
  "debug_info": "none" | "stripped" | "dwarf" | "pdb",
  "mitigations": {
    "aslr_pie": true,
    "nx": true,
    "stack_canary": true,
    "relro": "full" | "partial" | "none",
    "fortify_source": true,
    "cfi": false,
    "shadow_stack": false,
    "cet_ibt": false,
    "mte": false,
    "control_flow_guard": false               // PE only
  },
  "sections": [
    { "name": ".text", "vaddr": "0x401000", "size": 0x80000, "perm": "r-x" },
    ...
  ],
  "imports_count": 184,
  "exports_count": 22,
  "functions_count": 4812,
  "strings_count": 27431,
  "packed_indicators": {
    "high_entropy_sections": [".upx0"],
    "tiny_text_section": false,
    "import_table_suspicious": false,
    "verdict": "likely_packed" | "likely_clean" | "indeterminate"
  }
}
```

Notes:

- The `mitigations` block is what the obligation system gates on. The LLM can never claim "no NX bypass needed" without a successful `analyze_binary` call returning `nx: false`.
- `packed_indicators.verdict == "likely_packed"` short-circuits — per D-02 the module bails out with "target appears packed, not yet supported." The MCP doesn't try to unpack.
- `compiler` is best-effort and the LLM is instructed to treat it as a hint, not a fact.

#### `decompile(binary_id, address_or_name, options)`

Single-function decompilation. Address or symbol name; either resolves through the function manager.

```jsonc
{
  "address": "0x4012a0",
  "name": "parse_packet_header",
  "size_bytes": 412,
  "complexity_cyclomatic": 14,
  "instruction_count": 138,
  "stack_frame_size": 0x40,
  "calling_convention": "sysv_amd64",
  "prototype": "int parse_packet_header(uint8_t *buf, size_t len, packet_t *out)",
  "pseudocode": "int parse_packet_header(uint8_t *buf, size_t len, packet_t *out)\n{\n    ...\n}",
  "pseudocode_truncated": false,
  "decompilation_status": "ok" | "partial" | "failed",
  "decompilation_error": null,
  "callers": ["0x401400", "0x401580"],
  "callees": [
    { "name": "memcpy", "address": "0x4011a0", "is_import": true },
    { "name": "validate_length", "address": "0x401260", "is_import": false }
  ],
  "string_refs": [
    { "address": "0x402100", "value": "invalid header magic", "from_insn": "0x4012b8" }
  ],
  "data_refs": [
    { "address": "0x603020", "name": "g_max_packet_size", "from_insn": "0x4012c4" }
  ]
}
```

- `options.include_pseudocode: bool = true` lets the LLM cheaply ask for "metadata only" when listing.
- `options.max_pseudocode_lines: int | None` — caller-side cap (still capped by MCP-side safety limit, e.g. 5000 lines).
- `options.with_microcode: bool = false` — return IDA's microcode (mba) representation for the obligation system to cross-check claims about specific operations. Heavy; off by default.

#### `batch_decompile(binary_id, filter, options)`

The headline VR command. Decompiles every function matching a structural filter, returns array of the same shape as `decompile`.

The `filter` DSL is the interesting design surface. It needs to express the LLM's actual hypotheses without becoming a query language the LLM has to learn from scratch. A starting shape:

```jsonc
{
  "name_pattern": "parse_*",                // glob over symbol names
  "callers_of": ["recv", "read", "fread"],  // functions that call any of these
  "called_by": ["main", "dispatch_*"],      // functions called by these
  "section": [".text"],
  "min_size_bytes": 64,
  "max_size_bytes": 8192,
  "min_complexity": 5,
  "max_complexity": null,
  "has_string_ref_matching": "(?i)error|invalid|overflow",
  "has_data_ref_to": ["g_config", "g_state"],
  "has_loop": true,
  "has_indirect_call": null,                // null = either; true/false = filter
  "imports_only": false,
  "exclude_libc_thunks": true
}
```

All fields combine with implicit AND. The LLM constructs filters that map directly to its hypothesis: "parsers reachable from network input" ≈ `callers_of: [recv, read, recvfrom]`. The MCP resolves these against IDA's xref database without decompiling the world.

`options` controls fan-out:

```jsonc
{
  "max_results": 100,                       // hard cap
  "order_by": "complexity_desc" | "size_desc" | "blast_radius_desc" | "name",
  "metadata_only": false,                   // skip pseudocode for listing
  "parallel_workers": 1                     // see "Performance" below
}
```

Crucially, `batch_decompile` returns a **truncation indicator**:

```jsonc
{
  "results": [...],
  "matched_total": 312,
  "returned": 100,
  "dropped": 212,
  "drop_reason": "max_results",
  "next_filter_hint": "Add 'min_complexity: 10' to narrow."
}
```

The bounded-evidence-pack layer surfaces this to the LLM as "212 additional functions matched but were excluded; refine your filter to see them."

#### `list_functions(binary_id, sort_by, filter, page)`

Lighter than `batch_decompile`. Returns metadata only (no pseudocode), paginates.

```jsonc
{
  "functions": [
    {
      "name": "parse_packet_header",
      "address": "0x4012a0",
      "size_bytes": 412,
      "complexity": 14,
      "callers_count": 3,
      "callees_count": 7,
      "string_refs_count": 4,
      "blast_radius_downstream": 87,
      "blast_radius_upstream": 14,
      "is_imported": false,
      "is_thunk": false,
      "is_library": false                     // FLIRT/Lumina match
    },
    ...
  ],
  "page": 0,
  "page_size": 200,
  "total": 4812
}
```

The `blast_radius_*` fields are computed once at `analyze_binary` time and cached. They mirror the Trailmark pattern from the source-side analysis — same concept, computed on the IDA call graph instead of a Tree-sitter graph.

#### `xrefs_to(binary_id, address)` and `xrefs_from(binary_id, address)`

```jsonc
{
  "address": "0x4012a0",
  "xrefs": [
    {
      "from_address": "0x401400",
      "from_function": "main",
      "type": "call" | "jmp" | "data_read" | "data_write" | "offset",
      "instruction": "call sub_4012A0"
    },
    ...
  ],
  "total": 14
}
```

`type` is the discriminator the LLM relies on. "Where is `g_max_packet_size` written?" requires `xrefs_to(...) -> filter where type == data_write`.

#### `call_graph(binary_id, function, depth, direction)`

```jsonc
{
  "root": "0x4012a0",
  "direction": "callees" | "callers" | "both",
  "depth": 3,
  "nodes": [
    { "address": "0x4012a0", "name": "parse_packet_header" },
    ...
  ],
  "edges": [
    { "from": "0x4012a0", "to": "0x4011a0", "type": "call", "indirect": false },
    ...
  ],
  "truncated_at_depth": false,
  "node_count_cap_hit": false
}
```

The cap matters. A `depth=10` call from `main` of a chromium-sized binary returns most of the binary. Default `depth=3`, hard ceiling 6, hard ceiling on node count (e.g. 5000) regardless of depth.

#### `data_refs(binary_id, function)`

All globals/strings/imports referenced from inside a function. Distinct from `string_refs` returned by `decompile` because it includes pointer-to-data references that aren't strings.

#### `strings(binary_id, filter)`

```jsonc
{
  "strings": [
    {
      "address": "0x402100",
      "value": "invalid header magic",
      "encoding": "ascii" | "utf16le" | "utf8" | "wide",
      "section": ".rodata",
      "xrefs_count": 2,
      "first_xref_function": "parse_packet_header"
    },
    ...
  ],
  "total": 12
}
```

`filter` accepts `regex`, `min_length`, `max_length`, `encoding`, `section`. Common LLM pattern: pull all strings matching `error|invalid|fail|overflow|too large|too long`, then xref each to find the validation paths.

#### `imports(binary_id)` and `exports(binary_id)`

```jsonc
// imports
{
  "imports": [
    { "name": "memcpy", "library": "libc.so.6", "address": "0x4011a0", "ordinal": null },
    { "name": "recv",   "library": "libc.so.6", "address": "0x401120", "ordinal": null },
    ...
  ],
  "total": 184,
  "by_library": { "libc.so.6": 142, "libssl.so.3": 22, "libcrypto.so.3": 20 }
}
```

The grouping by library is what the LLM needs to ask "is this binary using OpenSSL?" without knowing OpenSSL's exact import names.

#### `segments(binary_id)`

Same shape as `analyze_binary.sections` but more detailed (includes uninitialized BSS layout, IDA's segment classification, whether any segment is RWX).

#### `structs(binary_id, source)`

```jsonc
{
  "source": "ida_recovered" | "ida_user" | "ooanalyzer" | "dwarf",
  "structs": [
    {
      "name": "packet_t",
      "size": 0x40,
      "fields": [
        { "offset": 0x00, "name": "magic",    "type": "uint32_t" },
        { "offset": 0x04, "name": "length",   "type": "uint32_t" },
        { "offset": 0x08, "name": "payload",  "type": "uint8_t[56]" }
      ],
      "from_addresses": ["0x4012a0"]          // where this struct is used
    },
    ...
  ]
}
```

`source: "ooanalyzer"` triggers a Pharos OOAnalyzer pass (separate Docker invocation per the Pharos doc), which is expensive — only run on demand, cache aggressively.

### 2. Pattern search

#### `search_pattern(binary_id, pattern_type, pattern, options)`

This is where IDA decompilation meets the LLM's reasoning. The MCP exposes a small library of pre-baked patterns, plus a `custom_pattern` escape hatch.

Built-in pattern types:

| `pattern_type` | What it looks for | How |
|---|---|---|
| `dangerous_function` | Calls to `memcpy`, `strcpy`, `sprintf`, `gets`, `strcat`, `system`, `popen`, etc. without a preceding bounds check or validation function on the same path | Call graph + data flow on size argument |
| `unchecked_length` | Size value flows from input source (recv/read/fread/argv) to allocation/copy size without passing through a comparison | Reverse data flow on size args of allocators/copies |
| `signed_size` | A signed integer used as a size argument | IDA microcode type analysis |
| `integer_overflow_arith` | Multiplication or addition where neither operand is bounded, used as size | Arithmetic on values with unbounded provenance |
| `format_string` | `printf`/`fprintf`/`syslog` with non-literal format argument | Trivial AST predicate over decompiled output |
| `function_pointer_write` | Write to a memory location that's later used in indirect call | Cross-reference from data write to indirect call |
| `double_free` | Freed pointer not nulled, second free reachable | Reaching-definitions on `free` argument |
| `toctou` | `access`/`stat`/`lstat` followed by `open`/`fopen` on same path with no atomic operation | Pharos APIAnalyzer-style sequence |
| `command_injection` | `system`/`exec*`/`popen` with non-literal argument | Trivial after decompilation |
| `custom_pattern` | User/LLM-supplied regex (or AST-pattern, see below) over decompiled output | Run regex over `pseudocode` of every function in scope |

Two layers, on purpose:

- **Built-ins** are deterministic and the obligation system can cite them: "the LLM claims `parse_packet_header` has an unchecked length, and `search_pattern(unchecked_length)` confirmed it at instruction X." This is auditable.
- **`custom_pattern`** is the LLM's escape hatch when its hypothesis doesn't fit a built-in. Less trustworthy as evidence (regex over pseudocode is brittle) — the obligation layer should mark these findings as "weak evidence" until corroborated.

`options` for pattern search:

```jsonc
{
  "scope_filter": { /* same shape as batch_decompile filter */ },
  "max_matches": 200,
  "include_context_lines": 5,                 // pseudocode lines around match
  "require_reachable_from": null              // entrypoint address; only matches reachable from here
}
```

`require_reachable_from` is the integration with Trailmark-style taint thinking on the binary side: "show me dangerous_function calls reachable from `recv`."

#### `find_similar(binary_id, function, options)`

Function similarity. Multiple backends, the MCP picks one based on `options.method`:

| Method | Backend | Strength | Weakness |
|---|---|---|---|
| `flirt` | IDA FLIRT/Lumina | Exact-pattern signature match for known library functions | Only finds what FLIRT signatures cover |
| `bindiff` | BinDiff | Structural similarity across two binaries | Requires a reference binary |
| `fn2hash` | Pharos FN2Hash | Multiple hash flavors (exact, mnemonic, PIC) | Heavy dep, run via Docker |
| `tlsh` | TLSH locality hash on bytes | Cheap, language-agnostic | Coarse |
| `ssdeep` | ssdeep | Cheap | Very noisy |
| `embedding` | LLM embedding of decompiled pseudocode against a vector index | Semantic similarity, not structural | Requires the index to be built |

```jsonc
// query
{
  "binary_id": "b_8a4f...",
  "function": "0x4012a0",
  "method": "fn2hash",
  "against": "self" | "binary_id_other" | "vuln_db",
  "min_similarity": 0.80,
  "max_results": 20
}

// response
{
  "matches": [
    {
      "function": "0x401580",
      "name": "parse_extension_header",
      "similarity": 0.94,
      "explanation": "Same prologue, identical loop structure, differs in error handling"
    },
    ...
  ]
}
```

`against: "vuln_db"` is the long-term play — a project-wide database of hashed known-vulnerable functions, populated as the team works on N-day cases. Out of scope for v0.1 of the MCP but the API shape should not preclude it.

### 3. Diff commands

#### `diff_binary(binary_id_old, binary_id_new, options)`

Structural diff between two analyzed binaries. The interesting question is whether to wrap BinDiff (best-in-class but a paid IDA plugin) or Diaphora (free, written in Python, integrates as IDAPython, slightly less accurate).

```jsonc
{
  "tool": "bindiff" | "diaphora",
  "summary": {
    "functions_added": 12,
    "functions_removed": 4,
    "functions_changed": 87,
    "functions_unchanged": 4234,
    "match_confidence_avg": 0.93
  },
  "added": [
    { "name": "validate_extension_length", "address": "0x4019a0", "size_bytes": 124 }
  ],
  "removed": [
    { "name": "old_helper",  "address": "0x401180" }
  ],
  "changed": [
    {
      "name_old": "parse_extension",
      "name_new": "parse_extension",
      "address_old": "0x401580",
      "address_new": "0x4015a0",
      "similarity": 0.78,
      "instruction_delta": +14,
      "callers_changed": false,
      "callees_added": ["validate_extension_length"],
      "callees_removed": []
    }
  ]
}
```

For N-day work the LLM's first move is `diff_binary(pre_patch, post_patch)`, then `diff_function` on each `changed` entry, ranked by similarity (lower similarity = bigger change = likely the security fix).

#### `diff_function(binary_id_old, addr_old, binary_id_new, addr_new)`

Detailed per-function diff returning side-by-side decompiled output with structural alignment:

```jsonc
{
  "old": {
    "address": "0x401580",
    "pseudocode": "...",
    "complexity": 14
  },
  "new": {
    "address": "0x4015a0",
    "pseudocode": "...",
    "complexity": 17
  },
  "diff_unified": "@@ -45,6 +45,9 @@ ...",
  "added_calls": ["validate_extension_length"],
  "removed_calls": [],
  "added_strings": ["extension length too large"],
  "summary_signal": "added_validation"        // heuristic: bounds_check_added | error_path_added | call_replaced | logic_rewritten | unknown
}
```

`summary_signal` is a deterministic heuristic the obligation layer can use: if the LLM claims "the patch adds a length check," `summary_signal == "bounds_check_added"` is corroborating evidence.

### 4. Annotation commands

These mutate the IDB. They need to be persistent across sessions and reproducible (re-running the project re-applies annotations from the project's annotation log).

#### `rename_function(binary_id, address, name, source)`

`source` is one of `llm_inference`, `operator`, `recovered_from_string`, `flirt`. Stored in the annotation log so we can later filter "show me only operator-confirmed names."

#### `set_type(binary_id, address_or_var, type_string, source)`

Set a function prototype, a stack variable type, or a global variable type. `type_string` is C syntax (`int (*)(char *, size_t)`).

#### `add_comment(binary_id, address, comment, source, attaches_to)`

`attaches_to` is `"instruction" | "function" | "variable"`. The MCP also supports a `category` field (`finding`, `hypothesis`, `evidence`, `note`) so the VR module can filter comments back out: "show me all comments where `category == finding`."

#### `create_struct(binary_id, name, fields, apply_at)`

```jsonc
{
  "name": "packet_t",
  "fields": [
    { "offset": 0, "name": "magic",   "type": "uint32_t" },
    { "offset": 4, "name": "length",  "type": "uint32_t" },
    { "offset": 8, "name": "payload", "type": "uint8_t[56]" }
  ],
  "apply_at": [
    { "address": "0x4012a0", "var_name": "v3" }
  ]
}
```

The interesting question is whether the LLM should be allowed to mutate the IDB at all. Two arguments:

- **Yes**: Without struct recovery, the decompiled output is full of `*(uint32_t *)(v3 + 4)` instead of `pkt->length`. Subsequent `decompile` calls return cleaner pseudocode. Improves every later turn.
- **No**: Mutations are LLM-driven and may be wrong. A bad struct definition makes downstream decompilation worse, not better. The LLM then reasons about garbage.

A middle ground: annotations are written to a **shadow layer**, not the master IDB. The master IDB has the pristine analysis state. Each project has its own annotation log applied on load. If an annotation turns out wrong, it's reverted by editing the log. This also makes the "redo from scratch with a different LLM" experiment cheap.

---

## Performance and Scaling

This is the hard part.

### The 50K-function problem

Real targets — Chromium, V8, the Linux kernel, large game engines — have tens of thousands of functions. "Decompile all" is hours of CPU and gigabytes of RAM.

Strategies, each with its own tradeoffs:

**1. Lazy decompilation with persistent cache.**

The MCP maintains `cache/<binary_sha256>/decompile/<function_address>.json`. First call decompiles and writes the cache. Subsequent calls hit the cache.

```python
def decompile(binary_id, addr):
    cache_key = (binary_sha256(binary_id), addr)
    if cached := cache.get(cache_key):
        if cached.ida_version == current_ida_version:
            return cached
    result = ida_decompile(addr)
    cache.put(cache_key, result)
    return result
```

The cache invalidates on:
- IDA version change (decompiler output differs across major versions)
- IDB modification (annotation applied — but only if the annotation might affect this function's decomp output, which is most of them)
- Manual flush

**Cost:** Disk space (a 50K-function binary's full decompilation is ~500MB of text). Worth it.

**Risk:** Stale cache after annotations. Solvable by content-hashing the IDB's relevant subset, but that's nontrivial. Pragmatic answer: invalidate the cache whenever the annotation log changes, accept the re-decompilation cost.

**2. Filter-first, decompile-second.**

`batch_decompile` should never decompile to filter. Filters operate on cheap metadata (function size, callers, string refs) read from IDA's existing analysis. Only the filtered set is decompiled.

```python
def batch_decompile(filter, options):
    candidates = function_index.query(filter)         # O(matches), in-memory
    candidates = candidates[:options.max_results]
    return [decompile(addr) for addr in candidates]   # one call per match, hits cache
```

This relies on building an in-memory function index at `analyze_binary` time: name, address, size, complexity, callers, callees, string refs, data refs. ~1KB per function uncompressed. 50KB functions × 1KB = 50MB. Easily fits.

**3. Parallel IDA workers.**

For fully cold caches, parallelize. IDA Pro licenses are per-user; the workstation typically has one license. But:

- `idat` headless can spawn multiple processes if licensing allows (floating license, named-user with concurrent permission).
- Decompilation specifically uses Hex-Rays which has its own license — same concurrency story.

A safer parallelism: separate IDA processes for **separate binaries**. One project may have v2.3, v2.4, v2.5 of the same binary. Three IDA processes, one per binary, run concurrently. Inside one binary, decompilation is serial.

For non-decompilation operations (xref queries, listing functions, string extraction), IDAPython is mostly thread-safe within one process, so a single warm process can serve concurrent metadata queries.

**4. Memory pressure.**

IDA on a 200MB binary uses 4–8GB RAM for the database plus another 2–4GB during decompilation. Three concurrent processes is realistic only on a 32GB+ workstation.

The MCP needs:
- An IDA process pool with a memory budget. If a new project would exceed the budget, evict the least-recently-used IDA process (saves the IDB, kills the process, can rehydrate later).
- A per-process "max idle time" — kill processes that haven't seen a request in N minutes.
- Refuse to load binaries above a hard size limit (e.g. 1GB) without explicit operator override.

**5. Chunked output.**

A `batch_decompile` returning 200 functions × 200 lines of pseudocode is 40KB-200KB of text. The transport handles it. The LLM's evidence pack does not — but that's the evidence pack's problem, not the MCP's. The MCP returns what was asked; the layer above trims.

When pseudocode is large, prefer streaming over a single response. The MCP-over-stdio variant can stream JSON-lines; the HTTP variant uses chunked transfer. Either way, the client reads as available, the bounded-evidence-pack builder applies its caps as it goes.

### Concrete budget for v0.1

| Resource | Soft cap | Hard cap | Action on overflow |
|---|---|---|---|
| Concurrent IDA processes | 2 | 4 | Evict LRU |
| Idle process timeout | 15 min | — | Save + reap |
| Binary size | 200 MB | 1 GB | Refuse (operator override required) |
| Single decompile result lines | 2000 | 5000 | Truncate, mark `pseudocode_truncated: true` |
| `batch_decompile` results | 100 | 500 | Drop, return `dropped` count |
| Cache size per binary | 500 MB | 2 GB | LRU evict cache files |

These should be settings, not hardcoded.

---

## Output Format and Decompiler Failures

The output format above is JSON-only. Two things deserve separate treatment.

### Decompilation failures

Hex-Rays fails on real binaries. Common causes:

- Functions with tail calls into other functions IDA didn't identify
- Indirect jumps the analysis couldn't resolve
- Functions split across non-contiguous chunks
- Hand-crafted assembly (kernel entry stubs, exception handlers, vmenter-style code)
- Stack analysis confusion (variable-frame-size functions)

The MCP must **not** silently return junk pseudocode. The `decompile` response shapes failure explicitly:

```jsonc
{
  "decompilation_status": "failed",
  "decompilation_error": "Hex-Rays: stack analysis failed (sp delta inconsistent)",
  "pseudocode": null,
  "fallback": {
    "available": true,
    "kind": "disassembly",
    "instruction_count": 138,
    "asm": "..."                              // raw IDA disassembly
  }
}
```

```jsonc
{
  "decompilation_status": "partial",
  "decompilation_error": "Hex-Rays: indirect call at 0x4012b8 not resolved",
  "pseudocode": "... /* call partially decompiled */ ...",
  "pseudocode_truncated": false
}
```

The LLM's prompt explicitly handles `failed` and `partial`: "If decompilation status is 'failed', request disassembly via `disassemble(addr)`. Do not assume the function exists or behaves as you expect."

This is exactly the obligation system's territory: the LLM cannot cite "this function does X" when `decompilation_status == "failed"` and it never asked for disassembly.

### Other status signals

Beyond decompilation outcome, the response carries integrity hints:

- `is_thunk: true` — wraps another function. Decompiled output is misleading. LLM should follow the thunk.
- `is_library: true` — matched FLIRT/Lumina. Almost certainly not a target. Down-rank.
- `is_runtime_glue: true` — compiler-generated (e.g. `_init`, `_fini`, ctor sections). Not a real attack surface.
- `tail_calls: ["0x401400"]` — IDA detected tail calls. Pseudocode may be missing the destination's logic.

### How big is "big" pseudocode?

Empirically:

- Median function: 30–80 lines
- 90th percentile: 200–400 lines
- Pathological: 5000+ lines (parser dispatch tables, autogenerated state machines)

The MCP-side cap of 5000 lines per single function is high enough to almost never truncate real targets, low enough to refuse pathological cases. Truncation always sets the flag and surfaces to the bounded-evidence-pack layer.

---

## IDA vs Ghidra Fallback

Two reasons to need a fallback:

- IDA Pro license unavailable on the workstation
- Specific Hex-Rays decompiler unavailable (decompiler is a separate license)
- Binary IDA chokes on (rare arches, custom file formats)

The same MCP interface, different backend. Ghidra Bridge (Python from outside Ghidra into a running ghidraScript process) is the practical glue.

What's equivalent:

| Capability | IDA | Ghidra | Notes |
|---|---|---|---|
| Decompilation | Hex-Rays | Ghidra Decompiler | Quality comparable for most targets. Ghidra wins on some non-x86 architectures. |
| Disassembly | Yes | Yes | Equivalent. |
| Xrefs | Yes | Yes | Equivalent. |
| Function discovery | Yes | Yes | IDA tends to find more on stripped binaries; Ghidra catches up after manual analysis runs. |
| Strings | Yes | Yes | Equivalent. |
| Imports/exports | Yes | Yes | Equivalent. |
| Type recovery | Hex-Rays' type system | Ghidra's type DB | Different shapes; the MCP normalizes to a common JSON. |
| Microcode access | Hex-Rays microcode | Ghidra PCode | Different intermediate languages; the MCP exposes them as `ir_kind: "microcode" \| "pcode"` with separate parsers. |

What's lost:

- **FLIRT signatures** for library function recognition. Ghidra has its own (`fid` files) but the corpus is smaller and worse maintained for proprietary libraries (Visual Studio runtime versions, BoringSSL builds, etc.). Practical impact: more false-positive "interesting functions" that are actually libc.
- **Hex-Rays type recovery quality.** Hex-Rays guesses better at struct field types from access patterns. Ghidra is closer to literal "byte at offset 8."
- **Lumina**. IDA's cloud function database. Ghidra has nothing analogous.
- **BinDiff** (the original) is IDA-only. Diaphora works on both. Ghidra has its own version-tracking tools for diffing but they're awkward to drive headlessly.

What's the same:

- Decompilation quality on x86_64 ELF/PE for typical compiler output is comparable. If the LLM can't tell which tool produced the pseudocode by reading it, the difference doesn't matter.
- All metadata commands (xrefs, strings, imports, segments) are equivalent.
- Annotation persistence — both tools have project files; the MCP saves both as `.i64` or `.gzf` respectively.

The MCP advertises its backend in `analyze_binary` response (`backend: "ida_9.0" | "ghidra_11.1"`) so the LLM knows what it's looking at, and the obligation system can suppress checks that depend on backend-specific features.

**Decision shape:** the MCP picks the backend per binary based on a config flag plus availability. The LLM doesn't choose. The shared interface means downstream code is backend-agnostic. The 10–20% quality delta in decompilation output is acceptable as a fallback; for production VR work, IDA is preferred.

---

## Security

The MCP runs on the research workstation. The workstation is, by design, a place where untrusted binaries get loaded into reverse-engineering tools. So the threat model has two parts.

### Who can connect

Only the AILA backend, only over the existing platform SSH tunnel.

```
backend (cloud or on-prem)
    |
    SSH (key auth, key on the backend host)
    |
    workstation localhost:8765 (MCP HTTP, bound to 127.0.0.1)
```

The MCP server binds to localhost only. The SSH tunnel forwards backend → workstation:8765. The MCP refuses connections from any IP other than 127.0.0.1. There is no "MCP token" because the security boundary is the SSH key, not an in-MCP credential.

If the workstation is multi-tenant (multiple researchers), each tenant gets their own MCP process bound to a different localhost port and a different project root. The SSH user is the tenant identity.

### File path scoping

All path-accepting commands (`analyze_binary`, the artifact retrieval endpoints) validate paths against a configured project root.

```python
PROJECT_ROOT = Path("/vr/projects").resolve()

def validate_path(p: str) -> Path:
    abs_path = (PROJECT_ROOT / p).resolve()
    if not abs_path.is_relative_to(PROJECT_ROOT):
        raise PermissionError(f"path escapes project root: {p}")
    if not abs_path.exists():
        raise FileNotFoundError(p)
    return abs_path
```

The LLM sees `binary_id`, never absolute paths. It can ask `analyze_binary("acme/v2.3.0/server.bin")` but not `analyze_binary("/etc/shadow")`. Symlinks inside the project root are followed only if their resolved target is also inside the project root.

### What the MCP cannot do

The MCP is **read-only against the system** by design. It does not:

- Execute the analyzed binary. Ever. There is no `run` command. (Execution is a separate concern, handled by the Exploit Test Runner with its own sandboxing.)
- Read files outside the project root.
- Write files outside the project root.
- Open network sockets except its own listening port.
- Spawn subprocesses other than `idat` / `ghidraHeadless` against project files.
- Accept arbitrary IDC/Python scripts from the LLM. (See below.)

### LLM-supplied scripts: NO

The interactive IDA MCP often exposes "run this IDAPython snippet." The headless VR MCP **does not**. Reasons:

- IDAPython has full filesystem and process access. An LLM-generated script can `os.system`, exfiltrate data, write to `~/.ssh`, etc.
- LLM-generated code is not auditable in the way structured commands are. The obligation system can't reason about a 50-line Python blob.
- Every legitimate use case (custom xref queries, custom pattern matching) is expressible as a parameterized command. If a use case requires arbitrary IDAPython, it should become a new structured command in the MCP after a code review.

The `custom_pattern` command takes a **regex over decompiled output**, not a script. Regex is a much smaller surface than Python.

### The binary itself is hostile

The binary being analyzed may be malicious (especially in malware module use). IDA's autoanalysis on a malicious binary runs IDA's parser, not the binary itself. But:

- Malformed PE/ELF structures have caused parser bugs in IDA in the past. Disclosed CVEs in IDA are mostly parser issues.
- Embedded scripts (`.idc`, IDAPython files inside the IDB if a previous analyst saved them) are NOT auto-executed by `idat -A` — but are by `idat` with default flags. Use `-A` (autonomous, no UI prompts, no script auto-run).

The workstation should be a disposable VM. Snapshot before each project, restore on suspicious behavior. This is workstation-hardening, not MCP-hardening, but the MCP design assumes it.

### Annotation log integrity

Annotations are persistent state. If two backend processes write to the same project's annotation log concurrently, the log corrupts. The MCP serializes writes per-project. For multi-tenant case (different projects, different workstation users), there's no contention.

### Audit trail

Every command logs:

```jsonc
{
  "ts": "2026-04-30T18:43:21Z",
  "request_id": "...",
  "tenant": "alice",
  "binary_id": "b_8a4f...",
  "command": "batch_decompile",
  "args_hash": "sha256:...",
  "duration_ms": 3421,
  "result_hash": "sha256:...",
  "result_size_bytes": 412034
}
```

The obligation system reads this log to verify "the LLM was actually shown evidence X at turn N." The log itself is append-only and lives outside the project root (in `/vr/audit/`).

---

## Open Questions

1. **Backend selection: per-binary or per-project?** A single project may include both binaries IDA handles well and binaries Ghidra handles better (rare ARCH, weird format). Letting the backend be per-binary complicates the diff commands (`diff_binary` across two backends?). Letting it be per-project forces a worse decompilation on at least one binary. Lean toward per-binary with diff commands erroring on cross-backend diffs.

2. **Annotation ownership across LLM and operator.** When the LLM renames `sub_4012A0` to `parse_packet_header` and the operator later overrides it to `parse_request_header`, what happens on the next batch operation that calls `rename_function` against the same address? Last-write-wins is wrong because the LLM's writes are noisier. Operator wins is more defensible, but the LLM doesn't know the operator wrote anything. Maybe annotations have priorities (`source: operator` outranks `source: llm_inference`) and the MCP refuses LLM writes that would clobber an operator annotation.

3. **Cache invalidation on annotation changes.** If the LLM applies a struct definition that changes the decompilation output for 200 functions, do we invalidate the cache for all 200? Tracking which functions touch a struct is doable but non-trivial. The cheap answer (invalidate everything on annotation change) defeats the cache. The right answer probably involves IDA telling us which functions referenced the modified type.

4. **Custom pattern safety.** The `custom_pattern` regex runs over decompiled pseudocode. A pathological regex (catastrophic backtracking) could stall the MCP. Use `re2` instead of Python's `re`? Cap regex evaluation time per function?

5. **Streaming vs request-response.** Long `batch_decompile` calls block the LLM for tens of seconds. Streaming partial results lets the LLM start reasoning sooner. But streaming complicates the obligation system (what does it mean to "have been shown" half a result?). Probably worth it; needs careful semantics.

6. **Cross-binary symbols.** A finding in `libfoo.so` may need context from `libbar.so` that links to it. Does the MCP support cross-binary xrefs ("show callers of `libfoo:parse_packet` in any binary in this project")? The data is there (LD_NEEDED relationships, symbol versions); the API isn't designed for it yet.

7. **Microcode/PCode exposure to the LLM.** The microcode is precise but voluminous and hard to reason about. Currently shaped as `with_microcode: false` opt-in. Will the LLM ever actually use it, or is it write-only territory for the obligation system's deterministic checks?

8. **Hex-Rays version skew.** Decompiler output changes meaningfully across IDA versions. A project started on IDA 9.0 and resumed on IDA 9.1 may produce different pseudocode for the same function, invalidating cached evidence and obligation references. Pin the IDA version per project? Detect and warn? Re-verify all obligations on version change?

9. **OOAnalyzer integration depth.** OOAnalyzer's JSON output is rich (class hierarchies, vtables, member layouts). Mapping it onto the MCP's `structs` command loses information. Do we expose `oo_recovery(binary_id)` as a separate command with its own response shape, or shoehorn it into `structs`?

10. **Ghidra Bridge stability.** Ghidra Bridge is a community RPC bridge (Python ↔ Ghidra Jython). It's not maintained at the same cadence as Ghidra itself. For a fallback we depend on, that's a concern. Alternative: pyhidra (loads Ghidra into a CPython process). Both have failure modes. Need to pick one and own the risk.

11. **Binary upload flow.** "Operator drops a binary into the project" maps to filesystem path scoping. But how does it get there — operator SSHes the binary to the workstation, or the platform provides an upload endpoint that lands it in the right project root with the right ownership? Affects path scoping assumptions.

12. **Annotation export.** When a project finishes, we want the annotated IDB to be downloadable as an artifact (for sharing with the vendor, for the vulnerability advisory). What format? Raw `.i64` is IDA-licensed; `.gzf` is Ghidra. A neutral export (annotations as JSON + binary as blob) is portable but loses fidelity.
