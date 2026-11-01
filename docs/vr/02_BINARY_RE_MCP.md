# VR Module -- Binary Reverse-Engineering MCP Layer

Binary analysis is served by two native MCP servers. Both speak MCP
JSON-RPC over stdio; AILA spawns one child per process on demand, so
there is no standalone service, port, or upload step.

> **History.** This document replaces the archived ida-headless design
> doc. The ida-headless HTTP server (81 tools over HTTP on port 18821)
> is retired; its tool surface is preserved across the two servers
> below, with REA covering core decompilation/disassembly and the
> in-tree `re_analytics` server covering everything REA lacks.

## Server 1: rea (rea-agents)

REA is the npm `rea-agents` package (morluto/rea) running its analysis
provider as a native MCP server. AILA pins the Ghidra provider.

- **Transport.** MCP stdio. One dedicated child per AILA process
  (backend, each worker); REA's HTTP listener serves one client with
  one shared active target, so a per-process stdio child avoids
  cross-process target thrash.
- **Spawn argv.** `REA_MCP_COMMAND` (shlex-split, forward slashes)
  overrides the spec default. `start.sh` exports working defaults
  alongside `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, and
  `REA_ANALYSIS_PROVIDER=ghidra`.
- **Target binding.** `ReaMiddleware` opens the binary named by the
  server-injected `target_path` kwarg (absolute local path) before
  every call; the kwarg is consumed server-side and never forwarded.

Tool mapping from the retired ida-headless names:

| ida-headless | rea |
|---|---|
| `decompile` / `decompile_function` | `procedure_pseudo_code` |
| `disassemble_function` | `procedure_assembly` |
| `xrefs_to` | `xrefs` / `procedure_callers` |
| `xrefs_from` | `procedure_callees` / `procedure_references` |
| `list_functions` | `list_procedures` |
| `list_strings` | `list_strings` |
| `search_pattern` | `search_bytes` |
| `imports` | `inspect_pe_imports` |
| `exports` | `inspect_native_exports` |
| `segments` | `list_segments` |
| `binary_metadata` / `binary_survey` | `binary_overview` |
| `read_memory` | `read_bytes` |
| `build_call_tree` | `get_call_graph` |
| `entropy_analysis` | `inspect_byte_entropy` |
| `stack_frame` | `procedure_info` |
| `open_binary` | `open_binary` |

`upload_binary` / `poll_analysis` / `list_binaries` are gone: REA opens
by local path, so target setup is the `target_path` injection.

## Server 2: re_analytics (in-tree)

`src/aila/platform/re_analytics` -- an AILA-owned MCP stdio server
(`python -m aila.platform.re_analytics`) preserving every ida-headless
tool REA does not provide, under the SAME tool names and argument
names. Every tool takes `target_path` (absolute local binary path)
instead of the retired binary id.

Groups:

- `tools_capability.py` -- `capa_scan`, `verify_capabilities`,
  `classify_behavior`, `classify_strings`, `detect_anti_analysis`,
  `detect_dynamic_resolution`, `detect_crypto_primitives`,
  `find_crypto_constants`, `resolve_api_hashes`, `trace_hash_xrefs`,
  `decrypt_function_strings`, `find_api_call_sites`, `checksec`,
  `entropy_analysis`.
- `tools_crypto.py` -- crypto-constant tables, API-hash resolution
  (ror13, crc32, djb2, fnv1a over a bundled export-name list).
- `tools_dataflow.py` -- `miasm_emulate`, `emulate_concrete`,
  `interprocedural_taint`, `value_ranges`, `path_feasibility`,
  `assess_exploitability`, `cross_binary_similarity`,
  `patch_assemble`, `recover_class_hierarchy`,
  `detect_protocol_state_machine`, `pseudocode_slice_view`.

Backed by real libraries (lief/pefile, capstone, flare-capa, unicorn,
keystone; miasm optional). Results carry an honest `limitations` field
where the analysis is intra-procedural or heuristic. A missing optional
dependency returns `isError` with an install hint, never a fabricated
result.

## Provenance

Every bridge call is recorded through the module `record_call` audit
context (`mcp_call_log` rows), giving the obligation system's rule
engine an append-only ground-truth log of exactly what ran, when, and
against which binary. The LLM's cited provenance is cross-referenced
against this log; mismatches raise `ProvenanceMismatch`.
