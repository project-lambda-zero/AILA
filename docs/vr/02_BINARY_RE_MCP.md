# VR Module -- Binary Reverse-Engineering MCP Layer

Binary analysis is served by two native MCP servers. Both speak MCP
JSON-RPC over stdio; AILA spawns one child per process on demand, so
there is no standalone service, port, or upload step.

> **History.** This document replaces the archived ida-headless design
> doc. The ida-headless HTTP server (81 tools over HTTP on port 18821)
> is retired; its tool surface is preserved across the two servers
> below, with REA covering core decompilation/disassembly and the
> `reverser_belt` server covering everything REA lacks.

## Server 1: rea (rea-agents)

REA is the npm `rea-agents` package (morluto/rea) running its analysis
provider as a native MCP server. AILA pins the Ghidra provider.

- **Transport.** MCP stdio. One dedicated child per AILA process
  (backend, each worker); REA's HTTP listener serves one client with
  one shared active target, so a per-process stdio child avoids
  cross-process target thrash.
- **Spawn argv.** `REA_MCP_COMMAND` (shlex-split, forward slashes)
  overrides the spec default `rea mcp`
  (`src/aila/platform/mcp/server_specs.py`, `rea` entry;
  `stdio_command` in `src/aila/platform/mcp/factory.py:114`).
  `start.sh` exports working defaults alongside `GHIDRA_INSTALL_DIR`,
  `JAVA_HOME`, and `REA_ANALYSIS_PROVIDER=ghidra`.
- **Target binding.** `ReaMiddleware`
  (`src/aila/platform/mcp/middleware/rea.py`) guarantees every call
  runs with the binary named by the server-injected `target_path`
  (absolute local path) as the active target; the module's tool
  executor injects the kwarg and it is never exposed to the agent.

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

`upload_binary` is gone and REA has no `poll_analysis` / `list_binaries`:
REA opens by local path, so target setup is the `target_path` injection.

## Server 2: reverser_belt (external package)

`reverser_belt` is the standalone reverser-belt-mcp server (repository
`ida-headless-mcp-exp`, Python package `reverser_belt_mcp`): a FastMCP
server backed by the Kuna decompiler, LIEF, and the binbit SMT solver.
It is not part of the AILA source tree; the in-platform `re_analytics`
package was deleted. It owns every analytic REA lacks and keeps the
legacy tool names. The static fallback catalog
`REVERSER_BELT_TOOLS` (`src/aila/platform/mcp/adapters/known_tools.py:310`)
lists its 84 tools; the live `tools/list` is authoritative at runtime.

- **Transport.** MCP stdio, one child per AILA process, default argv
  `python -m reverser_belt_mcp.server` in the current interpreter
  (`src/aila/platform/mcp/server_specs.py:142`). The package must be
  importable in that interpreter (`pip install -e <checkout>`, see the
  `start.sh` comment block above the `REA_MCP_COMMAND` defaults; Kuna and
  angr must be installed). `REVERSER_BELT_MCP_COMMAND` overrides the argv;
  `REVERSER_BELT_MCP_URL` (or the `reverser_belt_mcp_url` config key) set
  to an http(s) URL targets a shared instance instead.
- **Target binding.** The server is handle-based: `open_binary(path)`
  returns a `binary_id` and every analysis tool takes it.
  `ReverserBeltMiddleware`
  (`src/aila/platform/mcp/middleware/reverser_belt.py`) opens the
  server-injected `target_path` once per path, rewrites each call to carry
  the `binary_id`, never forwards `target_path`, and re-polls calls that
  answer `pending` / `queued` / `running` within a bounded wall-clock
  budget (`REVERSER_BELT_PENDING_POLL_TIMEOUT`, default 240 s). The agent
  never supplies a path or id.
- **Timeout.** 900 s default (`ServerSpec.default_timeout`), sized for a
  cold Kuna decompile plus capa rule load on a large binary.

Tool groups in the catalog (not exhaustive): capability and
classification (`capa_scan`, `verify_capabilities`, `classify_behavior`,
`classify_strings`, `detect_anti_analysis`, `detect_dynamic_resolution`,
`detect_crypto_primitives`, `detect_obfuscation`); string and hash
recovery (`decrypt_function_strings`, `decrypt_binary_strings`,
`detect_stack_strings`, `resolve_api_hashes`, `trace_hash_xrefs`);
emulation and dataflow (`miasm_emulate`, `emulate_concrete`,
`interprocedural_taint`, `value_ranges`, `path_feasibility`,
`trace_dataflow`); SMT proofs (`prove_bounds_sufficient`,
`prove_equivalence`, `prove_overflow`, `prove_predicate_opaque`,
`assess_exploitability`); deobfuscation and patching (`deflat_function`,
`patch_cff`, `patch_assemble`, `patch_bytes`); diffing and similarity
(`diff_function`, `diff_binary`, `cross_binary_similarity`,
`find_similar_functions`); `generate_yara_rule`; and the Hex-Rays-style
reads and session mutations (`decompile`, `xrefs_to`, `rename_function`,
`set_comment`, and the rest of the catalog). Tool results are rendered by
the adapters in `src/aila/platform/mcp/adapters/reverser_belt.py`.

## Provenance

Every bridge call is recorded through the module `record_call` audit
context (`mcp_call_log` rows), giving the obligation system's rule
engine an append-only ground-truth log of exactly what ran, when, and
against which binary. The LLM's cited provenance is cross-referenced
against this log; mismatches raise `ProvenanceMismatch`.
