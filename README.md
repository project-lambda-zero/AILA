<p align="center">
  <img src="assets/aila-logo.svg" alt="AILA monogram" width="160" />
</p>

# AILA -- AI Lab Assistant

Modular AI security platform with pluggable analysis modules: a Python core
exposing a Typer CLI and a FastAPI REST API, backed by PostgreSQL with pgvector
and an ARQ/Redis task queue, paired with a React + Vite + TypeScript frontend.

## Architecture Overview

```
+-------------------------------------------------------------+
|                     Frontend (frontend/)                    |
|              React 19 + Vite + TypeScript shell             |
|        Module UIs mounted from modules/<id>/frontend/       |
+----------------------------+--------------------------------+
                             |  HTTP / SSE / JWT
+----------------------------v--------------------------------+
|                    API (src/aila/api/)                      |
|   FastAPI app with 29 platform routers + module-contributed |
|              routers, JWT auth, RBAC,                       |
|              SSE event streams, OpenAPI at /docs            |
+----------------------------+--------------------------------+
                             |
        +--------------------+--------------------+
        |                                         |
+-------v-------------+                  +--------v-----------+
|  Platform           |                  |  Modules           |
|  src/aila/platform/ |                  |  src/aila/modules/ |
|                     |                  |                    |
|  routing/           |                  |  forensics/        |
|  runtime/           | <-- ModuleProto. |  hello_world/      |
|  services/          |     contracts -> |  vr/               |
|  contracts/         |                  |  vulnerability/    |
|  tools/             |                  |                    |
|  llm/               |                  |                    |
|  tasks/   (ARQ)     |                  |  Each module owns  |
|  workflows/         |                  |  its own runtime,  |
|  sse/               |                  |  tools, workflow,  |
|  events/            |                  |  contracts, API    |
|  automation/        |                  |  router, frontend, |
|  config.py, uow.py  |                  |  and DB models.    |
|                     |                  |                    |
|                     |                  |  See docs/vr/ for  |
|                     |                  |  the VR engine +   |
|                     |                  |  MCP architecture. |
|                     |                  |                    |
+----+-------------+--+                  +---------+----------+
     |             |                               |
+----v---+   +-----v------+                +-------v---------+
| Redis  |   | PostgreSQL |                | Per-module ARQ  |
| ARQ    |   | SQLModel + |                | queue tracks:   |
| queues |   | Alembic +  |                | default, vr,    |
|        |   | pgvector   |                | vulnerability,  |
+--------+   +------------+                | forensics       |
             src/aila/storage/             |                 |
                                           +-----------------+
```

**Layer responsibilities**

- **Platform** (`src/aila/platform/`) -- routing, runtime construction,
  shared services, module/tool contracts, LLM client and pipelines, ARQ task
  registration, workflow engine, SSE bus. Never imports from a feature module.
- **Modules** (`src/aila/modules/`) -- domain logic. Each module is a
  self-contained package implementing `ModuleProtocol`. One module never
  imports from another. Layout is fixed by `docs/MODULE_STANDARD.md`.
  Current modules: `vulnerability` (CVE/CWE scanning + intel),
  `forensics` (DFIR investigations), `vr` (vulnerability research --
  graph-aware audit, fuzz campaign proposals, enterprise PDF reports,
  exploit/PoC writer agent), `malware` (sample-centric reverse
  engineering over ida-headless-mcp-exp), and the `hello_world`
  reference module.
- **API** (`src/aila/api/`) -- FastAPI application (`aila.api.app:app`).
  Modules contribute additional routers via `api_router.py`.
- **Frontend** (`frontend/`) -- top-level Vite + React + TypeScript shell.
  Module UIs live under `src/aila/modules/<id>/frontend/` and are mounted by
  the shell through the frontend module spec. Managed as a **pnpm
  workspace** at the repo root.
- **Storage** (`src/aila/storage/`) -- SQLModel models, Alembic migrations,
  config registry, secret store. Vector search uses pgvector with
  384-dimensional embeddings.
- **Task queue** -- ARQ on Redis, with per-module queue tracks (default,
  vulnerability, forensics, vr) so long-running jobs don't
  starve each other.

For deeper detail see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Agent reasoning loop -- think / hypothesize / act / observe

Every reasoning module in AILA (vr, malware, anything future that
holds a multi-turn LLM conversation against an MCP backend) runs the
same four-phase loop driven by the platform's reasoning engine
(`src/aila/platform/services/reasoning.py`). Personas differ, tool
surfaces differ, terminal outcome kinds differ -- the loop does not.

```
            +----------------------------------+
            |        case_state.observables    |
            |  prior tool readings + directives|
            |  + agent scratchpad (capped)     |
            +-----------------+----------------+
                              |
                              v
   +---------+         +------+-------+        +--------+
   |  THINK  |-------->|  HYPOTHESIZE |------->|  ACT   |
   | persona |  reads  |  produce or  | emits  | tool_  |
   | prompt  |  state  |  refine list |  one   | run    |
   | + state |         |  with claim, |  action| OR     |
   |         |         |  why_plaus., |        | submit |
   |         |         |  kill_crit.  |        | OR text|
   +---------+         +--------------+        +----+---+
        ^                                            |
        |                                            |
        +-------------- OBSERVE ---------------------+
               tool result -> observables_delta
                          merged into case_state
```

**Think.** Each turn, one persona (researcher / critic / implementer)
receives the system prompt + persona prompt + the current
`case_state` projection. The case_state carries every prior tool
reading the platform decided was worth keeping in attention (tool
observables capped at the last 80, agent scratchpad capped at 15),
plus directives the auto-steering pipeline injected.

**Hypothesize.** The persona's output is a structured envelope
carrying a hypothesis list. Each hypothesis is a triple of
`{claim, why_plausible, kill_criterion}` -- the kill_criterion is the
specific evidence that would refute it. Hypotheses persist across
turns and accumulate state (`live` / `rejected` / `resolved`); the
rejection reason and resolution note travel with them. The frontend
renders the live + rejected + resolved aggregate per investigation
so the operator sees the deliberation drift in real time.

**Act.** The same envelope emits exactly one action: a
`tool_run` (dispatch one MCP tool call), a `submit` of a terminal
outcome (AnalysisReport, FindingDraft, TriageVerdict, ...), or a
text-only deliberation turn that updates hypotheses without
external action. The executor dispatches tool_runs through the
module's MCP bridge layer (which adds defenses: auto-poll on
pending, kwarg coercion, alias maps, address-format coercion --
see VR / Malware sections below).

**Observe.** The tool response flows through a per-adapter pass
that shapes the response into an `observables_delta` (key-value
pairs the next turn will see) plus a durable observation row in
the module's observation table (cross-investigation memory, kind +
polarity tagged). The case_state merges the delta; the renderer
decides which observables make it back into the next prompt under
the attention cap.

**Multi-persona adversarial discipline.** The reasoning module's
branch manager spawns multiple personas in parallel against the
same investigation. Each branch holds its own case_state. The
platform's deliberation broker surfaces rejection signal across
branches (a hypothesis rejected by 2+ siblings becomes a
`sibling_consensus_rejection` directive on the still-live branch).
Claim verifier promotes evidence reaching a confidence floor;
synth assembles the final outcome from the converged claims.

The pattern is what lets two very different modules (source-level
vulnerability hunting vs binary malware reverse engineering) share
the same engine + the same operator UI + the same observation
memory abstraction. Adding a third reasoning module is mostly
writing prompts + an MCP bridge + an outcome contract; the loop
is already there.

## VR Engine and MCP Architecture

The vulnerability research module (`vr`) drives a multi-MCP backend with
graph-aware code intelligence, semantic search, and binary analysis. Three
MCP servers run alongside AILA, exposed over HTTP and orchestrated by the
platform's task queue.

```
  +-------------------------------------------------------------+
  |                  AILA backend (Python + ARQ)                |
  |  agent loop -> tool_executor -> bridge tools -> MCP servers |
  +----+--------------------+--------------------+--------------+
       |                    |                    |
  +----v-----+      +-------v--------+    +------v---------+
  | audit-   |      | ida-headless-  |    | semble         |
  | mcp      |      | mcp            |    | (embedded in   |
  | 18822    |      | 18821          |    |  audit-mcp)    |
  +----------+      +----------------+    +----------------+
  trailmark        Hex-Rays + miasm     Model2Vec + BM25
  graph engine     binary engine        chunk retrieval
  + GPU CSR        + 81 tools
  + 58 tools
```

### audit-mcp -- source-code intelligence

- **Tool surface:** 58 tools over HTTP (`/tools` for catalog, `/tools/<name>` for invocation)
- **Graph engine:** trailmark builds a call graph + symbol table on `index_codebase`. Per-index cached on disk via `DurableIndexStore`, recovered automatically on restart.
- **GPU acceleration:** `from_trailmark()` constructs a GPU CSR adjacency matrix when CUDA is present; powers `attack_surface`, `fuzzing_targets`, `unreachable_from_entrypoints` on monorepo-scale graphs.
- **Semantic search via semble:**
  - Hybrid Model2Vec (potion-code-16M) embeddings + BM25 + RRF + code-aware reranker
  - Per-index lazy build in a **separate Python process** so the parent's GIL stays free during cold builds
  - Pickled to `~/.audit-mcp/semble-cache/<index_id>.pkl` after first build -- subsequent restarts load in ~9s instead of rebuilding
  - Tools: `semantic_search(query, top_k, alpha, rerank, filter_*)`, `find_related(file, line, top_k)`, `semble_stats(index_id)`
- **Read-function fast path:** `read_function` queries the semble chunk index first (matches by name + definition pattern); falls back to a process-cached `TypeResolver` instead of rebuilding it per call (was the source of 15-minute hangs on firefox-scale).
- **Multi-worker support:** `AUDIT_MCP_WORKERS` env / `--workers` CLI flag. Each worker holds its own engine + semble + TypeResolver caches; AILA's bridge pre-warms all workers on the first call to a new `index_id` (Linux/macOS only -- Windows uvicorn multi-worker is broken).

### ida-headless-mcp -- binary intelligence

- **Tool surface:** 81 tools over HTTP (`/tools` catalog)
- **Engines:** Hex-Rays decompiler + miasm IR for control-flow obfuscation, CFF deflattening, symbolic execution, CAPA behavioral rule scanning
- **Mutations:** Renames, comments, prototypes, and assembly patches are queued through `ida_headless/poll_mutation` so concurrent operator + agent edits don't race
- **Specialised tools:** GPU-backed call graph traversal, opaque-predicate proving via SMT, structural binary diffing, exploitability assessment (`assess_exploitability`, `prove_overflow`, `prove_bounds_sufficient`)

### Agent loop and reliability

The VR module runs adversarial 3-persona deliberation (researcher / critic / synthesizer) over the MCP tool surface. Each tool call goes through `AuditMcpBridgeTool` (or its IDA equivalent) which provides:

- **Schema-driven kwarg validation** -- catches LLM-hallucinated parameters (e.g. `fuzzing_targets(threshold=...)`) before the HTTP round-trip and returns a structured "did you mean" error so the next turn self-corrects
- **Per-action kwarg synonyms** -- transparently rewrites common aliases (`top_n` -> `limit`, `cutoff` -> `min_complexity`, etc.) per tool's actual signature
- **Circuit breaker** -- counts repeated failures by both `(server, tool, args)` AND `(server, tool, error_class)` so the agent can't burn turns varying the value of a bad kwarg name; injects a hard pivot directive after 3 consecutive failures
- **Survey-streak pivot** -- after 3 consecutive survey-tool calls (`attack_surface`, `complexity_hotspots`, `fuzzing_targets`, ...) without a source read, forces the agent into `read_function` / `taint_paths_to` / `callers_of` or a finding submission
- **Language-aware tool suppression** -- hides `dead_code` and `unreachable_from_entrypoints` from agents running against C++/Java/Kotlin/C#/Swift/Objective-C/Scala targets (static call graphs are blind to vtable + template dispatch on those languages)
- **Pending/poll pattern** -- heavy operations like `fuzzing_targets` on firefox return `status=pending + task_id`; the bridge polls `poll_task` for up to ~15 min so AILA's 900s HTTP timeout doesn't kill long graph queries
- **Lazy pre-warm fan-out** -- first call to a new `index_id` fires 16 parallel `summary` + `semble_stats` requests so every uvicorn worker warms its caches before the agent's real query lands

### Per-stage target analysis (durable)

Target ingestion is split into three independently-tracked stages with per-stage status, attempts counter, and reaper:

- `INGESTION` -- audit_mcp `index_codebase` clone + parse (timeout 14400s)
- `CAPABILITY_PROFILE` -- D-51 capability rule evaluation (timeout 1800s)
- `FUNCTION_RANKING` -- `fuzzing_targets` ranking with GPU CSR (timeout 1800s)

Operator can resume a stuck target via `POST /vr/targets/{id}/resume-analysis`; the endpoint fans out per non-DONE stage. Reaper runs every minute via ARQ cron, flips RUNNING stages past their timeout to FAILED with `"reaper: RUNNING for Xs > Ys timeout"`.

### Statistics (current deployment)

| Measurement | Value |
|---|---|
| audit-mcp tools available | **58** (incl. 3 semble tools, 8 graph tools, 7 specialised search, 5 deep-audit, etc.) |
| ida-headless-mcp tools | **81** |
| Trailmark graph -- nginx | ~10k functions, ~100k call edges |
| Trailmark graph -- firefox | **742,335 functions, 5M+ call edges** |
| Semble index -- nginx | 16 MB pickle, ~250ms cold build |
| Semble index -- openjpeg | 26 MB pickle, ~3s cold build |
| Semble index -- firefox | **3.4 GB pickle, ~85 min cold build, ~9s warm restore** |
| Semble chunks -- firefox | 700k+ across 17 languages (cpp 234k, c 221k, js 425k, rust 165k, ...) |
| Read-function on firefox | 15+ min hang **->** ~30s first call + cached, <100ms subsequent |
| Semantic search latency | ~250ms (nginx) / ~5ms in-process, ~200ms via MCP HTTP |
| Cold start (3 indexes recovered) | ~30s including all semble pickle loads |

### Bug-fix scorecard (recent)

| Issue | Fix |
|---|---|
| firefox `read_function` 15-min hang | TypeResolver cached on `IndexEntry`; reused across calls (`audit-mcp d091d94`) |
| audit-mcp full-server hang during semble build | Cold builds moved to a separate Python process (`audit-mcp 13dc2d6`) |
| `attack_surface` returning 0 entries on every call | Adapter was looking up wrong response key (`surfaces` vs actual `entrypoints`); fixed (`AILA ec1b4f3`) |
| `fuzzing_targets(threshold=...)` infinite loop | Per-action kwarg synonyms (was: global map rewrote correct `min_complexity` -> broken `threshold`) (`AILA ef1ca59`) |
| Agent surveying 10+ turns without reading source | Survey-streak pivot circuit breaker (`AILA b8aa54f`) |
| firefox classified as `python` (trailmark iteration order) | Byte-weighted language detection by walking `mcp_path` ourselves (`AILA c29d82b`) |
| Module-side Tailwind classes had no CSS | Explicit `@source` directives in `globals.css` for every module path (`AILA 02ef955`) |

For day-to-day MCP operations and the full VR agent design see [docs/vr/](docs/vr/).

## Malware Module

The `malware` module ports the VR adversarial-deliberation pattern
onto sample-centric reverse engineering. Same multi-persona loop
(halvar / noor researchers, maddie / yuki critics, renzo / wei
implementers), same SSE-streamed timeline, same observation memory --
but every tool dispatch is constrained to `ida-headless-mcp-exp`
only. `audit_mcp` and `android_mcp` are explicitly hidden from the
agent-facing catalog and rejected at the executor's allowlist
(backend services like the claim verifier still construct their own
bridge instances).

### Pipeline

```
sample upload
      |
      v
target_analysis stages (Alembic-tracked, per-stage durable)
   open_binary -> auto_analysis -> string_classification
      |
      v
investigation kinds:
   triage | full_analysis | unpack_only | config_extract
      | yara_generate | family_attribute
      |
      v
multi-persona reasoning loop:
   investigation_setup -> investigation_loop -> investigation_emit
      |
      v
outcomes:
   ANALYSIS_REPORT | TRIAGE_VERDICT | UNPACK_ARTIFACT
      | CONFIG_BLOB | YARA_RULE_DRAFT | FAMILY_ATTRIBUTION
      | FINDING | OUTCOME_REVIEW
```

### Tool surface (ida-headless-mcp-exp only)

The agent dispatches exclusively against `ida-headless-mcp-exp`
running on port `18821`. The bridge layer
(`platform/mcp/bridges/ida_headless.py`) adds nine defenses on top
of the raw catalog so the agent's habits don't cost turns:

- **Auto-poll on `status: pending`** -- bridge sleeps + re-POSTs the
  same call (2s -> 3s -> 4.5s -> 8s capped) until the per-call
  async work lands ready or the 240s budget runs out. `poll_analysis`
  itself is the only excluded action.
- **Dead-arbiter fail-fast** -- when the ida-headless response shape
  matches the dead-worker signature (`status=pending` +
  `worker_phase` in `{exiting_idle, crashed, ""}` +
  `heartbeat_age_s >= 600`), the bridge skips the 240s poll and
  returns a structured `dead_worker_diagnostic` error naming the SHA,
  heartbeat age, queue depth, and the exact operator action
  (restart ida-headless, clear `crash_counts.json`, re-upload to
  force fresh analysis). Threshold override:
  `IDA_HEADLESS_DEAD_WORKER_HEARTBEAT_S`.
- **Per-call dedup** -- identical `(action, sorted_kwargs)` within
  `IDA_HEADLESS_DEDUP_TTL_S` (default 300s) replays the cached
  ready payload. Scoped to 23 read-only actions (xrefs_to/from,
  decompile, find_api_call_sites, callers_of, build_call_tree,
  list_strings/functions, capa_scan, detect_crypto_primitives,
  etc.). State mutators (open_binary, upload, patch_assemble) and
  freshness-sensitive (poll_analysis) are excluded. Cached hits
  stamp `_ida_bridge_dedup: hit` so the executor can distinguish
  replay from fresh. Per-call bypass: pass `_ida_bridge_no_dedup=True`.
- **IDA auto-name -> hex coercion** -- 17 address-shaped kwargs across
  the 81-tool catalog rewrite `sub_<hex>` / `loc_<hex>` /
  `unk_<hex>` to `0x<hex>` before dispatch. `avoid_addresses`
  (list) gets per-element rewriting.
- **`encoding` value alias** -- the string-family tools
  (`list_strings`, `get_string_at`) accept `utf16` / `utf-16` /
  `utf-16le` / `utf16-le` as aliases for the canonical `utf16le`.
  Closes the round-trip with the same-named label the server emits
  under `by_encoding`; an agent passing back the value it just read
  from `count_only` no longer falls into a `total=0` false negative.
- **Pagination-noise drop** -- `offset` / `limit` / `cursor` /
  `top_k` get silently stripped when the target tool doesn't declare
  them, so snapshot tools no longer TypeError on agent habits.
- **`search_pattern` alias map** -- rewrites `pattern` / `pattern_str` /
  `query` to the canonical `pattern_type` enum kwarg.
- **`status=None` payload normalization** -- tools like
  `binary_metadata` that omit a top-level `status` field get
  `status='ready'` injected so the downstream executor's whitelist
  doesn't synthesize a spurious empty error.
- **`_ALWAYS_SUPPRESS` enforcement** -- a curated set of tools the
  agent must never reach is checked BEFORE the specialized-adapter
  lookup AND subtracted from `_effective_tools` (which would
  otherwise re-introduce them via the runtime bridge catalog).
  Current suppress set: `ida_headless.classify_strings` (regex
  categorizer that returns 19 buckets on a 10,254-string binary;
  agents derail by treating its empty output as evidence) and
  `audit_mcp.search_source` (deprecated). Suppressed tools also
  drop from `registered_tools()` + `specialized_tools()` so the
  diagnostic listings stay consistent.

The XREF adapter additionally surfaces a `pagination_hint` block
on `payload` + a one-line directive in the observable when
`total > MAX_LIST_PREVIEW=20`. The directive names the suppressed
row count + the exact follow-up call shape
(`offset=20`, `limit=20`) + the `call_id` for direct payload
access. The full xref array is preserved verbatim in `payload.xrefs`
regardless of length; only the per-turn observable preview is trimmed.

### Three tools added to ida-headless-mcp-exp (commit `f3d4147`+)

The agent had no static path to constant strings outside the
classifier-bucketed subset that `classify_strings` returns. Three
synchronous tools fix the gap (full PE reader, no IDA round-trip):

- **`list_strings(binary_id, min_length=4, filter_text="", section=None, count_only=False, ...)`** --
  enumerates every printable ASCII + UTF-16LE run across all sections
  with non-zero raw size. Returns per-section / per-encoding
  breakdown always; `count_only=True` is the cheap pre-flight that
  returns ONLY totals (no payload) so the agent can size unknown
  binaries before paging.
- **`read_memory(binary_id, address, size=64)`** -- VA -> file offset
  via the PE section table, returns hex + ascii rendering. Clipped
  at section boundaries so reads never bleed across sections.
- **`get_string_at(binary_id, address, max_length=512, encoding="ascii")`** --
  convenience wrapper around `read_memory` for resolving
  null-terminated C-strings or UTF-16LE strings at a known VA.

On a 813KB Delphi PE, `list_strings` returns 10,254 ASCII strings
with `min_length=4` -- enough to surface every hardcoded C2 URL,
embedded second-stage RAT config block in `.rsrc` UTF-16LE, and the
full IOC surface (brand strings, AES keys, mutex names, persistence
commands). The older `classify_strings` tool that bucketed strings
by regex returned only 19 entries on the same binary; it has been
added to `_ALWAYS_SUPPRESS` and is unreachable from the agent
surface (the empty buckets convinced agents the binary held no
strings worth looking at -- a load-bearing wrong inference that
derailed entire investigations).

### Agent prompt: deterministic C2 config extraction

The system prompt teaches a four-stage extraction workflow instead
of pattern-matching on hostname-shaped substrings:

1. **Locate the config loader** -- find via
   `find_api_call_sites('FindResourceW')` for embedded-resource
   patterns, decryptor xrefs for crypto blobs, or
   `RegQueryValueExW` for registry-stored configs.
2. **Recover the storage layout** -- decompile the loader, read off
   exact resource ID / data offset, decryption algorithm + key + IV,
   serialization format, field offsets.
3. **Apply the layout** -- `read_memory(VA, size)` the encrypted
   blob, decrypt with binary-sourced constants, parse with the
   known offsets, identify the C2 field.
4. **Cross-validate** -- walk from loader-populated global to its
   consumer at `WinHttpConnect` / `InternetOpenUrlA` / `connect`.
   If the path doesn't close, it isn't the C2 -- keep going.

### Server restart resilience

ida-headless-mcp-exp now eager-initializes `_Frontend` in `main()`
/ `main_http()` before binding the transport, so `recover_all()`
populates `_binaries` from `cache/<sha>/state.json` BEFORE the
server accepts the first HTTP request. AILA workers carrying stale
`binary_id` values in `mcp_handles_json` survive restarts without
seeing `Unknown binary_id`. Defensive `_sha` fallback handles
out-of-band registrations (e.g. a stdio MCP transport writing
state.json that the HTTP server's already-completed sweep missed).

### Operator workflows

- **Reset** -- toolbar button on the investigation page. Server
  endpoint at `POST /malware/investigations/{id}/reset` wipes
  messages + observations + outcomes + forked branches +
  `workflow_state_cursor` archive in one transaction, flips status
  back to `CREATED`. Refuses while `RUNNING` (operator must pause
  first); `PAUSED` is fine because the cursor wipe handles the
  archive that `/resume` would otherwise rely on.
- **Force Re-enqueue** -- visible when status is `RUNNING` and the
  reaper missed a stall (engine reports in-flight but no task
  heartbeat). Calls the same `/re-enqueue` endpoint the reaper
  would.
- **Re-synthesize** -- "Synthesize again" button on the investigation
  page (the `Synthesis & Narrative` card under the primary outcome).
  `POST /malware/investigations/{id}/synthesize` accepts
  `{ force, tone, length, enumerate_every_suspicious, operator_focus }`.
  Default `force=True`; tones `operator | executive | technical |
  analyst | forensic`; lengths `brief | standard | exhaustive`.
  `enumerate_every_suspicious=True` is the "don't drop anything"
  mode that walks every persona's answer + reasoning and surfaces
  every distinct suspicious item (string, address, function, IOC,
  persistence artifact, decoded blob). Runs against an already-
  `COMPLETED` investigation without flipping its status; the
  structured `panel_summary` is overwritten plus every promoted
  field (`family_attribution`, `capabilities`, `iocs`,
  `attribution_rationale`, `headline_verdict`, `detection_guidance`,
  `next_actions`, `panel_dissent`, `inconclusive_areas`,
  `inconclusive_capabilities`) is re-derived.
- **Generate narrative** -- separate artifact from synthesis. A
  long-form chronological writeup stored under
  `payload.investigation_narrative` on the canonical outcome,
  alongside (not replacing) `panel_summary`. Endpoint:
  `POST /malware/investigations/{id}/narrative` with
  `{ force, tone, length, operator_focus }`. Tones `blog |
  incident_report | thriller | academic | casual`; lengths
  `short` (~1.5-2.5K words), `standard` (~3.5-5.5K words), `long`
  (~8-15K words). Schema enforces `body.min_length=4000` so the
  LLM cannot bail with a 200-char intro stub. UI button opens the
  rendered markdown in a side modal with table of contents,
  copy-to-clipboard, and the title / tone / length / word count
  metadata strip.
- **Direct outcome edit** -- agents and operators alike can patch a
  draft outcome's payload via the `edit_outcome` action.
  Counterpart to the deferred `request_edit` vote (which only
  suggests edits the synthesis agent picks up on the next pass);
  `edit_outcome` merges patches immediately. Refused on non-draft
  outcomes; protected workflow-owned keys (`panel_contributions`,
  `panel_summary`, `verifier_report`, `applied_by_synthesis`) are
  dropped from the merge. Every applied edit writes an audit row.
- **Veto threshold = 2 (chorus, not solo)** -- a single sibling
  `reject` vote no longer kills an outcome. A second sibling must
  concur (`VETO_K=2` in `services/outcome_review.py`). Single rejects
  still record on the outcome and surface in the proposing branch's
  prompt so it can react; the state flip waits on the chorus.
  Approve quorum (`approve_count >= quorum_k`) still ships the
  outcome; veto is evaluated BEFORE approve so a tied chorus
  resolves to rejected.
- **Observations debug panel** -- operator-facing list of every
  observation row recorded under the investigation, with polarity
  and kind filter chips. Surfaces what evidence the agent has
  actually committed to durable storage.
- **Hypothesis aggregate** -- per-investigation projection of live /
  rejected / resolved hypotheses across every branch.

## Quick Start

**Prerequisites**

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+ with the `pgvector` extension available
- Redis 6+

**Steps**

1. Clone the repository.

   ```bash
   git clone <repo-url>
   cd AILA
   ```

2. Install backend and frontend dependencies.

   ```bash
   make install
   ```

   Equivalent to `pip install -e ".[dev]"` plus `corepack enable && pnpm install`. The frontend is a pnpm workspace at the repo root; one install wires the shell, `@aila/typescript-config`, and all module packages.

3. Copy the environment template and fill in real values.

   ```bash
   cp .env.example .env
   ```

   At minimum, set `AILA_DATABASE_URL`, `AILA_PLATFORM_REDIS_URL`, `AILA_JWT_SECRET_KEY`, `AILA_ADMIN_PASSWORD` (first-boot bootstrap, removed afterward), and the `AILA_PLATFORM_LLM_*` group. Generate the JWT secret with `openssl rand -hex 32`. See [docs/ENV_VARS.md](docs/ENV_VARS.md) for the full reference.

4. Bring up Postgres (pgvector) and Redis via Docker Compose.

   ```bash
   make dev-up
   ```

   This launches `pgvector/pgvector:pg16` on `:5432` and `redis:7-alpine` on `127.0.0.1:6379`, defined in `infra/utilities/docker-compose.yml`. Idempotent. Use `make dev-down` to stop (keeps volumes), `make dev-reset` to wipe.

5. Initialize or migrate the schema.

   ```bash
   make db-init        # FIRST RUN ONLY: create tables + stamp Alembic head
   make migrate        # subsequent runs: alembic upgrade head
   ```

6. Start the services in three terminals.

   ```bash
   # Terminal 1 -- REST API on :8000
   make backend

   # Terminal 2 -- Vite dev server on :3000 (single SPA, all module UIs)
   make frontend

   # Terminal 3 -- ARQ worker, default queue
   make worker
   ```

   For per-module queue tracks, run additional workers:

   ```bash
   make worker-vr           # vulnerability research
   make worker-vuln         # vulnerability scans
   make worker-forensics    # DFIR investigations
   make worker-malware      # malware reverse engineering
   ```

   On Windows, `bash start.sh` brings up audit-mcp + backend + 4 workers + frontend in a single command. Per-queue worker pool size is set via `WORKER_COUNT_<QUEUE>` env vars (e.g. `WORKER_COUNT_VR=3`, `WORKER_COUNT_MALWARE=2`, `WORKER_COUNT_SBD_NFR=0` to disable a queue). Defaults to 1 per queue. Bounce one queue's pool with `bash start.sh restart-worker <queue>`.

For the expanded walkthrough including admin user creation, smoke tests, and
common pitfalls, see [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Module Inventory

| module_id       | Description                                                                                       | Status     |
|-----------------|---------------------------------------------------------------------------------------------------|------------|
| `vulnerability` | SSH package inventory, distro-aware advisory resolution, CVE enrichment, scoring, and reporting.  | production |
| `forensics`     | Remote forensic evidence triage over SSH: disk images, memory dumps, PCAPs, write-up generation.  | production |
| `vr`            | Vulnerability research: graph-aware source/binary audit (audit-mcp + IDA Headless MCP), hypothesis-driven reasoning, fuzz campaign proposals (audit\u2192fuzz pipeline), enterprise PDF reports with LLM writer agent, automatic exploit/PoC drafting, variant hunting with child-investigation spawning. | production |
| `malware`       | Malware reverse engineering: VR-pattern multi-persona deliberation over `ida-headless-mcp-exp` only. Six investigation kinds (triage / full_analysis / unpack_only / config_extract / yara_generate / family_attribute), deterministic four-stage C2 config extraction with mandatory string-sweep + xref-chain follow-up, two-stage C2 hunt (Stage 1 loader URLs vs Stage 2 dropped-payload endpoints), fan-out sub-investigation spawning, observation memory with base64 / hex auto-decode, operator controls (reset / re-enqueue / re-synthesize with tone+length / generate-narrative writeup / direct `edit_outcome` patches), chorus-veto outcome review (`VETO_K=2`), structured synthesis promoting family / capabilities / IOCs / detection guidance / next actions onto the canonical payload. | production |
| `hello_world`   | Minimal reference module proving the `ModuleProtocol` contract end-to-end.                        | example    |

Modules are auto-discovered at platform boot by scanning `src/aila/modules/*`.
Packages whose name starts with `_` are skipped (used for templates and
fixtures). To add a new module, follow [docs/MODULE_STANDARD.md](docs/MODULE_STANDARD.md)
and the worked tutorial in [docs/MODULE_TUTORIAL.md](docs/MODULE_TUTORIAL.md).

## Development

Common targets in the root `Makefile`:

| Target                  | What it runs                                                              |
|-------------------------|---------------------------------------------------------------------------|
| `make install`          | `pip install -e ".[dev]"` plus `corepack enable && pnpm install`          |
| `make dev-up`           | `docker compose -f infra/utilities/docker-compose.yml up -d postgres redis` (idempotent) |
| `make dev-down`         | Stop dev infra containers (keeps data volumes)                            |
| `make dev-reset`        | Stop containers and wipe data volumes                                     |
| `make dev-logs`         | Follow compose service logs                                               |
| `make dev-status`       | `docker compose ps`                                                       |
| `make db-init`          | `python scripts/db_init.py` -- create tables + stamp Alembic head (first run only) |
| `make migrate`          | `cd src/aila && alembic upgrade head`                                     |
| `make dev`              | Print the canonical dev workflow (no services started)                    |
| `make backend`          | Ensure `dev-up` + `db-init`, free port 8000, run `uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload` |
| `make frontend`         | Free port 3000, run `pnpm --filter @aila/shell run dev` (Vite on :3000)   |
| `make frontend-build`   | `pnpm --filter @aila/shell run build` (production SPA bundle)             |
| `make storybook`        | `pnpm --filter @aila/shell run storybook`                                 |
| `make worker`           | `python -m aila worker` (default queue)                                   |
| `make worker-vr`        | `python -m aila worker -q vr`                                             |
| `make worker-vuln`      | `python -m aila worker -q vulnerability`                                  |
| `make worker-forensics` | `python -m aila worker -q forensics`                                      |
| `make dev-all`          | Bring up all services in one terminal (Ctrl+C stops everything)           |
| `bash start.sh`         | Spawn audit-mcp + backend + 4 workers + frontend in one shot (Windows: Git Bash + PowerShell) |
| `docker compose -f infra/utilities/docker-compose.full.yml up --build` | Full-stack containers: postgres + redis + api + 4 workers + frontend. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). |
| `make test`             | `pytest`, excluding `tests/test_e2e*.py`                                  |
| `make test-e2e`         | `pytest tests/test_e2e.py -v` (requires live infrastructure)              |
| `make test-frontend`    | `pnpm --filter @aila/shell run test` (shell package only; module frontends use `pnpm -r run test`) |
| `make lint`             | `ruff check src/aila/`                                                    |
| `make typecheck`        | `pnpm -r run type-check` (every workspace package, shell + modules)       |
| `make honesty`          | `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` |
| `make compile`          | `python -m compileall -q src/aila`                                        |
| `make build`            | `pnpm --filter @aila/shell run build` (production SPA bundle)             |
| `make check`            | `lint` + `honesty` + `compile` + `typecheck` (the full pre-PR gate)       |
| `make security-scan`    | `pip-audit --strict --desc` and `bandit -r src/aila -q -ll`               |
| `make clean`            | Remove `__pycache__/` directories and coverage artifacts                  |

Run `make check` before opening a PR. Contributor workflow, branch policy,
review expectations, and the honesty audit rules are documented in
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## CLI

The `aila` entry point (`aila = "aila.cli:app"`) is a Typer application.
Invoke `aila --help` to list every subcommand and command group; the most
common entry points are summarised below.

| Command                          | Purpose                                                                |
|----------------------------------|------------------------------------------------------------------------|
| `aila serve`                     | Start the FastAPI REST API via uvicorn                                 |
| `aila worker [-q <queue>]`       | Start an ARQ worker for the given queue track (default: `default`)     |
| `aila task "<question>"`         | Ask a natural-language question routed through the platform agent      |
| `aila analyze [--target <name>]` | Run a vulnerability scan across registered targets (or one)            |
| `aila add-ssh ...`               | Register an SSH-reachable system for the vulnerability module          |
| `aila create-api-key`            | Mint an admin-role API key for first-boot bootstrap                    |
| `aila health`                    | Probe platform and provider readiness                                  |

Command groups expose related subcommands:
`aila config` (runtime config registry),
`aila tool` (invoke registered platform tools directly),
`aila cache` (manage decision and intel caches),
`aila policy` (scoring policy management),
`aila feedback` (operator knowledge entries),
`aila report` (PDF and CSV reporting),
`aila schedule` (scheduled scans),
`aila intel`, `aila ops`, `aila auto`, `aila digest`
(fleet intelligence, operational metrics, automation, executive digests).

## REST API

- **Base URL (dev):** `http://localhost:8000`
- **OpenAPI / Swagger UI:** `http://localhost:8000/docs`
- **OpenAPI JSON:** `http://localhost:8000/openapi.json`
- **Authentication:** `POST /auth/login` with `{"username", "password"}` returns a JWT (`data.access_token`) used as `Authorization: Bearer <token>` for all subsequent calls; `POST /auth/token` exchanges an API key for the same envelope. RBAC roles
  are `admin`, `operator`, `reader` -- see
  [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
- **Streaming:** long-running scans, sessions, and tasks expose SSE endpoints
  (e.g. `/scans/{id}/events`, `/tasks/{id}/events`). Integration patterns are
  documented in [docs/SSE_GUIDE.md](docs/SSE_GUIDE.md).
- **Errors:** structured error envelope catalogued in
  [docs/API_ERRORS.md](docs/API_ERRORS.md).

The OpenAPI document is the source of truth for the route surface; the
`/docs` UI lists every endpoint, request schema, and response schema.

## Documentation Index

| Document                                                                    | Covers                                                                  |
|-----------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                                | System diagram, layer responsibilities, data flow, runtime constraints  |
| [docs/PLATFORM_INTERNALS.md](docs/PLATFORM_INTERNALS.md)                    | X-ray: full request lifecycle traced through every platform layer       |
| [docs/QUICKSTART.md](docs/QUICKSTART.md)                                    | Expanded onboarding walkthrough with troubleshooting                    |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)                                | Contributor workflow, branch policy, review expectations                |
| [docs/MODULE_STANDARD.md](docs/MODULE_STANDARD.md)                          | Required module layout, contracts, and lifecycle (v2.1)                 |
| [docs/MODULE_TUTORIAL.md](docs/MODULE_TUTORIAL.md)                          | Step-by-step authoring of a new module                                  |
| [docs/MODULE_AGENT_GUIDE.md](docs/MODULE_AGENT_GUIDE.md)                      | Module context conventions for LLM-driven flows                         |
| [docs/FRONTEND_MODULE_STANDARD.md](docs/FRONTEND_MODULE_STANDARD.md)        | Frontend shell and per-module UI contribution contract                  |
| [docs/forensics/](docs/forensics/)                                          | Forensics module domain reference and design history                     |
| [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md)                                      | Database tables, relationships, and ownership                           |
| [docs/DATABASE_MIGRATIONS.md](docs/DATABASE_MIGRATIONS.md)                  | Alembic policy, conventions, and migration authoring                    |
| [docs/CONFIG_REGISTRY.md](docs/CONFIG_REGISTRY.md)                          | Config resolution chain (env -> registry -> defaults)                   |
| [docs/ENV_VARS.md](docs/ENV_VARS.md)                                        | Environment variable reference                                          |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)                            | Auth, RBAC, API keys, JWT lifecycle                                     |
| [docs/DATA_PROTECTION.md](docs/DATA_PROTECTION.md)                          | Data posture modes, LLM redaction, input/output sanitization            |
| [docs/API_ERRORS.md](docs/API_ERRORS.md)                                    | API error catalog                                                       |
| [docs/OPENAPI_NOTES.md](docs/OPENAPI_NOTES.md)                              | OpenAPI generation notes and conventions                                |
| [docs/SSE_GUIDE.md](docs/SSE_GUIDE.md)                                      | Server-sent events: usage, reconnection, curl examples                  |
| [docs/TASK_QUEUE_OPS.md](docs/TASK_QUEUE_OPS.md)                            | ARQ worker operations, queue tracks, retry semantics                    |
| [docs/LLM_INTEGRATION.md](docs/LLM_INTEGRATION.md)                          | LLM client, pipelines, model selection, transparency posture            |
| [docs/WORKFLOW_GUIDE.md](docs/WORKFLOW_GUIDE.md)                              | Durable state machine: handler contract, do/don't, production examples  |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)                                    | Production deployment guide                                             |
| [docs/TEST_GUIDE.md](docs/TEST_GUIDE.md)                                    | Testing conventions, fixtures, e2e gating                               |
| [docs/GOLDEN_RULES.md](docs/GOLDEN_RULES.md)                                | Code quality rules enforced by review and tooling                       |
| [docs/HONESTY_AUDIT.md](docs/HONESTY_AUDIT.md)                              | Structural honesty rules enforced by `aila.tools.honesty_audit`         |
| [docs/PITFALL_GUIDE.md](docs/PITFALL_GUIDE.md)                              | Common mistakes when working on AILA                                    |
| [docs/PRODUCTION_RUBRIC.md](docs/PRODUCTION_RUBRIC.md)                      | Readiness rubric for shipping a module to production                    |
| [docs/vr/](docs/vr/)                                                        | VR engine internals: reasoning loop, IDA Headless MCP, exploit automation |
| [docs/VR_INSTALLATION_GUIDE.md](docs/VR_INSTALLATION_GUIDE.md)              | Standing up audit-mcp + IDA Headless MCP next to AILA                    |
| [CHANGELOG.md](CHANGELOG.md)                                                | Version history                                                         |

## License

AILA is licensed under the GNU Affero General Public License v3.0. See
[LICENSE](LICENSE) for the full text.
