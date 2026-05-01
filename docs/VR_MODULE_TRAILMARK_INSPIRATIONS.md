# VR Module — Lessons from Trail of Bits Trailmark

What Trailmark does, why it's the most directly useful of the three projects we studied, and what to steal.

---

## What Trailmark Actually Is

Trailmark is a **code graph builder** from Trail of Bits. It parses source code into a queryable graph of functions, classes, calls, and semantic annotations. Built on tree-sitter (parsing) + rustworkx (graph traversal).

It's not a vulnerability scanner. It's not an LLM tool. It's **infrastructure for asking structural questions about code.** "What can an attacker reach from this HTTP handler?" "Where do trust boundaries cross?" "What functions are tainted by external input?"

This is exactly the missing piece in our VR module for interpreted language targets.

---

## Why Trailmark Matters More Than Metis or Pharos

| Tool | Solves | For us |
|---|---|---|
| **Metis** | LLM-driven code review with evidence gating | Reasoning patterns (obligations, adjudication) — steal the ideas, not the tool |
| **Pharos** | Deep binary semantic analysis (def-use, OO recovery, path solving) | Binary-level concepts — use angr instead of Pharos directly |
| **Trailmark** | Structural code graph with attack surface, taint, privilege boundaries | **Directly usable as a dependency** for source-available targets. pip-installable. 21 languages. Solves our interpreted-language recon problem. |

Trailmark is the tool we should actually install on the research workstation and call from our module. Not "steal the ideas" — use the tool.

---

## The Four Pre-Analysis Passes

Trailmark runs four passes over the code graph. All four are directly useful for VR recon:

### Pass 1: Blast Radius Estimation

For every function, count how many functions are transitively reachable via call edges (downstream) and how many callers transitively reach it (upstream).

**Why this matters for VR:**
A function with blast radius 200 that processes untrusted input is a higher-priority target than one with blast radius 3. If you corrupt state inside a high-blast-radius function, the corruption propagates to hundreds of downstream consumers.

The LLM receives: "parse_request has blast radius 187 (downstream), 4 (upstream). Critical descendants: handle_file_upload (CC=42), execute_command (CC=28), update_database (CC=19)."

This directly answers: **"What should I fuzz first?"**

### Pass 2: Entrypoint Enumeration

Automatically detects entrypoints across 21 languages:
- Python: Flask/FastAPI routes, Click/Typer commands, Celery tasks
- Java: Spring @GetMapping, JAX-RS @GET, Kafka @KafkaListener
- JS/TS: NestJS decorators, Next.js route handlers, Lambda handlers
- Rust: actix-web/rocket handlers, FFI exports (#[no_mangle])
- Go: HTTP handlers, exported functions
- PHP: Symfony routes
- C#: ASP.NET [HttpGet], Azure Functions
- Solidity: external/public functions, fallback/receive
- etc.

**Why this matters for VR:**
The module doesn't need per-language entrypoint detection logic. Trailmark handles it for 21 languages. The LLM receives: "12 entrypoints detected. 8 are HTTP handlers (untrusted_external). 2 are CLI commands (semi_trusted_external). 2 are internal workers (trusted_internal)."

This directly answers: **"Where does untrusted input enter the codebase?"**

### Pass 3: Privilege Boundary Detection

Finds edges in the call graph where trust level changes — where a function reachable from an untrusted entrypoint calls into a function reachable only from trusted entrypoints.

**Why this matters for VR:**
Privilege boundaries are where bugs become vulnerabilities. A bug in internal-only code is low severity. The same bug reachable from an HTTP handler is critical. Trailmark identifies these crossings automatically.

The LLM receives: "privilege_boundary: handle_upload (untrusted_external) -> process_archive (trusted_internal). Trust transition: untrusted_external -> trusted_internal."

This directly answers: **"Where are the security-relevant trust boundaries?"**

### Pass 4: Taint Propagation

From every untrusted/semi-trusted entrypoint, walk the call graph forward and mark all reachable functions as "tainted" — they can be influenced by attacker-controlled input.

**Why this matters for VR:**
A dangerous function (eval, exec, subprocess, deserialization) that is NOT tainted is not exploitable from the network. Only tainted sinks matter.

The LLM receives: "execute_template is tainted via: handle_api_request, handle_webhook. It calls jinja2.Template(user_input).render() — this is a server-side template injection sink reachable from 2 HTTP entrypoints."

This directly answers: **"Which dangerous functions are actually reachable from attacker input?"**

---

## The Query Engine

Trailmark's QueryEngine API maps directly to VR research questions:

| Query | VR Use Case |
|---|---|
| `callers_of("dangerous_func")` | Who calls this dangerous function? Are any callers tainted? |
| `callees_of("handle_request")` | What does this entrypoint eventually call? Does it reach any sinks? |
| `ancestors_of("sql_query")` | Upward slice: every function that can transitively reach the SQL query |
| `reachable_from("http_handler")` | Everything reachable from this entrypoint — the full attack surface from this entry |
| `paths_between("recv", "exec")` | All call paths from network receive to command execution — injection path enumeration |
| `entrypoint_paths_to("deserialize")` | How does attacker input reach this deserialization call? |
| `attack_surface()` | All entrypoints with trust level and asset value — instant attack surface map |
| `complexity_hotspots(20)` | Functions with cyclomatic complexity >= 20 — likely bug-dense code |
| `diff_against(other_graph)` | What changed between versions? New functions, removed functions, changed edges — patch analysis |

---

## Integration Architecture

### For source-available targets (interpreted languages)

```
Project creation: target = /path/to/source/repo
  |
  v
Trailmark indexing (runs on research workstation via SSH):
  trailmark --codebase-path /target --output graph.json
  |
  v
Pre-analysis:
  trailmark preanalysis  -> blast_radius, entrypoints, privilege_boundaries, taint
  |
  v
Import into VR module:
  Parse graph.json -> VRCodeGraph (our data model)
  Store in project DB
  |
  v
LLM receives:
  - Attack surface: 12 entrypoints (8 HTTP, 2 CLI, 2 internal)
  - Tainted sinks: 4 dangerous functions reachable from untrusted input
  - Privilege boundaries: 3 trust transitions
  - Complexity hotspots: 7 functions with CC > 20
  - Blast radius leaders: top 5 high-impact functions
  |
  v
LLM generates hypotheses:
  "H1: SSTI in execute_template via handle_api_request path"
  "H2: Deserialization in process_message, tainted from webhook handler"
  "H3: SQL injection in search_users, complexity 34, blast radius 89"
```

### For binary targets

Trailmark doesn't apply (no source). The equivalent comes from IDA/Ghidra + angr:
- Entrypoints = exported functions, main, signal handlers
- Call graph = IDA xrefs
- Taint = angr symbolic execution from input sources
- Blast radius = IDA call graph traversal
- Complexity = IDA's function complexity metrics

Same concepts, different tools.

### For patch diffing

Trailmark has `diff_against(other_graph)` which produces:
- Added nodes (new functions)
- Removed nodes (deleted functions)
- Changed edges (call relationships modified)
- Modified nodes (parameters, complexity, return type changed)

For VR: index both versions of the source code, diff the graphs. The LLM sees: "3 functions changed in the security patch. handle_auth gained a new call to validate_token. parse_header lost a parameter. execute_query changed from CC=12 to CC=15 (new branches added — likely input validation)."

This is **source-level BinDiff.** For N-day research on open-source targets, this replaces binary diffing entirely.

---

## Data Model Enrichment

Trailmark's data model adds concepts our VR module should adopt:

### Trust Levels (on entrypoints)

```python
class TrustLevel(str, Enum):
    UNTRUSTED_EXTERNAL = "untrusted_external"      # HTTP handlers, WebSocket, public API
    SEMI_TRUSTED_EXTERNAL = "semi_trusted_external"  # Authenticated API, internal service calls
    TRUSTED_INTERNAL = "trusted_internal"             # CLI, cron, internal workers
```

### Asset Value (on entrypoints)

```python
class AssetValue(str, Enum):
    HIGH = "high"      # Auth, payment, PII, crypto key management
    MEDIUM = "medium"  # Business logic, data processing
    LOW = "low"        # Health checks, static content, logging
```

### Edge Confidence

```python
class EdgeConfidence(str, Enum):
    CERTAIN = "certain"        # Direct call, self.method()
    INFERRED = "inferred"      # Attribute access on non-self objects
    UNCERTAIN = "uncertain"    # Dynamic dispatch, reflection, eval
```

These enrich the LLM's reasoning: "This path has 2 uncertain edges (dynamic dispatch). The taint chain might not be real. Confirm dynamically before claiming exploitability."

This feeds directly into the Metis-inspired **evidence obligation system**: if the taint path includes uncertain edges, the obligation "confirm taint path dynamically" is required before accepting an exploitation claim.

---

## What We Don't Need From Trailmark

| Feature | Why skip |
|---|---|
| weAudit integration | Trail of Bits' internal audit tool. We have our own evidence graph. |
| SARIF augmentation | We're not triaging external tool findings. We find bugs ourselves. |
| Mermaid diagram output | Nice for docs, not needed at runtime. |
| Circom/Cairo/Miden parsers | Blockchain-specific. Not our domain (unless future module). |

---

## Summary: Three Tools, Three Layers

| Layer | Tool | What it provides |
|---|---|---|
| **Reasoning patterns** | Metis (ideas only) | Evidence obligations, deterministic adjudication, bounded evidence packs |
| **Binary semantics** | Pharos concepts via angr | Symbolic execution, constraint solving, def-use analysis, OO recovery, auto-ROP |
| **Source graph** | Trailmark (actual dependency) | Attack surface mapping, taint propagation, privilege boundaries, entrypoint detection, complexity hotspots, source-level diffing |

The VR module combines all three:
1. **Trailmark** builds the map (what exists, what's reachable, what's tainted)
2. **angr** explores the hard questions (is this path feasible? what input triggers it?)
3. **Metis patterns** keep the LLM honest (don't claim what you haven't proven)
4. **CyberReasoningEngine** drives the research (hypothesize, test, refine, exploit)
