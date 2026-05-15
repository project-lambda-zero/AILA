# VR Module v0.3 — Fuzzing Pipeline Implementation Plan

## What v0.3 does

Given a target binary + (optional) target function, run a fuzzing campaign that:
1. Picks an appropriate engine + strategy (mutational, coverage-guided, differential, generative)
2. Runs durable, observable, long-running campaigns (hours to days)
3. Auto-triages crashes (security-relevant vs harmless, dedup by stack hash)
4. Minimizes crashing inputs to smallest reproducer
5. Assesses exploitability (per-crash severity classification)
6. Hands findings to the v0.1 N-day workflow for advisory generation

Input: `target_binary` + `target_function` (optional) + `strategy_config` (optional)
Output: campaign_id (long-running) + stream of `VRFinding` records as crashes are discovered + minimization → triage → advisory chain

## Position in the VR roadmap

From `VR_MODULE_DECISIONS.md`:
- v0.1: N-day PoC writer (CVE → PoC + advisory) — **shipping**
- v0.2: Binary recon + target ranking — **next**
- **v0.3: Fuzzing pipeline (local, single binary)** — **this plan**
- v0.4: Full research workflow (recon + fuzzing + exploit + advisory)
- v0.5: Kernel/hypervisor exploitation

v0.3 builds on v0.2's recon (which functions are worth fuzzing) and feeds v0.1 (advisory generation from crashes).

---

## Gray Area Resolutions (v0.3 scope)

### GA-8: Engine binding model (FUZZILLI vs custom harness vs AFL++ vs WinAFL)

**Decision:** Strategy-based engine binding. Each strategy declares which engines it supports. Engines are pluggable, defined by a small protocol.

Rationale: V8 sandbox fuzzing wants FUZZILLI; native userspace wants AFL++; Windows wants WinAFL+DynamoRIO; Java wants Jazzer. One-size-fits-all wrapper would be wrong abstraction.

Engine protocol (`engines/base.py`):
```python
class FuzzEngine(Protocol):
    name: str                      # "v8_d8_sbx" | "afl++" | "fuzzilli" | "jazzer"
    binary_path: Path
    supported_strategies: set[str] # which strategies this engine can run
    
    def health_check(self) -> dict: ...
    def prepare_workdir(self, campaign_id: str) -> Path: ...
    def spawn_worker(self, strategy_config: dict, workdir: Path) -> WorkerHandle: ...
```

Engines built into v0.3:
- `v8_d8_sbx` — V8 d8 with `--sandbox-testing` (Linux + Windows)
- `pdfium_test_sbx` — PDFium test runner with `--js-flags=--sandbox-testing`
- `afl++_qemu` — AFL++ in QEMU mode for binary-only Linux fuzzing
- `fuzzilli_v8` — FUZZILLI bound to a custom V8 build with REPRL+coverage

Defer to v0.4: WinAFL+DynamoRIO, Jazzer, Atheris, syzkaller.

### GA-9: Strategy composition (built-in vs user-defined)

**Decision:** Strategies are Python classes implementing `FuzzStrategy` protocol AND user-composable JSON definitions over a primitive library.

Two layers:
- **Built-in strategies** = Python classes in `strategies/`. Can do anything. Versioned, tested.
- **User-defined strategies** = JSON compositions of built-in primitives. Created via API/UI. Versioned per project. Safe (no code execution).

JSON composition example:
```json
{
  "name": "v8_wasm_focused",
  "base_strategy": "mutational",
  "engine": "v8_d8_sbx",
  "primitives": [
    {"type": "forge_byte_length", "size_range": [1024, 65536]},
    {"type": "wasm_compile_random", "weight": 2.0},
    {"type": "descriptor_swap", "frequency": 0.3}
  ],
  "operations": [
    {"type": "wasm_struct_get_set", "weight": 3.0},
    {"type": "json_stringify", "weight": 0.5}
  ],
  "config": {
    "iterations_per_seed": 50,
    "respawn_per_minute": 30
  }
}
```

Primitives are tools registered with the platform's tool registry. The strategy executor composes them at runtime.

### GA-10: Crash triage classification (V8 sandbox-specific)

**Decision:** Engine-specific classification rules in `triage/rules/`. Each engine declares which output strings indicate which crash class. Rules are versioned data, not code.

For `v8_d8_sbx` engine:
```yaml
# triage/rules/v8_d8_sbx.yaml
classifications:
  sandbox_violation:
    severity: CRITICAL
    markers:
      - "## V8 sandbox violation detected!"
    notes: "Real out-of-sandbox crash. VRP-eligible."
  
  asan_finding:
    severity: HIGH
    markers:
      - "AddressSanitizer:"
    exclude_if_safe_region: true
  
  in_sandbox_oob:
    severity: HARMLESS
    markers:
      - "harmless memory access violation (inside sandbox)"
  
  safe_region_oob:
    severity: HARMLESS
    markers:
      - "harmless memory access violation (safe region)"
  
  csa_check:
    severity: HARMLESS
    markers:
      - "CSA check failure"
  
  gc_invariant:
    severity: HARMLESS
    markers:
      - "AllowHeapAllocationInRelease"
```

For `afl++_qemu` engine: ASAN report classification (heap-overflow, UAF, double-free, etc.).

Triage is a separate ARQ task, runs after each crash. Stores classification in `VRCrashRecord.classification`.

### GA-11: Stack hash dedup algorithm (sandbox-aware)

**Decision:** Reuse v0.1's `crash_signature` (GA-2 base-relative offset hashing) AND add tier filter for V8 (different optimization tiers produce different stacks for same bug; normalize by stripping JIT compiler frames).

Algorithm (`triage/dedup.py`):
```python
def crash_signature(report: CrashReport, engine: str) -> str:
    frames = parse_stack(report)
    
    # Engine-specific normalization
    if engine.startswith("v8_"):
        # Strip JIT compiler frames (Maglev/TurboFan/Liftoff have noisy stacks)
        frames = [f for f in frames if not is_jit_internal(f)]
        # Normalize tier markers
        frames = [strip_tier_marker(f) for f in frames]
    
    # Standard normalization (from GA-2)
    frames = normalize_addresses(frames)
    
    top5 = frames[:5]
    return sha256(crash_type + "|" + "|".join(top5))
```

### GA-12: Campaign storage tier (worker filesystem vs object storage)

**Decision:** Two-tier. Workers write to local filesystem (fast, ephemeral). Triage worker uploads triaged findings to object storage (durable, queryable).

Layout:
- **Worker filesystem** (ephemeral, on the machine running the fuzzer):
  ```
  /var/lib/aila/fuzz/<campaign_id>/
  ├── corpus/                  # current corpus (FUZZILLI manages this if present)
  ├── crashes/                 # raw crashes, pre-triage
  ├── stats/                   # per-worker stats files
  └── worker_<pid>.log         # worker stdout/stderr
  ```
- **Object storage** (durable):
  ```
  s3://aila-vr/fuzz/<campaign_id>/
  ├── findings/<finding_id>/
  │   ├── reproducer.{js,c,py}
  │   ├── crash_report.txt
  │   └── meta.json
  ├── corpus_snapshots/<timestamp>.tar.gz   # periodic
  └── stats_archive/<date>.parquet           # daily rotation
  ```
- **Postgres** (queryable):
  - `vr_fuzz_campaigns` table (metadata, status, config)
  - `vr_fuzz_findings` table (one row per unique crash signature)
  - `vr_fuzz_finding_instances` (every instance of a duplicate, linked to canonical finding)
  - `vr_fuzz_stats_snapshots` (time-series)

### GA-13: Stats sampling rate

**Decision:** Workers append a stats line every 10 seconds to `stats/worker_<pid>.jsonl`. A separate ARQ task (`fuzz_stats_aggregator`) runs every 60 seconds, aggregates across workers, writes a snapshot row to `vr_fuzz_stats_snapshots`. SSE pushes the latest snapshot to subscribed UIs.

Trade-off: 10s worker resolution + 60s aggregation. Live UI shows 1-min granularity. Historical analysis can use raw 10s data from object storage.

### GA-14: Resource limits (single-machine multi-campaign)

**Decision:** Per-campaign CPU + memory + disk budget enforced at worker spawn time. Configurable in campaign config; default budget pulled from `ConfigRegistry`.

Defaults:
- `cpu_quota_pct`: 50 (per-campaign max % of one machine's CPU)
- `memory_limit_mb`: 4096
- `disk_quota_gb`: 10 (corpus + crashes; crashes get rotated when over budget)
- `concurrent_workers`: 4
- `max_runtime_hours`: 24 (campaign auto-stops; can be extended)

When the platform has N machines, the campaign worker pool is partitioned: each machine runs at most `concurrent_workers` workers across all campaigns assigned to it. Scheduler in `services/campaign_scheduler.py`.

### GA-15: Coverage-guided integration (FUZZILLI bring-up)

**Decision:** FUZZILLI as an optional engine. Detected at startup; if absent, `fuzzilli_v8` strategy is unavailable. Build instructions in `data/setup/fuzzilli.md`. Custom V8 build with REPRL+coverage required (one-time per V8 version).

The `fuzzilli` engine implementation is a thin wrapper around the FUZZILLI subprocess:
- Spawn `fuzzilli` binary with `--profile=v8 --jobs=N --resume=<workdir>`
- Tail FUZZILLI's stats output → translate to AILA stats schema
- Watch FUZZILLI's `crashes/` directory → on new file, trigger triage task
- On stop signal: send SIGTERM to FUZZILLI, wait for graceful shutdown (preserves corpus)

### GA-16: Differential fuzzing as a first-class strategy

**Decision:** Build `differential` strategy. Targets V8 specifically (Ignition vs Sparkplug vs Maglev vs TurboFan). Compares output of same JS run through different tiers. Divergence = JIT bug = VRP-eligible.

Implementation:
```python
class DifferentialStrategy(FuzzStrategy):
    """Run same JS through multiple optimization tiers, report divergence."""
    
    config_schema = {
        "tiers": ["ignition", "sparkplug", "maglev", "turbofan"],
        "compare_strategy": "exact_output",  # or "side_effects" or "exception_kind"
        "tier_warmup_calls": 10000,
    }
    
    def execute_test(self, js: str) -> dict:
        results = {}
        for tier in self.config["tiers"]:
            results[tier] = self.engine.run_at_tier(js, tier)
        return self.compare_and_classify(results)
```

V8 supports per-function tier control via `%PrepareFunctionForOptimization` + `%OptimizeFunctionOnNextCall` natives (require `--allow-natives-syntax`). The strategy generates JS that exercises these.

### GA-17: Minimization timeout and budget

**Decision:** Minimization runs as separate ARQ task per crash. Time budget: 60 seconds default. Strategy: delta-debugging on the input + character-level reduction. Stops when no further reduction possible OR budget exhausted.

Minimized reproducer replaces the original in the finding record (original kept in object storage for audit trail).

### GA-18: Variant-hunt feedback loop

**Decision:** When a crash is classified `sandbox_violation`, automatically queue a variant-hunt task that:
1. Reads the reproducer
2. Extracts the crashing pattern (token sequence + corruption operations)
3. Generates 10 mutated variants
4. Runs each variant
5. Reports any new crashes as related findings (`parent_finding_id`)

Implements the "find all variants" obligation. Surface crashes don't get reported alone; the system asks "what other shapes of this bug exist?"

---

## File Layout

Building on the existing v0.1 structure:

```
src/aila/modules/vr/
├── ... (existing v0.1 files unchanged) ...
├── fuzzing/                              # NEW v0.3 subpackage
│   ├── __init__.py
│   ├── manager.py                        # CampaignManager singleton
│   ├── scheduler.py                      # Resource-aware worker assignment
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── campaign.py                   # FuzzCampaign Pydantic model
│   │   ├── finding.py                    # FuzzFinding (extends VRFinding)
│   │   ├── strategy.py                   # StrategyDefinition + composition schema
│   │   ├── engine.py                     # EngineDefinition
│   │   └── stats.py                      # StatsSnapshot + time-series
│   ├── strategies/
│   │   ├── __init__.py                   # Strategy registry
│   │   ├── base.py                       # FuzzStrategy ABC
│   │   ├── mutational.py                 # Random mutation w/ primitives
│   │   ├── differential.py               # Tier divergence
│   │   ├── fuzzilli.py                   # FUZZILLI subprocess wrapper
│   │   ├── generative.py                 # Grammar-based generation
│   │   └── composer.py                   # JSON-defined strategy executor
│   ├── engines/
│   │   ├── __init__.py                   # Engine registry
│   │   ├── base.py                       # FuzzEngine protocol
│   │   ├── v8_d8.py                      # V8 d8 with --sandbox-testing
│   │   ├── pdfium_test.py                # PDFium test runner
│   │   ├── afl_qemu.py                   # AFL++ QEMU mode
│   │   └── health.py                     # Engine health checks
│   ├── primitives/                       # Composable strategy building blocks
│   │   ├── __init__.py
│   │   ├── base.py                       # Primitive protocol
│   │   ├── v8_forge.py                   # L2 byte_length forge primitive
│   │   ├── v8_descswap.py                # Map descriptor swap
│   │   ├── v8_field_corrupt.py           # Random field corruption
│   │   ├── wasm_gen.py                   # WASM module generators
│   │   ├── regex_gen.py                  # Regex generators
│   │   └── jit_trigger.py                # %OptimizeFunctionOnNextCall etc.
│   ├── triage/
│   │   ├── __init__.py
│   │   ├── service.py                    # TriageService
│   │   ├── classifier.py                 # Output marker matching
│   │   ├── dedup.py                      # Stack hash + variant grouping
│   │   ├── exploitability.py             # Severity classifier
│   │   └── rules/                        # Per-engine classification rules
│   │       ├── v8_d8_sbx.yaml
│   │       ├── pdfium_test_sbx.yaml
│   │       └── afl_qemu.yaml
│   ├── minimization/
│   │   ├── __init__.py
│   │   ├── service.py                    # MinimizationService
│   │   └── delta_debugger.py             # Delta-debugging algorithm
│   ├── workers/                          # ARQ task definitions
│   │   ├── __init__.py
│   │   ├── fuzz_worker.py                # Run the actual fuzzing loop
│   │   ├── triage_worker.py              # Triage incoming crashes
│   │   ├── minimize_worker.py            # Minimize a finding
│   │   ├── variant_hunt_worker.py        # Find variants of confirmed bug
│   │   ├── stats_aggregator.py           # Aggregate per-worker stats every 60s
│   │   └── progression_worker.py         # Re-test old findings against new build
│   ├── workflow/
│   │   └── states/
│   │       ├── fuzz_setup.py             # Engine health check, corpus prep
│   │       ├── fuzz_campaign.py          # Long-running campaign supervisor
│   │       └── fuzz_summary.py           # Aggregate findings → advisory hand-off
│   ├── api_router.py                     # Fuzzing-specific REST endpoints
│   ├── reporting/
│   │   └── campaign_report.py            # Campaign summary + top findings
│   └── data/
│       ├── setup/
│       │   ├── fuzzilli.md               # FUZZILLI build + bring-up guide
│       │   └── afl_qemu.md
│       ├── strategies/                   # Built-in strategy presets
│       │   ├── v8_baseline.json
│       │   ├── v8_wasm_focused.json
│       │   ├── v8_jit_differential.json
│       │   └── pdfium_xfa_focused.json
│       └── corpora/                      # Seed corpora
│           ├── v8_baseline/
│           │   ├── 0001.js
│           │   └── ...
│           └── pdfium_xfa/
│               └── ...
├── frontend/
│   └── (additions to existing frontend)
│       ├── screens/
│       │   ├── FuzzCampaignsList.tsx     # All campaigns table
│       │   ├── FuzzCampaignDetail.tsx    # Live stats + crashes + controls
│       │   ├── FuzzFindingDetail.tsx     # Reproducer + minimization + classification
│       │   └── FuzzStrategyComposer.tsx  # JSON strategy editor with primitive picker
│       └── components/
│           ├── StatsTimelineChart.tsx
│           ├── CrashTriagePanel.tsx
│           ├── CorpusInspector.tsx
│           └── EngineHealthIndicator.tsx
└── alembic/versions/
    └── 029_vr_fuzzing_tables.py          # New migration
```

---

## DB Schema (additions to v0.1)

### vr_fuzz_campaigns
```sql
CREATE TABLE vr_fuzz_campaigns (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT REFERENCES vr_projects(id),  -- nullable: standalone fuzz allowed
    team_id             TEXT,
    name                TEXT NOT NULL,
    strategy_name       TEXT NOT NULL,            -- "mutational" | "differential" | "fuzzilli" | user-defined
    strategy_config_json TEXT NOT NULL,
    engine_name         TEXT NOT NULL,            -- "v8_d8_sbx" | "pdfium_test_sbx" | etc.
    engine_args_json    TEXT DEFAULT '[]',
    target_path         TEXT NOT NULL,            -- absolute path to engine binary
    target_function     TEXT,                     -- optional: function-level focus
    workdir             TEXT NOT NULL,            -- /var/lib/aila/fuzz/<id>/
    status              TEXT NOT NULL DEFAULT 'created',  -- created|running|paused|stopped|completed|error
    cpu_quota_pct       INTEGER DEFAULT 50,
    memory_limit_mb     INTEGER DEFAULT 4096,
    disk_quota_gb       INTEGER DEFAULT 10,
    concurrent_workers  INTEGER DEFAULT 4,
    max_runtime_hours   INTEGER DEFAULT 24,
    started_at          TIMESTAMPTZ,
    stopped_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);
```

### vr_fuzz_findings
```sql
CREATE TABLE vr_fuzz_findings (
    id                  TEXT PRIMARY KEY,
    campaign_id         TEXT NOT NULL REFERENCES vr_fuzz_campaigns(id),
    project_id          TEXT REFERENCES vr_projects(id),
    parent_finding_id   TEXT REFERENCES vr_fuzz_findings(id),  -- variant tree
    crash_signature     TEXT NOT NULL,            -- SHA256 (engine-aware normalization)
    classification      TEXT NOT NULL,            -- sandbox_violation|asan_finding|in_sandbox|csa_check|...
    severity            TEXT NOT NULL,            -- CRITICAL|HIGH|MEDIUM|LOW|HARMLESS
    crash_type          TEXT,                     -- D-19 vocabulary
    discovered_at       TIMESTAMPTZ NOT NULL,
    instance_count      INTEGER DEFAULT 1,        -- how many times this signature was seen
    first_seen_at       TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    reproducer_uri      TEXT,                     -- s3://.../reproducer.js
    crash_report_uri    TEXT,                     -- s3://.../crash_report.txt
    minimized_reproducer_uri TEXT,
    minimization_status TEXT DEFAULT 'pending',   -- pending|running|done|failed
    promoted_finding_id TEXT,                     -- if promoted to vr_findings
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX idx_fuzz_findings_signature_per_campaign 
    ON vr_fuzz_findings (campaign_id, crash_signature);
```

### vr_fuzz_stats_snapshots
```sql
CREATE TABLE vr_fuzz_stats_snapshots (
    id                  BIGSERIAL PRIMARY KEY,
    campaign_id         TEXT NOT NULL REFERENCES vr_fuzz_campaigns(id),
    snapshot_at         TIMESTAMPTZ NOT NULL,
    iterations          BIGINT NOT NULL,
    execs_per_sec       REAL NOT NULL,
    crashes_total       INTEGER NOT NULL,
    crashes_by_class_json TEXT NOT NULL,         -- {"sandbox_violation": 1, "in_sandbox": 1234, ...}
    unique_crashes      INTEGER NOT NULL,
    corpus_size         INTEGER,
    coverage_edges      INTEGER,                 -- if coverage-guided
    workers_alive       INTEGER NOT NULL
);
CREATE INDEX idx_fuzz_stats_campaign_time ON vr_fuzz_stats_snapshots (campaign_id, snapshot_at DESC);
```

### vr_fuzz_strategy_definitions (user-defined strategies)
```sql
CREATE TABLE vr_fuzz_strategy_definitions (
    id                  TEXT PRIMARY KEY,
    team_id             TEXT,
    name                TEXT NOT NULL,
    base_strategy       TEXT NOT NULL,            -- "mutational" | "generative"
    definition_json     TEXT NOT NULL,            -- full composition
    description         TEXT,
    created_by          TEXT,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (team_id, name)
);
```

Alembic migration: `src/aila/alembic/versions/029_vr_fuzzing_tables.py`

---

## Workflow: VR_FUZZ_CAMPAIGN_V1

Standalone workflow (separate from VR_NDAY_V1). Can be invoked directly OR composed into the future VR_FULL_RESEARCH_V1 (v0.4).

```
fuzz_setup -> fuzz_campaign -> fuzz_summary -> response_emit -> __succeeded__
                   |
                   v
         (long-running; stays in this state until campaign ends)
```

### State: fuzz_setup (timeout: 300s)
1. Verify engine binary exists and is executable
2. Engine health check (e.g., `d8 --version`, `afl-fuzz --help`)
3. Validate strategy config against schema
4. Allocate workdir
5. Pre-flight resource check (CPU/mem/disk available)
6. If `target_path` is from v0.2 recon: pull `binary_id` and any function-level metadata

**Output:** `campaign_record` initialized

### State: fuzz_campaign (timeout: max_runtime_hours * 3600, no retries)
1. Spawn `concurrent_workers` ARQ `fuzz_worker` tasks
2. Spawn one `stats_aggregator` ARQ task (interval-driven)
3. Spawn one `triage_worker` for incoming crashes
4. State enters wait-loop: campaign continues until:
   - `max_runtime_hours` hit
   - Operator stops via API (`fuzz_stop`)
   - All workers crash repeatedly (engine broken)
   - Disk quota exceeded
5. Throughout: SSE events push stat snapshots, new findings to subscribed clients

**Output:** Campaign summary (final stats, count of findings by classification)

### State: fuzz_summary (timeout: 300s)
1. Aggregate final stats
2. List top findings (sandbox_violations, ASAN, then HIGH severity)
3. For each non-harmless finding: ensure minimization completed (queue if not)
4. For each `sandbox_violation`: queue variant-hunt task
5. Write campaign report to object storage
6. If campaign was project-linked: update `vr_projects.findings_count`

**Output:** Campaign report

### State: response_emit (timeout: 60s)
Persist final state, mark campaign completed, return PlatformResponse.

---

## Strategies for v0.3

### `mutational` (built-in)
Random mutation of inputs from a corpus + composable primitives.
- Engine: any
- Config: `iterations_per_seed`, `respawn_per_minute`, `primitives` (list), `operations` (list)
- Use case: V8 sandbox fuzzing with our existing L2 forge + descriptor swap

### `differential` (built-in)
Run same JS through Ignition / Sparkplug / Maglev / TurboFan; report output divergence.
- Engine: `v8_d8_sbx` only
- Config: `tiers`, `compare_strategy`, `tier_warmup_calls`
- Use case: JIT type confusion bugs (CVE-2025-12428 family)

### `fuzzilli` (built-in, requires FUZZILLI binary)
Coverage-guided JS IL mutation.
- Engine: `fuzzilli_v8` (custom V8 build with REPRL+coverage)
- Config: `profile`, `jobs`, `engine_args`
- Use case: Deep coverage of JS engine paths. Highest CVE yield.

### `generative` (built-in)
Grammar-based input generation. Wraps Domato/jsfunfuzz-style generators.
- Engine: `v8_d8_sbx` or `pdfium_test_sbx`
- Config: `grammar`, `max_depth`, `seed_files`
- Use case: Specific feature exercise (custom descriptors, JSPI, regex)

### User-defined (composition)
JSON definition over built-in primitives. Stored in `vr_fuzz_strategy_definitions`. Created via API or UI strategy composer.

---

## API Endpoints (additions)

```
POST   /api/vr/fuzz/campaigns             create + start campaign
GET    /api/vr/fuzz/campaigns             list (filterable)
GET    /api/vr/fuzz/campaigns/<id>        full details + latest stats
DELETE /api/vr/fuzz/campaigns/<id>        stop campaign
POST   /api/vr/fuzz/campaigns/<id>/pause
POST   /api/vr/fuzz/campaigns/<id>/resume
GET    /api/vr/fuzz/campaigns/<id>/stats  time-series stats (with ?since=, ?metric=)
GET    /api/vr/fuzz/campaigns/<id>/findings  list findings (with ?classification=, ?since=)
POST   /api/vr/fuzz/campaigns/<id>/promote_finding/<finding_id>  promote to vr_finding for advisory

GET    /api/vr/fuzz/findings/<id>         full finding (with reproducer URLs)
POST   /api/vr/fuzz/findings/<id>/minimize  queue minimization
POST   /api/vr/fuzz/findings/<id>/variant_hunt  queue variant search

GET    /api/vr/fuzz/strategies            list built-in + user-defined
POST   /api/vr/fuzz/strategies            create user-defined strategy
GET    /api/vr/fuzz/strategies/<id>       definition + config schema
DELETE /api/vr/fuzz/strategies/<id>       delete user-defined

GET    /api/vr/fuzz/engines               list available engines + health
POST   /api/vr/fuzz/engines/refresh       re-run health checks

GET    /api/vr/fuzz/primitives            list available primitives + schemas

# SSE streams
GET    /api/vr/fuzz/campaigns/<id>/stream/stats    live stats updates
GET    /api/vr/fuzz/campaigns/<id>/stream/findings live finding notifications
```

---

## Build Order (Milestones)

### Milestone M3.1: Foundation (data model + DB)
**Goal:** Create the data layer; no fuzzing yet, just schema.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 1.1 | `fuzzing/contracts/campaign.py` | 80 | — |
| 1.2 | `fuzzing/contracts/finding.py` | 80 | v0.1 finding |
| 1.3 | `fuzzing/contracts/strategy.py` | 80 | — |
| 1.4 | `fuzzing/contracts/engine.py` | 50 | — |
| 1.5 | `fuzzing/contracts/stats.py` | 60 | — |
| 1.6 | `db_models/fuzz_campaign.py` | 60 | 1.1 |
| 1.7 | `db_models/fuzz_finding.py` | 70 | 1.2 |
| 1.8 | `db_models/fuzz_stats.py` | 50 | 1.5 |
| 1.9 | `db_models/fuzz_strategy_definition.py` | 50 | 1.3 |
| 1.10 | `alembic/versions/029_vr_fuzzing_tables.py` | 120 | 1.6-1.9 |

**Milestone exit:** Migrations apply. Pydantic models round-trip JSON. No business logic.

### Milestone M3.2: Engine + strategy abstractions
**Goal:** Define protocols and registry. No campaigns yet.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 2.1 | `fuzzing/engines/base.py` | 80 | — |
| 2.2 | `fuzzing/engines/health.py` | 60 | 2.1 |
| 2.3 | `fuzzing/engines/v8_d8.py` | 120 | 2.1 |
| 2.4 | `fuzzing/engines/__init__.py` (registry) | 40 | 2.1, 2.3 |
| 2.5 | `fuzzing/strategies/base.py` | 80 | — |
| 2.6 | `fuzzing/strategies/__init__.py` (registry) | 40 | 2.5 |
| 2.7 | `fuzzing/primitives/base.py` | 60 | — |
| 2.8 | `fuzzing/primitives/__init__.py` (registry) | 40 | 2.7 |

**Milestone exit:** `fuzz_list_engines()` returns `v8_d8_sbx` with health=OK. `fuzz_list_strategies()` returns empty. No execution yet.

### Milestone M3.3: First strategy (`mutational`) end-to-end
**Goal:** Run a mutational fuzz campaign through the full lifecycle once.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 3.1 | `fuzzing/primitives/v8_forge.py` | 100 | 2.7 |
| 3.2 | `fuzzing/primitives/v8_descswap.py` | 80 | 2.7 |
| 3.3 | `fuzzing/primitives/v8_field_corrupt.py` | 60 | 2.7 |
| 3.4 | `fuzzing/strategies/mutational.py` | 200 | 2.5, 3.1-3.3 |
| 3.5 | `fuzzing/manager.py` (CampaignManager) | 200 | 1.x, 2.x |
| 3.6 | `fuzzing/workers/fuzz_worker.py` (ARQ task) | 200 | 3.4, 3.5 |
| 3.7 | `fuzzing/data/strategies/v8_baseline.json` | 50 | 3.4 |
| 3.8 | `fuzzing/data/corpora/v8_baseline/0001.js` | 30 | — |
| 3.9 | `api_router.py` additions (campaign CRUD) | 200 | 3.5 |

**Milestone exit:** Can `POST /api/vr/fuzz/campaigns` with strategy=mutational, engine=v8_d8_sbx, target=our compiled d8. Campaign runs. Crashes appear in `crashes/` dir on disk.

### Milestone M3.4: Triage + dedup
**Goal:** Crashes get classified and deduped automatically.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 4.1 | `fuzzing/triage/classifier.py` | 150 | — |
| 4.2 | `fuzzing/triage/dedup.py` | 120 | — |
| 4.3 | `fuzzing/triage/exploitability.py` | 100 | — |
| 4.4 | `fuzzing/triage/service.py` | 150 | 4.1-4.3 |
| 4.5 | `fuzzing/triage/rules/v8_d8_sbx.yaml` | 80 | — |
| 4.6 | `fuzzing/workers/triage_worker.py` (ARQ task) | 100 | 4.4 |
| 4.7 | `fuzzing/api_router.py` finding endpoints | 100 | 4.4 |

**Milestone exit:** All crashes from M3.3 campaigns appear in `vr_fuzz_findings` with classification + severity + stack hash. `GET /api/vr/fuzz/campaigns/<id>/findings?classification=sandbox_violation` returns the gold ones.

### Milestone M3.5: Stats + observability
**Goal:** Campaign progress is observable while running.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 5.1 | `fuzzing/workers/stats_aggregator.py` | 100 | — |
| 5.2 | `fuzzing/manager.py` stats methods | 80 | 1.8 |
| 5.3 | `api_router.py` stats endpoints | 80 | 5.2 |
| 5.4 | `api_router.py` SSE stats stream | 100 | 5.3 |
| 5.5 | `reporting/campaign_report.py` | 150 | 5.2 |

**Milestone exit:** `GET /api/vr/fuzz/campaigns/<id>/stats` returns current snapshot. SSE stream pushes updates every 60s. Campaign report renders.

### Milestone M3.6: Workflow integration
**Goal:** Campaign is a first-class VR workflow, can be triggered by N-day workflow if a fuzz target identified.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 6.1 | `fuzzing/workflow/states/fuzz_setup.py` | 100 | 3.5 |
| 6.2 | `fuzzing/workflow/states/fuzz_campaign.py` | 150 | 3.5, 5.x |
| 6.3 | `fuzzing/workflow/states/fuzz_summary.py` | 100 | 5.5 |
| 6.4 | `fuzzing/workflow/definitions.py` (VR_FUZZ_CAMPAIGN_V1) | 60 | 6.1-6.3 |
| 6.5 | `runtime.py` updates (workflow dispatch) | 30 | 6.4 |

**Milestone exit:** Campaign can be created via PlatformRequest (workflow path), not just direct API. Status visible in workflow runs UI.

### Milestone M3.7: Frontend
**Goal:** Web UI for campaign monitoring.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 7.1 | `frontend/queries.ts` additions (fuzz queries) | 60 | API |
| 7.2 | `frontend/mutations.ts` additions | 40 | API |
| 7.3 | `frontend/screens/FuzzCampaignsList.tsx` | 200 | 7.1 |
| 7.4 | `frontend/screens/FuzzCampaignDetail.tsx` | 350 | 7.1, 7.2 |
| 7.5 | `frontend/screens/FuzzFindingDetail.tsx` | 200 | 7.1 |
| 7.6 | `frontend/components/StatsTimelineChart.tsx` | 150 | recharts (catalog) |
| 7.7 | `frontend/components/CrashTriagePanel.tsx` | 120 | 7.5 |
| 7.8 | `frontend/components/EngineHealthIndicator.tsx` | 80 | 7.3 |
| 7.9 | `frontend/spec.ts` route additions | 20 | 7.3-7.5 |

**Milestone exit:** Operator can browse campaigns, drill into one, see live stats graph, view findings, open reproducer.

### Milestone M3.8: Strategy composition (user-defined)
**Goal:** Users can build custom strategies through the UI without writing Python.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 8.1 | `fuzzing/strategies/composer.py` | 250 | 2.5, 3.1-3.3 |
| 8.2 | `api_router.py` strategy CRUD endpoints | 100 | 8.1 |
| 8.3 | `api_router.py` primitives catalog endpoint | 60 | 2.8 |
| 8.4 | `frontend/screens/FuzzStrategyComposer.tsx` | 400 | 8.2, 8.3 |

**Milestone exit:** User creates `v8_wasm_focused` strategy in UI, saves to DB, starts campaign with it. Strategy runs by composing primitives at runtime.

### Milestone M3.9: Minimization
**Goal:** Crashes are reduced to minimal reproducers.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 9.1 | `fuzzing/minimization/delta_debugger.py` | 200 | — |
| 9.2 | `fuzzing/minimization/service.py` | 150 | 9.1 |
| 9.3 | `fuzzing/workers/minimize_worker.py` (ARQ) | 100 | 9.2 |
| 9.4 | `api_router.py` minimize endpoint | 50 | 9.2 |

**Milestone exit:** `POST /api/vr/fuzz/findings/<id>/minimize` runs in background, replaces reproducer with minimum crashing input.

### Milestone M3.10: Variant hunt + advisory hand-off
**Goal:** Confirmed bugs auto-trigger variant search and feed N-day workflow.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 10.1 | `fuzzing/workers/variant_hunt_worker.py` | 200 | 9.x |
| 10.2 | `fuzzing/manager.py` promotion logic | 80 | v0.1 vr_findings |
| 10.3 | `api_router.py` promote endpoint | 50 | 10.2 |

**Milestone exit:** `sandbox_violation` finding auto-queues variant hunt + can be promoted to `vr_findings` for v0.1 advisory generation.

### Milestone M3.11: Differential strategy
**Goal:** Run same JS through multiple V8 tiers, report divergence.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 11.1 | `fuzzing/strategies/differential.py` | 250 | 2.5, 2.3 |
| 11.2 | `fuzzing/engines/v8_d8.py` tier control methods | 80 | 2.3 |
| 11.3 | `fuzzing/triage/classifier.py` divergence rules | 60 | 4.1 |

**Milestone exit:** `differential` strategy available. Detects output mismatch between Ignition and TurboFan as a divergence finding.

### Milestone M3.12: FUZZILLI integration (optional, gated on infrastructure)
**Goal:** Coverage-guided fuzzing via FUZZILLI subprocess.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 12.1 | `fuzzing/data/setup/fuzzilli.md` | doc | — |
| 12.2 | `fuzzing/engines/fuzzilli_v8.py` | 200 | 2.1 |
| 12.3 | `fuzzing/strategies/fuzzilli.py` | 250 | 2.5, 12.2 |
| 12.4 | Health check for fuzzilli binary | 40 | 2.2 |

**Milestone exit:** If FUZZILLI binary present, `fuzzilli` strategy available. Operator can start coverage-guided campaign.

### Milestone M3.13: Tests + benchmark
**Goal:** Verify v0.3 against known-buggy targets.
| # | File | LOC est | Depends on |
|---|---|---|---|
| 13.1 | `tests/vr/fuzzing/test_contracts.py` | 100 | 1.x |
| 13.2 | `tests/vr/fuzzing/test_triage.py` | 200 | 4.x |
| 13.3 | `tests/vr/fuzzing/test_strategy_composer.py` | 150 | 8.1 |
| 13.4 | `tests/vr/fuzzing/test_minimization.py` | 120 | 9.x |
| 13.5 | `tests/vr/fuzzing/benchmark/` (5 known-buggy V8 builds) | data | — |
| 13.6 | `tests/vr/fuzzing/benchmark/test_benchmark.py` | 200 | M3.1-M3.10 |

**Milestone exit:** Benchmark runs on a vulnerable V8 build (e.g., a pre-CVE version), finds the known crash, dedups correctly, minimizes, classifies as `sandbox_violation`. Score: hit rate, time-to-first-crash, false-positive rate.

---

## Total Estimate

| Milestone | Files | LOC | Cumulative |
|---|---|---|---|
| M3.1 Data model + DB | 10 | ~700 | 700 |
| M3.2 Abstractions | 8 | ~520 | 1220 |
| M3.3 First strategy E2E | 9 | ~1120 | 2340 |
| M3.4 Triage + dedup | 7 | ~800 | 3140 |
| M3.5 Stats + observability | 5 | ~510 | 3650 |
| M3.6 Workflow integration | 5 | ~440 | 4090 |
| M3.7 Frontend | 9 | ~1620 | 5710 |
| M3.8 Strategy composition | 4 | ~810 | 6520 |
| M3.9 Minimization | 4 | ~500 | 7020 |
| M3.10 Variant hunt + promotion | 3 | ~330 | 7350 |
| M3.11 Differential strategy | 3 | ~390 | 7740 |
| M3.12 FUZZILLI (optional) | 4 | ~490+doc | 8230 |
| M3.13 Tests + benchmark | 6 | ~770 | 9000 |
| **Total** | **77 files** | **~9000 LOC** | |

---

## Verification Checklist

Before marking v0.3 complete:

- [ ] All v0.1 verification items still pass
- [ ] `python -m compileall src/aila/modules/vr/fuzzing -q` — zero errors
- [ ] `python -m ruff check src/aila/modules/vr/fuzzing/` — clean
- [ ] `python -m aila.tools.honesty_audit src/aila/modules/vr/fuzzing` — zero findings
- [ ] `alembic upgrade head` — migration applies cleanly
- [ ] `cd frontend && pnpm -r run type-check` — clean (with new fuzz screens)
- [ ] Unit tests: contracts, triage, dedup, classifier, minimization
- [ ] Integration test: start campaign → see crashes appear → minimize → triage → SSE stream pushes updates
- [ ] Benchmark: vulnerable V8 build → finds known sandbox_violation within 10 min → minimizes to <100 lines → hands off to advisory
- [ ] Resource limits enforced (CPU/mem/disk caps respected)
- [ ] Concurrent campaigns isolate properly (one campaign's crash doesn't kill another's worker)
- [ ] Strategy composer: build a strategy in UI, save, run, see crashes
- [ ] Engine health: when d8 binary missing, campaign fails gracefully with clear error

---

## Risks & Open Questions

### R-1: FUZZILLI build complexity
FUZZILLI requires custom V8 build with REPRL+coverage. ~2 hours per V8 version. Document in `data/setup/fuzzilli.md`. If too painful, defer M3.12 to v0.4.

### R-2: Stats database growth
At 60s aggregation × 24h × 30 days × 100 campaigns = 4.3M rows in `vr_fuzz_stats_snapshots`. Need partitioning (by month) and a cleanup task.

### R-3: Crash storage growth
Sandbox-testing fuzzers produce thousands of crashes per hour. Without dedup, disk fills fast. Dedup happens AT TRIAGE TIME — first hour of a campaign may produce 10K duplicate crashes before triage catches up. Need backpressure: pause workers if `crashes/` dir > 500MB.

### R-4: Differential fuzzing false positives
Different V8 tiers DO produce slightly different output for valid programs (precision differences in Math operations, GC timing visible to JS, etc.). Need a baseline whitelist of "expected" divergences. Initial false-positive rate may be 80%+. Document as known limitation.

### R-5: Variant hunt explosion
A single sandbox_violation generating 10 variants, each potentially generating 10 more, = exponential. Cap variant tree depth at 2 levels. Reset budget per parent finding.

### R-6: Multi-machine scheduling deferred
v0.3 is single-machine multi-process. Multi-machine distributed fuzzing (FUZZILLI tree hierarchy, ClusterFuzz-style bots) is **explicitly deferred** to v0.5+ when kernel/hypervisor fuzzing brings broader infrastructure needs.

### R-7: Strategy plugin upload (security)
v0.3 user-defined strategies = composition over built-in primitives (safe). Plugin upload (drop a .py file with custom Strategy class) requires sandboxing the plugin execution. Defer to later when need is proven.

---

## Out of Scope (deferred to later versions)

- Network protocol fuzzing (live targets) — v0.5+
- Kernel fuzzing (syzkaller-style) — v0.5
- Distributed fuzzing across machines — v0.5
- Web UI strategy plugin upload — later
- Continuous fuzzing in CI/CD — later
- Automatic CVE attribution / public bug correlation — v0.4 cross-project knowledge
- Hypervisor / VM escape fuzzing — v0.5
