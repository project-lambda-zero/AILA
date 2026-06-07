# Platform Internals

What happens inside AILA when a request arrives, traced end-to-end through every layer. Read this before writing a module, debugging a scan, or changing platform code.

---

## The Full Path of a Request

A user types `scan raspi`. Here is every component it touches, in order.

```
User: "scan raspi"
  |
  +-- [1] CLI / API entry
  |     aila task "scan raspi"        (CLI: direct platform.handle)
  |     POST /analyze {targets: [...]} (API: TaskQueue -> ARQ -> platform.handle)
  |
  +-- [2] Platform orchestrator
  |     Creates RunState + WorkflowRunRecord
  |     Builds EventEmitter with 3 destinations (audit DB, run history, progress SSE)
  |
  +-- [3] LLM Router (two-tier)
  |     Tier 1: DecisionCache (keyed on query + profile hash, TTL-based)
  |     Tier 2: LLM call with all module CapabilityProfiles as candidates
  |     Output: RouteDecision(action_id="vulnerability.analyze_fleet", confidence=0.87)
  |
  +-- [4] Module dispatch
  |     PlatformRuntime.require_module("vulnerability") -> VulnerabilityRuntime
  |     VulnerabilityRuntime.handle(ModuleRequest) invoked
  |
  +-- [5] Two-level workflow dispatch
  |     analyze_fleet @platform_task(definition=VULNERABILITY_DISPATCHER_V1)
  |     Dispatcher: routing -> operation_selection -> __succeeded__
  |     Output: selected_definition_id = "full_analysis"
  |
  +-- [6] Inner workflow execution (DurableStateMachine)
  |     VULNERABILITY_FULL_ANALYSIS_V1:
  |     inventory -> advisory -> intel -> scoring -> report -> persist -> response_emit
  |     Each state: handler(state_input, services) -> StateResult(next_state, output)
  |     Cursor persisted to workflow_state_cursor between every transition
  |
  +-- [7] State handlers (module domain code)
  |     inventory:     SSH into raspi, collect 1617 packages
  |     advisory:      Query OSV + Debian feeds for 413 advisories
  |     intel:         Fetch EPSS + KEV + NVD for 364 CVEs
  |     scoring:       Score 366 findings (LLM or cache)
  |     report:        Generate summary narrative
  |     persist:       Write FindingRecords + ReportArtifact to DB
  |     response_emit: Build PlatformResponse with module_payload
  |
  +-- [8] Response assembly
  |     PlatformResponse returned up through orchestrator
  |     WorkflowRunRecord finalized (status, route_json, summary_json, report_path)
  |     Emitter writes final audit event
  |
  +-- [9] Output
        CLI: JSON printed to stdout
        API: TaskRecord updated to DONE, result available via GET /tasks/{id}
```

---

## Layer 1: Entry Points

Two paths into the platform. Both converge at `AILAPlatform.handle()`.

### CLI path (synchronous)

```
aila task "scan raspi"
  -> cli.py::task()
  -> asyncio.run(AILAPlatform().handle(query="scan raspi"))
```

Direct call. No task queue. No TaskRecord. The scan runs in the CLI process and blocks until complete. Used for development and one-off queries.

### API path (async via task queue)

```
POST /analyze {"query_text": "scan raspi", "targets": ["raspi"]}
  -> scans.py::submit_scan()
  -> TaskQueue.submit(track="vulnerability", fn=run_platform_handle, kwargs={...})
  -> TaskRecord created (status=QUEUED)
  -> ARQ enqueues to Redis (arq:queue:vulnerability)
  -> 202 Accepted returned immediately with task_id

Worker picks up job:
  -> on_job_start hook: TaskRecord -> RUNNING
  -> run_platform_handle(ctx, query="scan raspi", module_payload={...})
  -> platform.handle(query=..., run_id=task_id)
  -> on_job_end hook: TaskRecord -> DONE (or DEAD_LETTER on failure)
```

The API path decouples submission from execution. The caller polls `GET /tasks/{task_id}` for status. Long-running scans (minutes) use this path. ARQ runs five queues (`default | vulnerability | forensics | sbd_nfr | vr`), selected via the `track=` argument on `TaskQueue.submit()`.

### What TaskQueue.submit() does

1. Computes SHA-256 dedup hash of `{fn, kwargs}`. Returns existing handle if an identical active task exists.
2. Validates module boundary (the function must belong to the declared module).
3. Creates `TaskRecord` in DB (status QUEUED or WAITING if dependencies).
4. Validates dependency DAG for cycles.
5. Enqueues to ARQ via Redis `ZADD`.
6. Returns `TaskHandle(task_id)`.
7. If Redis is unreachable, `submit()` deletes the ghost `TaskRecord` and raises `WorkerUnreachableError` (HTTP 503). There is no in-process fallback execution (D-19, Phase 178).

---

## Layer 2: Platform Orchestrator

`AILAPlatform.handle()` in `platform/runtime/orchestrator.py`. The nerve center.

```python
async def handle(self, query, module_payload, module_options, ...):
    run_state = RunState(run_id=..., query=query)

    async with async_session_scope() as session:
        emitter = build_emitter(session, run_state, progress_callback)

        # Route
        route = await self.router.route(session, query)
        run_state.route = route

        # Dispatch
        response = await _dispatch_module_request(
            runtime, session, route.action_id, run_id, run_state,
            execution_context, module_payload, module_options
        )

        # Finalize
        await _finalize_run(session, run_record, run_state, "completed", response)
        return response
```

Effective middleware order (outer to inner): `_prometheus_request_middleware -> _reject_oversized_requests -> _catch_unhandled_exceptions -> CORSMiddleware -> IdempotencyMiddleware -> CorrelationIdMiddleware -> route handler`. Starlette applies middleware LIFO, so the last-added wrapper runs first; see `src/aila/api/app.py`.

**What it owns:**
- RunState lifecycle (creation through finalization)
- WorkflowRunRecord persistence (route_json, summary_json, short_memory_json)
- EventEmitter construction and fan-out wiring
- Error handling: any exception -> status="failed" finalization, event emitted, then re-raised

**What it does NOT own:**
- Module domain logic (delegated to module runtime)
- Workflow state machine (delegated to DurableStateMachine)
- LLM calls (delegated to AilaLLMClient)

---

## Layer 3: LLM Router

`ModuleRouter` in `platform/routing/router.py`. Decides which module handles a query.

### Two tiers

**Tier 1 -- Cache.** `DecisionCache` stores previous routing decisions keyed on `(query, module_profiles_hash)`. If a cached decision exists and hasn't expired, it's returned without an LLM call.

**Tier 2 -- Model.** Sends a structured JSON prompt to `AilaLLMClient` listing every registered module's `CapabilityProfile`:

```json
{
  "candidates": [
    {
      "module_id": "vulnerability",
      "action_id": "vulnerability.analyze_fleet",
      "description": "Analyze registered systems over SSH...",
      "tools": ["registry.systems", "ssh.command", ...],
      "examples": ["scan my fleet", "check for CVEs on arch-vm", ...]
    },
    ...
  ],
  "query": "scan raspi"
}
```

The model returns `RoutingSelection(module_id, action_id, confidence, rationale)`. If confidence < `minimum_confidence` (default 0.2), the query is marked unroutable.

### Where CapabilityProfiles come from

Each module defines them in `capabilities.py`:

```python
MODULE_DESCRIPTION = "Analyze registered systems over SSH..."
MODULE_TOOLS = ("vulnerability.scan", "vulnerability.score")
MODULE_EXAMPLES = ("scan my fleet", "check for CVEs on arch-vm")
```

The module's `capability_profiles()` method wraps these into `ModuleCapabilityProfile` objects. The platform's `ModuleRegistry` collects all profiles at boot and hands them to the router.

---

## Layer 4: LLM Pipeline

Every LLM call in the platform goes through `AilaLLMClient.chat()`, which runs a fixed-order middleware pipeline:

```
classify -> [API call] -> validate -> gate -> verify -> seal
```

| Step | What it does | Fail mode |
|---|---|---|
| **classify** | Content classification. Can block the call before it reaches the API. | Configurable: `transparent` (log only) or `restrictive` (block) |
| **API call** | OpenAI-compatible `chat/completions`. Temperature stripped for models in the rejection list. | Hard failure -> LLMTransientError (retriable) |
| **validate** | Response shape validation. Checks the response is parseable. | Fail-open (log + continue) or fail-closed (reject) |
| **gate** | Post-response gating. Can replace or block the response. | Configurable per task_type |
| **verify** | Evidence verification. Checks claims against stored data. | Fail-open |
| **seal** | Cryptographic audit seal. SHA-256 hash of (prompt + response + model + timestamp) stored as `AuditSealRecord`. | Fail-open |

### Configuration

Pipeline behavior is per-`task_type`. Each module names its task types (e.g., `forensics_freeflow`, `vulnerability_scoring`). The `LLMConfigProvider` resolves:

```
env var AILA_PLATFORM_LLM_PIPELINE_{STEP}_RESTRICTED_BEHAVIOR_{TASK_TYPE}
  -> ConfigRegistry platform.llm_pipeline_{step}_restricted_behavior_{task_type}
  -> default: "transparent"
```

Values: `transparent` (log classification, don't block), `restrictive` (block on classification match).

### Cost tracking

Every LLM call records token usage in `CostRecord`:
- `prompt_tokens`, `completion_tokens`, `total_tokens`
- `estimated_cost_usd` (derived from model pricing table)
- `task_type`, `run_id`, `model_id`

Accessible via `GET /admin/cost` (Cost Intelligence page).

---

## Layer 5: Event System

`EventEmitter` in `platform/events/emitter.py`. Fan-out delivery to 3 destinations per request.

```
emitter.emit(PlatformEvent(stage="inventory", action="start", message="..."))
  |
  +-- audit_db:    INSERT INTO workflowauditrecord
  +-- run_history: Append to RunState.events (in-memory, serialized at finalization)
  +-- progress:    SSE stream via Redis XADD (consumed by frontend EventSource)
```

### Thread safety

`ThreadSafeEventEmitter` wraps emit() in a drain queue with a non-blocking lock. Parallel SSH workers, DAG stages, and scoring threads all call emit() safely without external locking. The drain loop is synchronous; async destinations receive events in drain order without blocking fast sync destinations.

### PlatformEvent

```python
@dataclass(frozen=True, slots=True)
class PlatformEvent:
    stage: str                          # "routing", "inventory", "scoring", ...
    action: str                         # "start", "complete", "fail", "progress"
    key: str                            # dedup key for SSE reconnection
    message: str                        # human-readable summary
    details: dict = field(default_factory=dict)   # structured payload
    run_id: str = ""
    current: int | None = None          # progress: items completed
    total: int | None = None            # progress: total items
    progress_message: str | None = None # progress: status text
```

---

## Layer 6: Module Runtime

Each module's `runtime.py` implements `ModuleRuntime.handle()`. This is the entry point the orchestrator calls after routing.

For simple modules (hello_world), handle() runs the workflow directly and returns a PlatformResponse.

For complex modules (vulnerability, forensics), handle() calls the module's `@platform_task`-decorated entry point with a synthetic ARQ context, which drives the `DurableStateMachine` through the full workflow definition.

### What handle() receives

```python
ModuleRequest(
    session: AsyncSession,          # active DB session (do not create new ones)
    run_id: str,                    # unique run identifier
    action_id: str,                 # "vulnerability.analyze_fleet"
    run_state: RunState,            # contains RouteDecision + events
    execution_context: ModuleExecutionContext(
        memory_store: PermanentMemoryStore,
        report_artifact_store: ReportArtifactStore,
        progress_callback: Callable,
        emitter: EventEmitter,
        task_queue: TaskQueue | None,
    ),
    payload: dict,                  # module-specific input
    options: dict,                  # module-specific options
)
```

### Critical rule

Everything in `ModuleRequest` that gets passed as a kwarg to a `@platform_task` function **must be JSON-serializable**. Pydantic models must be `.model_dump(mode="json")`. The workflow engine validates this at entry via `json.dumps(initial_input, default=None)` (`src/aila/platform/workflows/engine.py:112`) and crashes with a clear TypeError if violated.

---

## Layer 7: Durable State Machine

`DurableStateMachine` in `platform/workflows/engine.py`. Drives workflow definitions through their state graph with crash recovery.

See `docs/WORKFLOW_GUIDE.md` for the full handler contract, StateSpec configuration, envelope pattern, and do/don't rules.

### What makes it durable

1. **Cursor persistence.** After every state transition, the engine writes `(run_id, current_state, state_input, version)` to `workflow_state_cursor`. If the worker crashes mid-flight, the next ARQ retry loads the cursor and resumes from the last committed state.

2. **Optimistic locking.** The cursor UPDATE guards `WHERE version = :loaded_version`. If two workers race on the same run_id, one sees 0 rows affected and raises `WorkflowConflictError`, which ARQ retries with backoff.

3. **Audit trail.** Every transition writes `entered` and `exited` rows to `workflowauditrecord` with timing, output snapshot, and error details. The timeline page renders these.

4. **Per-state retry.** Each `StateSpec` declares `max_retries` and `retriable_on`. The engine retries transient failures (network, DB, LLM) within the state before transitioning to `on_failure` or `__crashed__`.

---

## Layer 8: Cyber Reasoning Engine

`CyberReasoningEngine` in `platform/services/reasoning.py`. Multi-turn LLM reasoning protocol used inside workflow state handlers (currently by forensics and vr).

See `docs/WORKFLOW_GUIDE.md` (Cyber Reasoning Engine section) for the turn loop, case state merging, evidence graphs, domain profiles, and operator steering.

### Where it fits

```
Workflow state handler (e.g., state_freeflow)
  |
  +-- CyberReasoningEngine.decide_next_turn()    # LLM call
  |     +-- AilaLLMClient.chat()                 # goes through pipeline
  |           +-- classify -> call -> validate -> gate -> verify -> seal
  |
  +-- CyberReasoningEngine.absorb()              # merge decision into case state
  |
  +-- Module executes action                     # script_execute, tool_run
  |     +-- SSHCommandTool.forward()             # SSH into target
  |     +-- ScriptTool.execute()                 # run analysis script
  |
  +-- ReasoningGraphService.save_snapshot()       # persist evidence graph to DB
  |
  +-- Loop until submit or max_turns
```

The engine owns the protocol (prompt framing, JSON extraction, hypothesis tracking, evidence graph construction). The module owns the domain (which tools to run, how to interpret output, when to stop).

---

## Layer 9: Storage

### Database (PostgreSQL + SQLModel)

Key tables and who owns them:

| Table | Owner | Purpose |
|---|---|---|
| `workflowrunrecord` | Platform | One row per handle() call. Status, route, summary, report path. Writes use `session.merge()` (not `add()`) because orchestrator and engine may both create the row for the same `run_id`; see `src/aila/platform/runtime/orchestrator.py:304, 309`. |
| `workflow_state_cursor` | Platform | Durable state machine cursor. FK to workflowrunrecord. |
| `workflowauditrecord` | Platform | Audit trail: every state transition with timing and output. |
| `taskrecord` | Platform | Task queue: status, fn_path, kwargs, depends_on, heartbeat. |
| `auditsealrecord` | Platform | LLM audit seals: SHA-256 hash of prompt + response. |
| `costrecord` | Platform | LLM cost tracking: tokens, model, estimated USD. |
| `configentryrecord` | Platform | Runtime config: namespace + key + value (env var override). |
| `managedsystemrecord` | Platform | SSH targets: name, host, username, port, credentials. |
| `latestfindingrecord` | Vulnerability | Materialized findings: one row per (host, package, CVE). |
| `reportartifactrecord` | Platform | Report blobs: JSON artifacts keyed by run_id + artifact_type. |
| `seedversionrecord` | Platform | Per-module seed idempotency guard. |
| `reasoning_graph_snapshot` | Platform | Evidence graph snapshots per investigation turn. |

### Redis

Used for three things:
1. **ARQ task queue.** Sorted sets keyed by `arq:queue:{track}`. Workers poll with ZRANGEBYSCORE.
2. **SSE progress streams.** Redis Streams keyed by `aila:progress:{run_id}`. Frontend EventSource reads via XREAD.
3. **Worker heartbeat.** Workers write `aila:heartbeat:{worker_id}` with TTL. Health endpoint checks key existence.

A cron-driven sweep in `src/aila/platform/tasks/cursor_reaper.py` issues an ORM `delete(WorkflowStateCursor)` every minute for `__crashed__` cursors whose `run_id` no longer has an active `TaskRecord`.

### Report artifacts

Large outputs (finding rows, summary narratives) are stored as `ReportArtifactRecord` blobs, not inline in the run record. The `report_path` field on `WorkflowRunRecord` points to the primary artifact ID.

---

## Layer 10: Frontend Extension

Modules contribute UI via `ModuleFrontendSpec`:

```typescript
interface ModuleFrontendSpec {
  moduleId: string;
  nav?: NavContribution[];       // sidebar entries
  routes?: RouteContribution[];  // page routes
  panels?: PanelContribution[];  // injected panels (system detail, finding detail)
  widgets?: WidgetContribution[]; // dashboard widgets
}
```

The platform shell (`AppShell`, `AppSidebar`, `router.tsx`) discovers all module specs at boot via `loadModuleFrontendSpecs()` and merges their contributions into the app structure. No platform code changes needed to add a module's UI.

### Design system

All module UI uses the platform design system:
- CSS variables: `var(--color-base)`, `var(--color-surface)`, `var(--color-accent)`, `var(--color-text)`, `var(--color-border)`
- Tailwind tokens: `bg-base`, `bg-surface`, `bg-elevated`, `text-text`, `text-text-muted`, `text-accent`, `border-border`
- Components: `AilaCard`, `AilaBadge`, `EmptyState`, `PageFrame`, shadcn

No custom CSS files. No hardcoded hex colors. No Tailwind v4 arbitrary values (they don't generate CSS).

---

## How the Layers Connect

```
                    +-----------+
                    |  CLI/API  |  <-- entry
                    +-----+-----+
                          |
                    +-----v-----+
                    | TaskQueue |  <-- API path only (submit -> ARQ -> worker)
                    +-----+-----+
                          |
                    +-----v------+
                    | Orchestrator|  <-- RunState, emitter, finalization
                    +-----+------+
                          |
                +----+----v----+----+
                |                    |
          +-----v-----+    +--------v--------+
          |  LLM Router|    |  Module Dispatch |
          |  (2-tier)  |    |  (by action_id)  |
          +-----+------+    +--------+--------+
                |                     |
          +-----v------+    +--------v--------+
          |  LLM Client |    | Module Runtime  |
          |  (pipeline)  |    | handle()        |
          +--------------+    +--------+--------+
                                       |
                              +--------v--------+
                              | Durable State   |
                              | Machine (engine) |
                              +--------+--------+
                                       |
                    +------------------+------------------+
                    |                  |                   |
              +-----v-----+    +------v------+    +-------v-------+
              |  State     |    |  Reasoning  |    |  Services     |
              |  Handlers  |    |  Engine     |    |  (emitter,    |
              |  (module)  |    |  (platform) |    |   session,    |
              +-----+------+    +------+------+    |   tools)      |
                    |                  |            +---------------+
                    +--------+---------+
                             |
                    +--------v--------+
                    |   PostgreSQL    |
                    |   + Redis      |
                    +-----------------+
```

Each arrow is a function call you can grep for:
- `platform.handle()` -> orchestrator entry
- `router.route()` -> LLM routing
- `module_runtime.handle()` -> module dispatch
- `DurableStateMachine.execute()` -> workflow engine
- `handler(state_input, services)` -> state execution
- `engine.decide_next_turn()` -> reasoning LLM call
- `emitter.emit()` -> fan-out to audit/SSE/history
- `session.exec()` -> database
- `arq.enqueue_job()` -> Redis task queue
