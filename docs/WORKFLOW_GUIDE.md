# Workflow Stages Guide

How state machines work in AILA, with real examples from production modules.

---

## Architecture

Every module that does multi-step work uses the **DurableStateMachine** engine. The engine persists state to PostgreSQL (`workflow_state_cursor` table) between steps so work survives crashes and retries.

```
WorkflowDefinition
  |
  +-- definition_id: "vulnerability.full_analysis.v1"
  +-- start_state: "inventory"
  +-- states:
  |     "inventory"   -> StateSpec(handler, timeout, retries, on_success="advisory")
  |     "advisory"    -> StateSpec(handler, timeout, retries, on_success="intel")
  |     "intel"       -> StateSpec(handler, timeout, retries, on_success="scoring")
  |     "scoring"     -> StateSpec(handler, timeout, retries, on_success="report")
  |     "report"      -> StateSpec(handler, timeout, retries, on_success="persist")
  |     "persist"     -> StateSpec(handler, timeout, retries, on_success="response_emit")
  |     "response_emit" -> StateSpec(handler, timeout, on_success="__succeeded__")
  |     "__succeeded__" (auto-registered terminal)
  |     "__failed__"    (auto-registered terminal)
  |     "__crashed__"   (auto-registered terminal)
  |     "__cancelled__" (auto-registered terminal)
  +-- services_factory: async (run_id) -> WorkflowServices
```

A fifth reserved state, `__paused__`, exists for engine-level pause / resume
(Phase B). It is NOT a terminal -- the cursor sits at `__paused__` while
the prior `current_state` is preserved in the cursor's `archived_state` column
(migration 067). Resume swaps `archived_state` back to `current_state`.
`__paused__` is not a member of `RESERVED_TERMINAL_STATES`; the main engine
loop skips it. Source: `src/aila/platform/workflows/types.py:36-42`.

The engine loop:
1. Load or create cursor row for `run_id`
2. Call `services_factory(run_id)` to build a fresh services bundle
3. Call `handler(state_input, services)` -> `StateResult(next_state, output)`
4. Persist cursor: `state_input = output`, `current_state = next_state`
5. Repeat until a terminal state is reached

---

## Handler Contract

Every state handler is an async function with this exact signature:

```python
async def state_my_step(
    state_input: dict[str, Any],
    services: MyModuleWorkflowServices,
) -> StateResult:
```

**Parameters:**
- `state_input` -- the previous handler's `output` dict (or the initial kwargs on first entry)
- `services` -- a module-specific services bundle built fresh per state execution

**Return:** `StateResult(next_state="...", output={...})`

### Rules

1. **`output` must be JSON-serializable.** `StateResult` validates this at construction time via `json.dumps()`. If your output contains a Pydantic model, datetime, UUID, or any non-primitive, serialize it first. The engine will reject it with a `ValidationError` otherwise.
   - Validated by `StateResult` model_validator at `src/aila/platform/workflows/types.py:119`.

2. **`state_input` is a `dict[str, Any]`.** Not a Pydantic model. Not a dataclass. Every handler receives a raw dict and must parse what it needs from it.

3. **Handlers must be idempotent.** The engine may re-run a handler on retry (crash recovery, ARQ retry, timeout). If the handler already performed a side effect (wrote to DB, made an API call), re-running must not corrupt state.

4. **Side effects go through `services`.** Never create your own DB session, Redis connection, or HTTP client inside a handler. Use the services bundle -- it is scoped to the current execution and rolls back cleanly on cancellation.

5. **Emit progress via `services.emitter`.** This writes audit trail rows and feeds SSE streams.

---

## StateSpec Configuration

Each state in a `WorkflowDefinition` is described by a `StateSpec`:

```python
StateSpec(
    handler=_h(state_inventory),    # the async handler function
    timeout_s=600.0,                # asyncio.wait_for wraps the handler
    max_retries=2,                  # retry budget per state (0 = no retries)
    retriable_on=(TimeoutError,),   # exception types that trigger retry
    on_success="advisory",          # next state on success (static edge)
    on_failure="__crashed__",       # next state on exhausted retries (optional)
    output_schema=IntelOutput,      # Pydantic model to validate output (optional)
)
```

| Field | Default | Purpose |
|---|---|---|
| `handler` | required | The async function to call |
| `timeout_s` | 300.0 | Handler timeout in seconds |
| `max_retries` | 0 | Number of retries before transitioning to `on_failure` |
| `retriable_on` | `()` | Tuple of exception types that trigger retry |
| `on_success` | `None` | Static edge to next state (handler can override via `next_state`) |
| `on_failure` | `None` | State to transition to when retries exhausted (defaults to `__crashed__`) |
| `output_schema` | `None` | Pydantic model to validate handler output |
| `terminal` | `False` | If True, engine exits without calling handler |

---

## The Envelope Pattern

Production handlers use an "envelope" pattern to carry state between stages. The envelope is a dict with a stable outer shape and a serialized snapshot inside:

```python
def _envelope(state_input: dict[str, Any], snapshot: AnalysisStateSnapshot) -> dict[str, Any]:
    """Rebuild state_input with updated snapshot; preserve non-snapshot keys."""
    envelope = dict(state_input)
    envelope["snapshot"] = snapshot.model_dump(mode="json")
    return envelope
```

Each handler:
1. Extracts the snapshot: `snapshot = _extract_snapshot(state_input)`
2. Does its work
3. Updates the snapshot
4. Returns: `StateResult(next_state="...", output=_envelope(state_input, new_snapshot))`

This pattern ensures:
- Non-snapshot keys (e.g., `execution_mode`, `team_id`) survive across states
- The snapshot is always JSON-serializable (`model_dump(mode="json")`)
- Each handler only modifies the fields it owns

---

## Two-Level Dispatch

Complex modules use a **dispatcher** definition that selects a mode-specific inner definition:

```
Dispatcher (routing -> operation_selection -> __succeeded__)
  |
  +-- dispatches_to:
        "full_analysis"    -> VULNERABILITY_FULL_ANALYSIS_V1
        "report_summary"   -> VULNERABILITY_REPORT_SUMMARY_V1
        "report_count"     -> VULNERABILITY_REPORT_COUNT_V1
        "report_findings"  -> VULNERABILITY_REPORT_FINDINGS_V1
        "explain_cves"     -> VULNERABILITY_EXPLAIN_CVES_V1
```

The platform's `@platform_task` wrapper drives both levels:
1. Runs the dispatcher definition through the engine
2. Reads `selected_definition_id` from the terminal output
3. Looks up the inner definition from `dispatches_to`
4. Runs the inner definition through the engine (same `run_id`, phase handoff)

Module authors set `is_dispatcher=True` and populate `dispatches_to`. They never call `DurableStateMachine.execute` directly.

---

## Production Examples

### Vulnerability Module (8 states)

```
inventory -> advisory -> intel -> scoring -> report -> persist -> response_emit -> __succeeded__
```

| State | What it does | Retry policy |
|---|---|---|
| `inventory` | SSH into targets, collect package lists | 2 retries on TimeoutError, ConnectionError, OSError |
| `advisory` | Query OSV + distro feeds for advisories | 2 retries on httpx.HTTPError |
| `intel` | Fetch EPSS, KEV, NVD enrichment | 2 retries on httpx.HTTPError |
| `scoring` | LLM-score each finding | 3 retries on LLMTransientError |
| `report` | Generate summary narrative | 3 retries on LLMTransientError |
| `persist` | Write findings + report to DB | 2 retries on psycopg.OperationalError |
| `response_emit` | Build final PlatformResponse | No retries |

### Forensics Module (8 states, full analysis)

```
intake -> collection -> deep_analysis -> promotion -> resolution -> writeup -> response_emit -> __succeeded__
```

| State | What it does | Retry policy |
|---|---|---|
| `intake` | Validate evidence directory, classify files | 2 retries on SSH transient |
| `collection` | Run collectors (tshark, strings, capa, binwalk) | 3 retries on SSH transient |
| `deep_analysis` | LLM-driven analysis of collected artifacts | 2 retries on LLMTransientError |
| `promotion` | Promote findings from analysis to evidence graph | No retries |
| `resolution` | LLM resolve: connect findings to threat hypotheses | 2 retries on LLMTransientError |
| `writeup` | Generate investigation report narrative | 2 retries on LLMTransientError |
| `response_emit` | Build final PlatformResponse | No retries |

### Hello World Module (3 states, simple)

```
PREPARE -> EXECUTE -> RESPONSE_EMIT
```

Uses the old-style handler registry (pre-engine). Simple modules that don't need durability, retries, or persistence can use this pattern with a `workflow.py` file instead of the full engine.

---

## Do

### Do: serialize everything in `output`

```python
# Correct: model_dump before putting into output
return StateResult(
    next_state="advisory",
    output=_envelope(state_input, snapshot.model_copy(
        update={"package_count": count}
    )),
)
```

### Do: use the envelope pattern for multi-stage state

```python
def _envelope(state_input, snapshot):
    envelope = dict(state_input)
    envelope["snapshot"] = snapshot.model_dump(mode="json")
    return envelope
```

### Do: declare `on_success` on every state

```python
"inventory": StateSpec(
    handler=_h(state_inventory),
    on_success="advisory",        # static edge -- enables graph validation
),
```

The engine validates the full graph at definition time. If every state declares `on_success`, the engine checks:
- Every target state exists
- Every non-terminal state is reachable from `start_state`
- At least one terminal state is reachable

### Do: classify exceptions into retriable vs non-retriable

```python
# Network/transient: retry
_HTTP_TRANSIENT = (httpx.HTTPError,)

# DB/transient: retry
_PERSIST_TRANSIENT = (psycopg.OperationalError, asyncio.TimeoutError)

# LLM/transient: retry
_LLM_TRANSIENT = (LLMTransientError, asyncio.TimeoutError)
```

Define these as module-level tuples. Use the **parent** exception class so subclasses are automatically covered.

### Do: emit progress

```python
await services.emitter.emit(
    stage="inventory",
    message=f"Collected {len(inventories)} systems and {package_count} packages.",
)
```

This feeds the SSE stream, audit trail, and task progress UI.

### Do: use `services.session_factory()` for DB access

```python
async with services.session_factory() as session:
    result = await session.exec(select(MyTable).where(...))
```

The session factory is scoped to the current execution. It rolls back on cancellation or error.

---

## Do Not

### Do not: pass Pydantic models as task kwargs

```python
# WRONG: RouteDecision is a BaseModel, not JSON-serializable
terminal = await analyze_fleet(
    synthetic_ctx,
    route=request.run_state.route,  # <-- Pydantic model!
)

# CORRECT: serialize first
terminal = await analyze_fleet(
    synthetic_ctx,
    route=request.run_state.route.model_dump(mode="json") if request.run_state.route else None,
)
```

Task kwargs become `initial_input` in the engine. `initial_input` is stored in a JSONB column. Non-serializable objects crash the INSERT. The engine validates this at `execute()` entry with `json.dumps()` and raises a clear `TypeError` if it fails. Validated at `DurableStateMachine.execute()` entry via `json.dumps(initial_input, default=None)` -- see `src/aila/platform/workflows/engine.py:112`.

### Do not: put datetimes, UUIDs, or enums directly in `output`

```python
# WRONG: datetime is not JSON-serializable
return StateResult(
    next_state="persist",
    output={"completed_at": datetime.now(UTC)},  # TypeError at construction
)

# CORRECT: convert to string
return StateResult(
    next_state="persist",
    output={"completed_at": datetime.now(UTC).isoformat()},
)
```

`StateResult` runs `json.dumps(output)` at construction time. It will raise `ValueError` on non-serializable types.

### Do not: create DB sessions inside handlers

```python
# WRONG: handler manages its own session
async def state_persist(state_input, services):
    async with async_session_scope() as session:  # <-- don't do this
        session.add(MyRecord(...))
        await session.commit()
```

Use `services.session_factory()` instead. The engine owns session lifecycle for cancellation safety.

### Do not: import the engine or call `execute()` from module code

```python
# WRONG: module calling engine directly
from aila.platform.workflows import DurableStateMachine
result = await DurableStateMachine.execute(run_id, definition, input)
```

Modules declare `WorkflowDefinition` objects and wire them via `@platform_task(definition=...)`. The platform wrapper drives execution. Modules write pure state handlers and nothing else.

### Do not: use `session.add()` when a row might already exist

```python
# WRONG: crashes with IntegrityError if row exists
session.add(run_record)
await session.commit()

# CORRECT: merge handles both insert and update
await session.merge(run_record)
await session.commit()
```

The orchestrator and engine may both create `WorkflowRunRecord` rows for the same `run_id`. Use `merge()` or `INSERT ON CONFLICT DO NOTHING`. Live merge sites in `src/aila/platform/runtime/orchestrator.py` -- grep for `_merge_live_hypotheses` to locate.

### Do not: hard-code state transitions in handler logic

```python
# WRONG: handler decides next state conditionally
async def state_scoring(state_input, services):
    if snapshot.skip_scoring:
        return StateResult(next_state="persist", output=...)  # skips report
    return StateResult(next_state="report", output=...)
```

This hides the graph from static validation. If you need conditional branching, use a **dispatcher** that selects different definitions, or add an explicit `mode_selection` state whose job is choosing the path.

### Do not: swallow exceptions silently

```python
# WRONG: hides failures, handler appears to succeed
async def state_intel(state_input, services):
    try:
        data = await fetch_intel(...)
    except httpx.HTTPError:
        data = {}  # <-- caller never knows this failed
    return StateResult(next_state="scoring", output=...)
```

Let retriable exceptions propagate. Declare them in `retriable_on` on the `StateSpec`. The engine handles retry logic, backoff, and failure transitions.

---

## Creating a New Workflow

1. **Define your states** as `async def state_*(state_input, services) -> StateResult` functions in `workflow/states/`.

2. **Create a services class** implementing `WorkflowServices.build(run_id)` in `workflow/services.py`. Bundle emitter, session factory, and any module-specific runtime.

3. **Wire the definition** in `workflow/definitions.py`:
   ```python
   MY_WORKFLOW_V1 = WorkflowDefinition(
       definition_id="my_module.my_workflow.v1",
       start_state="step_one",
       states={
           "step_one": StateSpec(
               handler=_h(state_step_one),
               timeout_s=300.0,
               max_retries=2,
               retriable_on=(TimeoutError,),
               on_success="step_two",
           ),
           "step_two": StateSpec(
               handler=_h(state_step_two),
               timeout_s=60.0,
               on_success=RESERVED_SUCCEEDED,
           ),
       },
       services_factory=_build_services,
   )
   ```

4. **Register the task** in `workflow/task.py`:
   ```python
   @platform_task(
       track="my_module",
       module_id="my_module",
       definition=MY_WORKFLOW_V1,
   )
   async def run_my_workflow(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
       ...  # seed stub -- platform_task drives execution
   ```

5. **Use two-level dispatch** if your module has multiple modes:
   ```python
   MY_DISPATCHER_V1 = WorkflowDefinition(
       definition_id="my_module.dispatcher.v1",
       start_state="routing",
       is_dispatcher=True,
       dispatches_to={
           "full_analysis": MY_FULL_ANALYSIS_V1,
           "quick_check": MY_QUICK_CHECK_V1,
       },
       states={...},
       services_factory=_build_services,
   )
   ```

---

## Engine Safety Features

| Feature | What it catches |
|---|---|
| `json.dumps()` on `initial_input` | Non-serializable task kwargs (Pydantic models, etc.) |
| `StateResult` model validator | Non-serializable handler output |
| `max_retries` + `retriable_on` | Transient failures (network, DB, LLM) |
| `timeout_s` via `asyncio.wait_for` | Hung handlers |
| `MAX_STEPS_PER_JOB = 1000` | Infinite loops in malformed definitions |
| Static graph validation | Unreachable states, missing terminal, edge typos |
| Optimistic locking (`version` column) | Concurrent worker conflicts |
| `STATE_NAME_MAX_LEN = 128` | Storage DoS via crafted state names |
| `output_schema` validation | Handler returning wrong output shape |

---

## Platform-Owned Sweeps

### `__crashed__` cursor sweep (commit `af9a724`)

Lives at `src/aila/platform/tasks/cursor_reaper.py`. ORM `delete(WorkflowStateCursor)` filtered by `current_state == "__crashed__"` AND `run_id NOT IN (active TaskRecord ids)` (queued, running, waiting). Runs every minute from the worker reaper cron.

A `__crashed__` cursor is reclaimed only once its `TaskRecord` has settled to a non-active status (`done`, `failed`, `cancelled`, `dead_letter`). The crash event itself is preserved on the `TaskRecord`; only the cursor row is removed.

### VR wall-clock cap (commit `b47dd65`)

The per-investigation reaper clocks elapsed time from `coalesce(started_at, created_at)` rather than `created_at`.

- SQL site: `src/aila/modules/vr/services/investigation_reaper.py:112`
- Python site: `src/aila/modules/vr/services/investigation_emit.py:288`

The cap envelope (`VR_INVESTIGATION_WALL_CLOCK_HOURS`, default 6 hours) no longer fires while an investigation sits queued.

---

## File Layout

```
src/aila/modules/<module_id>/workflow/
  __init__.py         # re-exports: definitions, task entry point
  definitions.py      # WorkflowDefinition objects (frozen, statically validated)
  services.py         # WorkflowServices.build() implementation
  contracts.py        # Pydantic models for output_schema validation
  task.py             # @platform_task entry point (seed stub)
  states/
    __init__.py       # re-exports all state handler functions
    dispatch.py       # state_routing, state_operation_selection
    analysis.py       # state_inventory, state_advisory, ...
    reporting.py      # state_report, state_response_emit
    lookup.py         # state_report_lookup (for query modes)
```

See `src/aila/modules/vulnerability/workflow/` for the canonical production reference.


---

## Cyber Reasoning Engine

The platform provides `CyberReasoningEngine` (`platform/services/reasoning.py`) for modules that need multi-turn LLM reasoning inside a workflow state. The forensics and vr modules use it for bounded investigations; future modules (web_pentest, mobile_reverse) will share the same protocol.

The reasoning engine is **not** a workflow engine. It runs *inside* a single workflow state handler. A handler calls the engine in a loop:

```python
async def state_freeflow(state_input, services):
    engine = CyberReasoningEngine(services.llm_client)
    case_state = ReasoningCaseState()
    
    for turn in range(1, max_turns + 1):
        # 1. Engine selects strategy
        strategy = engine.select_strategy_family(
            question=question,
            case_state=case_state,
            evidence_listing=evidence,
        )
        
        # 2. Engine builds prompt from case model + evidence + operator steering
        user_prompt = engine.build_user_prompt(ReasoningPromptContext(
            turn=turn,
            max_turns=max_turns,
            question=question,
            case_model=engine.render_case_model(case_state),
            evidence_listing=evidence,
            artifacts=collected_artifacts,
            strategy_family=strategy,
        ))
        
        # 3. LLM returns a structured decision
        decision = await engine.decide_next_turn(
            task_type="forensics_freeflow",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        
        # 4. Engine merges decision into cumulative state
        case_state = engine.absorb(case_state, decision)
        
        # 5. Module executes the action (script, tool, submit)
        if decision.action == "submit":
            error = engine.validate_submission(...)
            if error is None:
                break  # answer accepted
        elif decision.action == "script_execute":
            result = await run_script(decision.script_content)
        elif decision.action == "tool_run":
            result = await run_tool(decision.command)
```

### Separation of Concerns

| Layer | Owns | Does NOT own |
|---|---|---|
| **Reasoning engine** (platform) | Prompt framing, JSON extraction, turn-decision validation, case-state merging, evidence graph construction, strategy selection, submission validation | Tool execution, file I/O, SSH commands, domain interpretation |
| **Module state handler** | Tool execution, evidence collection, domain-specific interpretation, deciding when to stop | Prompt construction, LLM round-trip, hypothesis tracking, answer validation |

The engine owns the *protocol*. The module owns the *domain*.

### Key Contracts

```
ReasoningTurnDecision
  reasoning: str           # LLM's chain-of-thought
  action: "script_execute" | "tool_run" | "reasoning" | "submit"
  contract: ReasoningContract | None   # answer type/format (derived once)
  hypotheses: [Hypothesis]             # live explanatory hypotheses
  rejected: [RejectedHypothesis]       # disproved hypotheses
  observables: {key: value}            # facts extracted this turn
  script_content: str | None           # script to execute (action=script_execute)
  command: str | None                  # tool to run (action=tool_run)
  answer: str | None                   # final answer (action=submit)
  confidence: "exact" | "strong" | "medium" | "caveated" | "unknown"
  provenance: EvidenceProvenance        # citations for the answer
```

### Case State Merging

The engine accumulates state across turns via `absorb()`:

- **Contract** is set once (first turn that derives it) and never overwritten
- **Hypotheses** are replaced wholesale each turn (LLM re-evaluates all)
- **Rejected hypotheses** are append-only and deduplicated by `(id, claim)`
- **Observables** are merged (new keys added, existing keys updated)

This ensures the LLM cannot "forget" disproved hypotheses or lose observables across turns.

### Evidence Graph

The engine builds a graph snapshot (`ReasoningEvidenceGraph`) from case state:

```
Node kinds: contract, hypothesis, rejected_hypothesis, observable, evidence, answer
Edge kinds: depends_on, supports, refutes, corroborates, answered_by
```

Graphs are persisted via `ReasoningGraphService.save_snapshot()` (DB table: `reasoning_graph_snapshot`). The forensics frontend renders these as investigation timelines.

### Domain Profiles

The engine ships with 4 built-in domain profiles:

| Domain | Strategy families |
|---|---|
| `forensics` | filesystem_triage, persistence_hunt, memory_forensics, network_forensics, malware_static, generic |
| `vulnerability_research` | vulnerability_research, generic |
| `web_pentest` | web_pentest, network_forensics, generic |
| `mobile_reverse` | mobile_reverse, malware_static, generic |

Strategy selection is deterministic (keyword matching on evidence + question). Operator steering can pin a strategy via `ReasoningOperatorSteering.pinned_strategy_family`.

### Operator Steering

Operators can influence reasoning without modifying code:

```python
steering = ReasoningOperatorSteering(
    confirmed_facts=["the intrusion used a Cobalt Strike beacon"],
    disproved_hypotheses=["H2: lateral movement via RDP"],
    guidance=["focus on DNS exfiltration channels"],
    pinned_strategy_family="network_forensics",
    required_artifacts=["pcap_analysis_summary"],
)
```

Confirmed facts and guidance are injected into the prompt. Disproved hypotheses bypass the engine's own rejection logic. Required artifacts enforce that the submission cites specific evidence.

### VR Submit / Quorum Lifecycle

Three gates from commit `2328b4e` plus the idempotent draft-review request from commit `8f2d1f5`.

**Pre-submit gate.** A `terminal_submit` is intercepted by `_maybe_reject_submit_when_draft_pending` (`src/aila/modules/vr/agents/vuln_researcher.py:1311-1403`) when an unvoted DRAFT outcome exists for the investigation (excluding drafts proposed by this branch). The submit is converted into a non-terminal `observe` carrying a `SUBMIT BLOCKED - UNVOTED DRAFT OUTCOMES` directive, and the original submit payload is preserved on observables under `_pending_draft_blocked_submit` so the agent can re-submit after voting.

**Auto-approve fallback in `evaluate_quorum`** (`src/aila/modules/vr/services/outcome_review.py:275-296`):

- `quorum_k == 0` (single-branch investigation) flips a DRAFT to APPROVED with `transition_reason="auto_approved_no_siblings"`.
- `quorum_k > 0` with every non-proposing sibling non-active and votes still below quorum flips a DRAFT to APPROVED with `transition_reason="auto_approved_no_active_voters_*"`.

`compute_quorum` returns `max(2, ceil(N/2))` for `N >= 1`.

**Empty-`tool_run` STOP threshold.** The second consecutive empty or malformed `tool_run` (`src/aila/modules/vr/agents/tool_executor.py:109-155`) injects a hard STOP directive listing valid options (`tool_run`, `submit`, `observe`). The first empty command receives a softer hint.

**Idempotent draft-review request (commit `8f2d1f5`).** `post_draft_review_request` (`src/aila/modules/vr/services/outcome_review.py:365-459`) builds `auto_steering_key = f"draft_review_request:{outcome_id}"`. Before inserting a new operator-kind message it runs a substring `.contains(auto_steering_key)` lookup against `VRInvestigationMessageRecord.payload_json` (lines 432-434); if a match exists no new row is written and the existing message id is returned.

### Do / Do Not

**Do:**
- Use `engine.validate_submission()` before accepting an answer -- it checks for empty answers, missing citations, and unreferenced artifacts
- Persist graph snapshots per turn via `ReasoningGraphService` for auditability
- Pass `operator_steering` through from the API/CLI layer -- do not drop it
- Use `model_dump(mode="json")` when storing case state in workflow `state_input`

**Do not:**
- Call the LLM directly from module code -- use `engine.decide_next_turn()`
- Parse the LLM JSON response yourself -- the engine's `_extract_json_object()` handles fences and validation
- Modify `case_state` directly -- use `engine.absorb()` to merge decisions
- Rely on hypothesis ordering -- the LLM re-evaluates all hypotheses each turn