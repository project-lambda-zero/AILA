# VR Module v0.3 — Reasoning / Discovery Implementation Plan

## What v0.3 reasoning does

Given an operator-supplied target + investigative question, the VR reasoning loop:
1. Picks a hypothesis-driven strategy from the platform's `vulnerability_research` strategy family (D-36)
2. Drives a multi-turn investigation across audit-mcp, IDA Headless MCP, source repos, decompiled functions, fuzzing campaigns
3. Supports branching (fork/merge/promote/abandon) so multiple persona-voiced hypotheses can be explored in parallel (D-39, D-41)
4. Persists every turn, message, branch, evidence reference, and outcome to Postgres
5. Routes to one of 11 typed outcomes (D-43) — direct PoC, n-day-targeted fuzz, discovery fuzz, audit memo, variant hunt order, etc.
6. Maintains an audit-memo store of dead-end pivots so future investigations don't re-explore them (D-38)
7. Surfaces the live investigation state to the operator through Monaco IDE + React Flow graph viz (D-44)

Input: `target` (binary, source repo, or CVE) + `question` (free-form natural-language investigative ask) + optional `operator_steering`
Output: `investigation_id` (durable, resumable) + stream of typed engine messages + final typed outcome

## Position in the VR roadmap

| Version | Status | Deliverable |
|---|---|---|
| v0.1 | superseded by v0.3 refactor (no users, no backport per D-53) | Original N-day PoC writer scope absorbed into v0.3 |
| **v0.3 reasoning** | **this plan** | **Hypothesis-engine-driven discovery + variant hunting + N-day PoC writer + branching** |
| v0.3 fuzzing | parallel plan | Fuzzing pipeline (`VR_V03_FUZZING_PLAN.md`) |
| v0.3 disclosure | parallel plan | Multi-track disclosure (`VR_V03_DISCLOSURE_LIFECYCLE_PLAN.md`) |
| v0.3 knowledge | parallel plan | Pattern catalog + RAG (`VR_V03_KNOWLEDGE_TRANSFER_PLAN.md`) |
| v0.3 target enrichment | M3.T milestone in this plan (absorbed v0.2 per D-53) | Workspaces, targets, capability profiles, mitigation analysis, function ranking |
| v0.4 | later | Full research workflow (autonomous multi-strategy + human-in-the-loop integration) |
| v0.5 | later | Kernel / hypervisor exploitation |

**Relationship to v0.3 fuzzing**: The fuzzing plan covers campaign infrastructure (engines, strategies, triage, minimization). This plan covers the **decision system that decides whether to launch a campaign** in the first place — and what to do with findings when they appear. Per D-37: fuzzing is OPTIONAL. The reasoning engine emits one of four outcomes per investigation: direct PoC / n-day-targeted fuzz / discovery fuzz / audit memo.

**Relationship to v0.1 N-day**: v0.1 is being refactored into v0.3 rather than preserved. Per D-53, there are no v0.1 production users; the N-day PoC writing workflow (`VR_NDAY_V1`) is reshaped as one of v0.3's investigation outcomes (`DirectFinding` → N-day workflow dispatch). The previously-shipped v0.1 schema (`vr_projects`, `vr_findings`) is being refactored to reference the new `vr_targets` and `vr_workspaces` tables introduced by M3.T-1.

---

## Gray Area Resolutions (v0.3 reasoning scope)

### GA-19: Reasoning agent class (single vs branched)

**Decision:** One `HonestVulnResearcher` agent class. Branching is a property of the **investigation**, not the agent. Each branch runs its own `HonestVulnResearcher` instance with isolated state.

Rationale: Forensics has `HonestInvestigator` (linear). VR needs branching (D-41) for multi-persona exploration. Putting branching in the investigation lifecycle keeps the agent class small and matches how a real researcher works — same researcher, different lines of inquiry, switchable.

Class signature mirrors `HonestInvestigator`:

```python
class HonestVulnResearcher:
    """Bounded, closed-loop vulnerability researcher.

    State per branch (each branch = independent agent instance):
    - contract: parsed once, locked after first turn
    - hypotheses: live set
    - rejected: dead hypotheses
    - observables: accumulated facts (decompiled functions, taint traces, etc.)
    - persona_voice: optional D-39 persona prompt voice for this branch
    - audit_memo_refs: which prior audit memos were consulted
    """

    def __init__(
        self,
        settings: Settings,
        reasoning_engine: CyberReasoningEngine,
        reasoning_graphs: ReasoningGraphService,
        mcp_client: MCPFleetClient,         # D-47/48
        run_id: str,
        investigation_id: str,
        branch_id: str,                     # NEW for v0.3
        target: VRTarget,
        persona_voice: PersonaVoice | None = None,  # D-39
        parent_branch_id: str | None = None,        # branching (D-41)
    ) -> None: ...
```

### GA-20: Investigation persistence granularity

**Decision:** Per-turn AgentStep + per-branch state snapshot. Same model as forensics. Add `vr_investigation_branches`, `vr_investigation_messages`, `vr_investigation_outcomes` tables to capture v0.3-specific concepts.

Rationale: Forensics persists per-turn `AgentStepRecord` and final `AnswerCandidateRecord`. VR needs additional tables because:
- An investigation has multiple branches (D-41) — each needs its own turn history
- Conversational UX (D-43) adds operator-typed messages interleaved with engine turns
- Typed outcomes (D-43) need their own table — each outcome row has different shape

DB schema added in M3.3a (see Build Order).

### GA-21: Operator collaboration runtime model (sync/async/blocking)

**Decision:** Non-blocking by default. Engine self-directs forward until one of three conditions triggers a pause-for-operator:
1. **Operator-initiated steering** — SSE-pushed interrupt from frontend (uses existing `ReasoningOperatorSteering`, D-40)
2. **Engine-detected ambiguity** — engine emits an `outcome_pending` payload (D-44) when it cannot pick between branches with sufficient confidence
3. **Cost budget threshold** — soft warning at 50/75/90% of budget; hard stop at 100%

Configurable per investigation: `auto_pilot=true` (default) skips condition 2 unless ambiguity is structural (e.g., two branches with equal evidence weight). `auto_pilot=false` makes the engine ask before every branch fork or outcome emission.

Implementation: `services/investigation_runtime.py` orchestrates the pause/resume cycle by writing `pause_reason` to `vr_investigations.status` and listening for resume signal via Postgres LISTEN/NOTIFY (same channel pattern as D-48 hot reload).

### GA-22: Outcome routing — when does the engine self-determine vs ask

**Decision:** Engine self-determines outcome ONLY when confidence is "strong" or "exact" (existing `ReasoningConfidence` enum, `reasoning.py:29`). Otherwise emits `outcome_pending` and waits for operator.

Outcome selection algorithm (`services/outcome_router.py`):

```python
def select_outcome(state: InvestigationState) -> VROutcome | OutcomePending:
    """Map terminal investigation state to one of D-43's 11 typed outcomes.

    Returns OutcomePending if confidence < "strong" or
    if multiple outcomes tie on evidence weight.
    """
    # Confidence gate
    if state.confidence in {"caveated", "unknown"}:
        return OutcomePending(reason="low_confidence", candidates=...)

    # Pattern dispatch (in priority order)
    if has_reproducible_crash(state):
        return DirectFinding(...)
    if has_known_cve_match(state) and has_target_binary(state):
        return VariantHuntOrder(...)  # n-day-targeted
    if has_strong_hypothesis_no_repro(state):
        return ProfileSpecDraft(...) | CampaignLaunch(...)  # discovery fuzz
    if has_audit_observations_no_bug(state):
        return AuditMemo(...)  # negative finding
    # Plus 6 more cases mapping to the remaining D-43 outcomes
    return OutcomePending(reason="no_match", candidates=...)
```

The 11 outcome types from D-43 are concrete Pydantic models in `contracts/outcomes.py`:
1. `AssessmentReport` — investigation summary without action
2. `StrategyDescriptor` — strategy file for FUZZILLI/AFL++
3. `ProfileSpecDraft` — `V8MapInferenceProfile`-like custom profile spec
4. `ConfigDelta` — change to existing strategy/profile
5. `VariantHuntOrder` — targeted n-day variant search
6. `PatchAssessmentReport` — patch analysis output (used by N-day workflow)
7. `AuditMemo` — negative finding with 90d expiry
8. `DirectFinding` — reproducible bug ready for advisory
9. `CrashTriageReport` — analysis of an existing crash
10. `CampaignLaunch` — execute a `CampaignLaunch` against the fuzzing pipeline
11. `SubInvestigation` — spawn nested investigation (branching trigger)

### GA-23: LLM model selection per strategy

**Decision:** Use platform's existing `RouteDecision` model selection. Add per-strategy default mapping in `data/strategy_model_defaults.json`. Operator can override at investigation start.

Strategy → default model:

```json
{
  "vulnerability_research.audit_only": "anthropic/claude-sonnet-4-5",
  "vulnerability_research.variant_hunt": "anthropic/claude-sonnet-4-5",
  "vulnerability_research.crash_triage": "anthropic/claude-haiku-4-5",
  "vulnerability_research.patch_diff_analysis": "anthropic/claude-sonnet-4-5",
  "vulnerability_research.discovery_research": "anthropic/claude-opus-4-1",
  "vulnerability_research.exploit_chain_design": "anthropic/claude-opus-4-1"
}
```

Rationale: Crash triage is mostly parsing + classification (cheap model). Discovery research and exploit chain design need deepest reasoning (Opus). Default sonnet balances cost and quality for the common case (audit, variant hunt, patch diff).

### GA-24: Cost budgets per investigation

**Decision:** Add `cost_budget_usd` and `cost_actual_usd` fields to `vr_investigations`. Reuse v0.1's `BudgetState` pattern (`cost_per_turn_usd`) but extend it to track three cost streams: LLM tokens, MCP call costs, fuzzing infrastructure costs.

```python
class InvestigationBudget(BaseModel):
    """Per-investigation cost ceiling tracked across three streams."""

    # Budget caps
    cost_budget_usd: float = 50.0  # default per investigation
    soft_warn_at_pct: float = 0.5
    hard_stop_at_pct: float = 1.0

    # Live actuals
    llm_tokens_cost_usd: float = 0.0       # LLM calls (input + output)
    mcp_calls_cost_usd: float = 0.0        # IDA seat seconds, audit-mcp calls
    fuzz_infra_cost_usd: float = 0.0       # Fuzzing campaign launches

    # Computed
    @property
    def total_actual_usd(self) -> float:
        return self.llm_tokens_cost_usd + self.mcp_calls_cost_usd + self.fuzz_infra_cost_usd
    
    @property
    def pct_consumed(self) -> float:
        return self.total_actual_usd / self.cost_budget_usd if self.cost_budget_usd else 0.0
```

When `pct_consumed >= soft_warn_at_pct`, engine emits warning to operator. At `hard_stop_at_pct`, engine forces termination of all active branches and emits whatever terminal state exists (likely `AssessmentReport` or `OutcomePending`).

### GA-25: Audit memo schema (D-38 implementation)

**Decision:** Audit memos are first-class Pydantic + DB records, embedded for semantic search, expire automatically after 90 days unless promoted.

```python
class AuditMemo(BaseModel):
    """Negative finding — an investigation concluded no bug exists in a region.

    Embedded into pgvector for retrieval at next investigation start.
    """

    id: str
    investigation_id: str       # which investigation produced this
    target_signature: str       # SHA256(target_path + region_descriptor)
    region_descriptor: str      # e.g., "function v8::FastAPI::serialize at v8/src/api/api-natives.cc:1024"
    claim: str                  # "Audited for integer overflow on length parameter; bounds check at line 1031 is correct"
    evidence_refs: list[str]    # AgentStepRecord IDs
    confidence: ReasoningConfidence
    pivot_history: list[str]    # Other approaches tried before reaching this verdict (D-35)
    expires_at: datetime        # +90 days from created_at
    promoted: bool = False      # if True, never expires
    embedding: list[float] | None = None  # 1536-dim
```

Retrieval at investigation start: vector search `target_signature` + free-form question text against the audit memo store. Top-K (default 5) injected into the engine's evidence pack with priority 70 (between caller context and other context).

Eviction: ARQ task `audit_memo_evictor` runs daily, deletes memos where `expires_at < now() AND promoted = false`. Promotion happens via API call when operator explicitly marks a memo as "verified canonical."

### GA-26: Branch lifecycle (fork / merge / promote / abandon per D-41)

**Decision:** Four operations on the investigation branch tree, each emitting an `AgentStepRecord` for audit trail:

| Operation | Trigger | Effect |
|---|---|---|
| `fork` | Engine emits `SubInvestigation` outcome OR persona dispatch (D-39) | Spawns child branch with parent's state copied at fork point; child gets new `branch_id` |
| `merge` | Two branches reach same conclusion with strong confidence | Both branches close; new evidence consolidated under a new `branch_id` with both parents linked |
| `promote` | One branch's outcome supersedes siblings | Sibling branches marked `abandoned`; chosen branch becomes the investigation's primary outcome |
| `abandon` | Branch dead-ends OR cost budget exceeded for that branch | Branch marked `abandoned`; remaining budget redistributed to live siblings |

Implementation:

```python
class BranchOperation(BaseModel):
    op: Literal["fork", "merge", "promote", "abandon"]
    investigation_id: str
    parent_branch_id: str
    child_branch_ids: list[str] = Field(default_factory=list)  # for merge: which branches consolidated
    reason: str
    actor: Literal["engine", "operator"]
    at_turn: int
    triggering_evidence_refs: list[str] = Field(default_factory=list)
```

Cost accounting: each branch tracks its own `branch_cost_usd`. Investigation total = sum of all live branches. Abandoned branches' costs are sunk but stay recorded.

### GA-27: MCP adapter pattern (D-44 typed payloads from D-47 MCP results)

**Decision:** Per-MCP-tool adapter functions in `reasoning/mcp_adapters/` transform raw MCP responses into D-44 typed engine message payloads. Each adapter is a pure function.

```python
# reasoning/mcp_adapters/ida_headless.py
def adapt_decompile_response(
    raw: dict[str, Any],
    ctx: AdapterContext,
) -> DecompiledFunctionPayload:
    """Transform IDA Headless `decompile()` response to typed payload for IDE rendering."""
    return DecompiledFunctionPayload(
        function_name=raw["function_name"],
        address=raw["address"],
        pseudocode=raw["pseudocode"],
        language="c",
        source_provenance=SourceProvenance(
            mcp_server=ctx.mcp_server_id,
            mcp_instance=ctx.mcp_instance_id,
            call_id=ctx.call_id,
            decompiler="hex-rays",
            decompiler_version=raw.get("decompiler_version"),
        ),
        annotations=[],  # populated by next adapter pass for taint highlights
    )

def adapt_xrefs_to_response(
    raw: dict[str, Any],
    ctx: AdapterContext,
) -> XrefViewPayload: ...

def adapt_call_chain_response(
    raw: dict[str, Any],
    ctx: AdapterContext,
) -> GraphViewPayload: ...
```

Registry: `reasoning/mcp_adapters/__init__.py` maps `(mcp_server_id, tool_name)` → adapter function. Tool dispatch in `HonestVulnResearcher._run_turn()` calls the adapter automatically after every tool execution.

### GA-28: Variant hunt as branched sub-investigation

**Decision:** `VariantHuntOrder` outcome from a primary investigation triggers a new investigation with `parent_investigation_id` set, marked `kind="variant_hunt"`. NOT a branch of the primary investigation — a full sibling investigation tracked separately.

Rationale: Branches share a single investigation's budget and lifecycle. A variant hunt may run for hours or days as its own first-class investigation. Treating it as a sibling investigation:
- Gives it its own cost budget
- Lets the operator pause/resume independently
- Makes parent-child relationships explicit in the DB (one investigation can spawn N variant hunts over time)
- Aligns with how Chrome VRP work happens — find one bug → spend a week hunting variants → submit cluster

DB: `vr_investigations.parent_investigation_id` (nullable) + `vr_investigations.kind` (`discovery` | `variant_hunt` | `triage` | `n_day` | `audit`).

### GA-29: Fuzzing campaign launch from reasoning context

**Decision:** When the engine emits `CampaignLaunch` outcome, the platform task `vr_launch_fuzz_campaign` (in `workers/fuzz_dispatcher.py`) is enqueued. The task:
1. Reads the launch spec from the outcome
2. Creates a `vr_fuzz_campaign` row (v0.3 fuzzing plan schema)
3. Enqueues the existing fuzz_worker tasks from v0.3 fuzzing
4. Writes back to the investigation: link to `campaign_id` and set investigation status to `running:awaiting_campaign`
5. SSE-pushes campaign status updates to the investigation's subscribers

Reverse direction: when the campaign produces a `vr_fuzz_finding` with severity `CRITICAL`, the fuzzing triage worker (v0.3 fuzzing M3.4) emits a `finding_promoted` event on the investigation's channel. The investigation's `HonestVulnResearcher` resumes from `awaiting_campaign`, ingests the finding as new evidence, and re-evaluates outcome.

### GA-30: Conversational message types (D-43 implementation)

**Decision:** `vr_investigation_messages` table has `sender_kind` enum: `engine` | `operator`. Each message has a `payload_kind` enum matching D-44's 10 typed payloads. Operator messages are free-text but get LLM-classified at insertion into one of:
- `steering` — adds to `ReasoningOperatorSteering`
- `question` — engine answers next turn
- `correction` — overrides a specific observable
- `dismissal` — closes a hypothesis the engine raised
- `outcome_selection` — picks among pending outcome candidates
- `branch_command` — explicit fork/merge/promote/abandon

Classification happens in a cheap LLM call (Haiku) so the engine knows how to react. Misclassified messages can be re-routed by operator clicking "interpret as ___" in the UI.

---

## File Layout

Building on the existing v0.1 + v0.3 fuzzing structure:

```
src/aila/modules/vr/
├── ... (existing v0.1 + v0.3 fuzzing files unchanged) ...
├── reasoning/                              # NEW v0.3 subpackage
│   ├── __init__.py
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── vuln_researcher.py              # HonestVulnResearcher (mirrors HonestInvestigator)
│   │   ├── persona_voices.py               # D-39 persona prompt prefixes
│   │   └── prompts/
│   │       ├── system_audit.md             # Audit-only strategy prompt
│   │       ├── system_variant_hunt.md      # Variant-hunt strategy prompt
│   │       ├── system_discovery.md         # Discovery-research strategy prompt
│   │       ├── system_crash_triage.md      # Crash-triage strategy prompt
│   │       ├── system_patch_diff.md        # Patch-diff strategy prompt
│   │       └── personas/                   # Per-persona voice modifiers
│   │           ├── halvar.md
│   │           ├── maddie.md
│   │           ├── yuki.md
│   │           ├── renzo.md
│   │           ├── noor.md
│   │           └── wei.md
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── investigation.py                # VRInvestigation, VRBranch, VRMessage
│   │   ├── outcomes.py                     # 11 D-43 outcome types (Pydantic)
│   │   ├── payloads.py                     # 10 D-44 message payload types
│   │   ├── budget.py                       # InvestigationBudget
│   │   └── memo.py                         # AuditMemo
│   ├── services/
│   │   ├── __init__.py
│   │   ├── investigation_runtime.py        # Pause/resume orchestration
│   │   ├── outcome_router.py               # GA-22 outcome selection
│   │   ├── branch_manager.py               # GA-26 fork/merge/promote/abandon
│   │   ├── memo_store.py                   # GA-25 audit memo CRUD + retrieval
│   │   ├── message_classifier.py           # GA-30 operator message classification
│   │   └── cost_tracker.py                 # GA-24 budget accounting
│   ├── mcp_adapters/
│   │   ├── __init__.py                     # adapter registry
│   │   ├── base.py                         # AdapterContext, AdapterFn protocol
│   │   ├── ida_headless.py                 # 20+ IDA tool adapters
│   │   ├── audit_mcp.py                    # 54+ audit-mcp tool adapters
│   │   └── fuzz_engine.py                  # fuzzing worker → engine payload
│   ├── workflow/
│   │   ├── __init__.py
│   │   ├── definitions.py                  # VR_INVESTIGATE_V1, VR_VARIANT_HUNT_V1
│   │   ├── services.py                     # VRReasoningWorkflowServices
│   │   └── states/
│   │       ├── __init__.py
│   │       ├── investigation_setup.py      # Target validation, MCP fleet health
│   │       ├── investigation_loop.py       # Long-running reasoning loop
│   │       ├── outcome_emit.py             # Persist outcome, dispatch downstream
│   │       └── response_emit.py            # Terminal state
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── fuzz_dispatcher.py              # GA-29 CampaignLaunch handler
│   │   ├── nday_dispatcher.py              # VariantHuntOrder → N-day workflow
│   │   ├── audit_memo_evictor.py           # 90d expiry sweep
│   │   ├── memo_embedder.py                # Embed new memos for vector search
│   │   └── investigation_resumer.py        # Resume paused investigations
│   ├── data/
│   │   ├── strategy_model_defaults.json    # GA-23 model selection
│   │   ├── persona_dispatch_policy.json    # When to fork by persona
│   │   └── outcome_routing_rules.json      # GA-22 declarative rule overrides
│   └── api_router.py                       # Reasoning-specific REST endpoints
├── db_models/                              # additions
│   ├── investigation.py                    # VRInvestigationRecord (+ branches + messages)
│   ├── outcome.py                          # VRInvestigationOutcomeRecord
│   └── audit_memo.py                       # AuditMemoRecord
└── alembic/versions/
    └── 030_vr_reasoning_tables.py          # NEW migration
```

Existing infrastructure reused (not modified):
- `src/aila/platform/services/reasoning_engine.py` — `CyberReasoningEngine` (drives turns)
- `src/aila/platform/services/reasoning_graphs.py` — `ReasoningGraphService` (graph CRUD)
- `src/aila/platform/contracts/reasoning.py` — `ReasoningStrategyFamily`, `ReasoningCaseState`, etc.
- `src/aila/platform/services/mcp_client.py` — `MCPFleetClient` (built in D-47/48 plan)
- `src/aila/modules/forensics/agents/investigator.py` — reference implementation pattern

---

## DB Schema (additions)

### vr_investigations
```sql
CREATE TABLE vr_investigations (
    id                      TEXT PRIMARY KEY,
    project_id              TEXT REFERENCES vr_projects(id),  -- nullable for standalone
    team_id                 TEXT,
    parent_investigation_id TEXT REFERENCES vr_investigations(id),  -- variant hunt (GA-28)
    kind                    TEXT NOT NULL DEFAULT 'discovery',
                                -- discovery|variant_hunt|triage|n_day|audit
    title                   TEXT NOT NULL,
    initial_question        TEXT NOT NULL,
    target_kind             TEXT NOT NULL,  -- binary|source_repo|cve|crash|patch_diff
    target_descriptor_json  TEXT NOT NULL,  -- {binary_id, repo_url, cve_id, etc.}
    status                  TEXT NOT NULL DEFAULT 'created',
                                -- created|running|paused|completed|failed|abandoned
    pause_reason            TEXT,           -- operator|low_confidence|cost_budget|awaiting_campaign
    auto_pilot              BOOLEAN NOT NULL DEFAULT true,
    -- Strategy + persona
    strategy_family         TEXT NOT NULL,  -- one of ReasoningStrategyFamily.vulnerability_research.*
    persona_dispatch_json   TEXT DEFAULT '{}',  -- which personas active, dispatch rules
    -- Cost (GA-24)
    cost_budget_usd         REAL NOT NULL DEFAULT 50.0,
    cost_actual_usd         REAL NOT NULL DEFAULT 0.0,
    llm_tokens_cost_usd     REAL NOT NULL DEFAULT 0.0,
    mcp_calls_cost_usd      REAL NOT NULL DEFAULT 0.0,
    fuzz_infra_cost_usd     REAL NOT NULL DEFAULT 0.0,
    -- Linkage
    primary_outcome_id      TEXT,           -- vr_investigation_outcomes.id
    linked_campaign_ids     TEXT DEFAULT '[]',  -- JSON array
    linked_finding_ids      TEXT DEFAULT '[]',  -- JSON array
    started_at              TIMESTAMPTZ,
    stopped_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL,
    updated_at              TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_inv_team_status ON vr_investigations (team_id, status);
CREATE INDEX idx_inv_parent ON vr_investigations (parent_investigation_id);
```

### vr_investigation_branches
```sql
CREATE TABLE vr_investigation_branches (
    id                  TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES vr_investigations(id),
    parent_branch_id    TEXT REFERENCES vr_investigation_branches(id),
    status              TEXT NOT NULL DEFAULT 'active',
                            -- active|paused|merged|promoted|abandoned
    persona_voice       TEXT,           -- halvar|maddie|yuki|renzo|noor|wei|null
    fork_reason         TEXT,
    fork_at_turn        INTEGER,
    case_state_json     TEXT NOT NULL DEFAULT '{}',  -- ReasoningCaseState snapshot
    branch_cost_usd     REAL NOT NULL DEFAULT 0.0,
    turn_count          INTEGER NOT NULL DEFAULT 0,
    closed_at           TIMESTAMPTZ,
    closed_reason       TEXT,
    merged_into_branch_id TEXT,         -- if status=merged
    promoted            BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_branch_inv ON vr_investigation_branches (investigation_id, status);
```

### vr_investigation_messages
```sql
CREATE TABLE vr_investigation_messages (
    id                  TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES vr_investigations(id),
    branch_id           TEXT NOT NULL REFERENCES vr_investigation_branches(id),
    sender_kind         TEXT NOT NULL,  -- engine|operator
    sender_id           TEXT,           -- operator user_id or engine instance label
    payload_kind        TEXT NOT NULL,
                            -- text|tool_call|code_pointer|graph_view|taint_flow
                            -- |xref_view|patch_diff|decompiled_function
                            -- |hypothesis_update|outcome_pending
    payload_json        TEXT NOT NULL,
    operator_intent     TEXT,           -- if operator: steering|question|correction|dismissal|outcome_selection|branch_command
    at_turn             INTEGER,
    evidence_refs_json  TEXT DEFAULT '[]',
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_msg_inv_time ON vr_investigation_messages (investigation_id, created_at);
CREATE INDEX idx_msg_branch ON vr_investigation_messages (branch_id, created_at);
```

### vr_investigation_outcomes
```sql
CREATE TABLE vr_investigation_outcomes (
    id                  TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES vr_investigations(id),
    branch_id           TEXT NOT NULL REFERENCES vr_investigation_branches(id),
    outcome_kind        TEXT NOT NULL,
                            -- assessment_report|strategy_descriptor|profile_spec_draft
                            -- |config_delta|variant_hunt_order|patch_assessment_report
                            -- |audit_memo|direct_finding|crash_triage_report
                            -- |campaign_launch|sub_investigation
    payload_json        TEXT NOT NULL,
    confidence          TEXT NOT NULL,  -- exact|strong|medium|caveated|unknown
    evidence_refs_json  TEXT DEFAULT '[]',
    accepted_by_operator BOOLEAN NOT NULL DEFAULT false,
    accepted_at         TIMESTAMPTZ,
    dispatch_status     TEXT DEFAULT 'pending',  -- pending|dispatched|failed
    dispatch_target     TEXT,           -- campaign_id, n_day_workflow_id, etc.
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_outcome_inv ON vr_investigation_outcomes (investigation_id);
```

### vr_audit_memos
```sql
CREATE TABLE vr_audit_memos (
    id                  TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES vr_investigations(id),
    team_id             TEXT,
    target_signature    TEXT NOT NULL,  -- SHA256(target + region)
    region_descriptor   TEXT NOT NULL,
    claim               TEXT NOT NULL,
    evidence_refs_json  TEXT NOT NULL,
    confidence          TEXT NOT NULL,
    pivot_history_json  TEXT DEFAULT '[]',
    expires_at          TIMESTAMPTZ NOT NULL,
    promoted            BOOLEAN NOT NULL DEFAULT false,
    embedding           vector(1536),   -- pgvector
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_memo_target ON vr_audit_memos (target_signature);
CREATE INDEX idx_memo_expires ON vr_audit_memos (expires_at) WHERE promoted = false;
CREATE INDEX idx_memo_embedding ON vr_audit_memos USING ivfflat (embedding vector_cosine_ops);
```

Alembic migration: `src/aila/alembic/versions/030_vr_reasoning_tables.py`

---

## Workflow: VR_INVESTIGATE_V1

Standalone workflow. Can be invoked directly via API OR composed into the future VR_FULL_RESEARCH_V1 (v0.4).

```
investigation_setup -> investigation_loop -> outcome_emit -> response_emit -> __succeeded__
                            |
                            v
              (long-running; stays in state until outcome
               selected OR operator stops OR budget exhausted)
```

### State: investigation_setup (timeout: 180s, retries: 2)
1. Validate target descriptor (binary exists, repo accessible, CVE valid)
2. Health check on MCP fleet — at least one healthy IDA instance for binary targets, at least one audit-mcp instance for source repos
3. Load relevant audit memos via vector search (target_signature + question)
4. Initialize primary branch with operator-selected persona (or default `wei`/coordinator)
5. Set status to `running`, emit initial `text` payload to operator UI
6. Validate cost budget against system per-investigation cap

**Output:** Initialized investigation + primary branch

### State: investigation_loop (timeout: max_runtime_hours * 3600, retries: 0)

The long-running reasoning loop. Each branch runs its own `HonestVulnResearcher`. The state stays here until terminal condition.

**Per-turn execution for each active branch:**
1. Build prompt context from branch's `ReasoningCaseState` + recent messages
2. Inject relevant audit memos (top-K=5 by similarity)
3. Call LLM with strategy-family system prompt + persona voice
4. Parse `ReasoningTurnDecision`
5. Execute action (tool call via MCP, reasoning step, or submit)
6. For tool calls: dispatch through `MCPFleetClient`, adapt response via `mcp_adapters`
7. Persist `AgentStepRecord` + emit typed payload to subscribers
8. Adjudicate (existing platform `adjudicate()`) — block evidence-free claims
9. Update branch case state
10. Check branch operations: fork/merge/promote/abandon eligible?

**Terminal conditions (any branch):**
- Branch reaches submit action with high-confidence outcome → outcome emit
- Branch dead-ends → mark `abandoned`
- Branch cost exceeds per-branch cap → mark `abandoned`

**Terminal conditions (investigation):**
- All branches closed (merged/promoted/abandoned)
- Operator stops via API
- Cost budget exceeded (hard stop)
- All branches abandoned with no outcome → emit `AssessmentReport` for what was learned

**Output:** Selected outcome + final case state

### State: outcome_emit (timeout: 120s, retries: 1)
1. Persist primary outcome to `vr_investigation_outcomes`
2. If `auto_pilot=false` OR confidence < strong: SSE-push to operator for confirmation
3. On operator accept (or auto-accept): dispatch outcome to downstream:
   - `DirectFinding` → enqueue `vr_promote_to_finding` task (writes `vr_findings` row)
   - `VariantHuntOrder` → spawn new investigation with `parent_investigation_id` set
   - `CampaignLaunch` → enqueue `vr_launch_fuzz_campaign` task (GA-29)
   - `AuditMemo` → write to `vr_audit_memos` + embed
   - `ProfileSpecDraft` / `StrategyDescriptor` → store + display to operator
   - `SubInvestigation` → spawn child investigation
4. Update investigation status to `completed`

**Output:** Dispatched outcome + downstream task IDs

### State: response_emit (timeout: 30s, retries: 0)
Persist final state, mark investigation completed, return PlatformResponse.

---

## Workflow: VR_VARIANT_HUNT_V1

Variant hunts get their own workflow definition. Same skeleton as VR_INVESTIGATE_V1 but:
- Pre-loaded with parent investigation's primary finding as starting context
- Strategy family pinned to `vulnerability_research.variant_hunt`
- Default persona = `maddie` (variant-pattern researcher)
- Default budget = 0.5x parent investigation's budget (smaller scope)
- Hard cap on branches = 3 (variant hunts spread thin without bound)

```
variant_setup -> investigation_loop -> outcome_emit -> response_emit -> __succeeded__
```

The `investigation_loop` state is shared (same handler), driven by initial state config.

---

## API Endpoints (additions)

```
POST   /api/vr/investigations                 create + start investigation
GET    /api/vr/investigations                 list (filterable: status, kind, team_id)
GET    /api/vr/investigations/<id>            full details + active branches
DELETE /api/vr/investigations/<id>            stop investigation
POST   /api/vr/investigations/<id>/pause      operator pause
POST   /api/vr/investigations/<id>/resume     operator resume
POST   /api/vr/investigations/<id>/budget     adjust cost budget mid-flight

POST   /api/vr/investigations/<id>/messages   send operator message (D-43 conversational)
GET    /api/vr/investigations/<id>/messages   list messages (paginated, branch-filterable)
GET    /api/vr/investigations/<id>/branches   list branches with status
POST   /api/vr/investigations/<id>/branches/<branch_id>/<op>  fork|merge|promote|abandon
GET    /api/vr/investigations/<id>/outcomes   list outcomes
POST   /api/vr/investigations/<id>/outcomes/<outcome_id>/accept  operator accept

GET    /api/vr/investigations/<id>/state      current ReasoningCaseState snapshot
GET    /api/vr/investigations/<id>/graph      ReasoningEvidenceGraph (for D-44 React Flow)
GET    /api/vr/investigations/<id>/cost       current InvestigationBudget

GET    /api/vr/audit_memos                    list (filterable: target, query text)
POST   /api/vr/audit_memos/<id>/promote       operator promote (skip 90d expiry)
DELETE /api/vr/audit_memos/<id>               operator delete

# SSE streams
GET    /api/vr/investigations/<id>/stream/messages  live messages
GET    /api/vr/investigations/<id>/stream/state     live case state updates
GET    /api/vr/investigations/<id>/stream/cost      live cost ticks (every 5s)
```

---

## Build Order (Milestones)

Mirrors v0.3 fuzzing plan's M3.x naming convention. Reasoning side uses M3.R-* to distinguish.

### Milestone M3.R-1: Foundation (data model + DB)
**Goal:** Create the data layer. No reasoning yet, just schema.

| # | File | LOC | Depends on |
|---|---|---|---|
| 1.1 | `reasoning/contracts/investigation.py` | 100 | — |
| 1.2 | `reasoning/contracts/outcomes.py` (11 types) | 220 | — |
| 1.3 | `reasoning/contracts/payloads.py` (10 types) | 200 | — |
| 1.4 | `reasoning/contracts/budget.py` | 70 | — |
| 1.5 | `reasoning/contracts/memo.py` | 60 | — |
| 1.6 | `db_models/investigation.py` (3 tables) | 200 | 1.1 |
| 1.7 | `db_models/outcome.py` | 70 | 1.2 |
| 1.8 | `db_models/audit_memo.py` | 80 | 1.5 |
| 1.9 | `alembic/versions/030_vr_reasoning_tables.py` | 250 | 1.6-1.8 |

**Exit:** Migrations apply. Pydantic models round-trip JSON. pgvector extension confirmed.

### Milestone M3.R-2: Reasoning agent (single-branch first)
**Goal:** `HonestVulnResearcher` works for a single linear investigation (no branching yet).

| # | File | LOC | Depends on |
|---|---|---|---|
| 2.1 | `reasoning/agents/prompts/system_audit.md` | 200 | — |
| 2.2 | `reasoning/agents/prompts/system_variant_hunt.md` | 180 | — |
| 2.3 | `reasoning/agents/prompts/system_discovery.md` | 220 | — |
| 2.4 | `reasoning/agents/prompts/system_crash_triage.md` | 160 | — |
| 2.5 | `reasoning/agents/prompts/system_patch_diff.md` | 180 | — |
| 2.6 | `reasoning/agents/vuln_researcher.py` | 800 | 1.x, prompts |
| 2.7 | `reasoning/services/cost_tracker.py` | 150 | 1.4 |
| 2.8 | `data/strategy_model_defaults.json` | 30 | — |

**Exit:** Run a single-branch investigation against d8 binary asking "Audit V8 Map Inference for missing alias checks." Engine drives turns, calls MCP, persists steps. No branching, no outcome routing yet.

### Milestone M3.R-3: MCP adapters
**Goal:** Raw MCP responses transform into typed D-44 payloads.

| # | File | LOC | Depends on |
|---|---|---|---|
| 3.1 | `reasoning/mcp_adapters/base.py` | 80 | 1.3 |
| 3.2 | `reasoning/mcp_adapters/ida_headless.py` (20+ tools) | 600 | 3.1 |
| 3.3 | `reasoning/mcp_adapters/audit_mcp.py` (54+ tools) | 500 | 3.1 |
| 3.4 | `reasoning/mcp_adapters/fuzz_engine.py` | 100 | 3.1 |
| 3.5 | `reasoning/mcp_adapters/__init__.py` registry | 60 | 3.1-3.4 |

**Exit:** All MCP tool calls return typed payloads. Engine messages render correctly in mock frontend tests.

### Milestone M3.R-4: Outcome routing
**Goal:** Engine self-determines outcome at terminal turn.

| # | File | LOC | Depends on |
|---|---|---|---|
| 4.1 | `reasoning/services/outcome_router.py` | 250 | 1.2, 2.6 |
| 4.2 | `data/outcome_routing_rules.json` | 60 | — |
| 4.3 | `reasoning/workers/audit_memo_evictor.py` (ARQ) | 80 | 1.8 |
| 4.4 | `reasoning/workers/memo_embedder.py` (ARQ) | 100 | 1.8 |
| 4.5 | `reasoning/services/memo_store.py` | 200 | 1.8 |

**Exit:** Single-branch investigation reaches submit and routes to one of 11 outcomes. AuditMemo outcomes persist + embed + evict on schedule. DirectFinding outcomes enqueue `vr_promote_to_finding` task.

### Milestone M3.R-5: Branching
**Goal:** Multi-branch investigations with fork/merge/promote/abandon.

| # | File | LOC | Depends on |
|---|---|---|---|
| 5.1 | `reasoning/services/branch_manager.py` | 350 | 1.1, 2.6 |
| 5.2 | `reasoning/agents/persona_voices.py` | 100 | — |
| 5.3 | `reasoning/agents/prompts/personas/*.md` (6 files) | 6*80=480 | — |
| 5.4 | `data/persona_dispatch_policy.json` | 50 | — |
| 5.5 | `reasoning/agents/vuln_researcher.py` branching support | 200 | 5.1, 2.6 |

**Exit:** Investigation with 3 forked branches each running a different persona. Branches merge when conclusions align. Engine emits `branch_command` payloads visible in mock UI.

### Milestone M3.R-6: Conversational messaging
**Goal:** Operator can chat with the engine mid-investigation.

| # | File | LOC | Depends on |
|---|---|---|---|
| 6.1 | `reasoning/services/message_classifier.py` | 200 | — |
| 6.2 | `reasoning/services/investigation_runtime.py` | 300 | 5.x |
| 6.3 | `reasoning/workers/investigation_resumer.py` (ARQ) | 150 | 6.2 |

**Exit:** Operator sends message during running investigation → engine classifies → engine responds in next turn. Investigation can be paused and resumed via API.

### Milestone M3.R-7: Workflow integration
**Goal:** Investigation is a first-class workflow.

| # | File | LOC | Depends on |
|---|---|---|---|
| 7.1 | `reasoning/workflow/services.py` | 100 | — |
| 7.2 | `reasoning/workflow/states/investigation_setup.py` | 200 | 2.6, 4.5 |
| 7.3 | `reasoning/workflow/states/investigation_loop.py` | 350 | 2.6, 5.x, 6.x |
| 7.4 | `reasoning/workflow/states/outcome_emit.py` | 200 | 4.1 |
| 7.5 | `reasoning/workflow/states/response_emit.py` | 80 | — |
| 7.6 | `reasoning/workflow/definitions.py` (VR_INVESTIGATE_V1 + VR_VARIANT_HUNT_V1) | 150 | 7.1-7.5 |
| 7.7 | `runtime.py` updates (workflow dispatch) | 60 | 7.6 |

**Exit:** Investigation can be created via PlatformRequest (workflow path). Status visible in workflow runs UI. Resume from paused state works.

### Milestone M3.R-8: Downstream dispatch
**Goal:** Outcomes dispatch to downstream tasks (fuzz, n-day, variant hunt).

| # | File | LOC | Depends on |
|---|---|---|---|
| 8.1 | `reasoning/workers/fuzz_dispatcher.py` (ARQ) | 200 | 1.2, v0.3 fuzzing M3.6 |
| 8.2 | `reasoning/workers/nday_dispatcher.py` (ARQ) | 150 | 1.2, v0.1 N-day |
| 8.3 | Reverse path: fuzz finding → investigation resume | 150 | 8.1, 6.x |

**Exit:** Investigation emits `CampaignLaunch` → fuzz campaign starts → critical finding produced → investigation resumes with new evidence → emits `DirectFinding`.

### Milestone M3.R-9: API + SSE
**Goal:** REST endpoints + live SSE streams.

| # | File | LOC | Depends on |
|---|---|---|---|
| 9.1 | `reasoning/api_router.py` (CRUD + lifecycle) | 400 | all services |
| 9.2 | `reasoning/api_router.py` SSE streams | 200 | 9.1 |
| 9.3 | API tests | 250 | 9.1, 9.2 |

**Exit:** All endpoints documented. SSE streams deliver state/messages/cost ticks. API tests pass.

### Milestone M3.R-10: Frontend integration
**Goal:** Investigation UI consumes the reasoning APIs (D-44 IDE + graph viz).

| # | File | LOC | Depends on |
|---|---|---|---|
| 10.1 | `frontend/queries.ts` reasoning queries | 100 | 9.1 |
| 10.2 | `frontend/mutations.ts` reasoning mutations | 80 | 9.1 |
| 10.3 | `frontend/screens/InvestigationsList.tsx` | 200 | 10.1 |
| 10.4 | `frontend/screens/InvestigationDetail.tsx` (main IDE-style layout) | 600 | 10.1, 10.2 |
| 10.5 | `frontend/components/CodeIDEPanel.tsx` (Monaco) | 350 | 10.4 |
| 10.6 | `frontend/components/ReasoningGraphPanel.tsx` (React Flow) | 300 | 10.4 |
| 10.7 | `frontend/components/InvestigationChatPanel.tsx` | 250 | 10.4 |
| 10.8 | `frontend/components/BranchTreePanel.tsx` | 200 | 10.4 |
| 10.9 | `frontend/components/OutcomePendingModal.tsx` | 180 | 10.4 |
| 10.10 | `frontend/components/CostBudgetIndicator.tsx` | 100 | 10.4 |
| 10.11 | `frontend/components/AuditMemoBrowser.tsx` | 200 | 10.1 |
| 10.12 | `frontend/spec.ts` route additions | 30 | 10.3, 10.4 |

**Exit:** Operator browses investigations, opens one, sees live IDE + graph, chats with engine, accepts/rejects pending outcomes. Cost budget visible. Audit memo browser separate page.

### Milestone M3.T-1: Target enrichment foundation (absorbed v0.2 per D-53)
**Goal:** Workspace + target data layer with capability_profile schema. No enrichment logic yet — just schema.

| # | File | LOC | Depends on |
|---|---|---|---|
| T1.1 | `contracts/workspace.py` (VRWorkspaceSummary, VRWorkspaceCreate) | 100 | — |
| T1.2 | `contracts/target.py` (VRTargetSummary, VRTargetCreate, TargetKind, TargetStatus) | 180 | — |
| T1.3 | `contracts/enrichment.py` (TargetCapabilityProfile, EnrichmentResult, MitigationFlags) | 200 | — |
| T1.4 | `db_models/workspace.py` (VRWorkspaceRecord) | 80 | T1.1 |
| T1.5 | `db_models/target.py` (VRTargetRecord, VRTargetTagIndexRecord) | 180 | T1.2 |
| T1.6 | `alembic/versions/NNN_vr_v03_schema.py` — coherent v0.3 schema, drops legacy v0.1 migrations | 250 | T1.4, T1.5 |
| T1.7 | Update `db_models/project.py` to reference `target_id` FK; drop redundant target columns | 80 | T1.6 |
| T1.8 | Update `db_models/finding.py` to reference `target_id` FK | 30 | T1.6 |
| T1.9 | Update `contracts/project.py` to split target ingestion from target persistence | 100 | T1.1, T1.2 |
| T1.10 | Update workflow states + agent + tools to read target metadata from `vr_targets` (not `vr_projects`) | 200 | T1.7 |
| T1.11 | `contracts/__init__.py` + `db_models/__init__.py` barrel exports | 30 | T1.x |

**Exit:** Migrations apply cleanly to fresh DB. Existing v0.1 code paths (workflow states, agent) read target metadata via `project.target` relation. `ruff check`, `honesty_audit`, `compileall` clean.

### Milestone M3.T-2: Mitigation analyzer
**Goal:** Per-binary mitigation analysis pipeline (extends v0.1's per-PoC checksec to upfront per-target).

| # | File | LOC | Depends on |
|---|---|---|---|
| T2.1 | `enrichment/contracts/mitigation.py` (MitigationReport, MitigationKind) | 100 | M3.T-1 |
| T2.2 | `enrichment/services/mitigation_analyzer.py` | 350 | T2.1, audit-mcp `checksec` |
| T2.3 | `enrichment/services/pe_mitigation_parser.py` | 200 | T2.2 |
| T2.4 | `enrichment/services/elf_mitigation_parser.py` | 200 | T2.2 |
| T2.5 | `enrichment/services/sanitizer_detector.py` (ASAN/MSAN/UBSAN build detection) | 150 | T2.2 |
| T2.6 | `enrichment/workers/mitigation_worker.py` (ARQ task) | 100 | T2.2 |
| T2.7 | Tests for parsers + worker | 250 | T2.x |

**Exit:** Upload a PE/ELF binary → mitigation worker fires → `vr_targets.capability_profile_json.mitigations` populated with full report (NX, ASLR, canary, CET, CFI, RELRO, PIE, sanitizers). Result visible in per-target dashboard.

### Milestone M3.T-3: Function-level exploitability ranker
**Goal:** Standalone batch service that ranks functions by risk-score for operator-facing "what should I focus on" reports.

| # | File | LOC | Depends on |
|---|---|---|---|
| T3.1 | `enrichment/contracts/ranking.py` (FunctionRiskScore, RankingReport) | 100 | M3.T-1 |
| T3.2 | `enrichment/services/function_ranker.py` (composite scoring) | 350 | T3.1, audit-mcp + IDA MCP |
| T3.3 | `enrichment/services/heuristics/parser_sink_detector.py` | 150 | T3.2 |
| T3.4 | `enrichment/services/heuristics/network_entry_detector.py` | 150 | T3.2 |
| T3.5 | `enrichment/services/heuristics/syscall_surface_detector.py` | 120 | T3.2 |
| T3.6 | `enrichment/services/heuristics/string_pattern_detector.py` | 100 | T3.2 |
| T3.7 | `enrichment/workers/ranking_worker.py` (ARQ task) | 100 | T3.2 |
| T3.8 | API endpoints for ranking | 100 | T3.7 |
| T3.9 | Tests for heuristics + ranker | 300 | T3.x |

**Exit:** Trigger ranking on a target → top-N functions ranked with score breakdown (parser=X, network=Y, syscall=Z, strings=W → composite=N). Report stored as artifact; visible in per-target dashboard.

### Milestone M3.T-4: Capability profile builder
**Goal:** One-shot enrichment pass on target ingestion that fills capability_profile_json from D-51 schema.

| # | File | LOC | Depends on |
|---|---|---|---|
| T4.1 | `enrichment/services/capability_profile_builder.py` | 400 | T2.x, T3.x |
| T4.2 | `enrichment/services/target_class_detector.py` (userspace/kernel/hypervisor inference) | 200 | T4.1 |
| T4.3 | `enrichment/services/language_detector.py` (primary + secondary languages) | 200 | T4.1, audit-mcp |
| T4.4 | `enrichment/services/applicable_strategy_filter.py` (matches D-45 TargetProfile) | 150 | T4.1 |
| T4.5 | `enrichment/workers/enrichment_orchestrator.py` (ARQ, chains T2+T3+T4) | 150 | T4.1 |
| T4.6 | Tests | 250 | T4.x |

**Exit:** Operator creates a target → enrichment orchestrator runs all three (mitigation + ranking + capability profile) in sequence → target dashboard shows complete capability profile. Investigation start filters strategies/engines by `applicable_*` lists from capability_profile.

---

### Milestone M3.R-11: Tests + benchmark
**Goal:** Verify v0.3 reasoning against known scenarios.

| # | File | LOC | Depends on |
|---|---|---|---|
| 11.1 | `tests/vr/reasoning/test_contracts.py` | 150 | 1.x |
| 11.2 | `tests/vr/reasoning/test_outcome_router.py` | 200 | 4.1 |
| 11.3 | `tests/vr/reasoning/test_branch_manager.py` | 200 | 5.1 |
| 11.4 | `tests/vr/reasoning/test_memo_store.py` | 150 | 4.5 |
| 11.5 | `tests/vr/reasoning/test_message_classifier.py` | 100 | 6.1 |
| 11.6 | `tests/vr/reasoning/test_mcp_adapters.py` | 200 | 3.x |
| 11.7 | `tests/vr/reasoning/test_investigation_runtime.py` | 250 | 6.2 |
| 11.8 | `tests/vr/reasoning/benchmark/scenarios/*.json` (5 scenarios) | 400 | — |
| 11.9 | `tests/vr/reasoning/benchmark/test_benchmark.py` | 250 | M3.R-1 to M3.R-8 |

**Exit benchmarks:**
- **Scenario A**: Replay D-30 derivation — given fresh CVE landscape, engine independently re-derives V8MapInferenceProfile design within 50 turns
- **Scenario B**: Audit-only memo — engine investigates a clean V8 region, concludes no bug, emits AuditMemo with appropriate confidence
- **Scenario C**: Variant hunt — given CVE-2025-2135, engine spawns variant hunt and identifies 2+ structurally similar functions
- **Scenario D**: Conversational steering — operator interrupts mid-investigation with correction, engine adjusts hypothesis
- **Scenario E**: Cost exhaustion — budget at $5 forces early termination with `AssessmentReport` instead of speculative findings

---

## Total Estimate

| Milestone | Files | LOC | Cumulative |
|---|---|---|---|
| M3.R-1 Data model + DB | 9 | ~1250 | 1250 |
| M3.R-2 Reasoning agent (single) | 8 | ~1920 | 3170 |
| M3.R-3 MCP adapters | 5 | ~1340 | 4510 |
| M3.R-4 Outcome routing | 5 | ~690 | 5200 |
| M3.R-5 Branching | 11 (incl 6 personas) | ~1180 | 6380 |
| M3.R-6 Conversational messaging | 3 | ~650 | 7030 |
| M3.R-7 Workflow integration | 7 | ~1140 | 8170 |
| M3.R-8 Downstream dispatch | 3 | ~500 | 8670 |
| M3.R-9 API + SSE | 3 | ~850 | 9520 |
| M3.R-10 Frontend integration | 12 | ~2590 | 12110 |
| M3.R-11 Tests + benchmark | 9 | ~1900 | 14010 |
| **Total** | **75 files** | **~14000 LOC** | |

**Cross-cutting v0.3 totals** (this plan + fuzzing plan + MCP fleet from D-47/48):
- v0.3 reasoning: ~14000 LOC
- v0.3 fuzzing: ~9000 LOC
- MCP fleet (platform): ~1900 LOC
- MCP fleet (frontend): ~700 LOC
- **Total v0.3: ~25600 LOC across ~190 files**

---

## Verification Checklist

Before marking v0.3 reasoning complete:

- [ ] All v0.1 and v0.3 fuzzing verification items still pass
- [ ] `python -m compileall src/aila/modules/vr/reasoning -q` — zero errors
- [ ] `python -m ruff check src/aila/modules/vr/reasoning/` — clean
- [ ] `python -m aila.tools.honesty_audit src/aila/modules/vr/reasoning` — zero findings
- [ ] `alembic upgrade head` — migration 030 applies cleanly
- [ ] pgvector extension confirmed present
- [ ] `cd frontend && pnpm -r run type-check` — clean
- [ ] All 5 benchmark scenarios pass
- [ ] Cost budget hard stop verified (investigation auto-terminates at $X cap)
- [ ] Audit memo eviction task verified (memos beyond 90d removed)
- [ ] SSE streams stable under 10+ concurrent subscribers
- [ ] Branching: 5-deep branch tree resolves without state corruption
- [ ] Operator pause/resume roundtrip works across process restart (durability)
- [ ] Downstream dispatch verified: outcome → fuzz campaign → finding → investigation resume → DirectFinding

---

## Risks & Open Questions

### R-R1: Persona prompt drift
Personas (Halvar/Maddie/Yuki/Renzo/Noor/Wei) are LLM voices defined by prompt prefixes. Without evaluation, prompts drift toward indistinguishable. M3.R-5 includes voice-distinctiveness test: 50 sample turns per persona scored against a checklist of voice markers.

### R-R2: Outcome routing brittleness
The 11-outcome enum may be too rigid for novel investigation shapes. Mitigation: `AssessmentReport` is the catch-all — engine falls through to it when no specific outcome fits. Periodic review of `AssessmentReport` outcomes identifies missing outcome types.

### R-R3: Audit memo accuracy
A bad audit memo causes false negatives forever (until 90d expiry). Mitigation: memos require `confidence >= "strong"` to be persisted. `caveated` or `unknown` confidence forces engine to emit `AssessmentReport` instead, which doesn't get auto-promoted.

### R-R4: Branching state explosion
With 6 personas + sub-branches, an investigation could spawn 36+ branches. Cap: max 8 active branches per investigation (configurable). When cap reached, engine must merge or abandon before forking again.

### R-R5: Resume durability across restarts
Postgres LISTEN/NOTIFY doesn't survive consumer restart. Need a fallback poll mechanism for `investigation_resumer.py` to catch pause-resume signals on cold start. ARQ provides delayed-task retry which covers this.

### R-R6: Conversational classification cost
Every operator message triggers a cheap LLM call for intent classification. At scale this dominates investigation cost. Mitigation: explicit operator UI options (buttons for "steering" / "correction" / "dismiss") avoid the LLM call when intent is unambiguous.

### R-R7: Frontend complexity
M3.R-10 is ~2600 LOC of frontend across 12 files. Risk of bloat. Mitigation: Monaco + React Flow are existing catalog deps; CodeIDEPanel and ReasoningGraphPanel are reusable across forensics module (which will adopt same UI pattern).

---

## Out of Scope (deferred to v0.4+)

- Cross-investigation knowledge graph (audit memos are point-lookups, not a graph)
- Investigation handoff between operators (assigned-to tracking only; no live multi-cursor)
- Real-time multi-operator collaboration (one operator per investigation in v0.3)
- Automatic investigation chaining (operator manually starts next investigation; no engine-initiated chains)
- Investigation templates / preset starting prompts (operator types freely; v0.4 adds presets)
- ML-trained outcome classifier (M3.R-4 uses rule-based dispatch; ML training in v0.4)
- Investigation export to external bug tracker (Phabricator, Jira) — manual copy/paste in v0.3
