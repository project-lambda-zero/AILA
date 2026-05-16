# VR Module — Hypothesis Engine Integration

## TL;DR

**The reasoning engine the VR module needs is already built.** `platform/services/reasoning.py` ships with `vulnerability_research` as a first-class `ReasoningStrategyFamily` value (line 36 of `platform/contracts/reasoning.py`). The forensics module is the reference consumer (`HonestInvestigator` in `modules/forensics/agents/investigator.py`).

VR's v0.3 fuzzing module wraps the same engine. Strategy discovery, hypothesis dispute, CVE-pattern audit, source-code reading, AND the eventual decision to fuzz are all just **actions the reasoning engine picks per turn**. Fuzzing is not the entry point; it's one outcome of a hypothesis investigation.

This doc explains the integration and reverses earlier framing in `VR_V03_FUZZING_PLAN.md` where fuzzing was the workflow root. Per the 2026-05-15 session, fuzzing is a CONCLUSION the engine reaches after disputing hypotheses, not the starting move.

## What the reasoning engine already does (verified by reading `platform/contracts/reasoning.py`)

|Concept|Type|Purpose|
|---|---|---|
|`ReasoningStrategyFamily`|Literal enum|Domain selector. Includes `"vulnerability_research"` already.|
|`Hypothesis`|Model|One live explanatory hypothesis with `kill_criterion` (what would refute it).|
|`RejectedHypothesis`|Model|A disproved hypothesis with `reason`. Persists so we don't re-propose it.|
|`EvidenceProvenance`|Model|Primary + supporting evidence per answer candidate, plus `rejected_alternatives`.|
|`ReasoningGraphNode` / `ReasoningGraphEdge`|Model|Persistent evidence graph. Node kinds: `contract`, `hypothesis`, `rejected_hypothesis`, `observable`, `evidence`, `answer`. Edge kinds: `depends_on`, `supports`, `refutes`, `corroborates`, `answered_by`.|
|`ReasoningGraphDiff`|Model|Between two snapshots — what hypotheses arose/died/got promoted between turns.|
|`ReasoningCaseState`|Model|Normalized state carried across investigation turns.|
|`ReasoningOperatorSteering`|Model|Operator constraints (the **interrupt** mechanism — analog to Topic 8 in `VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md`).|
|`ReasoningTurnDecision`|Model|Single-turn output. `ReasoningAction = "script_execute" \| "tool_run" \| "reasoning" \| "submit"`.|
|`ReasoningDomainProfile`|Model|Cross-domain adapter metadata. VR registers its own.|

The forensics agent (`HonestInvestigator`) docstring describes the loop explicitly:

> `parse contract → build case model → propose hypotheses → pick one action by information gain → execute → normalise observables → rescore hypotheses → answer gate → commit with provenance`

This is **exactly** what VR strategy discovery needs.

## What VR adds on top

VR registers its own `ReasoningDomainProfile` and its own `HonestVulnResearcher` agent. The agent uses the same engine but with VR-specific:
- prompt context
- tool/action vocabulary
- hypothesis kinds
- kill criteria
- evidence sources

### VR-specific question types

These are the **questions** the engine answers (the contract layer). One question → one full investigation → one or more committed findings.

|Question template|Example concrete question|
|---|---|
|*"Which fuzzing strategy should we run against TARGET for BUG_CLASS over BUDGET?"*|"Which strategy against V8 Maglev for JIT typer bugs over 72h?"|
|*"Is the recent CVE C exploitable in our environment? What's the variant landscape?"*|"Is CVE-2026-3910 variant landscape exhausted, or are more Phi-untagging bugs hiding?"|
|*"Has fuzzer F caught up to the bug class C, or is custom strategy still warranted?"*|"Has stock FUZZILLI v8 profile caught argument-aliasing patterns since CVE-2025-2135?"|
|*"What's the highest-EV target component in PROJECT given recent CVE data?"*|"Highest-EV V8 component for next 90d given 2026 CVE distribution?"|
|*"Does the patch for CVE C fully address the root cause, or only the trigger?"*|"Does the CVE-2025-2135 patch close all `InferMapsUnsafe` aliasing paths, or just the one Zellic exploited?"|

The questions are derived from operator intent + project context (current target, prior findings, time budget). They're persisted alongside the resulting investigation just like forensics questions.

### VR-specific hypothesis kinds

VR hypotheses fit three buckets:

|Bucket|Example hypothesis|Kill criterion|
|---|---|---|
|**Bug-class hypothesis**|"V8 Maglev Phi untagging has additional unfixed variants beyond CVE-2026-3910"|Find recent patches that close every `Phi*` untagging path; OR find a public researcher write-up claiming the area is exhausted.|
|**Strategy hypothesis**|"FUZZILLI's argument selection never produces aliasing, so custom alias-injection generator is novel"|Find a FUZZILLI generator that produces aliased args (would refute novelty); OR find a public talk saying alias-aware fuzzing has been done.|
|**Target hypothesis**|"V8 142.x ships a new optimization with under-fuzzed surface"|Find no design-doc reference to corresponding new generator in FUZZILLI's V8CommonProfile; find evidence V8 team announced new fuzz infrastructure for it.|

Each hypothesis lives in the `Hypothesis` model with `kill_criterion` filled. The engine picks actions to test the kill criterion.

### VR-specific actions

The 4 `ReasoningAction` values mapped to VR work:

|Action|VR usage examples|Implemented by|
|---|---|---|
|**`tool_run`**|`cve_lookup(CVE-2026-3910)`, `source_grep(fuzzilli, "randomArguments")`, `web_search(...)`, `audit_mcp_query(v8/src/maglev/...)`, `ida_function_decompile(...)`, `bountypanel_lookup(V8, "JIT type confusion")`|`tools/` registered with platform tool registry (per MODULE_STANDARD)|
|**`script_execute`**|Run a probe d8 program to verify a primitive works; run static analysis on V8 source for a specific pattern; clone-then-diff a FUZZILLI release|`ScriptExecutorTool` (reused from forensics)|
|**`reasoning`**|Propose new hypotheses given observations; rescore existing ones; check for contradictions in evidence graph|Pure LLM turn, no external tool|
|**`submit`**|Commit to a `FuzzCampaign` configuration; spin up a campaign via the v0.3 fuzzing workers; OR commit to "no fuzz needed, area exhausted, file an audit memo"|Calls `vr.fuzzing.start_campaign(strategy_id, target_id, budget)` which kicks the v0.3 campaign pipeline|

`submit` is THE moment where strategy discovery either spawns a fuzz campaign OR concludes without one. Fuzzing is downstream of decision, not upstream.

### VR-specific evidence sources

The `EvidenceProvenance.primary_evidence` field captures where the answer came from. For VR, evidence sources include:

|Source|Examples|
|---|---|
|**CVE databases**|NVD, vendor advisories, MITRE, chrome-security blog|
|**Patch commits**|V8 git log filtered for `Security:` / CVE refs / specific bug-tracker IDs|
|**Public research write-ups**|Zellic blog, Project Zero issue tracker, conference talks (recordings/slides)|
|**Source code**|V8 source tree, FUZZILLI source tree, Chromium tree, kernel source|
|**Audit-mcp queries**|Type resolution, callgraph, syntactic patterns at scale|
|**Prior internal findings**|This module's own `vr_findings` table — what we've already proven|
|**Live fuzzing telemetry**|Stats from active campaigns (e.g. "did mapinf_v8 find anything in last 24h?")|
|**Operator notes**|Steered constraints from `ReasoningOperatorSteering`|

Each source becomes a `ReasoningGraphNode` with `kind="evidence"` and edges (`supports` / `refutes` / `corroborates`) to the relevant hypotheses.

## End-to-end example: deciding to launch V8MapInferenceProfile

Following the actual session's flow, but as engine turns:

### Turn 1: Question intake
Operator: "What fuzzing strategy should we run against V8 Maglev for JIT typer bugs over 72h?"

Engine creates `ReasoningContract` with `answer_type="strategy_descriptor"`, `evidence_domain="v8_jit_compiler"`.

### Turn 2: Propose initial hypotheses (`reasoning` action)
Engine proposes 5 hypotheses:
- H1: "Stock v8Sandbox profile is sufficient"
- H2: "Custom alias-injection generator targets CVE-2025-2135 pattern"
- H3: "Custom Phi-mixer generator targets CVE-2026-3910 pattern"
- H4: "Concurrent compilation race is a fertile area"
- H5: "Multi-target rotation (V8 + SpiderMonkey) is better than V8 focus"

Each gets a `kill_criterion`.

### Turn 3: Test H1 via `tool_run` (CVE clustering audit)
Engine calls `cve_cluster_query(target="v8", since="2025-01-01", class="JIT type confusion")`. Result: 6+ CVEs in cluster, recurring class. H1 has a refute edge to "stock profile coverage is the same Google fleet operates 24/7 with the same yield as 2024." H1 enters `RejectedHypothesis` with reason.

### Turn 4: Test H2 via `tool_run` (FUZZILLI source grep)
Engine calls `source_grep(repo="fuzzilli", pattern="randomArguments")`. Result: `parameterTypes.map({ randomVariable(forUseAs: $0) })`. Each param picked independently → aliasing is essentially never produced.

Adds evidence node "fuzzilli/ProgramBuilder.swift:N — randomArguments independent-pick" → H2 with `supports` edge. H2 stays alive.

### Turn 5: Test H3 via `tool_run` (CVE patch reading)
Engine calls `cve_patch_lookup(CVE-2026-3910)`. Result: Maglev Phi untagging logic error confirmed at file/line. Evidence node supports H3.

### Turn 6: Test H4 via `tool_run` + `reasoning`
Engine calls `web_search("V8 concurrent compilation fuzzer bug CVE")`. Result: thin. No CVE patches matching. Researcher commentary saying "concurrent fuzzing is hard but no public tooling targets it" exists but no recent CVE. Score: weak evidence both ways.

Engine's `reasoning` turn: "H4 cannot be killed easily but evidence is too weak to invest 72h. Park as a future-work hypothesis. Demote priority."

H4 stays in graph but as `Hypothesis` with low priority; not selected for submit.

### Turn 7: Test H5 via `tool_run` (operator steering check)
Engine queries `ReasoningOperatorSteering`. Operator said "V8 only this quarter, deferring SpiderMonkey." H5 → `RejectedHypothesis` with reason "operator scope constraint".

### Turn 8: Engine scores surviving hypotheses
H2 and H3 survive. Both have:
- Strong supporting evidence (CVE patches, FUZZILLI source gap)
- Specific patterns implementable as FUZZILLI CodeGenerators
- Recent CVE confirming the class is hot

### Turn 9: `submit` action
Engine submits a strategy descriptor:
```json
{
  "strategy_id": "mapinf_v8",
  "rationale_hypothesis_ids": ["H2", "H3"],
  "evidence_graph_snapshot_id": "...",
  "campaign_config": {
    "engine": "v8_d8_std",
    "profile": "v8MapInference",
    "jobs": 8,
    "hours": 72,
    "novelty_evidence": { ... },
    "pivot_history": []
  }
}
```

The platform's submit handler kicks the v0.3 fuzzing module: `vr.fuzzing.start_campaign(...)`. Campaign begins.

### Turn 10+: Live feedback into engine
While campaign runs, the engine listens to telemetry. If crashes appear:
- New `observable` nodes added per crash
- New hypotheses get auto-proposed by the engine for variant hunting
- Operator can intervene via `ReasoningOperatorSteering`

If after the budget elapses no crashes:
- Hypotheses H2/H3 get `kill_criterion` updated ("no findings after N execs")
- If kill criterion met → hypotheses move to rejected, engine proposes next batch
- If not met (budget too small) → request extension OR commit to longer campaign

## Workflow integration

VR v0.3 workflow becomes a **two-phase** flow:

```
PHASE 1: REASONING (uses HonestVulnResearcher + reasoning engine)
   intake → propose_hypotheses → dispute_loop → submit_strategy

PHASE 2: EXECUTION (the existing v0.3 fuzzing pipeline)
   fuzz_setup → fuzz_campaign → fuzz_summary → response_emit

FEEDBACK: Findings from PHASE 2 spawn new hypotheses for PHASE 1.
```

This is a refinement to `VR_V03_FUZZING_PLAN.md`'s workflow section. The old `VR_FUZZ_CAMPAIGN_V1` workflow becomes PHASE 2 only; a new `VR_HYPOTHESIS_INVESTIGATION_V1` workflow wraps PHASE 1 and can optionally invoke PHASE 2 as a downstream workflow.

### State diagram

```
+-------------+
|   intake    |  question + project context + steering
+------+------+
       |
       v
+--------------------+
|  propose_hypotheses |  LLM generates initial Hypotheses
+--------+-----------+
         |
         v
+----------------------+
|    dispute_loop      |  iterative engine turns
|  (cve_lookup,        |  - tool_run actions
|   source_grep,       |  - script_execute actions
|   reasoning, ...)    |  - reasoning actions
|                      |  Updates evidence graph each turn.
|                      |  Loop until ALL hypotheses are either
|                      |  killed OR strongly supported.
+--------+-------------+
         |
         v
+---------------------+
|  submit_decision    |  Engine picks: launch campaign OR no-fuzz
+--------+------------+
         |
         +-----> NO FUZZ: emit audit memo. (Some questions resolve
         |                without fuzzing — "this area is exhausted,
         |                no strategy worthwhile, file the negative
         |                result so we don't re-explore for 90d.")
         |
         +-----> LAUNCH: spawn VR_FUZZ_CAMPAIGN_V1 with strategy
                         config from surviving hypotheses.
                         When campaign completes, FEEDBACK into a
                         new hypothesis turn (variant hunt, etc.).
```

### Audits without fuzzing — important

The user explicitly asked about this. The engine's `submit` action can decide **"no fuzz needed."** Three audit-only outcomes:

|Outcome|When|Artifact emitted|
|---|---|---|
|**Negative result memo**|All proposed hypotheses killed; no strategy survives|`vr_audit_memos` row with rationale, evidence graph snapshot, expiry (90d default)|
|**Pre-fuzz exploration note**|Hypotheses survive but evidence too thin to commit budget|`vr_audit_memos` with "needs more evidence" status, suggested next data sources|
|**Variant audit**|Hypothesis is about variants of existing finding, doesn't need new fuzz — pure source reading|Direct entry in `vr_findings` as a `claimed` confidence (per `VR_STAFF_RESEARCHER_DISCUSSION.md` D-Noor consensus)|

Audit memos prevent re-investigating the same dead ends. When a new question comes in, the engine queries memos first; if a recent memo says "this area has been investigated, here's why we passed," the engine either trusts that result or has to specifically argue why the memo's reasoning no longer holds (e.g., new CVE landed).

## Worked example: variant hunt with live IDE interaction

The most complex live-UI flow is variant hunting from a confirmed parent finding. The file explorer becomes a real-time status dashboard; the code viewer becomes a verification surface; the graph panel becomes a live variant tree. This worked example shows D-41 + D-43 + D-44 composing.

### The conversation

```
operator: hunt variants for F-12345

engine:   [Parsing context: variant_hunt_order intent inferred]
          F-12345 is the InferMapsUnsafe alias gap at
          v8/src/maglev/maglev-ir.cc:1247 (root cause class
          CVE-2025-2135).

          Proposing 4 variant hypotheses:
          ▸ H1: same pattern at sibling functions in same file
          ▸ H2: same pattern in caller/callee chain
          ▸ H3: structurally similar code elsewhere in V8 tree
          ▸ H4: Wasm-side equivalent (CanonicalSig / WCPT)

          Budget: $3.00, ~70 candidate sites estimated.
          Forking into 4 parallel branches (D-41) — one per hypothesis.

          [▶ Start variant hunt]   [Adjust budget]   [Drop H4 (Wasm out of scope)]

operator: drop H4, lets see

engine:   Steering updated: H4 abandoned (Wasm out of scope per operator).
          Starting 3 branches in parallel.
```

### The file explorer decorates in real time

As branches run, each file gets a status icon. Icons update via SSE events from the campaign workers.

```
File Tree (right panel)              Status legend
───────────────────────              ─────────────
▾ v8/src/                            ⚪  pending (queued for analysis)
  ▾ maglev/                          🔵  currently being analyzed
    ★ maglev-ir.cc                   ✓  cleared (no variant)
      └─ line 1247 [F-12345]         ⚠  candidate (pattern match, unconfirmed)
    🔵 maglev-graph-builder.cc       ★  confirmed variant (promoted to finding)
    🔵 maglev-phi-untagging.cc       ✗  rejected (operator dismissed)
  ▾ compiler/
    ⚪ js-create-lowering.cc
    ⚪ js-native-context-specialization.cc
    ⚪ js-typed-lowering.cc
    ...44 more pending H3 candidates
```

Hovering a file shows:
- Status reason (e.g., "matched pattern at line 1812, 87% structural similarity")
- Which branch/hypothesis flagged it
- Time analyzed / time remaining
- Click → opens file in code viewer with the suspected line highlighted

### The variant tree graph updates live

The graph panel (React Flow per D-44) renders the variant tree. Initial state:

```
        F-12345 (★ confirmed root)
          ├── H1 sibling (3 pending)
          ├── H2 callgraph (8 pending)
          └── H3 structural (47 pending)
          [H4 abandoned by operator]
```

As branches make progress, nodes appear under each hypothesis, color-coded by status. Click a candidate node → IDE auto-jumps to file/line.

### Candidate surfaces with auto-open

```
engine: [✓ checked maglev-graph-builder.cc:Visit — no variant]
engine: [✓ checked maglev-graph-builder.cc:VisitWithMaps — no variant]
engine: [⚠ candidate found]
        js-native-context-specialization.cc:1812
        Pattern match: 87% to F-12345's structure
        - IsSame(receiver, object_) check present
        - alias-handling code MISSING (parent's gap)
        - effect chain has Array.prototype.X.call (matches parent's effect)

        [▼ Opening in code viewer with side-by-side comparison]
```

The IDE auto-splits to side-by-side view:

```
┌─ js-native-context-specialization.cc:1812 ─┐ ┌─ F-12345 root: maglev-ir.cc:1247 ─┐
│ 1809  // ReduceElementAccess monomorphic   │ │ 1244  // InferMapsUnsafe traverse │
│ 1810  if (access_infos.size() == 1) {      │ │ 1245  while (true) {              │
│ 1811    access_info = access_infos.front() │ │ 1246    switch (effect->opcode) { │
│⚠1812    if (IsSame(receiver, object_)) {   │ │⭐1247      case kTransitionElems  │
│ 1813      // missing alias check here      │ │ 1248        if (IsSame(recv, obj))│
│ 1814    }                                  │ │ 1249          return reliable;    │
│ 1815  }                                    │ │ 1250        break;                │
└─────────────────────────────────────────────┘ └────────────────────────────────────┘

Engine annotation: "Both sites call IsSame() but neither handles the false-but-aliasing case.
                    Parent's bug was fixed by setting kUnreliableMaps; this site has the same
                    structure and may have the same vulnerability."

[★ Promote to confirmed]   [⚠ Mark suspicious, verify with fuzz]   [✗ Reject - not a variant]
```

### Operator confirms — engine launches verification

```
operator: verify with fuzz

engine:   Queuing fuzzilli micro-campaign on js-native-context-specialization.cc:1812
          - Budget: $0.20 (per D-41 per-variant budget)
          - Duration: 30 min  
          - Strategy: mapinf_v8 with seed corpus derived from F-12345
          - Engine: v8_d8_std on fuzz workstation
          ...

          [Live progress streams into the file tree decoration:
           ⚠ js-native-context-specialization.cc  →  📊 fuzzing 0:12s]

[30 min later]

engine:   [✓ Verification complete]
          Crash found: SBXCHECK at line 1819 (effect chain side effect)
          Stack signature matches F-12345 family.
          ★ Promoted to new finding: F-12348 (variant of F-12345)

          [▼ Side-by-side: F-12348 details ←→ F-12345 parent]
```

### File tree state at completion

```
▾ v8/src/
  ▾ maglev/
    ★ maglev-ir.cc              ← parent F-12345
    ✓ maglev-graph-builder.cc   ← 12 functions checked, none match
    ✓ maglev-phi-untagging.cc
  ▾ compiler/
    ★ js-native-context-specialization.cc  ← variant F-12348 ⬆
    ✓ js-create-lowering.cc
    ✓ js-typed-lowering.cc
    ⚠ js-call-reducer.cc        ← suspect, awaiting operator triage
    ✓ 43 more cleared
```

### Engine final summary

```
engine:   Variant hunt complete:
          - 58 candidate sites analyzed (avg $0.04/site)
          - 2 confirmed variants: F-12348, F-12349
          - 1 awaiting operator triage: js-call-reducer.cc
          - 55 cleared (no variant)
          - Spend: $2.42 of $3.00 budget

          Next actions:
          ▸ Triage 1 outstanding candidate? [Review]
          ▸ Generate patch-completeness assessment? (Topic 4)
          ▸ Update F-12345 with sibling-variant evidence?
          ▸ Done [Close investigation]
```

### What gets persisted

- Each candidate file decoration → `ReasoningGraphNode` (kind=evidence) with file path, line, pattern_match_score, branch_id
- Operator triage decisions → audit trail (who confirmed/rejected when)
- Each confirmed variant → row in `vr_findings` linked to parent via `parent_finding_id`
- Each branch's exploration history → preserved per D-41 (queryable even after merge/abandon)
- Live SSE event stream → re-playable via the investigation timeline view

### What the IDE provides that pure chat couldn't

|Without IDE+graph|With D-44 + this flow|
|---|---|
|Operator copy-pastes file paths from chat into separate editor|Click file in tree → opens in viewer|
|Operator manually compares parent vs candidate code (window-switching)|Auto side-by-side comparison panel|
|Operator tracks 50+ candidate files in their head|File tree decorations show full state at a glance|
|"How is this candidate related to the parent?" — operator has to remember chain|Click graph node → see chain visualized|
|Approve/reject requires typing exact file paths|Inline buttons on each candidate|
|Progress updates are buried in scroll-back chat|File tree status icons + graph nodes update live|

Variant hunt is the killer use case for D-44's interactive panels.

### Backend message-payload types this requires

Variant hunt depends on these from D-44's message-type catalog:
- `code_pointer` (each candidate site)
- `graph_view` (variant tree)
- `taint_flow` (showing how parent's bug pattern reaches each candidate)
- `patch_diff` (when comparing fixed-elsewhere code to unfixed candidate)
- `hypothesis_update` (variant tree node state changes)
- `outcome_pending` (each candidate awaits operator triage)

Plus three NEW payload types specific to variant hunt:
- `file_tree_decoration` — file path + status + reason. Frontend updates the tree decoration without losing scroll/expansion state.
- `candidate_for_triage` — file + line + pattern_match_score + comparison_context + accept/reject buttons embedded in chat
- `variant_hunt_progress` — branch_id + budget_used + candidates_processed + remaining_estimate (updates progress meter)

Cost addition over D-44 baseline: ~150 LOC backend (three new payload types), ~250 LOC frontend (file tree decoration subscriber + candidate triage card + progress meter).

---

## Branching — exploring multiple investigation paths in parallel

The single-thread reasoning loop (intake → propose → dispute → submit) handles most VR investigations. But certain decisions benefit from EXPLORING MULTIPLE PATHS in parallel before committing:

- Two competing strategies that could each consume the full 72h budget
- Two evidence-gathering approaches that pull from different sources (CVE-feed-first vs source-grep-first)
- A high-stakes call where the operator can't decide between A and B and wants to see both play out
- Variant hunt: one confirmed crash spawns N variant-mutation branches, each exploring a different transformation
- Multi-persona dispute literally as branches: each persona advocates their position in its own branch, then merge based on accumulated evidence

Branching extends the reasoning engine with **fork-merge** semantics. Forensics could benefit from the same extension but VR is the consumer driving it.

### Schema additions (platform-level)

New `ReasoningBranch` model in `platform/contracts/reasoning.py`:

```python
class ReasoningBranch(BaseModel):
    """One branch of a reasoning investigation.

    Branches fork off a parent branch at a specific reasoning state.
    Each branch carries its own hypothesis set, evidence subgraph,
    operator steering, and turn history. Branches can be:
    - active: currently being explored
    - abandoned: explored and discarded (with rationale)
    - merged: evidence promoted into parent
    - promoted: replaced the parent as canonical
    """
    id: str
    investigation_id: str
    parent_branch_id: str | None = None
    name: str = ""                              # short label: "mapinf_focus", "stock_baseline"
    rationale: str = ""                         # why this branch was forked
    forked_at: datetime
    forked_from_snapshot_id: str                # ReasoningEvidenceGraph snapshot at fork moment
    status: Literal["active", "abandoned", "merged", "promoted"] = "active"
    abandoned_reason: str = ""
    merged_into_branch_id: str | None = None
    cost_so_far_usd: float = 0.0
    cost_cap_usd: float = 5.0                   # per-branch budget
    turns_so_far: int = 0
    turns_cap: int = 20
```

`ReasoningCaseState` gets a `branch_id` field. `ReasoningGraphService` snapshots become branch-aware: each branch has its own evidence graph rooted at the fork snapshot.

New `BranchOperation` (Literal): `"fork"`, `"abandon"`, `"merge"`, `"promote"`, `"compare"`.

### Engine actions for branching

Two new `ReasoningAction` values:
- **`branch_fork`** — engine decides to fork into N branches at the current state. Returns the branch IDs.
- **`branch_resolve`** — engine looks at active branches and decides: which to keep, which to abandon, which to merge, which to promote.

Operator can also trigger branching via API (see below) — the engine doesn't have to initiate it.

### Default fork policy

The engine SHOULD fork when:
- Initial hypotheses split into >1 mutually-exclusive bug-class groups (e.g., "JIT typer" + "Wasm reftype" both look viable). Fork into one branch per group.
- Two evidence-gathering paths would consume similar budget but pull from different sources. Fork to gather both.
- Operator steering says "explore both A and B" explicitly.
- Variant hunt context: each crash spawns up to 10 variant branches per `VR_V03_FUZZING_PLAN.md` D-28.

The engine SHOULD NOT fork when:
- A single hypothesis is overwhelmingly dominant (>80% evidence weight from initial propose turn)
- Cost cap is near exhausted (forking just multiplies budget consumption)
- Operator steering explicitly says "commit to one path"

### Merge semantics

When two branches converge or one branch is abandoned, evidence merge follows these rules:

|Merge type|Rule|
|---|---|
|**Promote**|Replace parent's state entirely with the promoted branch's. Other sibling branches auto-abandoned with reason "sibling promoted".|
|**Merge into parent**|Branch's `evidence` and `observable` nodes are added to parent's graph. `Hypothesis` nodes added if not already present in parent. `RejectedHypothesis` rationales appended (don't overwrite parent's). Cost accumulates.|
|**Abandon**|Branch's evidence subgraph is preserved in storage but NOT merged into parent. The abandon-rationale becomes a `refutes` edge from "branch abandonment" node to any hypotheses the branch was exploring.|
|**Compare** (read-only)|Returns a `ReasoningGraphDiff` between two branches' graphs. No state change. Used by operator UI for side-by-side review.|

### Branch cost budgets

Each branch carries its own `cost_cap_usd` and `turns_cap`. When a branch hits its cap, the engine forces a `branch_resolve` turn — either promote (sufficient evidence), abandon (insufficient), or merge (partial result).

Default budgets:
- Strategy-discovery investigation: parent cap $5, max 4 active branches → per-branch cap $1.25
- Variant hunt: parent cap $2, max 10 branches → per-branch cap $0.20
- Operator can override via `ReasoningOperatorSteering`

### Operator API

```
# List all branches in an investigation
GET /api/vr/investigations/{id}/branches

# Fork the current state into a new branch
POST /api/vr/investigations/{id}/branches
{
  "from_branch_id": "<current>",
  "name": "explore_wasm_jit",
  "rationale": "operator suggests testing if Wasm/JS boundary hypotheses survive",
  "cost_cap_usd": 1.5,
  "initial_steering": {
    "scope": ["v8 wasm"],
    "constraints": ["assume Wasm GC type system is known-buggy"]
  }
}
# Returns: { branch_id, status: "active", forked_at_snapshot_id }

# Compare two branches
GET /api/vr/investigations/{id}/branches/compare?from={a}&to={b}
# Returns: ReasoningGraphDiff

# Promote a branch (operator decision)
POST /api/vr/investigations/{id}/branches/{branch_id}/promote
# Returns: list of auto-abandoned sibling branch_ids

# Abandon a branch
POST /api/vr/investigations/{id}/branches/{branch_id}/abandon
{ "reason": "operator decided wasm is out of scope this quarter" }

# Merge branch evidence into parent without promotion
POST /api/vr/investigations/{id}/branches/{branch_id}/merge
```

### Multi-persona dispute as branches

The cleanest application of branching is mapping the 6 personas from `VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md` to branches at high-stakes decision points. Each persona advocates their position as a separate branch:

- **Halvar branch:** explores PoC-first, "show me the primitive" approach
- **Maddie branch:** explores patch-diff-first approach
- **Yuki branch:** explores crash-triage-friendly approach
- **Renzo branch:** explores source-level approach (no fuzzing if source-read finds it faster)
- **Noor branch:** explores defense-feasibility approach (would mitigation X catch this?)
- **Wei branch:** explores IR-level / compiler-internals approach

Each branch runs its own dispute loop with a single-persona prompt. After all branches reach `submit` (or hit budget), the engine runs a `branch_resolve` turn that compares them:
- Which branches produced novel evidence?
- Which branches converged on the same submit decision?
- Which branches got stuck or produced contradictions?

Promote the highest-quality branch, merge corroborating branches' evidence, abandon contradicted ones. The operator gets a side-by-side view of all 6 personas' reasoning paths in the frontend.

### Branch UI in frontend (conceptual)

Borrow Git's mental model:
- Tree visualization of branch graph
- Each branch has commit-like history (one node per reasoning turn)
- Hovering a turn shows: action, evidence added, hypotheses changed
- Side-by-side diff view for two selected branches
- Promote/abandon/merge buttons with confirmation
- Cost meter per branch (red when approaching cap)

This is a substantial UI feature. Implementation deferred to v0.4 unless operator demand surfaces sooner; v0.3 ships with API-only branching (operator can fork/promote via curl).

### State diagram with branching

```
    intake
       |
       v
   propose_hypotheses
       |
       v
  +----+----+
  | hypotheses |
  | are mutually|
  | exclusive? |
  +----+----+
       |
  +----+----+
  |         |
  no        yes
  |         |
  v         v
dispute    fork_decision
  |         |
  |    +----+----+----+
  |    |    |    |    |
  |  br_A  br_B  br_C ...   (each gets its own intake state seeded
  |    |    |    |              with the question + that hypothesis)
  |    |    |    |
  |  dispute dispute dispute  (parallel reasoning loops)
  |    |    |    |
  |  submit submit submit    (each branch reaches its own conclusion)
  |    |    |    |
  |    +----+----+----+
  |         |
  |    branch_resolve         (engine picks: promote one, merge several,
  |         |                  abandon rest)
  |         v
  +-->  submit_decision        (canonical final outcome)
          |
          v
        emit (campaign or memo or finding)
```

### Backward compatibility

Investigations that DON'T need branching just run on a single implicit "main" branch. The `ReasoningCaseState.branch_id` defaults to a generated value at intake. Existing forensics workflows are unaffected.

### Cost of implementation

Net new beyond the M3.3a-d milestones already planned:

|#|Milestone|LOC est|Notes|
|---|---|---|---|
|M3.3e|`ReasoningBranch` schema + `branch_id` on case state + DB table|~250|Platform-level, benefits forensics too|
|M3.3f|Branch operations service (fork/abandon/merge/promote/compare)|~350|Platform-level|
|M3.3g|VR workflow states for `fork_decision` + `branch_resolve`|~200|VR-specific|
|M3.3h|Operator API endpoints + auth|~200|Platform-level|
|M3.3i|(deferred to v0.4) Frontend branch tree visualization|~600|Deferred|

Total platform-level: ~800 LOC. Total VR-specific: ~200 LOC. Frontend defer.

---

## What lands in `src/aila/modules/vr/` (per MODULE_STANDARD)

Per the v0.3 plan (`VR_V03_FUZZING_PLAN.md`), the VR module already has structure for fuzzing. This integration adds the reasoning layer.

### New files (additions on top of the v0.3 plan)

```
src/aila/modules/vr/
│
├── reasoning/                                NEW — shared reasoning layer (used by all outcomes)
│   ├── agents/
│   │   └── vuln_researcher.py                NEW — HonestVulnResearcher class
│   │                                              (parallel to HonestInvestigator;
│   │                                               same engine, VR prompts/tools)
│   ├── contracts/
│   │   └── strategy_descriptor.py            NEW — StrategyDescriptor (engine's submit output)
│   ├── data/
│   │   ├── domain_profile.json               NEW — VR's ReasoningDomainProfile
│   │   ├── prompts/
│   │   │   ├── vuln_researcher_system.md     NEW — system prompt (parallel to forensics' _SYSTEM_PROMPT_BASE)
│   │   │   ├── hypothesis_seeds.md           NEW — bootstrap hypotheses for common question types
│   │   │   └── kill_criteria_templates.md    NEW — reusable kill_criterion patterns
│   │   └── question_templates/
│   │       ├── strategy_selection.json       NEW — template for "which strategy" questions
│   │       ├── variant_landscape.json        NEW — template for "what variants exist" questions
│   │       └── target_prioritization.json    NEW — template for "highest-EV component" questions
│   ├── tools/                                NEW — engine-callable tools (cross-outcome)
│   │   ├── cve_lookup_tool.py                NEW — wraps NVD + vendor advisories
│   │   ├── cve_cluster_query_tool.py         NEW — statistical clustering of CVEs by class
│   │   ├── source_grep_tool.py               NEW — wraps audit-mcp ast queries
│   │   ├── patch_diff_tool.py                NEW — compare two versions, extract changed funcs
│   │   ├── audit_memo_query_tool.py          NEW — checks existing memos before investigating
│   │   └── strategy_descriptor_tool.py       NEW — emits StrategyDescriptor (submit -> campaign)
│   └── workflow/
│       ├── states/
│       │   ├── hypothesis_intake.py          NEW — parse question + project + steering
│       │   ├── hypothesis_propose.py         NEW — initial hypothesis generation
│       │   ├── hypothesis_dispute.py         NEW — the engine loop (calls tools, updates graph)
│       │   ├── fork_decision.py              NEW — branch when hypotheses split (D-41)
│       │   ├── branch_resolve.py             NEW — merge/promote/abandon branches (D-41)
│       │   └── submit_decision.py            NEW — emit campaign | memo | finding
│       └── definitions.py                    NEW — VR_HYPOTHESIS_INVESTIGATION_V1
│
├── audit/                                    NEW — code-audit outcome (no fuzz)
│   ├── contracts/
│   │   └── audit_memo.py                     NEW — VRAuditMemo Pydantic model
│   ├── db_models/
│   │   └── audit_memo.py                     NEW — vr_audit_memos table
│   ├── services/
│   │   ├── audit_memo_service.py             NEW — emit/query/expire memos
│   │   └── source_reading_service.py         NEW — guided code audit via audit-mcp
│   ├── tools/                                NEW — audit-specific reasoning tools
│   │   ├── fuzzilli_source_read_tool.py      NEW — version-aware FUZZILLI source access
│   │   ├── compiler_ir_inspect_tool.py       NEW — analyze JIT IR for invariant violations
│   │   └── ida_decompile_tool.py             NEW — wraps IDA Headless MCP for binary work
│   ├── workers/
│   │   └── audit_memo_emit_worker.py         NEW — ARQ task to finalize a no-fuzz outcome
│   ├── workflow/
│   │   └── states/
│   │       └── audit_memo_emit.py            NEW — workflow state for no-fuzz finalization
│   └── reporting/
│       └── audit_memo_report.py              NEW — human-readable memo formatting
│
├── fuzzing/                                  Existing v0.3 scope, now split by mode
│   ├── discovery/                            DISCOVERY fuzzing — hunt novel bugs
│   │   ├── engines/                          FUZZILLI subprocess wrappers (V8, SpiderMonkey, ...)
│   │   ├── strategies/                       data/strategies/ JSON: mapinf_v8, stock_v8, hole, sbx
│   │   └── (everything from VR_V03_FUZZING_PLAN.md M3.1-M3.13)
│   │       — invoked when reasoning's submit_decision picks discovery-campaign
│   │
│   └── nday/                                 NEW — N-day-targeted fuzzing (reproduce CVE + variant hunt)
│       ├── engines/
│       │   ├── afl_libfuzzer.py              NEW — AFL++ / libFuzzer wrapper for in-process harness
│       │   ├── winafl_dynamorio.py           NEW — WinAFL+DynamoRIO for Windows binary fuzzing
│       │   └── syzkaller.py                  NEW — syzkaller for kernel CVE reproduction (v0.5 preview)
│       ├── strategies/                       data/strategies/ JSON: nday_seeded_patch_diff,
│       │                                                            nday_advisory_corpus,
│       │                                                            nday_variant_hunt
│       ├── harness_gen/
│       │   ├── from_patch_diff.py            NEW — generate fuzz harness from patched function
│       │   ├── from_advisory.py              NEW — extract harness skeleton from advisory text
│       │   └── from_crash_report.py          NEW — seed corpus from public crash report
│       ├── services/
│       │   ├── corpus_seeder.py              NEW — build seed corpus from advisory PoC + patch context
│       │   └── patch_completeness.py         NEW — measure whether fuzz finds variants the patch missed
│       └── workflow/
│           └── states/
│               └── nday_fuzz_campaign.py     NEW — VR_NDAY_FUZZ_V1 workflow state
│
└── (existing v0.1 N-day code at module root)
     — its workflow becomes a third submit_decision outcome ("direct finding"),
       promoting reasoning state into a vr_findings row for v0.1's
       advisory generator to process.

### Files that DO NOT need changes

The reasoning engine itself (`platform/services/reasoning.py`, `platform/contracts/reasoning.py`, `platform/services/reasoning_graphs.py`) requires no changes. It already supports `vulnerability_research` strategy family.

## Wiring the discussion doc into the engine

`VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md` is **input material** for the engine's system prompt. The 9 topics + AILA Replay Protocols become:

|Discussion topic|How engine uses it|
|---|---|
|Topic 1 (stock vs custom)|Decision-tree the engine follows when proposing initial strategy hypotheses|
|Topic 2 (sandbox-API attack fallacy)|Built into `kill_criteria_templates.md` — strategies whose `attack_primitive` ⊆ `assumed_attacker_state` are auto-rejected|
|Topic 3 (novelty test)|Reusable kill criterion: must produce `novelty_evidence` triple to survive|
|Topic 4 (avoid speculation)|Reusable kill criterion: "underexplored" claims need ≥2 evidence sources|
|Topic 5 (throughput bottleneck)|Decision input to `submit_decision.py` — calculate target-attempt count vs available throughput|
|Topic 6 (production architecture)|Constraint at submit time — campaigns ONLY target dedicated workstations registered with the platform|
|Topic 7 (strategy authoring)|Drives `submit` action's downstream — produces engineer-bound PR + strategy JSON|
|Topic 8 (interrupt points)|Maps directly to `ReasoningOperatorSteering` and engine's loop reentry on new evidence|
|Topic 9 (triage hand-off)|Feedback loop from campaign findings back into hypothesis-generation turn|

So the discussion doc is **planning context the engine consumes**, plus the personas (Halvar, Maddie, Yuki, Renzo, Noor, Wei) become the **prompt voices the engine uses** when generating dispute rationales. Adversarial multi-persona prompting is a documented technique to reduce LLM sycophancy.

## Decisions to add to `VR_MODULE_DECISIONS.md`

### D-36: VR uses platform's reasoning engine, not a parallel system
Same engine that forensics uses (`platform/services/reasoning.py`). VR registers its own `ReasoningDomainProfile`, agent, prompts, tools. Strategy family `vulnerability_research` already exists in the engine.

### D-37: Strategy discovery is hypothesis-driven, not fuzzer-first
Fuzzing is one possible OUTCOME of a reasoning investigation, not the default starting move. The workflow `VR_HYPOTHESIS_INVESTIGATION_V1` runs FIRST. It may emit a fuzzing campaign OR an audit memo OR a direct finding entry.

### D-38: Audit memos prevent dead-end re-exploration
When the engine investigates and concludes no fuzzing is warranted (or no strategy survives), it MUST emit a `vr_audit_memos` row. New investigations query memos first. Memos expire after 90 days OR when triggered by new CVE in the area.

### D-39: Multi-persona prompting drives hypothesis dispute
The engine uses the 6 personas from `VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md` (Halvar/Maddie/Yuki/Renzo/Noor/Wei) as **prompt voices** during the `reasoning` action. Each turn that proposes or rescores hypotheses runs as a multi-persona dialogue, surfacing dispute rather than consensus. Reduces sycophancy.

### D-40: Engine interrupts via `ReasoningOperatorSteering`
The interrupt mechanism from Topic 8 of the discussion doc maps to existing `ReasoningOperatorSteering`. Operator can inject constraints mid-investigation. The engine's loop must check steering before each turn. Pivots logged to `pivot_history` (per D-35) AND to the evidence graph as `refutes` edges from the new operator constraint to any contradicted hypotheses.

## Open questions

1. **Hypothesis lifetime across investigations.** When investigation A rejects hypothesis H and investigation B (later) wants to propose H again — does the engine respect A's rejection? Probably yes for 90d (memo expiry), then re-evaluate. Need workflow.
2. **Cost cap per investigation.** Forensics uses turn limits. For VR, hypothesis investigations can be open-ended (audit-mcp queries, web searches). Need a budget — suggest 30 min OR $5 LLM spend, whichever first.
3. **Hypothesis graph visualization in frontend.** Forensics has `ReasoningGraph` UI. VR can reuse, but the node types differ slightly (more `evidence` nodes pointing to external sources). Probably just CSS variants. Defer to frontend implementation.
4. **Audit memo discovery.** When operator asks a new question, how does the engine find relevant memos? Need an embedding-based lookup over `vr_audit_memos.question` + `rationale`. Use AILA's existing knowledge embedding infra.
5. **CVE feed automation.** D-37 requires audit memo invalidation when "new CVE in the area" appears. Need automated CVE feed → memo-invalidation hook. Probably v0.4 work.

## Mapping to v0.3 plan

This integration **supersedes** parts of `VR_V03_FUZZING_PLAN.md`:

|v0.3 plan item|Replaced by|
|---|---|
|Workflow `VR_FUZZ_CAMPAIGN_V1` as entry point|Now PHASE 2 of `VR_HYPOTHESIS_INVESTIGATION_V1`|
|`API POST /api/vr/fuzz/campaigns` as primary entry|Still exists for direct-launch (operator override), but standard path is via `POST /api/vr/investigations` → engine decides|
|"Strategy = JSON composition over primitives" (GA-9 — already reversed in D-31)|Engine submits a complete `StrategyDescriptor` referencing a pre-built FUZZILLI commit|
|M3.3 (first strategy E2E)|Renumber: PHASE 1 (reasoning) becomes M3.3, original M3.3 becomes M3.4|

New milestones to insert:

|#|Milestone|LOC est|Depends on|
|---|---|---|---|
|M3.3a|VR reasoning agent (HonestVulnResearcher), basic prompts, 3 tools (cve_lookup, source_grep, audit_memo_query)|~400 Py|forensics' investigator as reference|
|M3.3b|VR question templates + domain_profile.json registration|~150 Py + data|M3.3a|
|M3.3c|Audit memo data model + tools + workflow state|~250 Py|M3.3a|
|M3.3d|Hypothesis investigation workflow definition + states (intake/propose/dispute/submit)|~400 Py|M3.3a, M3.3b, M3.3c|

Total addition: ~4 milestones, ~1200 LOC. Net new beyond v0.3 plan baseline.

## Quick-start for next session

When ready to build:

1. Read `modules/forensics/agents/investigator.py` end-to-end — that's the reference implementation
2. Copy structure to `modules/vr/agents/vuln_researcher.py`, replace forensics prompts/tools with VR ones
3. Use `vulnerability_research` strategy family in `ReasoningPromptContext` (already supported)
4. Wire workflow states per state diagram above
5. First test: ask "Is V8MapInferenceProfile still the right strategy?" — engine should re-derive D-30 by inspecting CVE landscape + FUZZILLI source itself

If the engine's answer matches the human-derived D-30 → integration works. If it diverges, surface the disagreement; either the engine is wrong (refine prompts) or human reasoning was incomplete (update memos).

## References

- `docs/VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md` — planning context the engine consumes
- `docs/VR_MODULE_DECISIONS.md` — D-1 through D-40 (D-36-40 added by this doc)
- `docs/VR_V03_FUZZING_PLAN.md` — fuzzing pipeline plan, now PHASE 2 of the workflow
- `src/aila/platform/contracts/reasoning.py` — engine contracts (already exists)
- `src/aila/platform/services/reasoning.py` — engine service (already exists)
- `src/aila/modules/forensics/agents/investigator.py` — reference consumer
- `src/aila/modules/forensics/workflow/states/freeflow.py` — reference workflow state
