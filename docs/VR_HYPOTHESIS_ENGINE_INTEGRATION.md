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

## What lands in `src/aila/modules/vr/` (per MODULE_STANDARD)

Per the v0.3 plan (`VR_V03_FUZZING_PLAN.md`), the VR module already has structure for fuzzing. This integration adds the reasoning layer.

### New files (additions on top of the v0.3 plan)

```
src/aila/modules/vr/
├── agents/
│   └── vuln_researcher.py                NEW — HonestVulnResearcher class
│                                              (parallel to HonestInvestigator;
│                                               same engine, VR prompts/tools)
├── contracts/
│   ├── audit_memo.py                     NEW — VRAuditMemo Pydantic model
│   └── strategy_descriptor.py            NEW — StrategyDescriptor (engine's submit output)
├── db_models/
│   └── audit_memo.py                     NEW — vr_audit_memos table
├── data/
│   ├── domain_profile.json               NEW — VR's ReasoningDomainProfile
│   ├── prompts/
│   │   ├── vuln_researcher_system.md     NEW — system prompt (parallel to forensics' _SYSTEM_PROMPT_BASE)
│   │   ├── hypothesis_seeds.md           NEW — bootstrap hypotheses for common question types
│   │   └── kill_criteria_templates.md    NEW — reusable kill_criterion patterns
│   └── question_templates/
│       ├── strategy_selection.json       NEW — template for "which strategy" questions
│       ├── variant_landscape.json        NEW — template for "what variants exist" questions
│       └── target_prioritization.json    NEW — template for "highest-EV component" questions
├── tools/
│   ├── cve_lookup_tool.py                NEW — wraps NVD + vendor advisories
│   ├── cve_cluster_query_tool.py         NEW — statistical clustering of CVEs by class
│   ├── source_grep_tool.py               NEW — wraps audit-mcp ast queries
│   ├── fuzzilli_source_read_tool.py      NEW — version-aware FUZZILLI source access
│   ├── patch_diff_tool.py                NEW — compare two versions, extract changed funcs
│   ├── audit_memo_query_tool.py          NEW — checks existing memos before investigating
│   └── strategy_descriptor_tool.py       NEW — emits a StrategyDescriptor (submit action target)
├── workflow/
│   ├── states/
│   │   ├── hypothesis_intake.py          NEW — parse question + project + steering
│   │   ├── hypothesis_propose.py         NEW — initial hypothesis generation
│   │   ├── hypothesis_dispute.py         NEW — the engine loop
│   │   ├── submit_decision.py            NEW — campaign-or-memo branch
│   │   └── audit_memo_emit.py            NEW — finalize a no-fuzz outcome
│   └── definitions.py                    UPDATE — add VR_HYPOTHESIS_INVESTIGATION_V1
```

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
