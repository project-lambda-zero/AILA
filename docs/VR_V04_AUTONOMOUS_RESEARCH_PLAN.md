# VR Module v0.4 — Autonomous Multi-Target Research Plan

## What v0.4 does

v0.3 shipped single-target investigations with operator-in-the-loop. v0.4
ships:

1. **Cross-target investigations** — one investigation can reason over
   multiple targets simultaneously ("compare nginx and apache approach to
   chunked transfer encoding"). Hypotheses cross-reference both
   codebases. (D-50 deferral made explicit.)
2. **Multi-strategy autonomous loops** — instead of one reasoning
   strategy per investigation, v0.4 lets the engine spawn parallel
   strategy branches (discovery_research + variant_hunt + patch_diff_analysis)
   and converge results.
3. **Human-in-the-loop refinement** — operator messages can attach to a
   specific strategy branch, not just the investigation root.
4. **CVE feed automation** — D-38 audit memo invalidation when new CVEs
   land in the area. Closes the v0.3 deferral.
5. **Profile expansion** — `js_engine_spidermonkey`, `js_engine_jsc`,
   `cpp_app`, `android_app`, `php_webapp`, `ruby_webapp` capability
   profiles. New fuzzers in audit-only mode (PHP/Ruby) + new strategy
   defaults.
6. **Branch tree visualization** — D-41 frontend deferral closed.
7. **Multi-model split-roles** — researcher/implementer/critic personas
   per branch. v0.3 ships single-persona-per-branch; v0.4 adds the
   per-role model routing.

## Position in the roadmap

|Version|Scope|
|---|---|
|v0.1 (superseded)|N-day workflow ground floor — collapsed into v0.3|
|v0.2 (collapsed)|Target enrichment — merged into v0.3 M3.T|
|**v0.3 (shipped)**|Hypothesis-driven discovery + fuzzing + disclosure + knowledge + target enrichment + workspaces|
|**v0.4 (this plan)**|Autonomous multi-target multi-strategy + CVE feed + branch UI + cross-codebase reasoning|
|v0.5|Kernel/hypervisor exploitation (QEMU/KVM test envs, kernel-specific primitives, VM escape strategies)|
|later|Network fuzzing · packed binary support · variant analysis · cross-project knowledge|

## Gray Area Resolutions (v0.4 scope)

### GA-49: Multi-target investigation contracts

**Decision:** Extend `vr_investigations` with a join table
`vr_investigation_targets` carrying `(investigation_id, target_id, role)`
where role is the existing D-50 enum (`primary | comparison | parallel_codebase
| parent_library | derived_fork`). The current `target_id` column stays
populated with the primary target for backward compatibility; secondary
targets live exclusively in the join table.

Rationale:
- Existing v0.3 single-target investigations stay queryable via the
  `target_id` column without changes
- Multi-target queries use the join table for cross-codebase analysis
- Cost attribution still goes to the primary target's workspace
  (per D-50)

### GA-50: Multi-strategy parallel branches

**Decision:** A v0.4 investigation can run N strategy branches in
parallel. Each strategy_family runs in its own VRInvestigationBranchRecord
with a `strategy_family` column added. Branches converge via the existing
M3.R-5 BranchManager `.merge()` operation, but with cross-strategy
adjudication weighting:

  discovery_research finding + variant_hunt confirmation
    → high-confidence DirectFinding outcome
  patch_diff_analysis dispute against discovery_research claim
    → CORRECTION request to discovery_research branch

A new BranchOperation `SPAWN_STRATEGY` creates a sibling branch with a
fresh strategy_family but the same target + initial_question.

### GA-51: CVE feed → audit memo invalidation

**Decision:** A periodic ARQ task `cve_feed_poller` (runs every 6h)
pulls from NVD JSON 2.0 + GitHub Security Advisory feed, normalizes to
`cve_records` table (new), and on each new CVE runs:

  1. Embed CVE description via KnowledgeService
  2. Retrieve audit memos within configurable similarity threshold
     (default 0.85) in same workspace
  3. For each match, append `invalidation_event` to the memo's metadata
     and surface an operator notification

Memos stay in the catalog but show "potentially invalidated by CVE-XXXX"
in the UI so operators can re-audit.

### GA-52: Per-role model routing (multi-persona)

**Decision:** Each strategy branch picks a model_profile from a new
`vr.branch_model_routing` config namespace:

  researcher  → Claude 4 Opus (high-context, deliberate)
  implementer → GPT-5 (broad tool ecosystem)
  critic      → Claude 4 Sonnet (cost-effective adversarial review)

A branch can be assigned one of {researcher, implementer, critic} via
its `persona_voice` column (M3.R-5 already added the column). Per-turn
LLM dispatch reads the persona → looks up model_profile → calls platform
LLM client with the right routing.

### GA-53: Branch tree visualization

**Decision:** D-41 graph: investigation root → branches as tree with
state colour-coding (active/merged/abandoned/paused). Edges labeled with
fork_reason. Operator can click a node to switch to that branch's
message log.

Reuses the platform's existing `ReasoningGraphService` so v0.4 frontend
doesn't introduce a new graph library.

## File Layout (v0.4 additions)

```
src/aila/modules/vr/
├── contracts/
│   ├── investigation.py          (extend with InvestigationTargetRef + InvestigationTargetRole)
│   ├── cve_feed.py               (new — CVE record + invalidation event)
│   └── persona.py                (extend M3.R-5 PersonaVoice with model_profile)
├── db_models/
│   ├── investigation_target.py   (new — join table)
│   ├── cve.py                    (new — cve_records + cve_feed_state)
│   └── investigation.py          (add strategy_family col on branch)
├── alembic/versions/
│   ├── 048_vr_investigation_targets.py
│   ├── 049_vr_cve_records.py
│   └── 050_vr_branch_strategy_family.py
├── services/
│   ├── multi_target_investigation.py   (cross-codebase reasoning helper)
│   └── cve_feed_poller.py              (NVD + GHSA pull + memo invalidation)
├── agents/
│   ├── persona_router.py               (persona → model_profile dispatch)
│   └── multi_strategy_orchestrator.py  (parallel branch spawn + converge)
├── workflow/
│   └── states/
│       ├── multi_strategy_spawn.py     (new state — spawn N strategy branches)
│       └── multi_strategy_converge.py  (new state — adjudicate + merge)
├── disclosure/
│   └── builtin_tracks_v04.py           (deferred — keep v0.3 set; add per-need)
└── frontend/
    └── screens/
        └── BranchTreePage.tsx           (D-41 visualization)
```

## Implementation phases

### Phase 1 — Multi-target investigation foundations (this commit)
- New contracts: `InvestigationTargetRole`, `InvestigationTargetRef`,
  `MultiTargetInvestigationCreate`
- New DB table: `vr_investigation_targets` (M:N join)
- Migration `048_vr_investigation_targets`
- Service helper: `add_target_to_investigation` / `list_investigation_targets`
- API endpoints: POST/GET/DELETE on investigation target attachments
- Tests

### Phase 2 — Multi-strategy branches
- Extend `VRInvestigationBranchRecord` with `strategy_family` column
- `multi_strategy_orchestrator.spawn_parallel(investigation, [strategies])`
- New BranchOperation: SPAWN_STRATEGY
- Workflow states for spawn + converge
- Tests

### Phase 3 — CVE feed automation
- `cve_records` table + `cve_feed_state` checkpoint table
- NVD JSON 2.0 poller (`cve_feed_poller`)
- GHSA poller
- Memo invalidation worker (embed CVE → semantic match audit memos)
- Operator notification surface (reuse existing investigation_message infra)

### Phase 4 — Per-role model routing
- `vr.branch_model_routing` config namespace seeds
- `persona_router.route(persona) → model_profile_id`
- Wire HonestVulnResearcher to read branch.persona_voice + route

### Phase 5 — Branch tree visualization
- Frontend BranchTreePage using ReasoningGraphService
- Investigation detail page → "View tree" tab

### Phase 6 — Expanded capability profiles
- `js_engine_spidermonkey` / `js_engine_jsc` + fuzzilli profile per engine
- `cpp_app` / `android_app` / `php_webapp` / `ruby_webapp` profiles
- Rule-table extensions in `profile_builder.py`

## Out of scope for v0.4

- Kernel / hypervisor exploitation (v0.5)
- Network protocol fuzzing (later)
- Packed binary support (later)
- Variant analysis across projects (later — needs cross-team knowledge)
- WinAFL+DynamoRIO (deferred from v0.3; v0.4 keeps audit-only on Windows)

## Backward compatibility

- All v0.3 single-target investigations work unchanged
- `vr_investigations.target_id` column stays the primary key for
  workspaces' cost attribution
- New join table `vr_investigation_targets` is additive
- v0.3 frontend continues to display single-target investigations the
  same way; multi-target view is a separate page accessible from the
  investigation detail tab
