# VR Frontend — Designed vs Implemented (Gap Audit)

Audit performed against `docs/vr/08_FRONTEND_UX.md` (the v0.5 spec) and
`docs/VR_FRONTEND_UX_DISCUSSION.md` (the v0.1 10-persona consensus).
Comparison target: `src/aila/modules/vr/frontend/` at commit `99eeb5b`.

The implementation has **17 pages** but is fundamentally misaligned with
the designed information architecture. The spec calls for a
**project-scoped hub model** where everything drills into a project
dashboard. The implementation is **flat lists** with no central
project view. Most pages were built bottom-up from API surfaces rather
than top-down from operator workflow.

---

## Page Inventory — Designed vs Implemented

| # | Designed page (§ in 08_FRONTEND_UX.md) | Designed URL | Implemented? | Closest current page |
|---|---|---|---|---|
| 1.1 | Projects List | `/vr` | ⚠️ Partial | `ProjectsPage` (no severity pulse, no scope blurb, no operator avatars, no live-activity timestamp) |
| 1.2 | New Project **3-stage Wizard** | `/vr/projects/new` | ❌ Missing | Workspaces+Targets forms split, no upload widget, no workstation picker, no scope/authorisation step |
| 1.3 | **Project Dashboard** (targets tree + active campaigns + findings summary + recent reasoning + timeline) | `/vr/projects/:id` | ❌ Missing | `ProjectDetailPage` has 4 tabs, **2 are empty stubs** ("Agent log will appear here", "Advisory will be generated") |
| 1.4 | Target Detail with 5 tabs (Attack surface / Hypotheses / Functions of interest / Imports-exports / Notes) | `/vr/projects/:id/targets/:id` | ❌ Missing | `TargetDetailPage` is flat (status banner + capability profile + mitigation badges + ranking table) |
| 1.5 | **Live Fuzzing Dashboard** (coverage chart, crashes/hour, corpus growth, stability %, resource band) | `/vr/projects/:id/campaigns/:id` | ⚠️ Partial | `FuzzCampaignDetailPage` has metrics but no live charts, no resource band, no SSE |
| 1.6 | Crash Detail with **triage chain narrative** | `/vr/projects/:id/crashes/:id` | ⚠️ Partial | `FuzzCrashDetailPage` shows stack hash + triage dropdown but no narrative chain, no minimised-input hex view, no re-run button |
| 1.7 | **Exploit Editor** (Monaco + reliability bar + test runs + lineage banner) | `/vr/projects/:id/exploits/:id` | ❌ Missing | No exploit/PoC editor anywhere |
| 1.8 | **Advisory Editor** (structured sections + CVSS calculator + disclosure timeline + multi-format export) | `/vr/projects/:id/advisories/:id` | ❌ Missing | `DisclosureDetailPage` has status workflow but no editor, no CVSS calc, no structured sections |
| 1.9 | **Evidence Graph Viewer** (ReactFlow with hypothesis/evidence/crash/exploit/advisory/obligation nodes) | `/vr/projects/:id/graph` | ❌ Missing | `BranchTreePage` uses ReactFlow but visualises investigation branches, not the evidence graph |
| 1.10 | **Investigation Timeline** (TurnCard stream with SSE live tail, action/confidence filters, operator interleavings) | `/vr/projects/:id/timeline` | ❌ Missing | `InvestigationDetailPage` shows messages flatly with no card structure, no filters, no live tail, no operator action interleavings |
| 1.11 | N-day Task View (4-stage state machine) | `/vr/projects/:id/ndays/:cveId` | ❌ Missing | No n-day workflow view; CVE records exist but aren't visualized as stages |
| 1.12 | **Operator Steering Panel** (right drawer: pause/inject context/pin strategy/confirm-disprove hypothesis/close obligation/steer next action) | drawer overlay | ❌ Missing | InvestigationDetailPage has Pause/Resume buttons only |

Add: pages built but not in the spec — these are flat lists not part of
the project-scoped IA:

| Page | URL | Spec match |
|---|---|---|
| `WorkspacesPage` | `/vr/workspaces` | Not in spec — workspaces concept introduced post-design |
| `TargetsPage` | `/vr/targets` | Spec has targets only inside a project (§1.4) |
| `InvestigationsListPage` | `/vr/investigations` | Spec has investigations as project-scoped (§1.10) |
| `PatternsPage`, `PatternDetailPage` | `/vr/patterns/*` | Cross-project reuse layer — added in v0.3, not in v0.1 spec |
| `DisclosuresPage`, `DisclosureDetailPage` | `/vr/disclosures/*` | Spec has advisories under project (§1.8); disclosures-as-toplevel was a v0.3 add |
| `FuzzCampaignsPage` | `/vr/fuzz/campaigns` | Spec has campaigns inside project (§1.5) |
| `McpServersPage`, `McpCallLogPage` | `/vr/mcp/*` | Added in v0.4.5 audit, not in original spec — operator-friendly addition, keep |

---

## Missing Components

These are widgets the spec calls for repeatedly that don't exist anywhere:

| Component | Used by | Status |
|---|---|---|
| `WorkflowStepper` (Setup → Research → PoC → Advisory → Done with active highlight) | Overview tab, Project Dashboard | ❌ Missing |
| `MitigationsRibbon` (NX/ASLR/PIE/RELRO/Canary/CFI/CET as green/red badges with provenance tooltips) | Target Detail header, Project Overview | ⚠️ Partial — TargetDetailPage has `MITIGATIONS` row but no tooltips, no provenance |
| `ObligationChecklist` (met/unmet/waived 3-state rows + tooltips + evidence-ref links) | Project Overview, Finding Detail | ❌ Missing |
| `BudgetGauge` (turns used / max + elapsed time) | Project Overview | ❌ Missing |
| `CVSSBadge` (NVD-coloured) + `CVSSBreakdown` (8-metric table) | Finding Detail, Advisory Editor, Project Overview preview | ❌ Missing |
| `CWEBadge` | Finding Detail | ❌ Missing |
| `TurnCard` (turn N, action badge, reasoning, expandable observation, hypothesis/evidence/obligation deltas) | Investigation Timeline | ❌ Missing |
| `LiveDot` (green/amber/red SSE state indicator) | Every page that subscribes to a stream | ❌ Missing |
| `SeverityPulse` | Project list rows | ❌ Missing |
| `HypothesisDetailRail` (supports + refutes + open obligations) | Reused across Graph / Target / Timeline | ❌ Missing |
| `SteeringDrawer` (right drawer, 6 sections) | Project Dashboard, Target Detail, Timeline, Crash Detail | ❌ Missing |
| `CVSSCalculator` (8-metric button groups + live score + vector string) | Advisory Editor | ❌ Missing |
| `EvidenceGraph` (ReactFlow with 6 node types + 5 edge types + filters) | Evidence Graph Viewer + modal overlay anywhere | ❌ Missing |
| `MonacoExploitEditor` (with author lineage banner + reliability bar) | Exploit Editor | ❌ Missing |
| `CoverageChart` / `CrashesPerHourChart` / `CorpusGrowthChart` / `StabilityChart` | Fuzzing Dashboard | ❌ Missing |
| `ResourceBand` (per-instance CPU/mem/IO from workstation telemetry) | Fuzzing Dashboard | ❌ Missing |
| `TriageChain` (narrative of turns that touched a crash) | Crash Detail | ❌ Missing |
| `DisclosureTimeline` (vertical thread of state transitions) | Advisory Editor, Project Overview | ❌ Missing |

---

## Missing Interactions

| Interaction (§ in 08_FRONTEND_UX.md) | Status |
|---|---|
| 2.1 — SSE reasoning stream (`/api/vr/projects/:id/events`) with type-discriminated events | ❌ Missing — no VR SSE endpoint exists |
| 2.2 — Pause → inject context → resume flow | ⚠️ Partial — Pause/Resume buttons on investigations only, no inject-context POST endpoint, no operator-context surface in prompts |
| 2.3 — Hypothesis-click rail across pages | ❌ Missing — no hypothesis concept surfaced anywhere in UI |
| 2.4 — Crash triage chain | ❌ Missing |
| 2.5 — Inline PoC editing with auto-test on save | ❌ Missing |
| 2.6 — Live fuzzing dashboard charts | ❌ Missing |
| URL state for tabs (`?tab=hypotheses`) | ❌ Missing |
| Deep-linking from crash stack frame to target functions-of-interest | ❌ Missing — function-of-interest tab doesn't exist |
| Browser notifications when project completes (§Topic 6) | ❌ Missing |
| Copy-to-clipboard for Markdown advisory + Download PoC button (§Topic 4/7) | ❌ Missing |

---

## URL / Information Architecture Mismatch

**Designed:** project-scoped tree
```
/vr                                          (project list)
/vr/projects/new                             (3-stage wizard)
/vr/projects/:id                             (project dashboard hub)
/vr/projects/:id/targets/:id?tab=hypotheses
/vr/projects/:id/campaigns/:id
/vr/projects/:id/crashes/:id
/vr/projects/:id/exploits/:id
/vr/projects/:id/advisories/:id
/vr/projects/:id/graph
/vr/projects/:id/timeline
/vr/projects/:id/ndays/:cveId
```

**Implemented:** 7 flat list pages parallel to projects
```
/vr                          /vr/disclosures
/vr/workspaces               /vr/fuzz/campaigns
/vr/targets                  /vr/fuzz/crashes/:id
/vr/investigations           /vr/mcp/servers
/vr/patterns                 /vr/mcp/calls
                             /vr/investigations/:id/tree
```

The flat layout means the operator can't see "what does THIS project
look like right now" — there is no single page that aggregates a
project's targets + campaigns + findings + recent reasoning. The
designed Project Dashboard (§1.3) was the single hub everything else
hung off; without it, the operator has to mentally join data across
7 list pages.

---

## Empty-Stub Tabs (Worst Offenders)

`ProjectDetailPage.tsx` declares 4 tabs but 2 are stubs:

```tsx
function AgentLogTab() {
  return <AilaCard>Agent log will appear here during analysis.</AilaCard>;
}

function AdvisoryTab() {
  return <AilaCard>Advisory will be generated after analysis completes.</AilaCard>;
}
```

This is the *only* place an operator can land for an n-day VR project,
and 50% of it is non-functional placeholder text. The Agent Log is
**designed as the most operationally important page** (§1.10) — it's
where the operator watches the LLM reason. The Advisory editor is the
**deliverable** of the entire workflow.

---

## Priority Order

What to ship next, in the order each unlocks the most user value:

### Tier 1 — unblock the operator

1. **Project Dashboard rewrite** (§1.3) — replace 4-tab page with a real
   hub showing targets tree, active campaigns, findings summary, recent
   reasoning turns, investigation timeline strip. Single page that
   answers "what is this engagement doing right now?"
2. **Investigation Timeline page** (§1.10) — replace the current
   message-stream view with `TurnCard`-based layout, action filters,
   live tail via SSE, operator action interleavings.
3. **Workflow Stepper + Live Status Strip** — visible workflow state
   transitions (Setup → Research → PoC → Advisory → Done) with active
   highlight and turn counter.
4. **Operator Steering Drawer** (§1.12) — 6-section right drawer
   wired to Pause/Resume + new InjectContext / PinStrategy / Confirm-
   Disprove-Hypothesis / Close-Obligation / Steer-Next-Action
   endpoints.

### Tier 2 — make findings shippable

5. **Mitigations ribbon + Obligation checklist + CVSS badge/breakdown**
   shared components, wired into Project Overview and Finding Detail.
6. **Finding Detail rewrite** with all 10 spec'd sections (root cause,
   vulnerable function, CVSS breakdown, CWE, PoC, ASAN, crash
   signature, exploitability, disclosure, advisory preview) including
   copy + download buttons.
7. **Advisory Editor rewrite** (§1.8) — structured sections with CVSS
   calculator, multi-format export (Markdown / JSON / MITRE template).

### Tier 3 — make fuzzing visible

8. **Live Fuzzing Dashboard rewrite** (§1.5) — coverage / crashes-per-
   hour / corpus / stability charts via AilaChart + SSE updates +
   resource band.
9. **Crash triage chain** narrative on `FuzzCrashDetailPage`.

### Tier 4 — distinguishing capabilities

10. **Evidence Graph Viewer** (§1.9) — ReactFlow with 6 node types, 5
    edge types, filters, hypothesis-click rail.
11. **N-day Stage View** (§1.11) — 4-stage progression with rewind.
12. **Exploit Editor** (§1.7) — Monaco + reliability bar + test runs.

### Tier 5 — IA cleanup

13. **URL restructure** — move `/vr/targets`, `/vr/investigations`,
    `/vr/fuzz/campaigns`, `/vr/disclosures` under `/vr/projects/:id/*`.
    Keep `/vr/workspaces` as the upstream grouping layer above
    projects.
14. **New Project Wizard** (§1.2) — 3-stage form with upload widget,
    workstation picker, scope/authorisation step.

---

## Recommendation

Ship **Tier 1 in one batch** since the four items reinforce each other
(Project Dashboard pulls data the Timeline page builds, Steering
Drawer mutates state both pages render, Workflow Stepper is shared).

Tier 2-5 are independent and can ship one per session.
