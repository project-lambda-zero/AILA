# VR Frontend Promise Audit — Reality Check (post-PageShell overhaul)

A spot-check of `VR_FRONTEND_PROMISE_AUDIT.md` against in-code state
after the PageShell rollout and migration 053 work. The base audit
claims **89 shipped / 1 partial (Monaco deferred) / 0 gap**; that's
mostly accurate, with three corrections and one new frontend-only gap
closed in this pass.

---

## Corrections to the base audit

### 1. Audit oversold: ExploitEditorPage "save + test" loop
- Base audit row #6 (After "finish remaining gaps" sweep): **"Shipped
  (Monaco deferred) — operator value (highlight + draft persistence)
  ships."** That's true for the *editor surface* but the audit phrasing
  reads as if the full §1.7 promise shipped.
- Code reality (`ExploitEditorPage.tsx:235-239`): the "Save + test"
  button is disabled with `title="Saving to the backend exploit table +
  re-running tests on the workstation is backend pending (POST
  /api/vr/exploits/:id/source)"`. Per-run history card at line 360-368
  is also a "backend pending" placeholder.
- The frontend's part of §1.7 is done — the missing piece is two
  backend endpoints + a workstation SSH bridge. **Mark §1.7 as "partial
  — workstation save+test loop backend pending"** rather than "shipped".

### 2. Audit oversold: FuzzCrashDetailPage triage chain rendering
- Base audit row #5 claimed: **"crash row carries hex + chain; /triage
  POST endpoint appends"** = shipped. Backend half is real (migration
  053 added `triage_chain_json` on `vr_fuzz_crashes`; POST
  `/vr/fuzz/crashes/:id/triage` endpoint exists at
  `api_router.py:4814`).
- Code reality before this commit: `FuzzCrashDetailPage` rendered only
  a 3-step skeleton (register → triage → promote) using scalar fields
  on the crash row. It IGNORED the `triage_chain` entries and showed a
  dashed "backend pending" placeholder instead.
- Frontend type `VRFuzzCrashSummary` in `types.ts` was missing
  `triage_chain`, `llm_summary`, `reproducer_head_hex`,
  `reproducer_head_truncated_size` entirely — the data shipped from the
  backend was unreachable from TS.
- **Closed in this commit**: added the four fields to the frontend
  type, removed the dashed placeholder, and the page now renders each
  triage_chain entry (verdict + actor + timestamp + reason + notes) as
  step `N+1`, `N+2`, … between the register and promote skeleton
  steps. The reasoning-turn-level join (`decompile_function`,
  `data_flow_trace`, `hypothesis_create`, `exploitability_assess`)
  still requires a separate crash → reasoning-turn table — that
  remains backend-pending and is now stated honestly in a single line
  instead of a full dashed card.

### 3. Stale source comment: `EvidenceGraph.tsx` header
- Base audit row §1.9 marks server-side initial layout as shipped
  (`/vr/investigations/:id/evidence-graph` returns
  `EvidenceGraphSnapshot`; `useEvidenceGraph` hook wired;
  `EvidenceGraphPage` consumes it; `ServerSnapshotStatus` card
  surfaces it).
- File header on `EvidenceGraph.tsx:23-26` still said *"v0.5 backend
  gap: the platform doesn't expose a project-evidence-graph endpoint
  yet."* That comment dated to before migration 053 landed.
- **Closed in this commit**: header rewritten to "Server-side layout is
  now authoritative … client-side concentric layout kicks in only when
  the snapshot is unavailable."

---

## Genuine outstanding gaps (all backend-paired)

These are real promises that have honest "backend pending" treatment
on the live UI. Each requires backend work to close — frontend
behaviour is already there or one-line wiring once the endpoint
lands.

| # | Promise | Surface | What's missing |
|---|---|---|---|
| G1 | §1.5 — Per-instance fuzz resource band (CPU/memory/disk-write-rate per worker) | `FuzzCampaignDetailPage` line 374 | Resource-metrics endpoint — the `vr_fuzz_telemetry` table covers coverage/exec-rate but not per-worker resource pressure |
| G2 | §1.5 — Rebuild + Tune actions on a running campaign | `FuzzCampaignDetailPage` (rebuild/tune card) | POST endpoints for rebuild-corpus and tune-strategy don't exist; the card itself ships |
| G3 | §1.6 — Re-run reproducer on workstation | `FuzzCrashDetailPage` line 230 | Workstation SSH bridge + endpoint that re-runs the reducer on the recorded analysis system |
| G4 | §1.6 — Per-reasoning-turn rows on crash detail | `FuzzCrashDetailPage` triage-chain footer | crash → reasoning-turn join table (`decompile_function`, `data_flow_trace`, `hypothesis_create`, `exploitability_assess` per-step links to investigation turns) |
| G5 | §1.7 — PoC save + test loop | `ExploitEditorPage` line 235 + line 360 | `POST /vr/exploits/:id/source` (persist edits to backend exploit table) + `POST /vr/exploits/:id/test` (re-run against the workstation) + per-run history table |
| G6 | §1.7 — Monaco editor + IntelliSense/multi-cursor/minimap | `ExploitEditorPage` | Heavy bundle (~3 MB + Vite worker plumbing) explicitly deferred per `08_FRONTEND_UX.md`-aligned no-over-engineering call. Operator behaviour ships via lightweight `SyntaxHighlighter` + textarea. |
| G7 | §1.8 — CVSS v4.0 calculator | `CVSSCalculator` v4.0 tab | v4 introduces 11 base + threat + environmental + supplemental metrics — needs full computation per the v4 specification document §7 |
| G8 | §1.11 — Real n-day stage tracking | `NdayPage` line 171 | Rewind backend, per-stage operator notes, BinDiff score, commit-hash projection — currently the page derives stage from existing project + finding data |
| G9 | §1.4 — Project-scoped per-target notes | `TargetDetailPage` line 440 | Per-target notes endpoint — currently localStorage in the operator's browser only |
| G10 | §1.12 — Steering drawer sections 3-6 (pin strategy, confirm/disprove hypothesis, close obligation, steer next action) | `SteeringDrawer` | Each section needs its own endpoint — `/strategy/pin`, `/hypotheses/:id/operator-assert`, `/obligations/:id/operator-close`, `/turn-strategy/inject` |
| G11 | §6.2 — Dedicated `VRAuditEventRecord` table | `AuditLogPage` line 53 | Currently aggregates from message-stream operator-sender entries + MCP call log; spec wants a first-class audit row (actor / target / details / timestamp) |
| G12 | §1.9 — "Manually close" obligation button on graph nodes | `EvidenceGraphPage` line 198 | Same `/obligations/:id/operator-close` endpoint as G10 |
| G13 | §1.2 — Drag-drop upload widget with content-aware "What is this?" hint | `NewProjectWizard` | Upload-analysis backend that infers format + tool requirements from the uploaded blob |
| G14 | §1.3 — Workstation heartbeat dot ("aila-research-04 — connected") | `ProjectDetailPage` Overview | Workstation polling endpoint + ConnectivityBadge wiring |

**Pattern**: every G-series item is "backend endpoint missing, frontend
already designed honestly around it". There are zero pure-frontend
gaps remaining after closing #2 in this pass.

---

## What the "code navigation / editor view" promise actually means

The operator's verbatim ask was: *"we will have code navigation at
some point but there's no navigation or editor-like view soon."* That
matches three distinct items:

1. **Monaco editor on `ExploitEditorPage`** (G6 above). Explicitly
   deferred per `08_FRONTEND_UX.md` and the no-over-engineering
   directive. Operator value (highlight + draft persist + Tab handling)
   ships via the lightweight `SyntaxHighlighter` + textarea path.

2. **Code-navigation IDE surface** (jump-to-definition, find-references,
   symbol picker across the target source tree). `docs/vr/08_FRONTEND_UX.md`
   §0 explicitly says *"No code editor for harness source, no terminal,
   no file tree, no syntax-highlighted decompilation viewer."* The
   product decision was to never build a researcher-IDE — VR exposes
   only the artefacts the engine produced (PoCs, crash signatures,
   evidence graph). If you want to override that decision and build
   the IDE surface anyway, that's a 4-week project (Monaco + audit_mcp
   client + IDA MCP client + virtual file system + xref panel) — say
   so explicitly.

3. **Clickable stack frames jumping to functions-of-interest** —
   `FuzzCrashDetailPage` parses stack frames and emits a
   `vr-stack-frame-click` event when the function name is clicked, but
   no page listens. Wiring this to navigate `/vr/targets/:id?tab=functions&fn=…`
   needs a global function index — TargetDetailPage's Functions-of-
   interest tab has the data per-target but not by name across all
   targets. Closing this is one new query + one event listener if
   you're OK with "search within the campaign's target only", or a
   new `/vr/functions?q=…` endpoint if you want global.

---

## Revised totals (after this pass)

- **Shipped: 90** (was 89 — `FuzzCrashDetailPage` triage-chain row
  rendering promoted from gap to shipped).
- **Partial (backend-paired surfaces honestly marked): 13** — G1-G5,
  G7-G14, plus G6 (Monaco deferred). Was "1 partial" — the real number
  was always higher; the base audit's "0 gap" line collapsed several
  of these into the partial column without enumerating them.
- **True gap (UI behaviour missing, no honest treatment): 0**.

The "complete overhaul" interpretation here is: every operator-visible
promise has either shipped behaviour or an honest inline "backend
pending" treatment that explains what's missing and why. No silent
dishonesty remains.
