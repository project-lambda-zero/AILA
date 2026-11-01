# VR Module -- Frontend UX

What the researcher sees. The VR UI is not a separate application or package: it is a set of pages inside the shared console shell (`@aila/shell`, `frontend/`). The VR module contributes a left-rail entry, page registrations, and bespoke page components; window chrome, auth, the chat console, wizards, and widgets belong to the shell. See `docs/FRONTEND_MODULE_STANDARD.md` for the shell architecture.

Cross-references:
- `docs/vr/01_REASONING_LOOP.md` -- what the LLM emits per turn (what the X-Ray turns stream renders)
- `docs/vr/02_BINARY_RE_MCP.md` -- what produces the binary metadata the target pages render
- `docs/vr/03_EXPLOIT_AUTOMATION.md` -- the exploit and PoC flow behind the finding layout
- `docs/vr/04_MULTI_TARGET.md` -- the workspace / target / campaign hierarchy the list pages walk
- `frontend/src/console/nav.ts` -- the `vr` entry in `MODULES`
- `frontend/src/console/pages/registry.tsx` and `configs.ts` -- the `vr:*` page registrations

---

## 0. Scope: What the UI Is Not

The researcher already has an IDE, a terminal, and a disassembler. The VR UI is the place where the LLM's reasoning, the platform's evidence, and the workflow state are visible together. It does not provide a terminal, a file tree, or a decompilation browser; actions are typed and produce typed observations that the investigation transcript shows.

What it does provide:

- Live visibility into the investigation loop (turn-by-turn reasoning, ledger, hypotheses, dispatch).
- Structured navigation across workspaces, targets, investigations, findings, patterns, disclosures, and fuzz campaigns.
- Steering controls that change what the LLM sees on its next turn.
- Review and triage surfaces for outcomes, findings, and proof-of-concept drafts.

---

## 1. Page Inventory

Pages are windows opened by the shell. Keys are `vr:<page-id>`. The rail entries come from the `vr` `ModuleDef` in `frontend/src/console/nav.ts` (workspaces, targets, investigations, cves, findings, patterns, disclosures, fuzz campaigns).

| Registry key | Implementation | Notes |
|---|---|---|
| `vr:workspaces` | `DataPage` (`PAGE_CONFIGS`) with a bespoke detail body (`WorkspaceTargets`) | Row detail lists the workspace's targets; can open the X-Ray. |
| `vr:targets` | `DataPage` + `VRTargetDetail` | Target detail with analysis state, failure reason, and re-enqueue actions; fetches `GET /vr/targets/{id}`. |
| `vr:investigations` | `DataPage`; row activation opens `vr:xray` | Server-side pagination and filters (`?q=&status=&kind=`). |
| `vr:cves` | `DataPage` + `CveReproduceDetail` | "reproduce" opens `vr:new-project` with the CVE id. |
| `vr:findings` | `DataPage` | Findings list and detail. |
| `vr:patterns` | `VrPatternsPage` | `DataPage` plus a "preview applicable" control that simulates the retrieval gate. |
| `vr:disclosures` | `DataPage` | Disclosure submissions. |
| `vr:fuzz-campaigns` | `DataPage` + `FuzzCampaignDetail` | Accordion with telemetry chart (`FuzzTelemetryChart`, `GET /vr/fuzz/campaigns/{id}/telemetry`), target proposals (accept/reject), and crashes with triage actions. |
| `vr:xray` | `XRayPage` | The per-investigation analysis workspace (section 2). |
| `vr:new-target` | `UploadForm module="vr"` | Upload a source or binary target. |
| `vr:new-project` | `NdayProjectForm` | N-day reproduction: binds workspace, vulnerable target, optional patched build, CVE, analysis workstation, optional PoC executor; drives `POST /vr/projects`. |

Wizards reachable from the chat `+ open wizard` picker are defined in `frontend/src/console/wizards/registry.ts`: `vr-intake` (new investigation, via `IntakeWizard`) and `vr-upload` (opens `vr:new-target`).

---

## 2. X-Ray

`XRayPage` (`frontend/src/console/pages/XRayPage.tsx`, panels in `pages/xray/` and `pages/xray/vr/`) is a five-layout multi-panel workspace over one investigation. Layouts are switched by the status-bar buttons or number keys 1-5 (`KEY_TO_VIEW` in `pages/xray/layout.ts`), and the layout name is the page `section`:

| Key | Layout | Panes (`VR_LAYOUT_PANES`) |
|---|---|---|
| 1 | overview | transcript, brief, records, engine, activity |
| 2 | records | ledger, ledger detail, hypotheses, hypothesis detail |
| 3 | graphs | phase graph |
| 4 | oracle | oracle, dispatch, MCP calls, detail |
| 5 | finding | finding, reachability, proof of concept, crash |

Every data-backed panel reads the live `/vr/investigations/{id}` API through react-query hooks in `frontend/src/api/hooks.ts` (`useInvestigation`, `useBranches`, `useHypotheses`, `useMessages`, `useDispatch`, `useLedger`, `useMcpCalls`, `useVrOutcomes`, `useVrFinding`). Panels with no backing data render an honest empty note; nothing is fabricated.

### Steering and controls

- `SteeringBar` posts operator messages with an explicit intent (`steering`, `correction`, `dismissal`, `question`, `outcome_selection`, `branch_command`) to `POST /vr/investigations/{id}/messages` (`usePostMessage`).
- `useInvestigationControl` issues the bodiless operator controls `POST /vr/investigations/{id}/{pause|resume|verify|reset}`.
- `BranchOps` and `useBranchOp` / `useSpawnStrategyBranch` operate on branches (`/vr/investigations/{id}/branches/...`, `/strategy-branches`).
- `OutcomeReviews` records review votes (`approve`, `reject`, `request_edit`, `abstain`, `not_ready`) on outcomes through `useCreateVrOutcomeReview`.
- `DraftPoc` drafts a proof of concept on the VR worker via `useDraftPoc` and polls the finding until the draft lands or the poll window ends.

### Liveness

The shell holds one authenticated SSE subscription to `GET /events/stream` (`frontend/src/api/liveEvents.tsx`, transport in `frontend/src/api/sse.ts`). `investigation.status_changed` events invalidate the affected module's investigation list and detail caches; after a reconnect every investigation cache is invalidated because events emitted while the stream was down are not replayed. The SSE client reconnects with exponential backoff. Panels that need near-live transcript data also poll (`useMessages` refetches every 8 s). A stalled stream degrades liveness only; pages continue to work from their queries.

---

## 3. Widgets

Widgets are shell-level and module-agnostic. The shell defines seven kinds in `WIDGET_KINDS` (`frontend/src/console/widgets/types.ts`): `bound-case`, `queue-depth`, `budget`, `recent-findings`, `mcp-health`, `dante-actions`, `clock`. The VR module does not contribute its own widgets. The `bound-case` widget reflects the investigation currently bound in the left rail.

---

## 4. Cross-Cutting UX Concerns

- **Styling:** plain CSS custom properties from `frontend/src/styles/globals.css` plus inline `css()` styles; no CSS framework.
- **Windows:** every page renders inside `ConsoleWindow` (close, minimize, fullscreen, z-order and focus managed by the shell host).
- **Admin gating:** pages that are restricted (for example reconcile and the cross-team heatmap) are hidden from the rail for non-god-tier admins and also gate inside the page (`GOD_TIER_ADMIN_ITEMS` in `nav.ts`).
- **Error and empty states:** list pages show explicit empty and error notes (`DataPage`); mutations surface errors through the shell toast (`frontend/src/console/toast.tsx`). Data-fetching components handle loading, error, and empty states honestly.
- **Authentication:** requests carry a Bearer token from the auth store; a 401 signs the user out (`frontend/src/api/client.ts`).

---

## 5. Where the UI Talks to the Backend

All calls go through `frontend/src/api/` (`apiFetch` / `apiFetchEnvelope`); page components never call `fetch()` directly. Query keys are module-scoped (`["vr", "investigations"]`, `["vr", "messages", id]`, ...) so mutations invalidate by prefix. Representative VR routes used by the UI:

| Endpoint | Used by |
|---|---|
| `GET /vr/investigations?limit=100`, `GET /vr/investigations/{id}` | investigation list, X-Ray |
| `GET /vr/investigations/{id}/messages`, `POST .../messages` | transcript, steering |
| `GET /vr/investigations/{id}/branches`, `POST .../branches/{branchId}/{op}`, `POST .../strategy-branches` | branch panels and ops |
| `POST /vr/investigations/{id}/{pause\|resume\|verify\|reset}` | investigation controls |
| `GET /vr/targets`, `GET /vr/targets/{id}` | `vr:targets`, `VRTargetDetail` |
| `GET /vr/fuzz/campaigns/{id}/telemetry` | `FuzzTelemetryChart` |
| `POST /vr/projects` | `NdayProjectForm` |
| `GET /events/stream` (SSE) | shell live events |

The list pages (`vr:workspaces`, `vr:targets`, `vr:investigations`, `vr:patterns`, `vr:findings`, `vr:disclosures`, `vr:fuzz-campaigns`, `vr:cves`) read the `endpoint` declared in `PAGE_CONFIGS` (`frontend/src/console/pages/configs.ts`).
