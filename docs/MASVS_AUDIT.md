# MASVS Audit — Operator Guide

How to run an OWASP MASVS audit against an Android APK in AILA, what
the platform produces at each step, and how to read the final report.

The MASVS audit is a thin batch-orchestration layer on top of the
existing `vuln_researcher` workflow. Each MASVS control becomes one
independent investigation that runs the full scout / critic / verifier
persona chain against the jadx-decompiled tree. The MASVS layer adds
nothing to investigation depth — it adds breadth (one per control) and
aggregation (per-control verdicts plus a single PDF report).

---

## Prerequisites

| Component | Requirement |
|---|---|
| Target kind | `android_apk` |
| Ingestion stages | `APK_DECODE` → `JADX_DECOMPILE` → `INDEX_DECOMPILED` → `STATIC_SUMMARY` must all be `done`. `MOBSF_SCAN` is optional. |
| `apk_overview.static_summary` | Non-empty. The dispatcher refuses with HTTP 409 when this cell is missing — the per-control prompt builder needs the package name, version, and decompiled-index id. |
| LLM budget | Default per-child budget is **$50** (`MASVS_DEFAULT_CHILD_BUDGET_USD`). With 46 L1 controls in catalog version `1.4.2-aila`, the parent records a total expected spend of **$2,300**. The button confirms this number before dispatch. |
| audit-mcp index | Must be live and the APK's decompiled tree must be indexed (handled automatically by `INDEX_DECOMPILED`). |

The MASVS catalog is curated under `src/aila/modules/vr/masvs/catalog.py`.
Catalog version is exposed as `aila.modules.vr.masvs.CATALOG_VERSION`
and recorded on every parent investigation for idempotency lookups.

---

## The operator-facing flow

### 1. Upload the APK

Use the target picker to upload the APK file. AILA writes the bytes
under the workspace artifact dir, then runs the 5-stage ingestion
pipeline (`APK_DECODE` → `JADX_DECOMPILE` → `INDEX_DECOMPILED` →
`STATIC_SUMMARY` → `MOBSF_SCAN`). The TargetDetailPage shows live
stage progress.

The MASVS dispatcher gates on `STATIC_SUMMARY` being `done` — once
that stage finishes the rest of the page unlocks. `MOBSF_SCAN` is
allowed to skip (`{skipped: true, reason: ...}` is a valid row).

### 2. Click "Run MASVS audit"

The "Run MASVS audit" card appears between the APK overview card and
the mitigations ribbon when:

- `target.kind === "android_apk"`, AND
- `apk_overview.static_summary` is a non-empty object.

The button label includes the total expected spend (per-child budget
× L1 control count, e.g. `Run MASVS audit (~$2300)`). Click confirms,
then POSTs to `/vr/targets/{id}/masvs-audit`.

The dispatcher creates:

1. **One parent investigation** with `kind=masvs_audit`,
   `strategy_family=vulnerability_research.masvs_audit`,
   `cost_budget_usd=$2300`, `secondary_target_refs_json=[{
   masvs_spec_version: "1.4.2-aila" }]`.
2. **N child investigations** (N=46 for the current L1 catalog), each
   with `kind=audit` (the existing kind),
   `parent_investigation_id` pointing at the parent,
   `secondary_target_refs_json=[{ masvs_control_id, masvs_spec_version
   }]`, `auto_pilot=true`, `cost_budget_usd=$50`, and
   `initial_question` built by `MasvsSeedBuilder` from the catalog
   entry + the parent target's `apk_overview`.
3. **One primary branch row** per child (so the standard
   vuln_researcher dispatch can pick the active branch).

After the commit, each child is submitted to the `vr` ARQ queue via
the existing `run_vr_investigate` task. The full scout / critic /
verifier chain runs unchanged on each child against the standard
`android_apk` tool surface (`android_mcp.*` + `audit_mcp.*` against
the jadx-decompiled index).

Per-child submit failures surface in `MasvsAuditDispatchResponse.enqueue_errors`
as `{child_id: error_message}`. A transient queue outage on one child
does NOT roll back the parent or sibling rows — re-enqueue the affected
children via `POST /vr/investigations/{id}/re-enqueue`.

#### Idempotency

If the same target already has an active MASVS audit parent
(`kind=masvs_audit`, status in `CREATED` / `RUNNING` / `PAUSED`) whose
`secondary_target_refs_json` records the current `CATALOG_VERSION`,
the dispatcher returns that parent's ids verbatim with
`idempotent_reuse=true` and HTTP 200. No second parent or sibling
children are materialized; the ARQ queue is not re-touched.

Terminal parents (`COMPLETED` / `FAILED` / `ABANDONED`) do NOT block a
fresh dispatch — an operator deliberately re-running an audit after
the previous batch finished expects a new batch against the latest
target state. The frontend mutation distinguishes the three success
branches via sonner toast variants: idempotent reuse → `info`, partial
enqueue (any `enqueue_errors` populated) → `warning`, clean fan-out →
`success`.

### 3. Watch child investigations progress

The MASVS audit progress card surfaces below the dispatch button once
a parent row exists. It shows:

- Total / completed / running / failed counts.
- Per-control median duration (P50 of `stopped_at - started_at` across
  terminal children with both timestamps; failed children are
  intentionally included since they consumed worker time).
- ETA labelled "serial upper bound" (`median × remaining`). Real
  wall-clock is shorter because the ARQ queue runs children in
  parallel — the upper bound is honest about the slowest case.

The per-control table (`MasvsControlTable`) lists every control with
its child investigation status, verdict, and confidence once complete.
Each row links to the child investigation detail page so an operator
can drill into the scout / critic / verifier transcript and the
verifier's evidence excerpts.

#### Parent status reconciliation

The parent investigation status transitions from `RUNNING` → `COMPLETED`
once every child reaches a terminal state. This is handled by
`aila.modules.vr.masvs.parent_reconciler.sweep_masvs_audit_parents`,
wired into the existing ARQ reaper cron (`platform.tasks.worker`) at
the standard 1-minute cadence. The reconciler does NOT edit the
investigation state machine — it reads child statuses and writes the
parent row directly.

### 4. Download the MASVS report

Once the parent reaches a terminal state OR at least one child has a
terminal outcome, the "Download MASVS report" button enables. Partial
reports are valid — children still in flight render as `INCONCLUSIVE`
rows so an operator can hand the CISO a checkpoint copy without
waiting for the full batch.

The button fires `GET /vr/targets/{id}/masvs-report?audit_id=<parent>`
which returns:

- `Content-Type: application/pdf`
- `Content-Disposition: attachment; filename="masvs_<package>_<YYYYMMDD>.pdf"`

The filename helper (`_masvs_report_filename`) falls back through
`apk_overview.static_summary.package` → `android_package_name` → the
sentinel `android-apk`. Non-`[A-Za-z0-9._-]` bytes fold to `_`,
leading/trailing punctuation strips, and the package label caps at
64 chars.

The PDF is rendered synchronously via ReportLab on a worker thread
(`asyncio.to_thread`) so the event loop stays responsive while
ReportLab walks the ~46-control aggregate.

---

## Reading the report

The PDF mirrors the layout from the existing single-investigation
`pdf_report.py`:

| Section | Content |
|---|---|
| Cover | APK package, version, SHA-256, generation date, AILA branding. |
| Executive summary | Counts: X findings, Y not-applicable, Z no-finding, W inconclusive across N controls. |
| Per-group sections | One section per MASVS group (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY) with a TOC entry. |
| Per-control subsections | Verdict badge (color-coded by severity), evidence excerpts from the verifier report's `affected_components`, remediation paragraph derived from the control's `description` + `verification_steps`, and a link back to the child investigation. |

### Verdict mapping

`aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict` is the
pure rule that turns each child's primary outcome into a MASVS
verdict:

| Child outcome | MASVS verdict |
|---|---|
| `direct_finding` with verifier confidence ≥ 0.6 | `finding` |
| `refuted` | `no_finding` |
| outcome carries an explicit `not_applicable` tag | `not_applicable` |
| anything else (timeout, cost cap, abandoned mid-flight, no primary outcome) | `inconclusive` with the underlying reason carried through |

Confidence extraction prefers a real float in
`payload['verifier_report']['confidence']`. When only a categorical
label is available, `OutcomeConfidence.HIGH/MEDIUM/LOW` maps to 0.85
/ 0.6 / 0.3 — the same gate the auto-promotion path uses elsewhere.

Inconclusive verdicts are NOT silent failures. They surface in the
executive summary count and as their own subsection so an operator
can see exactly which controls did not converge and why
(`reason="timeout"`, `reason="cost_cap"`, `reason="no_primary_outcome"`,
etc.). The MASVS layer never fabricates a verdict — if the child did
not return a conclusive outcome, the PDF says so.

### Evidence honesty

Every `verdict=finding` cites a real evidence excerpt from the
underlying child investigation's verifier report. Each entry includes
the file path (relative to the decompiled tree), function name, and
the snippet that justified the finding. The dispatcher does NOT
post-process or alter these excerpts — they are the exact strings the
verifier persona wrote.

---

## API surface

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/vr/targets/{target_id}/masvs-audit` | Dispatch a MASVS audit. Returns `MasvsAuditDispatchResponse` (parent id, child ids, total controls, spec version, total budget, per-child enqueue errors). HTTP 201 on fresh dispatch, HTTP 200 on idempotent reuse. |
| `GET` | `/vr/targets/{target_id}/masvs-report?audit_id=<parent>` | Stream the PDF. Refuses with HTTP 404 (target/parent missing or cross-target audit id) or HTTP 409 (parent kind is not `masvs_audit`). |
| `GET` | `/vr/targets/{target_id}/masvs-audit-aggregate?audit_id=<parent>` | Return the structured aggregate as JSON (`DataEnvelope[MasvsAuditAggregate]`). Same auth + target + parent + kind + cross-target validation as the PDF endpoint so the two surfaces stay symmetric. |

Each endpoint enforces team scoping through `_team_filter`. Cross-team
audit ids are invisible (404). Cross-target audit ids (a valid audit
id pasted under the wrong target) return 404 as a defensive guard.

Rate limits:

- `POST .../masvs-audit`: 6/minute per IP.
- `GET .../masvs-report`: 10/minute per IP.
- `GET .../masvs-audit-aggregate`: 30/minute per IP.

---

## Operational notes

- **No infrastructure changes are required to run a MASVS audit.**
  The dispatcher reuses the existing `vr` ARQ queue, the existing
  `run_vr_investigate` task, the existing `audit_mcp` index, and the
  existing scout / critic / verifier persona chain. No new worker
  queue, no new persona, no new strategy family beyond the parent's
  descriptive `vulnerability_research.masvs_audit` sentinel.
- **MOBSF_SCAN may be skipped.** When MobSF is unreachable or
  `MOBSF_API_KEY` is unset, the ingestion pipeline writes
  `{skipped: true, reason: ...}` and proceeds. The MASVS dispatcher
  does NOT block on this — it only gates on `STATIC_SUMMARY`.
- **The MASVS layer never touches `vuln_researcher`, personas,
  dispatch routing, or the tool surface.** Hard rule from the spec.
  Per-control investigations run with the full standard tool budget
  and persona depth.
- **L2 and R-level controls are out of scope for the L1 dispatcher.**
  The 4 R-level RESILIENCE controls live in the catalog (so the
  reporting layer can render them when an operator adds them later)
  but the dispatcher filters by `level == MasvsLevel.L1` before
  fanning out.

---

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| HTTP 409 on dispatch, "STATIC_SUMMARY ingestion stage" message | The APK ingestion pipeline has not reached `STATIC_SUMMARY` yet. | Wait for the stage to complete on the TargetDetailPage, then retry. |
| HTTP 409 on dispatch, "kind is ... ; MASVS audit applies to android_apk targets only" | Target is not an `android_apk` row. | MASVS is APK-specific. Recreate the target with the APK file. |
| HTTP 200 with `idempotent_reuse=true` | Active parent exists for the same catalog version. | Use the returned parent id directly; the existing batch is the live one. To force a fresh batch, wait for the active parent to reach a terminal state first. |
| Per-child `enqueue_errors` populated | Transient ARQ queue outage on one or more children. | Children stay in `CREATED`. Call `POST /vr/investigations/{id}/re-enqueue` per affected child. |
| All children land in `INCONCLUSIVE` | Verifier persona did not converge on conclusive outcomes (typical for an under-resourced budget or a heavily-obfuscated APK). | Inspect the verifier transcripts on individual child detail pages. Raising the per-child budget cap is a configuration question — speak with the operator before changing `MASVS_DEFAULT_CHILD_BUDGET_USD`. |
| `verdict=finding` row has no evidence excerpts | The verifier report contained `affected_components` entries that failed schema validation (skipped non-list / non-dict / half-populated entries; trimmed surrounding whitespace; capped at the per-finding limit). | Open the child investigation detail page to inspect the raw verifier output; the table view is honest about what it could parse. |
| Parent stays in `RUNNING` after every child reached a terminal state | The parent reconciler cron has not yet ticked, OR the worker is down. | The reconciler runs every minute via the ARQ reaper. Check `worker.status` and the reaper logs. |

---

## Reference

- Spec: `.run/ralph/apk-masvs/specs/PRD.md`
- Catalog: `src/aila/modules/vr/masvs/catalog.py`
- Seed builder: `src/aila/modules/vr/masvs/seed.py`
- Verdict mapper: `src/aila/modules/vr/masvs/verdict_mapper.py`
- Aggregator + PDF renderer: `src/aila/modules/vr/reporting/masvs_report.py`
- API router routes: `src/aila/modules/vr/api_router.py` (search for
  `masvs-audit`, `masvs-report`, `masvs-audit-aggregate`)
- Parent reconciler: `src/aila/modules/vr/masvs/parent_reconciler.py`
- Frontend UI: `src/aila/modules/vr/frontend/screens/TargetDetailPage.tsx`
  (`MasvsAuditCard`, `MasvsProgressCard`, `MasvsReportCard`,
  `MasvsControlTable`)
- Frontend mutation: `src/aila/modules/vr/frontend/mutations.ts`
  (`useMasvsAudit`, `MASVS_DEFAULT_CHILD_BUDGET_USD`)
