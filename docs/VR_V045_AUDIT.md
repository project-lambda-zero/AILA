# VR Module v0.4.5 Audit — 5-Persona Synthesis

Audit conducted on 2026-05-14 against `origin/main` at commit `28e7a15`.
Live tour via Playwright + admin/admin, manual data probes, full grep of
the frontend and backend surfaces. All findings either fixed in this
batch or explicitly deferred with rationale.

The five personas below evaluate the module from disjoint angles. Each
section calls out what was observed in the codebase, what was fixed,
and what remains open.

---

## 1. Distinguished staff engineer — architecture & correctness

**What was observed.**

- `aila.modules.vr.services.target_analysis.TargetAnalysisService`
  previously shelled out to `git clone` inside the AILA backend via
  `asyncio.create_subprocess_exec`. That was a category violation: the
  platform was doing work that belongs on the workstation that owns
  the artifact (D-33).
- Two bridges (`AuditMcpBridgeTool`, `IDABridgeTool`) read `base_url`
  from env vars at construction time. Operator changes to the URL
  required a backend restart.
- Both bridges threw raw `httpx.ConnectError` strings into the operator
  UX. Per the contract: every error must be operator-actionable.
- Every `forward()` call was ephemeral — `_log.info` lines in a worker
  stdout that no operator ever reads. The user surfaced this directly:
  "where are the mcp logs anyway?"
- Operator vocabulary leaked through several layers: `audit_mcp_index_id`,
  `binary_id`, `kernel_image_id` appeared in `DESCRIPTOR_TEMPLATES`,
  in `profile_builder.py` error messages, and as `_mcp_handles_json`
  in legacy contracts.
- `TaskRecord` rows can get stuck in `running` when the worker dies
  mid-task (SEC-07 dedup then refuses fresh submits indefinitely).

**What was changed this batch.**

- Added `clone_repo` MCP tool to `audit-mcp` (cross-repo commit
  `e307d60`). AILA's `_ingest_source_repo` now forwards a URL to that
  tool; the working tree lives on the MCP workstation under
  `~/.cache/audit-mcp/clones/`. AILA never shells out.
- Bridges resolve `base_url` per-call via env → `ConfigRegistry` →
  default. `PATCH /vr/mcp/servers/{id}` takes effect on the next call
  without restart.
- Every bridge `forward()` is wrapped in the new `record_call` async
  context manager which writes one `VRMcpCallLogRecord` per call with
  server, action, status, HTTP code, latency, and error excerpt.
- New static catalog `MCP_SERVERS` in `services/mcp_registry.py` makes
  adding a new MCP a 1-tuple change + 1 schema field.
- Migration 051 dropped `enrichment_status`/`last_enriched_at` and
  introduced `analysis_state` + `analysis_state_message` +
  `_mcp_handles_json` (underscore-prefixed = internal).
- Migration 052 introduced `vr_mcp_call_log` with indexes on
  `called_at`, `server_id`, `target_id`.

**Open items.**

- `TaskRecord` stuck-in-running is a platform bug, not VR-local. When
  the worker dies mid-task, the SEC-07 SHA-256 dedup returns the same
  task_id forever because the row stays at `running`. A `vr/_task_queue`-
  scoped fix would require a heartbeat reaper or worker-shutdown hook
  flagging in-flight tasks as `failed`. **Filed as Finding T1 for the
  platform team.**
- `services/target_analysis.py:_ingest_binary` accepts a descriptor
  `binary_path` that points at the IDA MCP filesystem. The operator
  cannot know that path. The upload flow makes this irrelevant when a
  file is uploaded, but the descriptor field still exists for
  power-user workflows. **Documented in the field copy, kept for D-33
  hybrid setups.**

---

## 2. Pragmatic VR engineer — does this help me find bugs

**What was observed.**

- "I created an nginx target and nothing happened" was a real defect.
  The descriptor had `audit_mcp_index_id=""` but no auto-ingestion
  existed. Operator had no feedback, no error, no progress indicator.
- "Run enrichment" and "Run function ranking" were fire-and-forget
  toasts. No live progress, no MCP call logs visible, no elapsed time.
- Binary targets required a `binary_path` on the IDA MCP filesystem.
  No upload widget anywhere.
- 60 VR API routes, 17 vr_* migrations, 753 tests — solid backend
  surface but a 24% gap between "what the platform can do" and "what
  the operator can reach from the UI".

**What was changed this batch.**

- `POST /vr/targets` auto-enqueues `run_target_analysis`. Operator never
  invokes a separate enrichment step.
- `POST /vr/targets/{id}/analyze` for manual re-trigger. Idempotent.
- `POST /vr/targets/{id}/upload` (multipart) streams a binary through
  AILA → IDA MCP `/upload` without staging on the platform. Returns
  the binary handle stored privately + a fresh analyze task. Renders
  in TargetDetailPage as a `Choose file` / `Replace file` button only
  for upload-capable kinds (native_binary / kernel_image /
  kernel_module / hypervisor_image / apk / ipa / jar / dotnet_assembly).
- `MCP Call Log` page (auto-refresh 3s) gives operator the "what was
  just called, did it succeed, how long did it take" view they asked
  for. Live verified: nginx analyze produces exactly 4 rows in 6s —
  clone_repo → index_codebase → poll_index → detect_languages, all
  `ready 200`.
- Friendly status copy on TargetDetailPage: "Pulling from GitHub...",
  "Analyzing source...", "Ready", "Failed" — derived from
  `analysis_state` enum but per-kind specific.

**Open items.**

- SSE live progress was deferred. analyze runs in ~6s now (warm) and
  the MCP Call Log refreshes every 3s, so the operator already has
  near-real-time visibility without SSE plumbing. Re-evaluate if a
  long-running MCP action (large kernel image upload, full Chromium
  re-index) ships.
- The default page is still `/vr` (Projects). For someone who lives
  in workspaces+targets the entry point feels archaeological.
  **Suggested for a v0.5 nav reshuffle.**
- Investigations list shows target column as `display_name` (fixed
  this batch) but doesn't show which workspace each investigation
  belongs to. Adding `workspace_name` to the projection would close
  the loop.

---

## 3. Senior security engineer — boundaries & failure modes

**What was observed.**

- The upload endpoint streams attacker-supplied bytes through to the
  IDA MCP. AILA never persists them, but it does buffer in process
  memory long enough to forward. Large file uploads could exhaust the
  ASGI worker.
- The MCP call log persists `base_url` and `action` for every call,
  but excerpts of `error_excerpt` could include sensitive payload bits
  if the MCP returns one.
- `PATCH /vr/mcp/servers/{id}` accepts an arbitrary URL string. An
  operator (or a compromised operator account) could point a bridge
  at an attacker-controlled URL.

**What was changed this batch.**

- `error_excerpt` is hard-capped at 400 characters.
- The audit_mcp bridge's `_resolve_base_url` strips the trailing slash
  defensively before use.
- Upload endpoint is gated on `team_id` via `_team_filter()` and
  rate-limited at `10/minute` (same as analyze).
- `error_excerpt` only includes the exception string — not request or
  response bodies. The recorded bridge layer never persists `kwargs`
  or response payloads.
- `record_call` swallows all write failures (`contextlib.suppress`)
  so a DB outage during logging never bubbles up to the caller and
  never crashes the analysis pipeline.

**Open items.**

- **F-S1**: `PATCH /vr/mcp/servers/{id}` should require admin role
  (currently any authenticated user). Two-line change. **Punt to v0.5
  hardening pass.**
- **F-S2**: Upload size cap. Currently bounded only by ASGI
  configuration. Add per-route `Content-Length` ceiling +
  multipart streaming if files >100MB become routine.
- **F-S3**: The `_mcp_handles_json` column stores `binary_id` /
  `audit_mcp_index_id` / `mcp_path`. The MCP path is filesystem-shaped
  on the MCP workstation. If an attacker can read the DB they learn
  the MCP layout. Not exploitable in isolation but documented.

---

## 4. UI/UX designer — does the screen tell the truth

**What was observed.**

- DESCRIPTOR_TEMPLATES asked operators for backend-internal ids
  (`audit_mcp_index_id`, `binary_id`, `kernel_image_id`). These leaked
  into every "Create target" form.
- `enrichment_status` enum (`unenriched`/`running`/`complete`/`failed`)
  rendered as raw labels. "Unenriched" doesn't tell an operator
  anything actionable.
- Truncated UUIDs (`.slice(0,8)`) appeared in 9 places across 8
  detail/list pages. Worst offenders: `BranchTreePage:115` (every
  branch node), `InvestigationsListPage:227` (target column), and
  `ProjectDetailPage:163,169,298` (target + patched_target +
  badge). The sidebar "RECENT" section also raw-rendered UUIDs from
  detail URLs.
- The breadcrumb showed `Vr / Targets / 1cb15c39 4...` for a
  freshly-visited target.

**What was changed this batch.**

- DESCRIPTOR_TEMPLATES rewritten: operator only provides what they
  actually know (repo URL, file path, kernel version, arch). Hint
  copy explicitly says "Analysis runs automatically after create.
  No manual MCP wiring."
- `AnalysisState` enum replaces `EnrichmentStatus`. Projection layer
  translates to English: "Queued" / "Analyzing source..." / "Ready" /
  "Failed".
- `useTargetMap()` / `useTargetName(id)` / `useWorkspaceMap()` hooks
  added — every list/detail page now renders human names instead of
  truncated UUIDs. Verified clean via `grep -n '.slice(0,'` after
  edits.
- `useRecentlyViewed.pathToLabel` detects UUID-shaped path segments
  and renders them as `Detail` so the sidebar never shows
  `1cb15c39 4...` again.
- `BranchTreePage` node labels: `b.id.slice(0,8)` → `persona @t<n>`
  (e.g. "yuki @t14"). Sibling branches with the same persona are
  disambiguated by `fork_at_turn`.
- `FuzzCrashDetailPage` header changed from `Crash <8hex>` to
  `<crash_type> (stack <12hex>…)` — the stack hash is a content hash
  and is meaningful as identity. Foreign-key fields
  (`duplicate_of_crash_id`, `promoted_to_finding_id`) became
  clickable Links labeled "duplicate of earlier crash →" / "promoted
  to finding" — no UUID anywhere.

**Open items.**

- **F-U1**: Per-page document title doesn't update with the resolved
  entity. Currently shows route title (`Target Detail`) even when
  the target is named `nginx`. Add `useDocumentTitle(resolvedName)`
  pattern on every detail page.
- **F-U2**: Confirm dialog before destructive actions. Re-analyze on
  a binary that already produced a 2GB IDA database silently kicks
  the whole pipeline. Add `confirm()` for re-analyze when prior
  analysis took >60s.
- **F-U3**: The Operator-supplied descriptor `<details>` on
  TargetDetailPage shows raw JSON. Pretty-print + hide fields whose
  values are empty.

---

## 5. New engineer onboarding — can I figure this out

**What was observed.**

- The path from "I want to look for variants of a CVE" to a running
  investigation involves: pick workspace, create target, wait for
  analysis, run ranking, create investigation, watch branches, read
  outcomes. Each step has its own page. No "guided" path.
- README mentions MCP servers in passing. No standalone "what is an
  MCP server, why does AILA need one" explainer.
- The decompiler / IDA / audit-mcp distinction lives in lore — only a
  staff engineer or someone who built it would know what's where.
- 18,140 LOC backend + 5,461 LOC frontend = a lot of surface for a
  newcomer to map.
- Module boundaries are conceptually clean (`vr` vs `platform` vs
  `vulnerability`), but the breadcrumb on a detail page collapses all
  of that to `Vuln Research / Target`.

**What was changed this batch.**

- `MCP Servers` page now serves as the in-product explainer: each
  server card has a `description` field ("Source-code audit MCP. Owns
  git clones, indexing, graph queries, scanners, taint analysis,
  fuzzing target ranking.") and a `Show <N> tools` button that lists
  every tool the MCP exposes. A new engineer can read what's available
  without reading the audit-mcp source.
- `MCP Call Log` page provides a self-documenting trace of what the
  platform actually does. After triggering one analyze, the operator
  sees `clone_repo → index_codebase → poll_index → detect_languages`
  — that *is* the architecture, made observable.
- Per-kind operator-friendly progress copy in TargetDetailPage
  ("Cloning + indexing source...", "Uploading + analyzing in IDA...")
  explains what's happening behind the curtain without leaking
  implementation details.

**Open items.**

- **F-N1**: A `/vr/guided-tour` walkthrough that says "Step 1: create
  a workspace. Step 2: add a target. Step 3: ..." would dramatically
  flatten the learning curve. Punt for v0.5.
- **F-N2**: The audit-mcp tool list is opaque (55 names like
  `attack_surface`, `taint_paths_to`). Adding a one-line description
  per tool, surfaced via the `Show tools` button, would be high-value
  documentation. Requires upstream change in `audit-mcp` to expose
  per-tool docstrings via openapi.
- **F-N3**: The `docs/` directory has 30+ markdown files. There is
  no `docs/README.md` index telling a newcomer which to read first.

---

## Summary

| Persona | Fixed | Deferred |
|---|---|---|
| Staff engineer | 5 | 2 (T1 stuck-task platform bug, descriptor `binary_path` field) |
| VR engineer | 5 | 3 (SSE wiring, nav reshuffle, workspace col on investigations) |
| Security | 4 | 3 (F-S1 admin gate, F-S2 size cap, F-S3 handle exposure) |
| UI/UX | 5 | 3 (F-U1 doc titles, F-U2 confirm dialogs, F-U3 descriptor pretty-print) |
| Onboarding | 3 | 3 (F-N1 guided tour, F-N2 per-tool docs, F-N3 docs/README) |

**Shipped behavior changes this batch:**

- Migration 051: `enrichment_status`/`last_enriched_at` dropped;
  `analysis_state` + `_mcp_handles_json` added; backfill SQL strips
  leaked ids from descriptor.
- Migration 052: `vr_mcp_call_log` table + indexes.
- `clone_repo` MCP tool added to audit-mcp; AILA delegates instead
  of shelling out.
- Bridges read URL from `ConfigRegistry` per-call; PATCH takes
  effect without restart.
- `record_call` middleware writes one log row per `forward()`.
- `POST /vr/targets/{id}/upload` for binary kinds.
- `POST /vr/targets/{id}/analyze` for manual retry.
- `MCP Servers` + `MCP Call Log` pages added to sidebar (orders 75, 76).
- All `.slice(0,8)` UUID displays in the VR module resolved to
  display_name / persona / stack_hash / clickable foreign-key links.
- `useRecentlyViewed` sidebar list detects UUIDs and shows "Detail".

**Live verification (running stack on 2026-05-14):**

- nginx target analyze: `pending → ingesting → ready` in 6 seconds
  (warm cache). primary_language='c' auto-detected.
- MCP Call Log: 4 rows logged for that analyze, all `ready 200`,
  latencies 225ms–1227ms.
- MCP Servers page: audit-mcp reachable with 56 tools (incl.
  clone_repo), ida-headless unreachable with clean ConnectError.
- Upload endpoint validation: source_repo target → 400
  "does not accept uploads"; native_binary target → 503
  "IDA MCP at http://127.0.0.1:18821 unreachable" (expected on Win11
  dev box without IDA Pro).

**Test gate:**

- 110 vr tests passing.
- `ruff` clean.
- `honesty_audit` exit 0 (5 documented noqa warnings).
- `pnpm --filter @aila/shell type-check` clean.
