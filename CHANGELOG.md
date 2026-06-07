# Changelog

All notable changes to AILA are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- `vr` module: enterprise PDF report renderer (`reporting/pdf_report.py`)
  with cover page + severity callout + sectioned body. Built on
  ReportLab so the install path has no native deps. Export button on
  `InvestigationDetailPage` triggers `GET /vr/investigations/{id}/report.pdf`.
- `vr` module: `ReportWriter` LLM agent (`reporting/writer_agent.py`)
  produces polished prose for each PDF section under a strict typed
  schema. Refuses to invent facts not present in the investigation
  trail. Surfaces variants spawned + PoC drafts in the report body.
- `vr` module: `PocWriter` LLM agent (`reporting/poc_writer.py`) plus
  `run_vr_draft_poc` task. Drafts a runnable exploit / PoC for a
  confirmed finding. `can_run=False` skeleton when the finding lacks
  inputs (no fabricated exploits). Auto-queued when a variant-child
  investigation lands a `DIRECT_FINDING`; also exposed via
  `POST /vr/findings/{id}/draft-poc`.
- `vr` module: variant-hunt pipeline — `system_audit.md` mandate to
  emit `variant_hunt_orders` for `kind=variant_hunt` investigations;
  dispatcher walks the bundle and spawns child investigations via
  the shared `_spawn_variant_child` helper. One submit → primary
  finding + N variant probes.
- `vr` module: Re-enqueue button on `InvestigationDetailPage` (visible
  when status is `completed` or `failed`). Resets to `created` and
  submits a fresh `run_vr_investigate` task while preserving the
  branch case state.
- `vr` module: schema-driven prompt — agent now sees per-tool
  signatures (`audit_mcp.read_function(index_id: string [required],
  file_path: string [required], name: string [required])`) instead
  of just tool names. Fetched live from each MCP server's `/tools`
  catalog and cached per process.
- `Dockerfile` + `.dockerignore` — multi-stage build producing a
  minimal runtime image for the API and workers. ENTRYPOINT is
  `aila`; override CMD to switch between `serve` and `worker -q <q>`.
- `infra/utilities/docker-compose.full.yml` — full-stack compose
  spinning up postgres + redis + api + 5 workers + frontend. The
  existing `docker-compose.yml` (infra-only) remains the default
  for developers running AILA locally.
- `requirements.txt` + `requirements-dev.txt` — generated from
  `pyproject.toml` for pip-only workflows. `pyproject.toml` is still
  the source of truth.
- Tool-priority steering section in `system_audit.md`: agent is now
  told to prefer symbol-graph tools (`callers_of`, `taint_paths_to`,
  `type_resolver`) over `search_source` (raw grep). Repeated
  `search_source` calls are flagged as a code smell.

### Changed

- `pyproject.toml` core deps: added `sqlalchemy==2.0.45`,
  `jinja2==3.1.6`, `reportlab==4.5.1`. WeasyPrint moved to optional
  `[pdf-weasyprint]` extra since the default PDF renderer uses
  ReportLab (no native deps on Windows).
- `CyberReasoningEngine.absorb` merges live hypotheses by id instead
  of replacing the entire list every turn. Previously, if the LLM
  forgot to repeat h3 in its current view, h3 silently disappeared.
  Now the only way to remove a hypothesis is to explicitly reject it.
- `CyberReasoningEngine.decide_next_turn` uses `chat_structured`
  instead of plain `chat` — gateway enforces the
  `ReasoningTurnDecision` JSON schema upstream when the routed model
  supports strict mode. Removes the prior failure mode where the LLM
  emitted partial schemas missing required fields.
- `_extract_json_object` uses `json.JSONDecoder.raw_decode` so an LLM
  emitting two JSON-looking blocks no longer breaks parsing.
- `audit-mcp` adapter observable keys carry an args fingerprint so
  repeated `search_source(pattern=X)` calls no longer overwrite each
  other in `case_state.observables`.
- `_MAX_OBS_READ_FUNCTION` bumped 3KB → 12KB so most C functions fit
  in the observable without truncation.
- `investigation_emit` auto-re-enqueues on `max_turns` exit without
  terminal outcome, bounded by `_OVERALL_TURN_CAP=200`. Per-task cap
  of 25 is no longer a hard stop.
- `/vr/investigations/{id}/resume` endpoint now submits a fresh
  `run_vr_investigate` task. Previously it just flipped status and
  left the investigation dead.
- `DurableStateMachine` reaper at worker startup SKIPS task records
  whose workflow cursor is still in a non-terminal state (D-86).
- Frontend message limit raised 100 → 500 in `useInvestigationMessages`
  so long investigations past T100 actually render.
- `TurnCard` collapses by default — click the header to expand the
  body. One-line preview when collapsed.
- Documentation: README module inventory now lists `vr` with its
  full capability surface. Quick-start uses `pnpm` (not `npm`) and
  references the full-stack docker compose option.
- Frontend live-tail of investigation messages is now opt-in (commit
  `ca1ff83`). The previous `useInvestigationMessages` default fired
  `refetchInterval: 3000` against `/messages?limit=50000` from every
  open tab, generating more bytes than the rest of the UI combined and
  contributing to two uvicorn OOMs (D-251 / D-252). Live updates now
  flow exclusively through `useInvestigationMessagesStream` (SSE);
  callers that still want polling pass
  `useInvestigationMessages(id, undefined, 0, 50000, { liveTail: true })`.
  Existing positional args remain compatible.
- VR investigation wall-clock cap clocks from `coalesce(started_at,
  created_at)` instead of `created_at` (commit `b47dd65`). Both the
  reaper and the per-turn cap stop killing investigations whose only
  "age" is queue-wait time during long target ingestion. Caught by the
  WebKit JSC incident (`9e99eda0`) where every branch died at turn 1
  with `cap_exceeded:investigation_wall_clock:32.7h/6.0h`.
- `post_draft_review_request` is now idempotent (commit `8f2d1f5`).
  Investigation_emit re-entry on sibling vote, workflow restart, or
  operator pause/resume no longer re-posts the `*** DRAFT OUTCOME UP
  FOR REVIEW ***` notice. Dedupe keys on
  `auto_steering_key='draft_review_request:<outcome_id>'`; if a prior
  post exists, returns its id as a no-op. Observed 12 duplicate posts
  on a single outcome in investigation `b3eebd6b` before the fix.
- Three fixes for the stuck-investigation pattern (commit `2328b4e`):
  (1) `tool_executor` lowers `_count_consecutive_malformed` from `>=2`
      to `>=1` and points both error texts at `action=observe` as the
      explicit safe fallback;
  (2) `vuln_researcher` gains `_maybe_reject_submit_when_draft_pending`,
      which refuses a terminal_submit when another sibling has an
      un-voted draft in this investigation (runs before the unresolved-
      hypothesis and variant-hunt gates);
  (3) `outcome_review.evaluate_quorum` auto-approves when `quorum_k > 0`
      but `len(active_siblings) == 0` and votes are still below quorum,
      under transition reason `auto_approved_no_active_voters_*` so the
      operator can audit which outcomes shipped without corroboration.
- Hard submit-gate forces every live hypothesis to be settled before
  terminal submit (commit `9bb2c29`). `_maybe_reject_submit_with_unresolved_hypotheses`
  runs before the variant_hunt gate on every submit. Computes
  `unresolved = live_ids - newly_rejected`; if non-empty, converts the
  submit into a non-terminal placeholder and injects
  `_directive.unresolved_hyp_submit_rejected` at prompt position 2 of
  the next turn. After `VR_UNRESOLVED_HYP_REJECT_CAP` (default 3) the
  submit is forced through with `payload.unresolved_hypotheses_at_submit_advisory`
  stamped naming the survivors. Negative results (0 live hypotheses)
  terminate cleanly as `assessment_report` through the same gate.
- `__crashed__` workflow cursor sweep moved from VR to platform tasks
  with an ORM `delete()` (commit `af9a724`), so any module that lands
  in `__crashed__` is reaped on worker startup.
- ARQ stale-heartbeat zombies are now reaped with an unconditional
  commit (commit `e42dea2`) — the previous reaper logged the reap but
  did not always commit, leaving heartbeats stuck.
- VR branch reaper switched from raw `text()` SQL to an ORM `update()`
  construct (commit `c7c6820`) after the prior race window between
  SELECT and UPDATE could mark a healthy branch as terminated (commit
  `ffb8f93`). Atomic UPDATE with safety graces closes the race.
- VR bridge schema cache now expires (commit `15311b7`), so a newly
  added MCP tool surface is picked up without a worker restart, and
  xref tools that return zero results carry an auto-suggestion for
  the operator's next step.
- Auto-correction for hallucinated `audit_mcp` `index_id` values: the
  bridge rewrites obviously-bad ids to the active investigation's
  target and surfaces a sharper prompt callout (commit `ad2af51`).

### Fixed

- `audit-mcp` `read_function` / `extract_class` AST-only resolution
  via `TypeResolver` — eliminates three classes of failure: Windows
  path slash mismatch, K&R-style multi-line definitions, and matching
  call sites instead of definitions.
- VR adapter for `audit_mcp.read_function`: handles the list-of-lines
  body shape by joining with newlines instead of `str(list)`. Agent
  no longer sees a Python list repr in observables.
- Repository hygiene: stripped 60+ tracked `.audit*`, `.logs/`,
  `.backend_*`, `.vr_*`, `.test_*` artifacts from full history via
  `git filter-repo`. `.gitignore` extended to keep them out.

---


## [v7.0] - 2026-04-29 -- Repository Zero Checkpoint

Onboarding-ready repository for new module contributors. Documentation remaster, directory cleanup, developer tooling.

### Added

- `.env.example` with all required env vars grouped by section (database, Redis, auth, CORS, LLM, forensics, server)
- `docs/CONTRIBUTING.md` -- contributor workflow, branch naming, commit format, quality gates, module authoring quick-start
- `docs/QUICKSTART.md` -- zero-to-running guide (prereqs, install, DB setup, migrations, start services, verify)
- `.claude/CLAUDE.md` -- Claude Code project instructions (architecture, rules, common mistakes, verification checklist)
- `start-linux.sh` -- Linux/macOS startup script with PID-based shutdown
- `hello_world/README.md` -- module purpose, API endpoints, extending guide
- `hello_world/frontend/` -- React page stub (spec.ts, HelloWorldPage.tsx, api.ts)
- `_template/README.md` -- copy-and-rename instructions for new modules
- `docs/forensics/` directory consolidating all forensics-specific documentation
- Makefile expanded to 20 targets: install, dev, backend, frontend, worker(-vuln/-forensics), migrate, test, test-e2e, lint, typecheck, honesty, build, compile, check, security-scan, audit, bandit, clean

### Fixed

- `hello_world/module.py` top-level `api_router` import replaced with deferred import inside `route_specs()` per MODULE_STANDARD
- `start.sh` no longer kills all `python.exe` on the box; matches only AILA processes by command line
- `start.sh` uses `python -m aila serve --reload` instead of raw uvicorn; single forensics worker instead of 3
- `docs/ENV_VARS.md` database URL default corrected from SQLite to PostgreSQL; `AILA_LLM_MODELS_REJECTING_TEMPERATURE` documented

### Changed

- `README.md` rewritten from scratch for developer onboarding (architecture diagram, module inventory, CLI reference, doc index)
- `AGENTS.md` rewritten as contributor guide (project structure, build commands, coding conventions, commit format, PR gates)
- `CLAUDE.md` moved from repo root to `.claude/CLAUDE.md` (Claude Code project-level discovery); Codex references and Karpathy appendix removed
- `docs/ARCHITECTURE.md` expanded from 50 lines to full architecture document (text diagram, 12 platform package descriptions, extension points, 4 INFRA constraints)
- Forensics docs reorganized: `FORENSICS_MODULE.md` -> `docs/forensics/README.md`, CTF roadmap/playbook/pre-discussion moved under `docs/forensics/`

### Removed

- `scratch/` directory (18 files: probe scripts, screenshots, extracted Electron app)
- `reports/` directory (57 PNGs + report.json from v6.0 UI audit)
- Root `__pycache__/` orphaned bytecache (4 `.pyc` files with no source)
- `aila.db`, `agentdb.rvf`, `ruvector.db`, `mb.plist`, `.coverage`, `coverage.json` (runtime artifacts)
- `.planning/REQUIREMENTS_v19_backup.md`, `.planning/research/FEATURES_v3_old.md`, `.planning/research/FEATURES_frontend_v3.md` (superseded)
- `.planning/milestones/v1.5-*`, `.planning/milestones/v2.0-*`, `.planning/milestones/v5.0-*` (shipped, archived in MILESTONES.md)
- `.planning/codebase/`, `.planning/CODEBASE-AUDIT.md`, `.planning/vulnerability-radar/` (stale v5.0 artifacts)
- `docs/TEST_COVERAGE_MAP.md` (self-described stale v1.7 snapshot)
- `docs/STORYBOOK_PLAN.md` (moved to `.planning/STORYBOOK_PLAN.md`)

---

## [v6.0] - 2026-04-29 -- Platform Frontend Completion

15 phases (189-204). Complete frontend coverage of all backend capabilities. No backend endpoint left without a UI surface.

### Added

- ReactFlow blueprint schema editor for SbD NFR (164 question nodes, section headers, subgroup labels, drag-to-connect dependencies, click-to-edit drawer)
- 164-question production questionnaire seeded (12 sections, 21 subgroups, 120 options, 48 subtask mappings, 29 question deps)
- Findings workflow UI: triage state machine (new -> investigating -> mitigated -> verified -> closed) with transition dialogs and state badges
- 5 new admin pages: dead letter queue inspector, automation schedule manager, scheduled reports manager, cost intelligence dashboard, executive dashboard with PDF export
- System tagging UX: tag vocabulary admin page, inline tag assignment on systems list
- Saved filters CRUD page
- Task queue admin: queue depth display, drain, requeue-failed controls
- Module extension points: `PanelContribution.label` field; vulnerability module contributes Findings/Scans tabs to system detail via `PanelContribution`
- Forensics frontend: 5 pages, 22 typed query hooks, 20 mutations, 6 screens
- Storybook user journey plan (`docs/STORYBOOK_PLAN.md`)
- `useThemeChartColors()` hook resolving CSS variables to hex values for Recharts SVG fill attributes
- LLM temperature rejection list configurable via env var `AILA_LLM_MODELS_REJECTING_TEMPERATURE` and config DB entry

### Fixed

- Tools page 500: `ModuleStatusTool` didn't inherit `Tool` base class, causing `AttributeError` on `.name` in `list_tools`
- Dashboard TopFindings/Trend widgets reading empty `module_data` -- rewired to fetch `/vulnerability/findings` directly
- Radar page height collapse (`h-full` inside unconstrained parent) -- replaced with explicit viewport height
- ARQ worker startup crash: `get_task_tuning()` called `asyncio.run()` during module import, creating stale asyncpg connections; simplified to always return compiled default
- Worker queue routing: vulnerability tasks enqueue to `vulnerability` track; worker command corrected to `-q vulnerability`
- Global breadcrumb DOM structure
- Route-level Suspense for lazy-loaded module routes
- SbD NFR schema editor rewired to nested `/sbd_nfr/schema` tree
- Assessment flow routing normalized via `sessionFlow.ts` (draft -> wizard, resolved -> results, in_review -> review, approved -> report)

### Changed

- Radar, Viz, Console moved from platform sidebar to vulnerability module sidebar (they consume 100% vulnerability data)
- Platform sidebar reduced to cross-module features only: Dashboard, Systems, Tasks, Chat
- SystemDetailPage modularized: platform owns Overview + Tags built-in; modules contribute tabs dynamically via `PanelContribution` with `slot: "system.detail"`
- SbD NFR wizard layout rewritten with inline grid template (no custom CSS, no fixed overlay)
- 23 SbD NFR component files rewritten to use platform Tailwind tokens (zero `wizard-*` classes)

### Removed

- `styles.css` (3,367 lines dead CSS) and `wizard.css` (199 lines) from SbD NFR module

---

## [v5.1] - 2026-04-16 -- Forensics Module Compliance Fix

3 phases (186-188). Bring forensics module to honesty audit and typing compliance.

### Fixed

- 3 silent exception swallows replaced with typed catches and logging
- 40+ bare `except` blocks typed to specific exception classes
- Typed return annotations on all public functions
- `__all__` added to 15 files missing it
- `get_ssh_service` converted to `async def` with `asyncio.Lock`; all 14 call sites updated with `await`
- `register_tools`/`seed_data` kept `async def` (platform protocol uses `await`)

### Changed

- Honesty audit, mypy, and all tests pass (gate verification Phase 188)

---

## [v5.0] - 2026-04-14 -- Platform Debt Resolution

16 phases (162-177). Async hardening, observability, multi-tenancy, and frontend architecture.

### Added

- LLM cost intelligence: per-call token tracking, cost estimation, budget alerts
- Multi-tenancy: team-scoped data isolation at service layer
- Rate limiting middleware with per-user and per-endpoint quotas
- Prometheus metrics: request latency, LLM call counters, token usage gauges
- Graceful shutdown: drain workers, close DB pools, flush Redis streams
- Platform reasoning contracts and reasoning graph snapshots (Alembic 038)
- Forensics directive controls (Alembic 039)

### Changed

- Async hardening across all DB access paths
- Frontend architecture overhaul: platform design system, extension registry, module contribution pattern

---

## [v4.1] - 2026-04-10 -- Platform Integrity Restoration

3 phases (159-161). Fix everything broken by the v4.0 rapid ship.

### Fixed

- Applied v3.0 seed data to live PostgreSQL (80 questions, 11 sections, 76 mappings)
- Added 4 missing DB columns (`condition_expr_json`, `risk_tier`, `posture_index`, `pre_triage_context_json`)
- ModuleRegistry accepts tool-less modules (SbD NFR has no tools)
- Schema Editor response shape mismatch (3 query hooks rewired)
- TaskRepository sync-to-async mismatch (500 error on `GET /tasks`)
- 22 stale test assertions updated; stale test file deleted
- Duplicate Findings sidebar entry removed; Scans and Tasks sidebar items unhidden

### Added

- SSH credential support: API + frontend PEM textarea, password, passphrase (AES-256-GCM encrypted)
- `private_key_secret_id` column on `ManagedSystemRecord`
- Server-side findings pagination (Prev/Next with page count)

---

## [v4.0] - 2026-04-10 -- NFR Questionnaire Overhaul

8 phases (151-158). STRIDE-grounded security assessment questionnaire.

### Added

- 80 STRIDE-grounded NFR questions across 11 sections replacing 213 ad-hoc questions
- SAMM 3-level maturity scoring (0.0-3.0 per section + posture index)
- Risk tier derivation (LOW/MEDIUM/HIGH/CRITICAL from scope answers)
- Pre-triage context export feeding finding severity adjustment
- Schema editor frontend: section tree, question editor, subtask mapping, conditional logic visualizer, live preview, publish
- Cyberpunk wizard frontend: 3-column layout, binary/maturity inputs, Framer Motion animations, schema version pinning
- Seed validator with 6 error classes + integration tests
- Multi-condition skip logic with `condition_expr_json` AND/OR gating

---

## [v3.0] - 2026-04-10 -- Frontend Platform Overhaul

13 phases (138-150). First production frontend with design system.

### Added

- shadcn component library integration
- Cyberpunk design system with CSS variables and Tailwind tokens
- Widget-based dashboard with drag-and-drop grid layout
- ReactFlow graph visualization
- OAuth / OIDC provider management
- Storybook component stories
- Playwright E2E test infrastructure

---

## [v2.2] - 2026-04-09 -- SbD NFR Module Full Rewrite

4 phases (134-137). Complete rewrite of the Security by Design NFR assessment module.

### Added

- STRIDE-grounded questionnaire architecture
- SAMM maturity scoring engine
- Schema editor with conditional logic
- Cyberpunk assessment wizard

---

## [v1.8] - 2026-04-06 -- LLM Overhaul: Zero-Trust AI Layer

10 phases (114-123). Replace smolagents with platform-owned LLM pipeline.

### Added

- Platform-owned `AilaLLMClient` with retry, cost tracking, and seal verification
- Zero-trust LLM pipeline: classify -> gate -> call -> validate -> seal
- LLM drift detection and cost estimation
- Async-sync boundary fix (v1.8.1, absorbed)

### Removed

- smolagents dependency and agent abstraction layer
- All direct OpenAI SDK calls from module code

---

## [v1.7] - 2026-04-05 -- Deep Architecture Review & Quality Assurance

50-phase deep review (Phases 64-113): every source file read line-by-line, every decision questioned, every fix proven with tests.

### Reviewed & Hardened

- **Per-file deep review** of all 45 API, task queue, module, and platform source files (Phases 64-92)
- **Cross-cutting verification** of 15 system-level concerns: RBAC matrix, token lifecycle, task queue full cycle, SSE streaming, session isolation, export correctness, health state machine, error consistency, sync/async boundaries, import boundaries, OpenAPI completeness, module discovery, config read-through, audit trail (Phases 93-102)
- **Stress testing** of 15 edge cases: concurrent submission, bulk atomicity, Redis failure resilience, worker crash recovery, input fuzzing, SQL injection, JWT attack surface, concurrent revocation (Phases 103-110)

### Fixed

- Renamed `_decode_and_blacklist_check` to public (cross-module function)
- Added `jti` (UUID) claim to every JWT for individual token identification
- Fixed `get_run_audit_events` reporting 1 page for empty results (now 0)
- Removed redundant endpoint-level `Depends(require_api_key)` across 6 routers
- Replaced manual XREAD loop with `ProgressStream.stream_events()`
- Re-raised exceptions after logging in `run_platform_handle` (ARQ needs propagated exceptions)
- Fixed SSE done sentinel emitted outside `finally` block
- Moved HTTPException from inside `asyncio.to_thread` to router boundary in `invoke_tool`
- Fixed `system_findings` score field using `r.score` instead of hardcoded None
- Replaced Python-side facet counting with SQL GROUP BY + COUNT queries
- Fixed `session.refresh(record)` after audit commit preventing DetachedInstanceError
- Fixed `hello_world` SEED_VERSION from int to str
- Replaced `os.getenv` for JWT expiry with `get_task_tuning` (ConfigRegistry pattern)

### Added

- Custom exception handlers reshaping all errors into `ErrorResponse(detail, code, errors)` envelope
- `Literal` types for closed enum fields in Pydantic schemas
- Content-Length header check in middleware rejecting >10MB before body read
- `sync_in_async` and `api_imports_module_internals` honesty audit rules
- Default implementations for `report_filter_keys`, `filter_report_rows`, `seed_data` in ModuleProtocol

### Documentation

- MODULE_STANDARD.md v2, HONESTY_AUDIT.md, PITFALL_GUIDE.md, TEST_GUIDE.md
- 5 Architecture Decision Records (JWT, SQLite+Redis, module protocol, ConfigRegistry, single-scan)
- ENV_VARS.md, CONFIG_REGISTRY.md, SECURITY_MODEL.md, TASK_QUEUE_OPS.md, SSE_GUIDE.md
- DB_SCHEMA.md, DEPLOYMENT.md, Golden Rules updated to 58

### Tests

- 95 requirements verified across 3316 tests
- RBAC exhaustive matrix, token lifecycle, concurrent submission, worker crash recovery, input fuzzing, SQL injection prevention

---

## [v1.6] - 2026-04-04 -- Architecture Overhaul & Honesty Review

6 phases (58-63). Honesty audit, code quality pass, wiring verification, race condition testing.

### Added

- AST-based honesty audit with 15 rules
- Random-order test isolation with `pytest-randomly`
- Negative test suites for auth, scans, sessions, systems, tasks
- Race condition tests for concurrent DB access

### Fixed

- Import cycle elimination, type annotations on all public functions, sync/async boundary violations, naming consistency

### Changed

- Golden Rules established (55 rules)
- MODULE_STANDARD.md with compliance verification
- `_template` and `hello_world` modules updated

---

## [v1.5] - 2026-04-04 -- FastAPI REST API

6 phases (52-57). Complete REST API with JWT auth, task queue, SSE streaming, and report exports.

### Added

- **FastAPI REST API** with 42 endpoints across 9 routers
- **JWT authentication** with API key exchange, HS256 signing, refresh token flow
- **RBAC** with 3 roles: admin, operator, reader
- **Platform task queue** with ARQ + Redis, background workers, heartbeat monitoring, zombie reaper, checkpoint/resume
- **SSE streaming** for scan progress, chat tokens, and task progress
- **Report exports**: JSON streaming, CSV streaming, PDF via WeasyPrint
- **Session management**, system CRUD, bulk findings update, tool invocation, audit trail, health endpoint, bootstrap key, CORS middleware

### Changed

- Settings slimmed to 5 infrastructure-only fields (module config moved to ConfigRegistry)

---

*Versions prior to v1.5 were internal development milestones (v1.0-v1.4) focused on structural integrity, platform readiness, production hardening, data architecture, and honesty infrastructure.*
