# Changelog

All notable changes to AILA are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] -- Investigation-engine extraction program (RFC-01 through RFC-12)

The vulnerability-research and malware investigation engines are unified
onto a shared platform: one turn runner, one tool executor, one set of
support services and data-model bases, one agent primitive per concern.
Modules now bind their record types, prompts, and gates to platform bases
instead of carrying parallel copies. Also adds prompt versioning and
deployment, an eval-gated agent lifecycle, a DB-backed MCP catalog, and
per-vector knowledge provenance. Read the Changed section: the agent
config env-var names and the promotion contract changed and may require
operator action.

### Added

- Platform agent runtime (RFC-03): `AgentTurnRunnerBase`,
  `ToolExecutorHelpersBase`, the shared turn helpers, and platform bases
  for the pattern extractor, claim verifier, synthesis runner, persona
  router, and outcome dispatcher. The vr and malware agents are thin
  subclasses that set class attributes and override hooks; no agent
  primitive is defined twice. Honesty rules 42 and 49 lock this in.
- Prompt registry, immutable version store, and an admin deploy API so a
  prompt change ships by an alias flip with no code release (RFC-09,
  migrations 086/087/089). Every LLM call routed through the idempotency
  wrapper now records a `prompt_content_hash`, and cost + seal records
  gain a `prompt_version` column (migration 094).
- Per-investigation prompt pinning: an investigation resolves and pins its
  prompt versions on first use, so a later production-alias flip does not
  re-route a running investigation (migration 095).
- Eval-gated prompt promotion (RFC-08, migration 090) and an agent
  lifecycle control plane with evaluate/approve/promote/rollback, a
  distinct-approver review quorum, and an admin HTTP surface (RFC-10,
  migration 091).
- DB-backed MCP server instance catalog with a live-resolving registry and
  an admin CRUD API, so a server can be added, disabled, retargeted, or
  duplicated with no code change or worker restart (RFC-11, migration
  092).
- Content-aware knowledge chunker and per-vector provenance (`model_id`,
  `content_hash`, `source_type`, `updated_at`) on knowledge entries
  (RFC-12, migration 093).
- Self-healing infra-death classifier that marks a multi-turn
  infra-failed investigation retryable instead of emitting a hollow
  no-finding outcome, plus an `aila_sse_write_failures_total` metric
  replacing silent SSE-write swallows (RFC-07).
- `_template` now scaffolds a `ModuleConfigBase` config schema and the
  ModuleProtocol registry declarations so a copied module starts
  boundary-clean.
- A single platform `ResilienceLayer` facade over the fail-open sites
  (classify failure, conservative default with a signal, retry decision),
  funnelling every fail-closed signal through one
  `aila_resilience_signals_total` counter (RFC-07).
- Self-improvement loop behind the eval gate (RFC-08): an ExperienceWriter
  that turns accept/reject review verdicts into signed positive/negative
  patterns, a CalibrationProposer that aggregates per-outcome_kind history
  into a versioned, reversible threshold proposal (migration 097), and a
  RoutingLearner that publishes a routing recommendation.
- Shadow and canary lifecycle stages (RFC-10, migration 096): a candidate
  can be shadowed, canaried to a stable cohort fraction of new
  investigations by an investigation-id hash, held on a drift or cost
  spike, then promoted through the eval + quorum gate, all over admin
  endpoints with no code release.
- A generic `McpClient` with capability-based server resolution and
  instance pooling; each MCP tool call records the serving `instance_id`
  (RFC-11, migration 098). The three bridges keep only their server-
  specific request/response shaping.
- Adaptive knowledge retrieval (RFC-12): a router that picks a stable-core
  (preloaded cache), simple (hybrid), or graph path; a knowledge-entry
  edge table with bounded multi-hop traversal (migration 100); a
  sanitize/classify + provenance gate on results; a record-replay
  retrieval-quality eval with precision/recall/MRR/nDCG and a beats() gate
  (migration 099); and opt-in LLM contextual enrichment of chunks on
  ingest.

### Changed

- Investigation lifecycle, support services, and data-model bases are
  hoisted to the platform and shared by both modules (RFC-01/02/04);
  modules bind their record and enum types. The platform never imports a
  module (RFC-05), enforced by honesty rules 44 through 48.
- Agent submit-gate caps resolve through `ConfigRegistry`. The operator
  env-var names change from the raw `VR_*` / `MALWARE_*` form to the
  standard `AILA_VR_<KEY>` / `AILA_MALWARE_<KEY>` form; defaults are
  unchanged, so an operator who never set the old names sees no
  difference.
- Agent-behavior promotion now requires the eval gate AND a distinct
  -approver quorum (`agent_promotion_quorum`, default 1) before the
  production alias flips.

### Fixed

- The shared search router derived a finding result's `module_id` from a
  hardcoded `"vulnerability"` literal even though the module was resolved
  by capability; it now reads the resolved module's id, so a second
  module exposing findings is labeled correctly.
- Investigation pause/resume keyed workflow cursors by the random ARQ task
  id, so the lifecycle service's investigation-scoped cursor queries
  matched nothing and fell through to weaker fallbacks. Cursors now carry
  investigation and branch ids (migration 101) and the lifecycle service
  finds them by those keys, with the prior key kept as a fallback for
  cursors created before the change (RFC-02).

### Removed

- Duplicated agent primitives, support services, and data-model records
  across the vr and malware modules, consolidated onto the platform bases
  above.

---

## [0.3.0] - 2026-07-21 -- Security, correctness, and reliability hardening

A broad hardening pass across authentication and tenant isolation,
secret handling, LLM cost and resilience, audit integrity, and
per-module correctness, plus a migration of the test suite onto
PostgreSQL. Read the Changed section first: the CORS and OIDC
credential defaults changed and may require caller action.

### Added

- Observability join keys on cost and MCP-call records (#39):
  `llm_cost_records` and `vr_mcp_call_log` gain nullable
  `investigation_id`, `branch_id`, and `turn_number` columns. The agent
  turn loop sets an ambient correlation (a ContextVar) before it drives
  the LLM and MCP calls, and the cost-record writer and VR MCP-call
  logger stamp it, so a cost row or a tool-call row can be joined back to
  the investigation, branch, and turn that produced it. Calls outside a
  turn (scoring, report generation) leave the columns null. Migration
  082 adds the columns and their indexes.
- Append-only, hash-chained platform journal for tamper-evident audit;
  the CLI audit trail now writes to it. (C2)
- Evidence packs sealed with a merkle digest so later tampering is
  detectable.
- Per-run LLM token budget with a hard stop and a pre-call check;
  embedding computation offloaded off the event loop. (#38, #64)
- Team-scope request resolver and an `owned_or_404` helper for
  single-resource authorization. (C1, #36, #57)
- Secret redaction at the log boundary and for non-admin config reads.
  (C6, #50)
- Optional `page` and `page_size` params on the forensics list
  endpoints (evidence, findings, investigations); the response stays a
  `DataEnvelope` list. (#59)
- Workflow-transition validation on findings bulk-update: an off-graph
  transition is now rejected with 422. (#55)
- Per-call LLM cost ceiling and output-size bound for forensics
  writeups. (#48)
- Freeflow investigation cost ceiling
  (`forensics.freeflow_max_cost_usd`, default 25.0) with a monitor that
  cancels a run once its cost crosses the ceiling. Known limitation: it
  is inert in production until the reasoning engine threads the
  investigation run_id into its LLM cost records; the mechanism and
  termination path are unit-tested with seeded cost rows. (#59)
- TLS hardening for report email: admin CA bundle, implicit TLS, and
  certificate verification. (#48)
- `ConfigRegistry.get_sync` for synchronous call sites. (C3)
- Eval metric functions: expected calibration error, precision,
  recall, determinism, faithfulness. (C7)
- Deduplication of malware observation writes via a partial unique
  index. (#61)
- Per-tool-execution LLM timeout and pooled AsyncOpenAI clients that
  stop a per-call file-descriptor leak. (#44)
- Supervised automation tick loop: a malformed schedule row can no
  longer kill the loop and silently halt automation. Faults are caught,
  counted on `aila_automation_tick_failures_total`, and backed off
  exponentially (60s base, 300s cap) with a reset on the next success.
  (#46)
- Database connection pool sizing is tunable via env vars
  (`AILA_DB_POOL_SIZE`, `AILA_DB_MAX_OVERFLOW`, `AILA_DB_POOL_TIMEOUT`,
  `AILA_DB_POOL_RECYCLE`); the defaults match the previous hardcoded
  values, so nothing changes unless an operator opts in. (#45)
- Task-engine team propagation: a task inherits the submitting caller's
  team through a context var set by the task wrapper, so worker and
  agent follow-up submits carry it without per-site changes; task list
  and read queries are team-scoped for non-god-tier callers. (#53, #36)
- Confidence-drift retention sweep prunes drift records past their
  configured window. (#45)
- Hot-column indexes on the workflow-run, audit-event, and
  report-artifact query columns. (#45)
- Composite index on notification reads (`user_id`, `created_at`) so the
  per-user notifications list and unread queries stop scanning
  sequentially. (#45)
- Platform LLM config keys that were read but never declared -- the
  routing defaults (`llm_default_model`, `llm_base_url`,
  `llm_default_max_tokens`, `llm_default_temperature`,
  `llm_tool_timeout_s`) and `llm_kill_switch` -- are now schema fields,
  so `PUT /config` sets them instead of rejecting them as unknown; the
  defaults match the prior hardcoded fallbacks. Per-task-type and
  per-team keys (`llm_model_{task_type}`, `llm_monthly_budget_usd_{team_id}`,
  the pipeline gate and verify overrides, ...) are declared as typed
  dynamic-key families, so an open key space stays settable and cast on
  read through the same contract as static fields. (#45)
- The knowledge base embedding provider is selected by the platform
  config key `knowledge_embedding_model` (default `bge-m3`), read once
  when a KnowledgeService is constructed. (#49)

### Changed

- The vulnerability findings list pushes its pagination, ordering, and
  count into SQL instead of slicing in Python. The response envelope
  (`total`, `items`, `page`, `page_size`) is unchanged. (#55)
- Behavior: CORS credentials are disabled when origins are wildcarded,
  and OIDC cookies are marked `secure` by default. A client that relied
  on credentials with a wildcard origin must now configure explicit
  origins. (#36)
- `POST /sessions/{id}/messages` awaits the platform and returns a real
  assistant response on both the JSON and SSE paths; it previously
  discarded the un-awaited coroutine and echoed the request text.
- The event emitter reuses a pooled synchronous Redis client, and SSE
  streams are bounded by a lifetime cap with disconnect detection and
  an active-connection gauge. (#60)
- `upsert_many` batches its writes; observation reads are bounded and
  keyset-paginated. (#61)
- Legacy `AILAError` subclasses map to their real HTTP status codes.
- The test suite runs against PostgreSQL with async fixtures instead of
  SQLite. (#62)

### Fixed

Security and tenant isolation:

- OIDC callback validates the state against the signed cookie; every
  callback previously failed against a nonce field the state JWT never
  emitted. (#36)
- Refresh-token issuance no longer crashes on Alembic-migrated
  databases: `refresh_token_records` gains the `ip_address` and
  `user_agent` columns the model and login path already write but
  migration 002 never created. Fresh installs (schema built from the
  model via create_all) were unaffected; migrated databases raised a
  500 on every login. (#36)
- IDOR closed across malware investigation, observation, and
  subresource routes; team ownership enforced on target, systems, and
  tags routers. (#57, #36)
- Untrusted tool output and report facts fenced against prompt
  injection; markdown link schemes guarded in the forensics writeup
  viewer; vulnerability and synchronous PDF render environments
  hardened with autoescape and URL-scheme guards. (#43)
- SSRF policy re-validated on every redirect hop; secrets redacted from
  surfaced httpx and provider errors. (#42, #44)
- SFTP path traversal rejected on upload and download; playbook step
  dispatch gated behind a tool allowlist; pulled evidence re-hashed
  locally instead of trusting the analyzer; non-zero script exit
  surfaced instead of reported as success. (#58)
- Crash discovery rejects symlinks and oversized files. (#51)
- API key revocation made atomic to close a duplicate-revoke race;
  audit rows committed inside the business transaction and failing
  loud on drop. (#52)
- Team ownership extended to the topology, user-management, dashboard,
  executive, search, audit-event, vulnerability-findings, and
  scheduled-report reads; team and dead-letter administration
  restricted to god-tier callers. (#36, #48)
- Workflow runs are stamped with the submitting team at creation, so a
  team's own scan reports and module health summaries surface for that
  team instead of staying hidden behind the team-scoped read filter;
  queued scans, the dispatcher engine path, and interactive session
  dispatch all carry the team through. (#36)
- Vulnerability findings are stamped with the scan's owning team on
  persist, so team users see their own findings across the findings
  list, executive, search, and dashboard reads; previously findings
  were written team-less and the team-scoped read filters hid all of
  them from non-god-tier users. Scheduled report PDFs are scoped to the
  report owner's team, so a team's report no longer includes another
  team's findings. (#36)
- Systems registered through the agent system_registry tool are stamped
  with the calling team, matching the REST create path, so team-scoped
  reads surface them; the tool path previously wrote them team-less.
  (#36)
- Audit events are stamped with the acting team, so a team-scoped audit
  read surfaces a team's own events instead of an empty trail. Request
  handlers stamp the request team; worker and workflow events inherit
  the running task's team; pre-authentication login failures stay
  team-less. (#36)
- API keys are team-scoped: create stamps the creating admin's team,
  and list and revoke filter by team so a team-scoped admin can neither
  see nor revoke another team's keys; a god-tier admin (team_id=None)
  still manages every team's keys. Previously keys were written
  team-less and the key list was unfiltered, exposing every team's key
  metadata to any admin. (#36)
- OIDC login no longer silently grants god-tier access. The issued
  access and refresh JWTs now carry the user's team; previously the
  team claim was omitted, so a team-assigned OIDC user was treated as
  god-tier (TEAM-06) for the token lifetime. An OIDC provider can be
  bound to a `default_team_id` (create/update) so auto-provisioned
  users are scoped on first login; a user left without a team still
  gets god-tier but the grant is now logged. Adds the
  `oidc_provider_records.default_team_id` column (migration 076). (#36)

LLM and cost:

- `LLMResponse` declares its pipeline metadata fields (populating them
  previously raised `TypeError`); temperature-reject markers match on
  token boundaries; the dead health lock removed. (#44)
- Non-retryable provider errors fail fast; cost-telemetry failures no
  longer fail the LLM call; budget alerting never raises spuriously;
  the per-run token budget is enforced via the sync config read. (#44,
  #38)
- LLM retry backoff aborts on the cancellation token, so a cancelled
  run stops deferring instead of sleeping out its remaining attempts.
  (#44)
- Knowledge store and retrieve tools embed through the canonical
  provider, so vectors written by one path and queried by the other no
  longer land in incompatible embedding spaces; hybrid retrieve applies
  a relevance floor; and the knowledge_store dedup INSERT resolves a
  concurrent (namespace, dedup_key) race idempotently rather than
  surfacing an error. (#37)
- Knowledge base embeddings store at full 1024 dimensions. The pgvector
  column widened from `Vector(384)` to `Vector(1024)` to match the
  default BGE-M3 provider, ending the truncation that discarded 640 of
  every vector's dimensions on store and query and degraded retrieval to
  a sub-MiniLM signal. Migration `077` clears the prior truncated
  vectors and `scripts/reembed_knowledge.py` re-embeds every row from its
  stored content; the hybrid retrieve vector leg skips null-embedding
  rows so retrieval stays available during the backfill. (#49)

Modules:

- Vulnerability: GHSA matches gated by version, cve TTL honored, the
  NVD limiter moved off the event loop; criticality vocabulary and
  fallback scoring corrected; proxy resolved via the sync read;
  `weekly_digest` made async; `list_system_tags` returns full rows.
  (#55)
- Forensics: deep-analysis SSH runs off the DB connection; readiness
  enqueue moved outside the DB session; child tables purged on project
  delete; real `ArtifactRecord` fields read in the writeup builder.
  (#59, #63)
- Malware: investigation narrative sanitized on persist; deterministic
  token-boundary family match; workspace and tag-index constraint
  names module-prefixed to match their migrations.
- VR: finding evidence refs schema-validated at write time; a null
  outcome timestamp treated as never-fresh in the section cache. (#48)

Platform, async, and correctness:

- Blocking calls offloaded off the event loop; two discarded-coroutine
  config reads resolved. (#64, #65)
- Module seeding isolated per module with the malware seed version
  stamped; each module constructed once during discovery; periodic
  sweep re-registration made idempotent. (#45, #41, #46)
- Automation gains an overlap guard, claim-before-submit ordering,
  per-schedule isolation, and a registry lock. (#46)
- `UnitOfWork` fails loud on uncommitted writes. (#63)
- Scan SSE stream closes cleanly on a mid-stream backend error; binary
  response content declared for file-download routes.
- Knowledge dedup update uses the correct scalar-id subscript.
- `RegisteredSystem` tolerates extra DB columns; observables guarded
  against non-JSON values at construction. (#61)
- Journal hash-length check uses a portable `length()` constraint. (C2)
- SMTP scheduled-report config keys (`smtp_host`, `smtp_port`,
  `smtp_from`, `smtp_username`, `smtp_password`, `smtp_ca_bundle_path`,
  `smtp_use_implicit_tls`) are declared in the platform config schema,
  so operators can set them through `PUT /config/platform/*`; report
  delivery read them but the config API previously rejected them as
  unknown keys. `smtp_password` redacts for non-admin readers. (#45)
- Declared config keys the code ignored are now read through
  ConfigRegistry so a `PUT /config` override takes effect: the platform
  LLM pipeline-step and budget defaults and the reaper thresholds; the
  VR lifecycle caps (branch cap, nday and PoC limits, stale-branch and
  total-turn caps) previously read from `VR_*` env vars or fresh schema
  defaults; and the forensics SSH, script, and collection timeouts, the
  freeflow attempt cap, and the forensics LLM model. Defaults are
  unchanged, so behavior only differs when an operator sets an override. (#45)
- Model and migration schema converged where they had drifted so fresh
  installs (create_all) and migrated databases match: the
  `scheduled_report_records.team_id`, `reasoning_graph_snapshots`
  identifier columns, and `automation_schedule_records.cron_timezone`
  widths reconcile to the models' TEXT; `team_records` gains the named
  unique constraint the model declares; the VR workspace and tag-index
  unique constraints are module-prefixed (matching malware, avoiding a
  cross-module name collision); and the VR message, investigation, and
  finding index shapes and `project_id` type align to what the
  migrations already built. Migrations 080 and 081 converge existing
  databases; the redundant standalone per-column indexes create_all
  built on `platform_journal` are dropped from the model. (#45)
- Workflow retry backoff no longer starts one exponent too high. The
  caller passed ARQ's 1-based attempt counter to `default_backoff`
  instead of the completed-retry count, so the first retry deferred in
  [2.0, 3.0)s; it now defers in [1.0, 2.0)s. (#40)
- Investigation LLM spend is attributed to the investigation.
  `decide_next_turn` threads the investigation_id as the LLM run_id, so
  `LLMCostRecord.run_id` is populated for every reasoning turn. The
  per-investigation cost display now reads real spend (was $0.00), and
  the VR live-cost aggregator sums directly on `run_id` instead of
  joining through TaskRecord. **Behavior change:** the forensics
  freeflow cost ceiling (`forensics.freeflow_max_cost_usd`, default
  $25) was previously inert because those cost rows were never
  attributed; it now sums real spend and cancels a freeflow run once
  the cap is crossed. (#39/#59)
- Task requeue, resume, and cancel perform their ARQ side-effects
  (abort or re-enqueue) instead of only rewriting DB state; the
  Redis-URL lookup is guarded against a missing configuration. Workflow
  cursor recreation preserves its version chain. (#40)
- Automation cron is evaluated in the schedule's timezone; a schedule
  that fails to parse auto-disables instead of erroring on every tick;
  the concurrent runner claims due schedules with SKIP LOCKED; and
  platform health checks run real dependency probes. (#46)
- Malware observation dict-value payloads are size-capped on persist.
  (#61)

- `PlatformResponse.module_payload` is a real Pydantic discriminated
  union keyed on `query_mode`, so a response dict validates as exactly
  the member its tag names instead of silently matching the first
  structurally-compatible model (#61). A free-form module result dict
  (forensics, hello_world, and the module template return arbitrary
  shapes with no `query_mode`) now passes through untyped rather than
  being coerced into an unrelated member and losing its data; the
  unroutable response gained a dedicated typed member.
- Recovery paths that failed open now fail closed (#31):
  - The investigation rate limiter defers by a bounded step when it
    cannot read in-flight task load, instead of returning a zero defer
    that floods the queue under database pressure.
  - The second-model verification step propagates an internal failure
    instead of swallowing it, so the pipeline blocks an unverified
    response rather than passing it (verification is a security-critical
    pipeline step and defaults to fail-closed).
  - Malware's no-finding reconciler skips synthesizing an outcome while
    the LLM is recently unhealthy, matching the guard already present in
    the vulnerability-research finalizer, so an outage is not recorded
    as a clean "no finding" audit.

### Removed

- Dead `notification_types` and an unreachable unscoped cross-tenant
  cost query. (#41, #57)

---

## [0.2.1] - 2026-07-12 -- Reconciler no longer fabricates completions

### Fixed

- `synthesize_no_finding_outcomes` (the reconciler sweep that ensures
  every investigation terminates with an outcome) could mark an
  investigation `completed` with a synthetic `no_finding` audit_memo
  even when it ran zero reasoning turns. During an LLM outage every
  branch fails its turn and is driven terminal with no real work, so
  the reconciler was reporting infrastructure failures as clean
  "audited, found nothing" results. Two guards added:
  - Skip the whole sweep while the LLM is unhealthy
    (`is_llm_recently_unhealthy(600.0)`), matching the existing guard
    in `abandon_stale_branches_impl`.
  - When an orphaned investigation has zero turns across all branches,
    mark it `failed` (retryable via reopen / re-enqueue) instead of
    synthesizing a hollow audit_memo.

---

## [0.2.0] - 2026-07-12 -- Retrieval-augmented reasoning case model

The platform reasoning engine (shared by the vulnerability-research
and malware modules) previously trimmed cumulative case state by
blindly slicing it every turn: only the first 10 live hypotheses,
the last 80 tool readings, and the last 15 agent scratchpad entries
reached the model's prompt. On long investigations this silently
dropped the agent's own state mid-run and degraded outcome quality.
This release replaces blind slicing with a retrieval model: state
the agent needs is always indexed and available on demand.

### Added

- New `recall` reasoning action with a `recall_keys` field on
  `ReasoningTurnDecision`. The agent names tool-reading keys from the
  always-visible index and the engine renders those bodies in full
  on the next turn. Up to 8 keys stay pinned; a validator rejects an
  empty `recall_keys`. Backward compatible: the field defaults to an
  empty list and existing actions are unchanged.
- Tool-readings INDEX in the case model: every stored reading renders
  as `key (N lines / ~T tok) preview` each turn, so the agent can see
  what is available to recall without the full body cost.
- Recall guidance documented in the vr audit / kernel / hypervisor
  system prompts and the malware analysis system prompt.

### Changed

- Live hypotheses now render in full (ceiling 60) instead of the
  first 10, so an investigation's open threads are never hidden from
  the agent.
- Agent scratchpad now renders as a full index (ceiling 150) instead
  of only the last 15 entries.
- Tool readings render the most recent 12 in full plus any recalled
  keys; older readings remain reachable through the index + recall
  rather than being dropped.
- Per-branch observable storage cap raised from 200 to 400 in the vr
  and malware tool executors; the engine agent-key cap raised from 50
  to 150. The `_recall.pinned` list is preserved across eviction
  alongside `_directive.*`.

No schema change: case state already persists in the existing
`case_state_json` column, so this release needs no Alembic migration.

---

## [0.1.0] - 2026-06-27 -- Initial public release

AILA is a modular AI security platform. This first public release
includes the platform core, four production-ready modules, a
React + Vite frontend, and a Docker deployment story.

### Platform

- FastAPI REST API with JWT, OIDC, and API-key authentication;
  per-team scoping enforced through the auth context.
- ARQ + Redis task queue with per-queue workers, the durable
  state machine cursor (`workflow_state_cursor`), and the
  workflow engine that drives every multi-step backend action.
- LLM gateway with per-task-type model routing, request-keyed
  idempotency cache, cost tracking, classification + verification
  + seal pipeline, and budget enforcement.
- `ConfigRegistry` -- typed configuration resolved env -> DB ->
  schema default, with TTL cache and per-namespace validators.
- MCP bridges to audit-mcp (source-code indexing + semantic
  search), ida-headless-mcp (binary decompilation), and
  android-mcp (APK analysis). A shared tool-registry layer
  exposes a uniform tool surface to every module.
- Module discovery -- drop a directory under `src/aila/modules/`
  with `module.py` + `create_module()` and the platform wires it
  at boot. Platform never imports from modules.
- Honesty audit (`python -m aila.tools.honesty_audit`) -- 33
  structural rules that enforce the architectural boundaries
  documented in `docs/GOLDEN_RULES.md` and `docs/HONESTY_AUDIT.md`.
- React + Vite + TypeScript frontend organized as a pnpm
  workspace. Tailwind v4 design system, shadcn/ui primitives,
  module-local extension points via the extension registry.
- Docker image for the API + workers; full-stack
  `docker-compose.full.yml` for development.

### Modules

- `vulnerability` -- CVE scanning, advisory ingestion, remediation
  scoring, inventory drift analysis, peer comparison across hosts.
- `forensics` -- DFIR investigation pipeline. Disk + memory image
  triage, evidence carving, freeflow LLM agent over example
  workflows, machine readiness checks for analyzer tooling.
- `vr` -- vulnerability research agent loop with multi-persona
  branch coordination, claim verification, pattern extraction,
  variant hunt with auto-spawned child investigations, PoC
  drafting, and ReportLab PDF export. Includes the OWASP MASVS
  L1/L2 audit framework and an Android APK + jadx + MobSF pipeline.
- `hello_world` -- reference module showing the minimal contract
  every new module must implement.

### Documentation

- 40+ docs covering architecture, deployment, the module
  standard, the frontend module standard, the config registry,
  the LLM integration layer, task queue ops, SSE, testing,
  the production rubric, and the honesty audit ruleset.
- Tutorial walkthrough for building a new module
  (`docs/MODULE_TUTORIAL.md`) and the contributor guide
  (`docs/CONTRIBUTING.md`).
