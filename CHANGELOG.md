# Changelog

All notable changes to AILA are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

## [0.5.1] - 2026-08-13 -- Wire dead config keys and columns from the liveness triage (#209)

### Fixed

- Seven previously-ignored ConfigRegistry keys and columns now take effect.
  Each was declared or promised but no live path read or wrote it; defaults are
  unchanged, so behavior differs only when an operator sets a non-default value:
  - `platform.heartbeat_interval_s` now drives the SSE/progress Redis XREAD
    block timeout (was a hardcoded 30000ms; the dead `XREAD_BLOCK_MS` constant
    is removed).
  - vulnerability `osv_advisory_cache_ttl_hours` and
    `scoring_review_cache_ttl_hours` now expire their caches (both were
    keep-forever, so stale advisories and stale scoring verdicts were returned
    indefinitely); `ssh_max_workers` now caps inventory SSH concurrency (was an
    unbounded gather over the whole fleet).
  - vr `poc_reliability_target` now drives the PoC reliability gate (was
    hardcoded to 5 runs); `VRFindingRecord.obligations_json` is now persisted
    (obligations were computed and a UI existed, but the advisory state dropped
    them before the insert).
  - malware `cross_target_similarity_threshold` now gates cross-target
    observation propagation.

### Changed

- Recorded a liveness-audit whitelist (`liveness_whitelist.py`) for four
  confirmed false positives (`WorkflowStateCursor.archived_state`, written via
  raw SQL; `KnowledgeEntryRecord.search_vector`, a Postgres generated tsvector;
  and the two `_template` scaffold keys). The liveness residual drops from 27 to
  16; the remaining 16 are documented unbuilt features tracked on #209 for a
  build-or-remove decision (malware playbook auto-trigger and function-ranking
  knobs, the VR CVE feed-state columns, dead-letter replay, and
  `inherit_observations`).

## [0.5.0] - 2026-08-13 -- P3 capabilities: judge harness, per-persona models, semantic memory

### Added

- Judge-reliability harness (`platform/eval/judge_harness.py`, #152): calibration
  metrics (ECE, Brier, Wilson interval) plus label-free position and verbosity
  bias stress tests for the claim verifier, a provenance-checked seed loader, a
  bootstrap seed, and a CLI (`python -m aila.platform.eval.judge_harness`). Makes
  the anti-hallucination guarantee measurable instead of asserted.
- Per-persona model routing (#151): a `persona_voice -> model_role` map
  (ConfigRegistry key `platform.persona_model_role_map`, empty by default) read
  live at turn dispatch so each sibling persona can run a distinct base model,
  turning multi-persona debate into real adversarial diversity. An empty map is
  byte-identical to prior behavior; no model or route names live in code.
- Semantic memory consolidation (`platform/services/memory/consolidator.py`,
  #150): a nightly automation job distills resolved-investigation ledger traces
  into de-contextualized semantic facts, written to the existing knowledge store
  under a per-workspace semantic namespace that the vr and malware knowledge
  retrievers now read, so each investigation's learnings are retrievable by
  later ones. Idempotent with a pre-call dedup probe, reuses the existing
  pgvector table (no migration), and unconfigured it falls back to the default
  model. The procedural/skill-library tier remains a follow-up.

## [0.4.3] - 2026-08-13 -- Docs refresh: schema, reasoning engine, lifecycle, embeddings

### Changed

- Regenerated `docs/DB_SCHEMA.md` from the live SQLModel metadata: 120 tables
  across platform and all modules (the malware module's 17 tables were
  previously absent), with the Alembic head corrected from `081` to
  `121_backfill_investigation_cost`.
- `docs/ARCHITECTURE.md` gains four sections matching the current
  implementation: the reasoning engine and phase graph (a static frozen
  `WorkflowDefinition` with a condition-checked dispatch hub and a
  ledger-based replan/ratify oracle -- not a learning planner), the reasoning
  vs deterministic-pipeline module distinction, prompt lifecycle management
  (evaluate to approve to shadow to canary to promote), and the knowledge
  embedding dimension (1024 BGE-M3; MiniLM fallback zero-padded) (#143, #138).

## [0.4.2] - 2026-08-13 -- Platform/module boundary: domain knowledge to module hooks, vulnerability classified

### Changed

- Vulnerability-research domain vocabulary no longer lives in the platform
  reasoning layer. The defense-check allocator/reader tables, the lateral-
  pattern regexes, and the persona-role map are now per-module hooks
  (agent-subclass class variables) with empty platform defaults; the VR module
  supplies its own vocabulary. A module that supplies none gets a graceful
  no-op, and no FFmpeg/nginx/kernel/persona names remain in platform code (#136).
- The vulnerability module is classified as a deterministic pipeline module via
  a machine-readable `module_kind()` on the module protocol (default
  "reasoning"; vulnerability returns "pipeline"), so cross-module capability
  routing distinguishes it from the reasoning modules (vr, malware, forensics)
  that run the shared CyberReasoningEngine (#138).

## [0.4.1] - 2026-08-13 -- Engine consolidation: narrative base, event dispatch, sweep ordering

### Changed

- NarrativeAgent is now a shared platform base (`platform/agents/narrative_agent.py`);
  the VR and malware agents are thin subclasses that supply only their data
  loaders and task type. Removes ~700 lines of duplicated skeleton and unifies
  the persisted narrative payload on one shape (`tone_used`, `length_used`,
  `narrative_words`) across both modules (#112, #137).
- The two event systems (`EventEmitter` fan-out and `DomainEventBus`) now share
  one dispatch primitive (`platform/events/_dispatch.py`) for per-subscriber
  isolation and failure counting, replacing two copies of the isolation tuple
  that were documented as needing to stay in sync (partial #134; the full
  System-A-to-B migration remains a follow-up).
- Periodic recovery sweeps now run in a declared deterministic order via a
  `SweepPriority` bin on registration, so the cap-exceeded reaper reliably runs
  before no-finding synthesis. Each sweep keeps its own transaction and
  module-generic binding; failures stay isolated per sweep (partial #133; the
  policy-engine merge remains a follow-up).

## [0.4.0] - 2026-08-13 -- Liveness auditor and stable-core knowledge seeding

### Added

- `aila.tools.liveness_audit`: a precision-first static reachability auditor
  that flags wired-but-dead platform capabilities. Two rules encode the dead-path
  shapes found in the peer review: `unread_config_key` (a ConfigRegistry key
  written but never read -- the shape of the #104 gate-threshold bug) and
  `unwritten_column` (a table column with no application writer -- the shape of
  the #135 cost bug). Ships with a `liveness_whitelist.py` for known dynamic
  lookups and runs as a report (`python -m aila.tools.liveness_audit src/aila
  --whitelist liveness_whitelist.py`), not yet a hard gate (#139, #200).
- Stable-core knowledge seeding: a startup seeder loads verified rubric and
  policy entries from `platform/knowledge/stable_core/` into the
  `platform:stable_core:*` namespace and invalidates the cache (#107).

### Fixed

- The RFC-12 stable-core cache-augmented retrieval route had no writer, so every
  agent query about rubrics, policies, and checklists silently returned empty.
  It is now seeded at startup with entries derived from existing platform policy
  artifacts, so the route returns real results (#107).

## [0.3.23] - 2026-08-13 -- Cost materialization: investigation spend writeback

### Fixed

- LLM cost is written to the owning investigation's `cost_actual_usd` and
  `llm_tokens_cost_usd` columns as each call is recorded, in the same
  transaction as the cost record. List views and the per-investigation
  budget cap now read real spend instead of the permanent $0.00 a
  never-written column reported, so the budget cap can fire (#135).

### Added

- Migration 121 backfills `cost_actual_usd` and `llm_tokens_cost_usd` on
  every existing investigation from its recorded LLM spend, so historical
  investigations display real cost immediately after upgrade (#135).

## [0.3.22] - 2026-08-13 -- P1 concurrency hardening and wired-but-dead paths

### Fixed

- Investigation-terminal writers now acquire the investigation row lock
  before branch rows, removing the AB/BA deadlock window between the
  investigation reaper and the lifecycle/finalizer paths (#177).
- `evaluate_quorum` locks the outcome row FOR UPDATE for the full
  read-tally-write, so two branch workers can no longer race the
  draft to approved/rejected transition (#166).
- `close_rejected_outcomes` locks the investigation row and guards on
  RUNNING state; `synthesize_no_finding_outcomes` isolates each
  investigation in a savepoint and uses ON CONFLICT DO NOTHING so a
  single duplicate no longer rolls back the whole batch (#202).
- Calibrator promotion and calibration-proposal supersession lock their
  rows FOR UPDATE, preventing duplicate ACTIVE records (#202).
- Dependent-task promotion, task-status reconciliation, workflow cursor
  recreation, and the fuzz crash-count increment are now lock-guarded or
  atomic, closing lost-update and noisy-retry windows (#203).

### Changed

- The confidence gate honors a promoted calibration threshold:
  `platform.calibration_threshold_{outcome_kind}` (falling back to the
  task_type key) overrides the reject threshold when present, so an
  operator-promoted calibration proposal reaches the live decision (#104).
- Synthesis annotates each panel entry with its claim-verifier status
  (confirmed / refuted / inconclusive / unverified) and surfaces a
  verifier-annotation block in the synthesis prompt, so a refuted claim
  no longer weighs the same as a confirmed one in the consolidated
  verdict (#105).

## [0.3.21] - 2026-08-13 -- P0 security and reliability fixes from the platform peer review

### Security

- Finding-workflow endpoints (`GET /{id}/workflow`, `POST /{id}/transition`,
  `GET /{id}/evidence-chain`) now enforce team isolation. `team_id` is
  stamped on each transition and every read/write is gated to the caller's
  team; cross-team access returns 404 (no existence oracle). Admins see all
  teams (#99).
- Specialist-agent endpoints now enforce team scoping, require operator role
  on create/seed/delete, and carry rate limits. Built-in defaults remain
  platform-global (team_id NULL) and visible to every team (#100).
- User JWT access and refresh token lifetimes corrected from 1 year to
  1 hour and 7 days respectively, matching the documented design (#171).
- The rate-limit bucket key now verifies the JWT signature before trusting
  the identity claim. Forged or tampered tokens fall back to per-IP
  bucketing, closing a brute-force-limit bypass on the auth endpoints (#172).

### Fixed

- The defense-check submit gate no longer crashes with a TypeError on every
  rejection. The directive is written to `case_state.observables` instead of
  an unsupported dict subscript on the Pydantic case state (#97).
- Orphan-task re-enqueue now passes the fully-qualified function name to ARQ
  so the job resolves and resumable workflows resume instead of stalling
  indefinitely (#98).

### Changed

- CI now runs the backend pytest suite against Postgres (pgvector) and Redis
  service containers on every pull request, and the coverage floor is raised
  from 25 to 50 (#164).
- Stale specialist-registry test expectations updated to the current
  built-in names (snake / jak / kratos / lara, alucard / vincent).

### Added

- Alembic migration 120 adds a nullable, indexed `team_id` column to
  `finding_workflow_records` to back the finding-workflow team gate.

## [0.3.20] - 2026-08-09 -- Defense-check submit gate + lateral pattern discovery

### Added

- Defense-check submit gate (#94): a code-level gate in the platform
  submit path that rejects overflow/allocation findings when the branch's
  tool-call history is missing allocator reads, input-range verification,
  or ``callers_of`` reachability traces. Rejection converts the submit to
  a reasoning turn with a directive telling the agent exactly what to
  read. Platform-bound (``platform/agents/submit_gates.py``).
- Lateral pattern discovery (#95 Wave 1): after every ``read_function``
  / ``read_lines`` / ``semantic_search`` result, the auto-steering layer
  scans the returned source code for suspicious patterns outside the
  current hypothesis scope. Hits are auto-posted to the investigation
  ledger as ``lateral_observation`` discoveries with idempotency.
- System prompt updated to document the defense-check gate.

## [0.3.19] - 2026-08-09 -- Zero-turn wall-clock cap maps to STALLED, not COMPLETED

### Fixed

- An investigation that hit the wall-clock cap (6 hours) with zero
  completed turns (provider outage the entire window) was sealed as
  ``COMPLETED`` via the ``cap_exceeded`` path in ``investigation_emit``.
  Zero-turn cap-exceeded now maps to ``STALLED`` so the auto-recovery
  reaper picks it up. Investigations with real turns still complete
  normally on cap-exceeded.

## [0.3.18] - 2026-08-09 -- Branch lifecycle is platform-owned

### Changed

- Moved abandoned-branch purge and live-branch counting from VR's
  ``api_router`` to platform utilities in ``branch_cleanup.py``:
  ``purge_abandoned_branches`` (hard-deletes all abandoned branches for
  an investigation, cleaning FK refs first) and ``count_live_branches``
  (excludes abandoned from the count). Modules call the platform helpers
  instead of reimplementing branch lifecycle logic. The reopen handler,
  branch list endpoint, and summary builders all use the platform layer.

## [0.3.17] - 2026-08-09 -- Stall/reopen cycles no longer stack branches; stalled recovery is immediate

### Fixed

- Every stall/reopen cycle spawned new branches without cleaning up
  abandoned zero-turn branches from prior cycles, so the branch count
  grew with each provider outage (11 branches queued on a 2-persona
  investigation). The persona spawner now hard-deletes zero-turn
  abandoned branches (messages + parent refs cleaned first) instead of
  leaving them as abandoned rows. Active and branches with real turns
  are untouched.
- The stall-recovery reaper required a 15-minute idle threshold before
  picking up stalled investigations. Stalled rows now bypass the idle
  wait entirely and are re-enqueued on the very next reaper tick
  (every 60 seconds).
- Branch counts in both the investigation list and detail endpoints now
  exclude abandoned branches so the UI reflects the actual active panel.

## [0.3.16] - 2026-08-09 -- Stalled investigations auto-recover

### Fixed

- Stalled investigations were excluded from the periodic stall-recovery
  reaper (``sweep_stalled_investigations``). The reaper's SQL filter only
  matched ``status IN ('created', 'running')``, so a provider outage that
  stalled the fleet required manual re-enqueue for every investigation.
  Added ``'stalled'`` to the eligible statuses and a ``stalled->running``
  flip before re-enqueue so the setup handler accepts the row. The reaper
  runs every minute; stalled investigations now auto-recover once the
  provider stabilizes, with no operator intervention.

## [0.3.15] - 2026-08-09 -- poc_development gates on non-recon findings; failed investigations surface a reason

### Fixed

- The ``poc_development`` phase activated on any quorum-confirmed discovery,
  including confirmed recon hypotheses (``source=recon_hypothesis``) that
  carry no exploitable finding. Added ``payload_exclude`` to
  ``make_discovery_condition`` (additive, default None, no behavior change
  for other callers), and wired the VR hub's poc_development to exclude
  recon-hypothesis discoveries. Only agent-emitted confirmed findings now
  activate the phase.

### Added

- Investigation-level ``failure_reason`` on the VR detail summary, derived
  from branch ``closed_reason`` values when the investigation status is
  ``failed``. The finalizer already persisted causes like
  ``zero_turn_no_progress`` and ``auto_closed_infra`` on each branch; this
  surfaces them at the investigation level so operators see why a run failed
  without digging into individual branches. Rendered as a red mono-font
  label below the status indicator on the investigation detail page.

## [0.3.14] - 2026-08-09 -- Claim verifier runs its probes; a no-finding no longer reads as a finding

### Fixed

- The claim verifier refused every source probe when the extractor named a
  tool without the ``audit_mcp.`` namespace prefix (``search_source`` vs
  ``audit_mcp.search_source``). A bare name collapsed to the empty string at
  the allowlist gate and was rejected as "not on verifier allowlist", so the
  verifier gathered no evidence and every verdict returned ``inconclusive``
  at low confidence -- the confirm/refute gate was effectively a no-op.
  Probe tool names are now normalized to the bare allowlist key through a
  single shared helper, so both bare and server-qualified names resolve.
- A strong-confidence negative conclusion ("...found no memory-safety
  vulnerabilities", "No evidence of out-of-bounds writes...") was stamped as
  a strong ``direct_finding`` instead of an ``audit_memo``. The
  negative-conclusion detector matched only the ordering where the security
  noun sits between "no" and the verb; the verb-first ordering ("found no
  X") and the "no evidence of ..." lead slipped through, so an audited-clean
  result surfaced as a confirmed bug. The detector now matches all three
  orderings.
- The canonical outcome row's ``evidence_refs_json`` column was seeded to
  ``"[]"`` on creation and never updated on merge, so every outcome surfaced
  zero structured evidence even when the submission cited source. The column
  is now populated from the union of each panel contribution's evidence and
  the provenance citations (primary_artifact + corroboration), deduped.

## [0.3.13] - 2026-08-08 -- Remove superseded malware investigation workflow versions

### Removed

- Deleted the two dead malware investigation workflow definitions that the
  task layer no longer bound: ``MALWARE_INVESTIGATE_V1`` (single-loop) in
  ``workflow/definitions.py`` and ``MALWARE_INVESTIGATE_V2`` (kind-router
  phase graph) in ``workflow/definitions_v2.py``. Every malware
  investigation runs ``MALWARE_INVESTIGATE_HUB`` (the RFC-13 dispatch-hub
  graph); the two older graphs were wired to nothing. The live phase
  directives, the setup and loop builders, the target-readiness gate, and
  the service factory that the hub imported from those files are now
  defined directly in ``definitions_hub.py``, and both files plus the V2
  test are deleted. This mirrors the VR cleanup in 0.3.11. Behavior is
  unchanged: the hub graph, its four phases, and their activation
  conditions are identical (4 phases, 11 states, byte-identical phase
  specs).
- Removed the ``v0.3.0`` through ``v0.3.11`` release tags from the
  repository; ``v0.3.12`` is retained as the immediately prior release.

## [0.3.12] - 2026-08-08 -- A dispatch-hub stall is never completed

### Fixed

- A within-window dispatch-hub stall (``hub_stalled``) was mapped to
  COMPLETED by ``resolve_final_status``'s default fallthrough, so an
  investigation the hub could not advance -- branches cut mid-audit with
  live, unresolved hypotheses -- was sealed as ``completed`` with zero
  outcomes, hiding open leads behind a blank row. Both ``hub_stalled`` and
  the escalated ``hub_stalled_timeout`` now resolve to ``STALLED``.
  Operator invariant: a stalled investigation is never interpreted as
  completed; its only forward move is resume (re-enqueue). Genuine
  completions (``terminal_submit``, ``max_turns``, clean ``hub_complete``)
  are unaffected.

## [0.3.11] - 2026-08-08 -- Remove superseded VR investigation workflow versions

### Removed

- Deleted the two dead VR investigation workflow definitions that the
  task layer no longer bound: ``VR_INVESTIGATE_V1`` (single-loop) in
  ``workflow/definitions.py`` and ``VR_INVESTIGATE_V2`` (kind-router
  phase graph) in ``workflow/definitions_v2.py``. Every VR investigation
  runs ``VR_INVESTIGATE_HUB`` (the RFC-13 dispatch-hub graph); the two
  older graphs were wired to nothing and only added confusion. The live
  phase directives and the setup/loop builders that the hub imported from
  ``definitions_v2`` are now defined directly in ``definitions_hub.py``,
  and ``definitions_v2.py`` plus its test are deleted. ``VR_NDAY_V1`` (the
  n-day pipeline, still bound) is untouched. Behavior is unchanged: the
  hub graph, its phases, and their conditions are identical.

## [0.3.10] - 2026-08-08 -- Evidence graph surfaces MCP readings and rejection rationale

### Added

- The investigation evidence graph now surfaces the actual evidence, not
  just hypothesis ids. Each MCP tool reading a persona gathered (stored in
  a branch's case-state observables) becomes an ``evidence`` node labeled
  by tool and target, attributed to the observing branch(es) via a
  ``found_by`` edge (so it shows who ran which call). A reading links to a
  hypothesis only when the hypothesis text names the reading's target: a
  ``supports`` edge when a live or resolved claim cites it, a ``refutes``
  edge when a rejected hypothesis's reason cites it. No text match leaves
  the reading as an unlinked evidence node; no relation the reasoning did
  not assert is invented, and every reading is surfaced without a cap.
- Hypothesis nodes now carry their ``claim``, ``why_plausible``, and
  ``rejection_reason`` so the panel shows why a hypothesis was rejected.
- ``GET /vr/investigations/{id}/observable?key=`` returns the full,
  untruncated value of one observable. The evidence graph carries only the
  observable key on each node (no inline preview, so the snapshot stays
  lean); the frontend fetches the complete tool output on evidence-node
  click and renders it in the selection panel.

## [0.3.9] - 2026-08-08 -- Re-enqueue resets the dispatch replan clock

### Fixed

- A re-enqueued investigation re-stalled within seconds instead of
  running. When the dispatch hub cannot activate a phase it raises one
  idempotent ``replan`` ledger request per visited-set and waits for
  ratification; in auto-pilot nothing ratifies it, so the request lives
  in the ledger. ``dispatch_replan_timeout_s`` (default 1800s) ages that
  request, so once it is older than the window every later re-enqueue
  inherited the same hours-old request and the hub emitted
  ``hub_stalled_timeout`` on its first tick, flipping the whole
  investigation to stalled and abandoning every branch, including ones
  that were actively running turns and generating hypotheses. Re-enqueue
  now marks stale unratified replan requests ``status='superseded'`` and
  the hub's stall/timeout helpers skip superseded rows, so a re-enqueued
  investigation gets a fresh replan clock: the branches run, and a hub
  that still cannot advance emits the within-window ``hub_stalled``
  (completed) instead of the terminal ``hub_stalled_timeout``. Superseding
  flips a status column rather than deleting the audit row.

## [0.3.8] - 2026-08-08 -- Stalled investigations get a re-enqueue action

### Fixed

- The investigation detail page rendered no action button for an
  investigation in the stalled state: the toolbar covered running
  (Pause), paused (Resume), created (Start), and completed/failed
  (Re-enqueue / Reopen), so a stalled investigation had no way to be
  restarted from the UI. The Re-enqueue action now also renders for
  stalled, matching the completed/failed path. Re-enqueue resets the
  investigation to created and submits a fresh worker task, which forks
  a new primary branch and resumes the loop. This is the correct restart
  path for an investigation that stalled on a transient provider outage.

## [0.3.7] - 2026-08-08 -- Stalled and Abandoned investigation filter pills

### Added

- The investigations list status-filter row now includes Stalled and
  Abandoned pills alongside All, Running, Completed, Failed, Created, and
  Paused. Investigations that reached a stalled or abandoned state were
  previously reachable only by folding them into the All view with no
  dedicated filter or count, so an investigation that stalled effectively
  disappeared from the filter bar. Both pills show their live count and
  filter the list to that status. The list endpoint already accepted these
  status values; this exposes them in the UI.

## [0.3.6] - 2026-08-08 -- Retry combo-member provider failures instead of stalling

### Fixed

- An investigation stalled the moment a routed provider returned a 4xx
  (e.g. `400: model ... is not supported`, `403`, `410 Gone`,
  `no credentials`). When the model is a weighted routing combo, that 4xx
  means the rolled-to member is unavailable, not that the request is
  malformed, so `_is_retryable` now classifies these as retryable: the
  message carries an upstream-status bracket (`[410]:`) or an availability
  marker (`not supported`, `no credentials`, `credits`, `circuit breaker`,
  `quota`, `banned`, `expired`, ...). The in-call retry then re-rolls the
  combo to a different member, and a turn that still cannot land a live
  member surfaces `retryable=True` so the workflow re-enqueues instead of
  marking the investigation stalled. A genuine request-validation 4xx (bad
  parameter or schema, no bracket/marker) stays non-retryable and still
  fails fast. Net effect: investigations keep retrying across a degraded
  or partially-available provider pool and resume automatically as members
  recover, rather than dying on the first bad roll.

## [0.3.5] - 2026-08-08 -- Reasoning-loop dispatch recovery + output-cap default

### Fixed

- The reasoning loop still burned turns when the model placed a `tool_run`
  dispatch in a sibling field instead of the canonical `command` string.
  The model (Claude in particular) emits the dispatch as a nested
  `tool_run` object or as top-level `tool`+`args` next to `action`, leaving
  `command` empty or as junk such as a lone `{`. `ReasoningTurnDecision`
  dropped those extra fields (default `extra="ignore"`) and its validator
  rejected the empty/junk command, failing the whole turn even though the
  outer decision JSON was complete. The model now sets `extra="allow"` so
  the misplaced fields survive, and `_validate_tool_run_command` recovers a
  canonical `{"tool","args"}` command from a nested `tool_run` object or
  top-level `tool`+`args` before failing. A turn fails only when no
  dispatch is recoverable anywhere. The misleading "max_tokens truncation"
  hint was removed from that validation error: this after-validator runs
  only when the outer JSON already parsed, so truncation is never its
  cause.

### Changed

- `PlatformConfigSchema.llm_default_max_tokens` schema default raised from
  4096 to 32768 so a fresh install matches the reasonable output ceiling
  existing deployments already carry. A reasoning decision under
  extended-thinking needs the larger ceiling; 4096 risked truncating large
  decisions. Per-task overrides via `llm_max_tokens_{task}` are unchanged.

## [0.3.4] - 2026-08-08 -- Reasoning-loop tool_run command coercion

### Fixed

- The vulnerability-research and forensics reasoning loops stalled at the
  first tool-using turn. `ReasoningTurnDecision`'s validator required the
  `tool_run` `command` field to be strict `{"tool","args"}` JSON, but the
  model reliably emits a natural function call
  (`server.tool(k=v, ...)` or `server.tool({json})`) or a bare tool id
  (`server.tool`). The validator rejected these complete emissions as if
  truncated; the three in-call correction retries reproduced the same form
  and the turn hard-failed with `Failed to parse LLM response into
  ReasoningTurnDecision`, leaving an investigation unable to run a single
  tool. The validator and the shared `parse_command` executor now coerce
  these forms into canonical `{"tool","args"}` JSON: `server.tool(k=v)`
  maps args by key with per-value JSON/scalar typing, `server.tool({...})`
  parses the JSON args, and a bare `server.tool` becomes an empty-args call
  so the tool's own contract error teaches the required arguments on the
  next turn. Valid JSON passes through byte-identical; a genuinely
  truncated or non-tool-shaped emission (`{`, `NULL`, prose) still fails so
  the truncation-correction retry fires. No migration; pure
  decision-parsing logic.

## [0.3.3] - 2026-08-07 -- Graph retrieval floor fix (RFC-14)

### Fixed

- The Personalized PageRank graph route in
  `KnowledgeService.retrieve_routed` returned zero hits whenever a nonzero
  relevance floor was supplied. The post-gate re-rank applied the caller's
  `min_score` (a cosine-scale figure) to each hit's stationary PPR mass.
  PPR mass sums to about 1.0 across the reachable subgraph, so a per-hit
  value (about 0.1 for a small graph) always fell below the 0.3 pattern
  relevance floor and every graph hit was dropped.
  `PatternStoreBase.applicable` (inherited by every module pattern store)
  then fell back to the structured stage-1 pool alone, so a linked
  workspace never surfaced its graph-connected patterns and reported the
  survivors as `matched_by="structured"` with a zero score. The floor now
  gates only the hybrid seed stage (its calibrated layer); the PPR-ranked
  hits are no longer re-cut by it. Curated writeups sharing a CVE / CWE
  now surface as `matched_by="both"` carrying their PPR mass, delivering
  the [0.3.2] RFC-14 graph-retrieval contract that the seed-floor gate had
  suppressed. Pure retrieval-path logic change, no migration.

## [0.3.2] - 2026-08-07 -- Platform graph retrieval via Personalized PageRank (RFC-14)

### Added

- Platform knowledge retrieval gains a Personalized PageRank (PPR) graph
  route (RFC-14, #73). The graph route in
  `KnowledgeService.retrieve_routed` ranks by PPR over the
  `knowledge_entry_edges` graph, seeded from the hybrid lookup, so a
  matching entry surfaces its graph-connected neighbors (same CVE family,
  shared component, adjacent chunks) instead of flat top-k. PPR with no
  edges degenerates to the hybrid seed ranking, so a sparse corpus behaves
  as before.
- `KnowledgeService.link_entity_neighbors` writes bidirectional
  `shares_entity` edges between knowledge entries that share an extracted
  security identifier (CVE / CWE / CAPEC / ATT&CK / MASVS) at write time,
  so curated writeups form a navigable per-workspace subgraph the PPR
  route traverses. Derived structurally from the entity extractor with no
  model calls and no relation extraction.

### Changed

- Pattern retrieval (`PatternStoreBase.applicable`, inherited by every
  module pattern store) routes through the PPR graph path. The structured
  stage-1 gate (active status, scope chain, team scope, trust-tier
  partition) remains the authoritative filter; the cosine relevance floor
  is forwarded to the hybrid seed stage but no longer re-applied to
  PPR-scored graph hits.
- Graph propagation is trust-weighted: target-derived (untrusted, burned
  off tool output) nodes receive less PPR mass, extending the RFC-08 (#32)
  and RFC-12 (#49) poisoning defense into the graph layer. The post-rank
  trust overlay is not double-applied on the graph route.
- The PPR graph route is the default with no on/off switch and no
  breadth-first fallback; the prior hop-decay traversal is no longer used
  by the route. Tuning knobs live in `PlatformConfigSchema`
  (`knowledge_graph_ppr_damping`, `knowledge_graph_ppr_max_iter`,
  `knowledge_graph_ppr_max_nodes`, `knowledge_graph_entity_edge_weight`)
  and self-seed on startup. No migration; the edge table already exists.

## [0.3.1] - 2026-08-07 -- Activate dormant RFC features in the wiring; dashboard, evidence graph, cost, and dependency-security work

### Added

- The confidence-calibrator fit path now runs on its own. The trainer and
  proposer sweeps register as automation actions and seed default daily
  schedules at startup, so the RFC-08 Tier D calibrator fits and proposes
  from accept/reject review history without an operator manually creating a
  schedule. Promotion of a fitted candidate to active stays behind the
  existing eval + quorum gate.
- The agent-config bundle roster, when populated, drives the persona panel
  composition; an empty roster (the shipped default) keeps the baseline
  panel, so behavior is unchanged until a bundle carries a roster (RFC-09).
- The cross-module dashboard now reflects the vr and malware investigation
  engines (#70). Both modules implement the system-summary, report-count,
  and health-check hooks: the dashboard totals and the system detail page
  carry investigation counts by status plus recent outcomes (kept distinct
  from the vulnerability module's finding counts, which vr and malware do
  not own), and `GET /health` probes each module's MCP server dependencies
  through the platform transport.

### Changed

- Knowledge retrieval post-rank is unconditional and active by default:
  target-derived (untrusted, tool-burned) memory is down-weighted (0.5) and
  every hit carrying a provenance timestamp decays on a 90-day half-life, so
  quorum-verified entries win ties over untrusted memory (RFC-12 ASI06).
  Identity values remain a no-op. New deployments get these defaults;
  existing deployments keep their configured values until updated through
  the config surface.
- Canary promotion enforces a minimum observed-signal count (default 5)
  unconditionally, so a candidate that never saw canary traffic cannot be
  promoted (RFC-10). New deployments get the default; existing deployments
  keep their configured value.
- Multi-persona deliberation always runs. The auto-deliberation environment
  toggle and its single-branch fallback are removed, so every investigation
  spawns the full persona panel (RFC-03).
- The capability-router scope derives from the executor's module id, so
  catalog-aware routing applies to every module executor rather than only
  those that overrode the hook (RFC-07 / RFC-11). The MCP instance health
  probe now filters to approved catalog rows, matching the live dispatch
  resolve path.
- Every investigation branch carries a strategy_family, inherited from the
  parent branch or the investigation at spawn time; existing branch rows are
  backfilled from their investigation (migration 119), so strategy-family
  branch grouping reflects the real strategy again instead of collapsing
  into one bucket (RFC-13 / RFC-03).
- cryptography pinned to 50.0.0 and the frontend workspace dependency
  overrides raised (axios, hono, @hono/node-server, dompurify, react-router,
  fast-uri, brace-expansion, ip-address, postcss, body-parser) for
  dependency-security currency.

### Fixed

- The vr investigation evidence graph now surfaces the investigation's
  actual reasoning: hypothesis nodes aggregated across branches (with a
  live / rejected / resolved / mixed state) and finding nodes wired to the
  outcome that produced them, alongside the existing branch and outcome
  nodes. Previously the section drew only investigation, branch, and
  outcome nodes, so a mid-flight investigation with live branches and no
  terminal outcomes showed almost nothing (#17).
- The vr timeline labels a source read (audit-mcp `read_function` /
  `read_lines`) as "Read" instead of "Decompiled"; only an ida-headless
  decompile renders as "Decompiled". The prior label guessed from a
  file-extension allowlist and mislabeled Kotlin, XML, smali, and
  extensionless source reads (#20).
- LLM pricing keys are settable through the config schema (per-model
  prompt and completion price families), and a model that resolves to no
  configured price logs a warning instead of silently costing zero,
  closing the last two open findings on cost correctness (#38).
- Human-cost estimation stores the full aggregate on the earliest cost
  record and clears the rest, so a re-estimate over a changed record set
  stays coherent and a late-arriving record no longer skews the per-record
  split (#38).

### Removed

- The `llm_calibrator_enabled` config flag. The post-hoc confidence
  calibrator applies whenever an active calibrator exists for the task type
  and passes the raw score through when none is fitted; the flag's
  raw-passthrough escape is gone (RFC-08).
- The legacy `payload_json.auto_steering_key` duplicate on auto-steering
  messages. The indexed column is the sole source and every dedup reader
  already uses it (RFC-09).

## [0.3.0] - 2026-08-05 -- Investigation-engine extraction program plus security, correctness, and reliability hardening

The vulnerability-research and malware investigation engines are unified
onto a shared platform: one turn runner, one tool executor, one set of
support services and data-model bases, one agent primitive per concern.
Modules now bind their record types, prompts, and gates to platform bases
instead of carrying parallel copies. Also adds prompt versioning and
deployment, an eval-gated agent lifecycle, a DB-backed MCP catalog, and
per-vector knowledge provenance. Read the Changed section: the agent
config env-var names and the promotion contract changed and may require
operator action.

A broad hardening pass across authentication and tenant isolation,
secret handling, LLM cost and resilience, audit integrity, and
per-module correctness, plus a migration of the test suite onto
PostgreSQL. Read the Changed section first: the CORS and OIDC
credential defaults changed and may require caller action.

### Added

- One generic MCP client and bridge tool that serves every MCP server
  (RFC-11 #35). Per-server behavior now lives in pluggable middleware over
  a single transport rather than in a bespoke bridge class per server. The
  operator-editable server catalog is the routing authority: adding,
  disabling, or retargeting a server takes effect on the next dispatch
  with no worker restart, and two instances that advertise one capability
  share load by round-robin with automatic failover and health-driven
  drop of an unreachable instance. Tool availability resolves by a
  module's declared capability instead of a hardcoded server name, and the
  live tool list is the dispatch authority, so a tool present on a server
  but absent from the static inventory is still dispatchable. A server
  with no bespoke middleware falls back to a pass-through client, so a
  newly registered server advertising a bound capability dispatches
  without a code change.
- A zero-trust gate on the MCP server catalog (RFC-11 #35). A newly
  registered server is unapproved and cannot serve a live call until an
  operator approves it; approval pins a hash of the server's tool schema,
  and a later schema change is reported as drift. Free-text tool and
  parameter descriptions from a server are sanitized before they enter an
  agent prompt, closing a tool-description injection path. Catalog rows
  carry team ownership and record every approval and revocation with
  actor and reason, and only approved rows resolve on the live dispatch
  path. Existing operator-seeded rows are grandfathered to approved by the
  accompanying migration so live dispatch is unchanged.
- Four RFC-11 honesty guardrails (#35). Build-time findings now fire on
  reintroducing a bespoke per-server HTTP transport, a static
  server-to-bridge map, a hardcoded server-dispatch lookup, or a
  tool-description projection into a prompt without sanitization.
- An agent development lifecycle for prompt and agent-config change
  (RFC-10 #34). Agent behavior now has its own governed release path,
  separate from and faster than the code release: a candidate bundle is
  evaluated against a frozen benchmark, shadowed off the critical path,
  canaried to a cohort of new investigations, monitored, then promoted by
  an alias flip or rolled back by one. Every stage transition is journaled
  with actor, a metrics snapshot, and a reason. A candidate cannot reach
  production without both passing the eval gate and a distinct-approver
  quorum, and per-version metrics (eval verdict, cost, quorum accept rate,
  drift) are observable through an admin endpoint.
- A shadow runner for the lifecycle (RFC-10 #34). An operator can replay a
  sample of recorded investigation turns against a candidate bundle off
  the critical path (reusing the record-replay path), producing a shadow
  report that scores mean faithfulness, mean determinism, and a regression
  count per candidate, so a canary decision rests on data rather than
  faith. The runner reads recorded state only and has no effect on any
  running investigation; a turn whose transcript cannot be reconstructed
  is skipped and counted, never aborting the run.
- An operator-facing alert on a canary hold (RFC-10 #34). When a canary
  bundle version breaches the drift or cost ceiling, the assignment is
  held and, in addition to the journaled transition, a first-class
  resilience signal is raised on the operator dashboard (and a durable
  recovery entry is written when an investigation context is present),
  so a hold surfaces to the operator rather than only to a worker log.
- A fourth RFC-10 honesty guardrail, `adlc_structural_change` (#34). A
  structural change (a new node kind, a graph edge, or a tool
  registration) entering through the lifecycle control plane is now a
  build-time finding, enforcing the boundary that the lifecycle tunes
  prompts, config, and routing only, while structural changes go through
  the code lifecycle.
- Prompt registry with per-investigation pinning and alias deployment
  (RFC-09 #33). Prompts are now immutable, content-hashed, versioned
  entries resolved at runtime through the platform registry and addressed
  by candidate / staging / production aliases. A prompt change ships by
  flipping an alias, with no code release and no worker restart, and every
  flip is an audited event; rollback is a single flip. Each investigation
  pins the version it resolved at first use, so a live alias flip changes
  only new investigations and never rewrites a prompt on a running one.
  Model-family variants resolve by the routed model. The inline system
  prompts and templates across the claim verifier, the vr and malware
  narrative and synthesis agents, the n-day researcher, the apk-static and
  masvs seeders, and the report writers now resolve from versioned files
  through the registry rather than from inline literals; the shared claim
  verifier prompt is a single platform entry used by both modules.
- Forensics prompts on the versioned prompt path (RFC-09 #33). The
  forensics investigator resolves its free-flow prompt through the version
  store with per-investigation pinning, and its LLM calls now record a
  prompt version like the vulnerability and malware modules. Adds a
  prompt-pin column to the forensics investigation row.
- The agent-config bundle as the versioned unit (RFC-09 Amendment 2 #33).
  A registered version now carries the prompt body plus an optional
  persona roster, model routing, and exemplar set, and the content hash
  covers all four, so a routing or roster or exemplar change is a
  versioned event with its own immutable identity, not an out-of-band
  edit. A pinned bundle's exemplars fold into the resolved prompt body and
  a pinned bundle's model routing overrides model selection for that
  investigation; both are pinned per investigation. A prompt-only bundle
  (empty roster, routing, and exemplars) resolves byte-identically to the
  prior behavior. The existing prompt-version and content-hash columns on
  the cost and seal records identify the bundle end to end.
- A fourth RFC-09 honesty guardrail, `unpinned_investigation_prompt`
  (#33). Agent-runtime code that resolves a prompt by live alias instead
  of the per-investigation pin (bypassing the canonical pinned-resolve
  path) is now a build-time finding, so the pin-per-investigation
  guarantee is enforced structurally rather than by discipline alone.
- Eval-gated experience, calibration, and learned routing (RFC-08 #32).
  Reviewed investigation outcomes now feed a bounded self-improvement
  loop that proposes parameter changes and gates them, never rewriting
  its own structure. An offline eval harness scores a candidate config
  against a frozen benchmark of verified findings and verified non-bugs
  and reports per-case diffs; a per-outcome_kind calibration proposal is
  generated from accept/reject history and is versioned and reversible;
  a routing recommendation feeds pre-execution sibling sizing; and
  accepted or rejected outcomes write signed patterns into the platform
  pattern store. No pattern, threshold, or routing change reaches
  production without both beating the eval and passing the review quorum.
- A record-replay path for the eval harness (RFC-08 #32). A recorded
  investigation turn can be replayed against a candidate config with the
  clock, retrieval results, and tool outputs frozen from the recording,
  so only the config varies. The replay reports a decision diff plus a
  determinism score (identical re-runs must match) and a faithfulness
  score (the reconstruction reproduces the recorded decision). Previously
  the harness scored only pre-supplied case bundles and could not replay
  a real turn.
- A post-hoc confidence calibrator for the LLM gate (RFC-08 #32). A
  monotone recalibration model (isotonic or temperature scaling) is fit
  on accept/reject history, scored by expected calibration error, and
  persisted as a versioned candidate. Promoting a calibrator to active
  requires a strict ECE improvement over the current active version and a
  distinct-approver quorum. New admin routes train a calibrator, list
  versions, promote a calibrator, and promote a calibration threshold
  into live config, each behind the eval-plus-quorum gate.
- Per-pattern trust tiering and provenance in the pattern store
  (RFC-08 #32). Every stored pattern now carries a trust tier (verified,
  unreviewed, or negative) and a provenance record naming what produced
  it. Review-signed patterns are verified; per-turn auto-extracted
  patterns are unreviewed proposals; rejected-outcome patterns are
  negative. At retrieval a negative pattern is never returned as
  standalone guidance and instead lowers the score of an overlapping
  positive (a prior, never a hard block); unreviewed patterns retrieve at
  a reduced weight. Previously all patterns retrieved at equal weight
  with no provenance.
- A fourth self-improvement honesty guardrail (RFC-08 #32,
  `structural_self_modification`). The self-improvement layer may propose
  parameter changes only; a proposer that constructs or mutates graph
  structure (a new node, edge, dispatch router, or persona roster) is now
  a build-time finding. The three prior guardrails (ungated pattern
  write, self-labeled reward, unversioned threshold promotion) were also
  tightened: the ungated-write rule now recognizes the `_store` receiver
  shape and exempts only the sanctioned draft proposers.
- An automated investigation-level stuck-investigation healer (RFC-07 #31).
  A periodic platform sweep detects an investigation stuck at RUNNING with
  no live task and no resumable cursor, and re-enqueues it through the
  lifecycle service instead of leaving it running with no worker forever.
  Registered for the vulnerability, malware, and forensics modules; the
  idle grace and per-tick heal cap are config-tunable. Previously only
  task-level zombies were healed automatically; an investigation whose
  tasks all died with no resumable cursor required an operator to
  re-enqueue it by hand.
- Durable, auditable recovery events (RFC-07 #31). Every heal (state
  reconcile, orphan-task re-enqueue, investigation re-enqueue, stuck-heal)
  now writes a durable recovery entry to the shared investigation ledger
  through the resilience layer, so a repair is a record the run keeps, not
  only a log line. The recovery entries are filtered out of the agent
  prompt board. Honesty rule 54 (heal_without_journal) was narrowed so the
  heal orchestrators must journal rather than being blanket-exempt.
- A dispatch-hub stall escalation and a STALLED terminal investigation
  status (RFC-13 #68). When the adaptive investigation hub raises a replan
  request that stays unratified past a configured wall-clock window
  (`platform.dispatch_replan_timeout_s`, default 1800s), the hub posts an
  operator-steering escalation naming the blocked phases and flips the
  investigation to the new STALLED status. Previously the hub emitted the
  stall as a completed run, so a wedged panel looked successful. A
  within-window unratified stall and a ratified replan keep their prior
  behavior; a value of 0 or less disables the escalation. The frontend
  investigation lists and detail views render STALLED as a distinct
  terminal state.
- Malware dispatch-hub deep phases activate on real discoveries (RFC-13
  #68). A deterministic bridge in the malware tool executor posts and
  auto-confirms a `finding: packed` ledger discovery when an ida-headless
  result shows packing (UPX-style section names, a high-entropy section, or
  an obfuscation verdict), so the confirmed-trust unpack phase activates on
  the real analysis rather than on the panel choosing to post it. A
  detector-derived discovery is operator code reading the binary's own
  sections, not an unreviewed model claim, so it confirms without a quorum
  vote. The malware agent prompt also guides the panel to post ledger
  discoveries and raise or approve phase-activation requests. Previously the
  packing finding stayed a private branch hypothesis and never reached the
  ledger, so the two confirmed-trust phases could not activate and only
  triage plus the fallback full-analysis phase ran.
- Generic platform workflow and entity events (RFC-05 #30). The platform now
  owns ModuleWorkflowStarted, ModuleWorkflowCompleted, and
  ModuleEntityBatchUpserted; a module emits them with its own module id,
  workflow id, and free-form payload. The vulnerability scan, the forensics
  investigation, and the module template publish these at workflow start and
  completion, and every published event lands in the platform journal.
- A platform-owned task-queue query (RFC-05 #30). A module reconciler now asks
  TaskQueue which investigations already have a queued task instead of querying
  the task table directly, so a module never reads a platform-owned table.
- Honesty rule 72 (`platform_hardcodes_strategy_family`) blocks a platform file
  from naming a module reasoning-strategy family as a string literal; families
  are declared by each module and resolved through the registry (RFC-05 #30).
- The module config base is now complete (RFC-04 #29). ModuleConfigBase
  carries an llm_model field defaulting to the platform default model, and
  ModuleConfigReader gains get_typed and get_bool alongside the existing typed
  getters. Module config schemas inherit the llm_model field instead of each
  redeclaring it.
- The module template now ships the full investigation support layer and a
  frontend (RFC-04 #29). `_template/services/` constructs every platform
  support primitive (pattern store, stage tracker, branch reaper and cleanup,
  multi-target, machine readiness, cap reaper, finalizer, stall recovery, MCP
  registry and call logger) as thin bindings, and `_template/frontend/` wraps
  the shared message-stream hook, so a copied module inherits the support layer
  by construction.
- Honesty-audit guardrails against support-layer re-duplication (RFC-04 #29):
  a rule flagging an MCP server catalog hardcoded inside the platform layer, a
  rule flagging os.environ / os.getenv reads inside module services, and a
  frontend audit rule flagging a module message-stream hook that does not wrap
  the shared platform hook.
- The module template now scaffolds a full investigation on the shared agent
  runtime (RFC-03 #28). `_template/agents/` subclasses every platform agent
  primitive (turn runner, tool executor, claim verifier, pattern extractor,
  synthesis runner, outcome dispatcher, branch pool, persona router) as
  minimal bindings, the workflow loop and emit states bind those primitives,
  and the module declares its residue config keys. A module copied from the
  template inherits the correct per-turn engine by construction; a copier
  supplies its own prompts, outcome kinds, tool bridges, and record
  projections.
- The module template now scaffolds the investigation lifecycle against the
  platform primitives (RFC-02 #27). A new module inherits pause / resume /
  re-enqueue / cost handlers that dispatch straight to the platform lifecycle
  and cost services, plus workflow setup / loop / emit states that bind the
  platform state factories, so the correct four-source-of-truth behavior is
  present by construction rather than copied from an existing module.
- A structural-similarity guardrail (honesty rule 69,
  `lifecycle_binding_copy_of_platform`) flags a module
  `workflow/pause_resume.py` that re-copies the platform atomic lifecycle body
  instead of binding the shared service. (RFC-02 #27)
- The planner oracle now adjudicates open `request_specialist` entries when
  no distinct sibling branch has cast the ratifying vote
  (`Oracle.adjudicate_specialist_requests`). Previously a specialist request
  was ratified only by a distinct approver, so on a small panel (one filer
  plus a single sibling that never votes) or an early pause the request stayed
  open and the specialist never spawned. When the
  `oracle_specialist_adjudication` toggle is on (default 1), the oracle asks
  the model whether each open request is warranted given the investigation's
  gathered evidence and records its own distinct-approver decision, so a
  warranted request reaches quorum and spawns on the same cycle while a
  rejected one is marked and never re-judged. The adjudicator prompt is a
  versioned file resolved through PromptRegistry. Set the toggle to 0 to
  require a sibling vote (the prior behavior). (RFC-13 #68)
- Contextual chunk enrichment (RFC-12 Phase 3) is now reachable through the
  canonical `ServiceFactory.knowledge`, which wires the platform LLM client
  into the `KnowledgeService` it builds. Previously the factory produced a
  service with no LLM client, so `store(..., chunked=True, enrich=True)` was a
  silent no-op for every factory-built caller. Enrichment stays opt-in per
  call and default-off, so the client is exercised only when a caller
  explicitly requests it; pure-retrieval code that builds `KnowledgeService()`
  directly is unaffected. (RFC-12 #49)
- A new honesty-audit guardrail, `content_slice_truncation` (rule 68), flags a
  constant-bound slice (`x[:N]`) applied to content stored into or returned
  from the knowledge base: the direct value of a `content=`-family keyword
  argument, or a dict value keyed by `content` / `query` / `body` / `text` /
  `sanitized_content` / `root_cause`. Stored and retrieved knowledge data must
  be kept in full; only the render layer bounds size. It is a
  flag-then-whitelist rule, so a genuinely required cap is recorded in
  `honesty_whitelist.py` with a reason. Two existing audit-log query caps that
  bound an audit-record detail field (not knowledge data) are whitelisted.
  (RFC-12 #49)
- The retrieved-knowledge prompt tier now refreshes on the branch's live
  focus (RFC-12 Phase 1). Prior knowledge was retrieved once at investigation
  setup, keyed on the opening question, and never updated, so a long
  investigation that pivoted onto a different question kept seeing recall for
  the original one. Each turn now re-queries the knowledge base on the
  branch's current hypotheses when that focus changes from the last
  retrieval, so recalled prior findings track what the branch is
  investigating now. The refresh is bounded to real pivots (an unchanged
  focus does not re-query), scoped to the workspace, journaled like the setup
  retrieval, and best-effort so a retrieval fault never breaks the turn.
  (RFC-12 #49)
- An ingest-time classification gate for the knowledge base (RFC-12 Phase 5,
  ASI06 governance). Every knowledge write now classifies its content and
  records the classification tier plus an injection flag in the entry
  metadata, so trust tiering and the retrieval relevance floor can act on an
  untrusted or poisoned write, and a restricted write is logged for audit.
  The gate is metadata-only: the raw content is stored in full and the
  existing retrieval-time sanitize and classify gate is unchanged, so no
  stored data is altered. Chunked writes route through the same path and are
  gated per chunk. This closes the ingest side of the RFC-12 acceptance
  criterion that content pass the sanitize and classify gate at both ingest
  and retrieval. (RFC-12 #49)
- Trust-weight and temporal-decay ranking controls for knowledge retrieval
  (RFC-12 Phase 5). Two config knobs, `knowledge_target_derived_weight` and
  `knowledge_decay_half_life_hours`, let an operator down-weight untrusted
  target-derived memory (burned off tool output) so quorum-gated verified
  entries win ties, and favor fresh memory by scaling each hit's score by an
  exponential half-life. Both apply after the relevance gate, so the hot
  scoring path is untouched, and both default to a no-op, so retrieval ranking
  is unchanged until an operator opts in and validates the change against
  `aila eval-retrieval`. A hit pushed below the relevance floor by either
  control is dropped, and the pre-adjustment score is preserved for audit.
  (RFC-12 #49)
- The knowledge retrieval eval is now runnable end to end (RFC-12 Phase 6).
  A new `aila eval-retrieval` command builds a recall benchmark from stored
  findings (query = the originating investigation's question, relevant = the
  finding's knowledge entry), replays it through the live routed-retrieval
  path, and reports recall, precision, and MRR at k with a pass/fail verdict
  against the prior baseline. This turns the record-replay harness from library
  code into a live gate, so a later retrieval change (ingestion or ranking) is
  measured before it ships. (RFC-12 #49)
- A knowledge-base backfill command (RFC-12 Phase 6). The store started empty
  because writes were failing (#37), so findings recorded before the fix never
  reached the vector database. The new `aila backfill-knowledge` command (with
  a `--dry-run` report) re-embeds each stored finding into its workspace-scoped
  finding namespace through the canonical embedding and knowledge services,
  including negative results that spare a later investigation from repeating a
  dead end. The write is idempotent (upsert on namespace plus dedup key) and
  stamps the embedding model id, so a re-run updates in place and a future
  embedding-model swap re-embeds rather than duplicating. (RFC-12 #49)
- A retrieval journal for the knowledge base (RFC-12 Phase 5, ASI06
  governance). When an investigation retrieves prior knowledge, at setup and
  on demand through the agent retrieve tool, the platform appends an audit
  record to the append-only journal naming the query, the route, and each
  hit's entry id, namespace, relevance score, trust tier, and
  classification. Trust tier is derived from the namespace: observations
  burned straight off tool output are the lower target-derived tier, while
  quorum- or promotion-gated findings, audit memos, and patterns are the
  verified tier. An operator can now audit which prior knowledge, at what
  trust level, informed a finding. The journal write is best-effort and
  never blocks retrieval; scope and investigation context are injected
  server-side, so the agent cannot forge or widen them. (RFC-12 #49)
- Agentic knowledge retrieval (RFC-12 agentic path). The vulnerability-
  research and malware agents can now call a read-only knowledge.retrieve
  tool mid-turn to pull prior workspace knowledge on demand, alongside
  their code-index tools. The tool routes through the gated retrieve_routed
  path (relevance-floored + sanitize/classify), exposes no write action,
  and its search scope is injected server-side from the investigation's
  workspace, so an agent (or a prompt-injected instruction) cannot widen
  retrieval beyond its own workspace. Delivered as an in-process bridge
  registered on the agent tool surface next to the code-index bridges.
  (RFC-12 #49, RFC-11 #35, #43)
- Four RFC-12 knowledge-base honesty guardrails in the CI audit:
  second_embedding_path (an embedding provider built outside the canonical
  embedding + knowledge services), vector_without_provenance (a
  KnowledgeEntryRecord stored with an embedding but no model_id),
  retrieval_without_gate (agent-runtime code using the raw retrieve instead
  of the relevance-floored, sanitize/classify gated retrieve_routed), and
  unsanitized_retrieved_content (a retrieve_routed body that stops applying
  the gate). Each self-exempts or scopes to the surface it locks in, so the
  one embedding path, per-vector provenance, and gated agent retrieval stay
  enforced. (RFC-12 #49, #37, #43)
- The knowledge base read loop. An investigation now retrieves prior
  knowledge (audit memos, findings, strategy notes from earlier
  investigations on the same workspace's similar targets) at setup and
  renders it as a RETRIEVED prompt tier, so the knowledge the platform
  writes is finally read back into a reasoning turn. Retrieval is
  workspace-scoped and runs through the adaptive routed path, so every
  hit is relevance-floored and passes the sanitize/classify gate; the
  tier degrades to a budget summary and drops first under context
  pressure since it is augmentation, not a precondition. Wired for the
  vulnerability-research and malware modules through a per-module setup
  resolver; forensics leaves the hook unset. (RFC-12 #49, RFC-24 #24)
- Malware evidence now reaches the knowledge base. Dispatching a durable
  malware outcome (a YARA rule, a config-extractor script, a family
  verdict, or an analysis report) now stores its content in the vector
  database under a workspace-scoped malware finding namespace, in addition
  to the module table it already wrote, so a later investigation on the
  same target can retrieve it by query. The malware pattern proposer now
  routes every proposed pattern through the shared pattern store, so each
  pattern pair-writes a queryable row and a semantically retrievable
  knowledge mirror instead of a table row alone. The writes are
  best-effort and never fail the dispatch. (RFC-12 #49)
- Forensics joins the cross-investigation knowledge loop. A new forensics
  pattern catalog (the forensics_patterns table) stores reusable
  techniques with a knowledge-base mirror, using the project as the
  workspace scope. On a terminal panel verdict the module now writes a
  signed pattern through the shared experience writer (positive on
  approve, negative on reject), and at panel setup it retrieves applicable
  prior patterns plus a scope snapshot and surfaces them into the
  investigation, matching the vulnerability-research and malware modules.
  The write and the retrieval are best-effort and never break the panel.
  (RFC-12 #49)
- Evicted working-memory observations now persist to the knowledge base.
  An investigation keeps a bounded live store of observations; when it
  passes its cap and drops the oldest, each dropped observation is now
  written to the vector database under a workspace-scoped observation
  namespace, stamped with the investigation, branch, turn, and observation
  key that produced it. On a long investigation this keeps the middle of
  the run semantically retrievable through the setup read loop and the
  agent retrieve tool, instead of recoverable only by exact-key recall or
  by re-running the tool. The write is best-effort and never fails the
  tool result it follows. Wired for the vulnerability-research and malware
  modules through a base tool-executor hook the modules override. (RFC-12
  #49)
- Confirmed vulnerability findings now reach the knowledge base. When a
  direct-finding outcome is dispatched, its root-cause text is stored in
  the vector database under a workspace-scoped finding namespace, carrying
  the finding id, target signature, vulnerable function, crash type, and
  evidence refs as metadata, in addition to the findings-table row it
  already wrote. The agent's primary output was previously written only to
  the findings table, so a later investigation on the same target could
  not retrieve it through knowledge retrieval; it now surfaces in both the
  setup read loop and the agent retrieve tool, retrievable by semantic
  query and selectable by metadata. The write is best-effort and never
  fails the dispatch. (RFC-12 #49)
- Startup seeding of file-backed agent prompts into the version store. On
  boot each module registers its prompt bodies and points the production
  alias at them only when a key has none yet, so the pin-per-investigation
  and canary-routing paths resolve against the store by default while an
  operator-promoted or canary-routed version survives a restart untouched.
  (RFC-09, RFC-10)
- Capability-scoped MCP client pooling. Resolving a capability composes the
  matched server descriptors into a tuple of clients, each built with the
  same resolver and dependency wiring as a single-server open, and returns
  an empty tuple when nothing matches. (RFC-11)
- A target-enrichment orchestrator that runs capability-profile build and
  function ranking in sequence as one queued task, replacing the earlier
  pair of parallel downstream tasks. The direct rank endpoint and the
  standalone stage tasks stay available.
- Dispatch handlers for four investigation outcome kinds that were routed
  but inert. Strategy descriptors, crash-triage reports, and config-delta
  proposals are recorded to the knowledge store; a sub-investigation
  outcome spawns a child investigation guarded by a depth ceiling and a
  per-parent child cap. The assessment-report kind stays terminal.
- A `restore-db` CLI command that restores the database from a pg_dump
  custom-format backup (`pg_restore --clean --if-exists`), the companion to
  the existing `backup-db`.
- Retention sweeps for on-disk report artifacts and workflow transition-log
  rows, wired into the reaper cron alongside the idempotency-cache and drift
  purges, so neither surface grows without bound. (#46)
- A process-wide domain event bus with typed events and a durable
  journal. System registration and deregistration publish typed domain
  events through the bus; a default subscriber persists them to the
  platform journal, and a replay service re-derives state from the
  journal. (#39, #52)
- A global server-sent-events ceiling. A new event stream is refused with
  a clear status when the process-wide active-stream count is at or above
  the configured cap, so a runaway client cannot exhaust the connection
  budget. (#60)
- An admin state-reconciliation endpoint. `POST /admin/reconcile` heals a
  single task's TaskRecord, workflow cursor, and queue lock in one
  operation. (RFC-07)
- Tool-storage and working-memory pruning. A pruner reclaims expired
  tool-storage rows, and expired working-memory rows are removed on a
  schedule. (#46, #56)
- A canonical agent-configuration directory (`.agents/`) with a setup
  script that links shared agent config. Repo-authored shared content is
  tracked while bulk external skill installs stay out of version control.
  (#5, #41)
- Team scoping on forensics child records. Investigation runs, agent
  steps, write-ups, and answer candidates carry a team id, backfilled
  from the parent project by a migration. (#59)
- Honesty-audit self-improvement guardrail rules that flag ungated
  promotion writes, self-labeled rewards, unversioned config promotion,
  inline prompt literals, untagged model calls, and canary flips below a
  minimum sample count. (#32, #33, #34)
- Reasoning synthesis records an explicit audit scope. Each consolidated
  panel verdict now opens with what was examined -- the control or check
  under audit, the code surface inspected, and the evidence base -- so a
  reader knows the coverage before the verdict instead of only seeing a
  one-line conclusion. The scope is carried on the synthesis output and
  promoted onto the investigation panel summary for both the
  vulnerability-research and malware synthesisers.
- An apk_static audit aggregate surface: `GET
  /vr/targets/{id}/apk-static-audit-aggregate` returns per-check verdicts
  grouped by apk_static group, mirroring the MASVS aggregate. Each verdict
  row carries the child synthesis scope, headline, and key points, plus
  the evidence locations, so the aggregate is self-describing per check
  rather than a bare pass/fail list.
- An APK static-analysis audit: a catalog of concrete, statically-
  answerable checks plus a dispatcher that fans one investigation per
  check against an android_apk target. The endpoint
  `POST /vr/targets/{id}/apk-static-audit` creates one parent
  investigation plus one child per static check, each child running the
  standard scout / critic / verifier chain
  against a single check (manifest posture, signing, dangerous
  permissions, hardcoded secrets, cryptography, network and TLS config,
  WebView, data storage, IPC, injection sinks, deserialization, dynamic
  code loading, resilience presence, privacy identifiers, dependency CVE
  exposure, high-yield exploit chains such as intent redirection and
  deep-link-to-WebView, local biometric authentication, native-library
  hardening / JNI surface / vulnerable-version fingerprint, and a
  bundled-component inventory (SBOM)). The catalog ships 87 checks: 86
  static checks are dispatched, and one Flutter Dart-AOT check is
  catalogued for a later android_mcp extraction stage. This complements
  the MASVS audit with sharp, evidence-backed checks that each carry a
  definite source location, rather than broad compliance controls; every
  check maps to CWE and OWASP MASVS v2.1.0 ids. The dispatcher is
  idempotent on the target plus catalog version and throttles enqueue
  through the same batch reconciler that governs the MASVS audit, so a
  large fan-out does not overwhelm the model proxy. A dispatch control on
  the target detail page surfaces the audit for android_apk targets whose
  ingestion has reached the static-summary stage.
- Terminal-convergence gates stop an investigation panel from closing
  prematurely or thrashing. A no-finding or inconclusive submission is
  blocked while a sibling branch still holds a live hypothesis no branch
  has rejected, so the scope is not declared clean while a peer holds a
  live lead. A hypothesis left open past a configurable turn threshold
  raises a directive naming it and requiring the agent to resolve,
  reject, or explicitly defer it that turn. A new not_ready review vote
  lets a reviewer decline to ship a sibling's draft with a stated
  blocker, recording the reason without a stalling abstain or a
  premature approve/reject; a panel where every recorded response is
  not_ready stays open pending evidence instead of falling silent. The
  staleness threshold and the sibling-gate force-through cap are
  config-tunable, and the audit prompt documents the recall protocol
  that backs lossless working-set trims.
- Reasoning-agent recall is now lossless: when an agent recalls a tool
  finding whose body was evicted from the live working set, the body is
  retrieved from durable message history instead of being gone for good.
  Tool-result bodies are persisted keyed by their observable id, so an
  eviction only trims the live prompt window and never loses
  information. The working-set size limits (agent-key, observable, and
  recall-pin caps) move to the platform config namespace with their
  previous values as defaults, so they are tunable rather than hardcoded.
- At an investigation's final verdict, a no-finding or inconclusive
  result whose panel recommended further discoveries now automatically
  spawns one follow-up discovery investigation that takes over those
  recommendations as its mandate, instead of dead-ending. The take-over
  is a platform primitive any module can bind (wired for vulnerability
  research); it is depth-capped, budget-halved with a floor, and
  idempotent, so it self-terminates and a small-budget run never
  spawns.
- The vulnerability-research module generates a long-form narrative
  writeup for an investigation, mirroring the malware module: a
  chronological story (persona panel, hypotheses, the tool-driven audit,
  disagreements, and the final finding / patch-present / no-finding
  verdict) generated on demand in one of five voices and three lengths,
  stored beside the structured synthesis and rendered with a chapter
  table of contents on the investigation detail page.
- Self-healing runtime (RFC-07): a ToolRouter reroutes a capability call to
  another healthy instance on infra failure and disables an instance after
  repeated failures; a StateReconciler deterministically heals drift across
  the task status, workflow cursor, and in-progress lock; a ModelHealthRouter
  routes around infra-unhealthy endpoints with a recovery cooldown. All three
  are inert on the happy path, so dispatch and routing are unchanged when
  nothing is failing, and no process, gateway config, or model alias is
  altered. Three honesty rules enforce that recovery paths log or re-raise,
  no-finding closures classify infra death, and healing paths journal their
  state mutations (issue #31).
- Hot-pluggable MCP integration foundation (RFC-11): a config-driven generic
  McpClient plus a capability registry resolve a server by advertised
  capability (android_audit, binary_audit, source_audit) rather than by a
  bespoke bridge class, and modules declare their servers to the platform.
  One server is routed through the generic client as a behavior-preserving
  proof; the existing bridges remain intact and in use, and no live server
  URL, port, or process is changed (issue #35).
- The platform/module boundary (RFC-05) is enforced by the honesty audit:
  platform and API code can no longer read a feature module's config
  namespace by literal, name a module through a runtime aila.modules string,
  or reach into module internals. The concrete de-welding landed in earlier
  RFC-05 work; these rules lock it against regression (issue #30).
- The forensics module runs investigations through a role panel (researcher,
  critic, implementer) with a sibling-review quorum on findings, built on the
  shared platform investigation engine, instead of a single self-directed
  think-act-observe loop (issue #18).
- Budget-aware context assembly in the platform reasoning engine (RFC-24,
  first increment): an agent's turn context is assembled in priority tiers
  under an optional token budget, evicting or summarizing lower-priority
  tiers when the budget is tight while never dropping pinned directives or
  operator steering. With no budget configured (the default) the assembled
  context is byte-identical to before (issue #24).
- Module lifecycle and frontend extensibility: the module registry can
  unregister a module (removing its routes and tools), and the frontend
  discovers module UI specs dynamically instead of from a hardcoded list, so
  a missing module package no longer breaks the shell build (issue #41).
- Config resolution transparency in the platform config API and admin screen.
  `GET /config` now returns, per entry, the effective value the system resolves
  to (environment variable > stored value > schema default), the resolution
  source, the overriding environment-variable name, and the schema default,
  alongside the stored value. The admin config screen shows the effective value,
  a source badge, an environment-override indicator, the stored fallback, and a
  caution when editing a value an environment variable currently overrides.
  Secret values stay redacted for non-admin callers across every value field.
- On-demand specialist spawn + CRUD API for the specialist-agent registry.
  A core branch asks the oracle for a specialist (`request_specialist`
  ledger request, target capability); a distinct branch (the critic)
  ratifies it; the module resolves the ratified capability to a registry
  specialist and spawns one branch (`spawn_specialist_branch`, idempotent)
  at setup AND at every live loop turn -- so a request ratified mid-run
  (the real case: the agent asks for an expert eye after recon, long after
  setup ran) spawns on the next turn, not only when the request predates
  setup. The spawned branch's persona_voice resolves back to
  `_branch_capability` so the hub routes it to the capability-scoped
  phases. The
  `/agents/specialists` router lists, creates/updates, seeds, and deletes
  specialists so operators define new expert perspectives without a code
  change.
- User-extensible specialist-agent registry (`platform/services/specialist_registry.py`,
  migration 103): the investigation panel is a fixed 3-role spine
  (researcher, critic, implementer) plus optional specialist agents a core
  branch can request from the oracle for a different expert perspective. A
  specialist is data -- a `specialist_agent` row carrying a `capability`
  (matching a dispatch phase so the hub routes it), an optional prompt
  family, and a description -- so users define their own specialists
  (reverse engineering, crypto, exploit-dev, or anything) through CRUD
  without a code change; every module inherits the mechanism. Built-in
  defaults seed per module. Migration 103 ships unapplied (operator-gated).
- Phase-graph workflow substrate (`platform/workflows/phase_graph.py`): a
  module declares its investigation lifecycle as a `PhaseGraphSpec`, a
  graph of bounded adaptive loops wired by static edges, dynamic routers,
  and entry gates over the durable state machine. Each phase carries its
  own tool allowlist, turn cap, and mission directive (surfaced to the
  panel as the `_directive.phase_mission` observable). Opt-in
  `malware.investigate.v2` (target-readiness gate plus a kind router into
  triage / config_extract / yara_generate / full_analysis) and
  `vr.investigate.v2` (kind router into source / variant / binary / mobile
  audit, each scoped to an enforced per-phase MCP server allowlist) ship
  alongside the V1 single-loop definitions. Every module seed stays bound
  to V1; a V2 is enabled by rebinding the seed's `definition` after a live
  smoke. The loop factory gains `phase_directive`, `phase_max_turns`, and
  `phase_allowed_servers` (all default to prior behavior), and the shared
  tool executor enforces the per-phase server allowlist on dispatch.
- Discovery-driven dispatch hub (RFC-13 #68,
  `platform/workflows/phase_graph.py`): a `build_dispatch_workflow` shape
  (setup, hub, phase, hub, and so on until emit) where the hub re-decides
  after each phase, activating the first unvisited phase whose `condition`
  holds and whose `capability` matches the branch, bounded by a per-branch
  visited set and the overall turn cap. `PhaseSpec` gains `condition`,
  `capability`, and `trust` (confirmed or advisory). These fields are
  unused by the static `build_phase_workflow`, so the V1 and V2 graphs are
  unaffected.
- Four vulnerability-research hub phases (RFC-13 #68): `taint_analysis`
  traces each untrusted-input entry point to the sinks it reaches and
  confirms the path is unsanitized; `dependency_audit` audits declared and
  transitive dependencies for known-vulnerable versions and whether the
  vulnerable code is reached; `crypto_audit` audits cryptographic misuse
  (weak or broken primitives, static keys, IVs, and nonces, weak
  randomness, unauthenticated encryption, and certificate or signature
  validation); `fuzz_targeting` ranks the parsers, decoders, and
  deserializers that consume untrusted bytes and specifies a harness for
  each. Each is scoped to the target kinds it can operate on -- taint and
  dependency to source repositories, crypto and fuzz to source and binary
  targets -- so a source-repo investigation walks recon, source_audit,
  taint_analysis, dependency_audit, crypto_audit, variant_hunt, then
  fuzz_targeting.
- Shared investigation ledger (RFC-13 #68, migration 102,
  `platform/services/ledger.py`): one append-only `investigation_ledger`
  table per investigation. Branches append discoveries, notes, and
  capability requests; objectives are tagged entries folded to the latest
  owner and status by a read view, so there is no separate objective table
  and private per-branch hypotheses stay in the branch case state.
  `append_general` is idempotent under retries, `read_general` with
  `confirmed_only` returns only quorum-confirmed discoveries, and
  `make_discovery_condition` turns a ledger read into a dispatch-hub
  activation predicate. Migration 102 ships unapplied (operator-gated).
- Agent ledger writes and shared-board render (RFC-13 #68): a reasoning
  decision may carry `ledger_writes` (discovery, note, or request, capped
  per turn and idempotency-keyed) that the turn runner posts inside the
  post-turn transaction. Each turn renders a bounded digest of the shared
  ledger back into the prompt as the reserved `_ledger.board` observable,
  stripped at fork and re-derived from the DB each turn.
- Objective ownership lifecycle on the shared ledger (RFC-13 #68): a branch
  may change only the objectives it owns; a non-owner attempt is refused
  and must file a request. Branch merge transfers a source branch's
  objectives to the merge-result branch, and abandon or promote orphans a
  closed branch's objectives to the investigation, so a terminal branch
  never keeps a live objective. No new table (objectives stay tagged
  ledger entries).
- Planner oracle + discovery-driven malware hub (RFC-13 #68): a thin
  request router (`platform/services/oracle.py`) resolves ledger requests
  (activate_phase / open_objective / write_objective / replan) to their
  decider by `target_capability`, enforces a distinct-approver rule (a
  branch cannot ratify its own request), and applies only the declared
  mechanical effect once a quorum ratifies -- it decides nothing itself.
  The loop is wired end to end: a decider approves a request by naming it
  in the decision's `ledger_approvals` (the turn runner routes each vote
  through the oracle), and the dispatch hub calls `apply_all_ratified` on
  every visit so a ratified request takes effect (its discovery confirmed,
  its objective opened) before the hub re-evaluates activation. A phase's
  `trust` tier is the single source of truth for confirmed-versus-advisory:
  the hub threads it into each condition, which resolves whether a
  quorum-confirmed discovery is required.
  The dispatch hub gained overall-cap handling (emits `budget_truncated`),
  a stall path that raises one `replan` request per visited-set, and a
  ratified-replan relaxation that drops confirmed trust to advisory for
  one pass so a quorum deadlock cannot freeze the graph.
  `malware.investigate.hub` ships the malware phases as a discovery-driven
  dispatch (unpack capability=re, config_extract capability=crypto, both
  confirmed-trust; full_analysis the advisory fallback), bound nowhere
  live -- enabled by an operator seed rebind after smoke, like the V2
  graphs.
- Discovery-driven vr hub (RFC-13 #68, `vr.investigate.hub`): recon runs
  first and posts scoping discoveries; the audit phases (source / variant /
  binary / mobile, each keeping its V2 MCP server allowlist) activate on
  those discoveries under advisory trust and per-capability routing; and
  poc_development is gated -- `trust="confirmed"`, `capability="exploit-dev"`
  -- so it activates only once the panel confirms an exploitable finding by
  quorum. Reuses the Phase 0-4 substrate with no new platform code; ships
  bound nowhere live (operator rebind after smoke).
- Discovery-driven forensics hub + evidence board (RFC-13 #68,
  `forensics.investigate.hub`): a content-aware `make_evidence_condition`
  matches a discovery's `evidence_type`, so a discovered disk image opens
  the disk and binary lanes and a discovered pcap opens the network lane,
  reusing the existing `_LANE_EVIDENCE_TYPES` classification. The hub runs
  the proven forensics stages unchanged -- each phase adapter runs the real
  stage and only overrides the transition back to the hub, and each lane
  phase scopes `state_collection` to its single lane via `active_lanes` --
  then runs the deterministic tail (deep_analysis, promotion, resolution,
  writeup) unconditionally. `record_evidence` posts a discovered evidence
  item to the shared ledger as the cross-branch evidence board. No
  collector machinery is rewritten and the live `FORENSICS_DISPATCHER_V1`
  is untouched; the hub ships bound nowhere (operator rebind after smoke).
- RFC-13 guardrails + module scaffold (#68): two honesty-audit rules lock
  the invariants. `static_node_mutation` (rule 50) forbids mutating a
  `WorkflowDefinition.states` map after construction -- the node set is
  frozen so every transition target stays declared and auditable, and
  agents activate declared phases rather than minting a node at runtime.
  `ledger_write_bypass` (rule 51) forbids a direct write to the
  investigation_ledger table (pg_insert / session.add of the record, or a
  raw INSERT) outside LedgerService, keeping it the sole writer that owns
  idempotency and the append-only rule. The `_template` module documents
  the optional discovery-driven dispatch path and the shared-ledger usage
  so a new module adopts the pattern by example.
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
- Knowledge-graph edge populators so the graph retrieval route stops
  degrading to seed-only (RFC-12 criterion 5). Opt-in `link_chunks` joins
  adjacent same-document chunks with bidirectional `adjacent_chunk` edges;
  opt-in `link_neighbors` joins a stored entry to its nearest
  same-namespace entries above a similarity floor with weighted `related`
  edges (cross-document hops by meaning). Both are deterministic and
  idempotent on re-ingest. `retrieve` gains a `source_types` shape filter
  on the indexed `source_type` column so a caller can scope retrieval to
  code, document, or pattern knowledge. All default to prior behavior; no
  new migration (the edge table and column already exist).
- Content-derived knowledge metadata for intelligent retrieval (RFC-12):
  opt-in `extract_entities` on store stamps the security identifiers found
  in the content (CVE / CWE / CAPEC / ATT&CK technique / MASVS ids, a
  deterministic no-cost regex pass) under `entry_metadata["entities"]`, and
  `retrieve` gains a `metadata_filter` predicate so a caller can scope the
  hybrid candidate set by any metadata key (scalar equality or list
  membership), e.g. every entry tagged CVE-2024-1234. Default off; no
  migration.
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

- The offline eval runner no longer promotes on its own (RFC-10 #34). The
  eval-run path scores a candidate and records a verdict; it can no longer
  flip the production alias on an eval pass. Promotion to production is now
  exclusively the lifecycle controller's gated path (a passing evaluation
  plus a distinct-approver quorum), so no code path reaches production on
  the eval score alone. The `auto_promote` option is removed from the eval
  run API.
- Model selection now consults the pinned agent-config bundle first
  (RFC-09 #33). When a running investigation's pinned bundle specifies a
  model for the task type, that routing wins; an empty bundle routing
  falls through to the existing registry-based resolution unchanged, so
  behavior is identical for every prompt-only bundle. A prompt version's
  content hash now covers the whole bundle (body plus roster, routing,
  and exemplars) rather than the body alone, so re-registering an
  identical prompt with different routing produces a new immutable
  version.
- The confidence-gate score now passes through the active post-hoc
  calibrator before it is mapped to a HIGH/MEDIUM/LOW/REJECT level
  (RFC-08 #32). When a calibrator is fitted and active for the task type,
  the recalibrated probability is the authoritative gate confidence,
  replacing the length-of-response heuristic as the number that drives
  the decision; the heuristic remains only as the raw fallback when a
  response carries no structured confidence, and the gate falls through
  to the raw score when no calibrator is active or the calibrator flag is
  off. Gate audit metadata now records both the raw and the calibrated
  score.
- The shared dispatch-hub discovery condition (`make_discovery_condition`)
  takes an optional `payload_match` filter so a phase activates only on a
  discovery whose payload carries a matching key and value (RFC-13 #68). The
  default preserves the prior any-entry-of-the-kind behavior, so the
  vulnerability and forensics hub conditions are unchanged.
- The dispatch-hub investigation seeds and the vulnerability investigations
  list help text now name the adaptive hub definition they bind rather than a
  removed linear-workflow name, so the source and the UI describe the live
  execution path (RFC-13 #68).
- Reasoning strategy families are module-declared (RFC-05 #30). Each module
  publishes its families with their own match keywords and priority; the
  platform seeds only the generic family and classifies a turn by consulting
  the registry. The platform no longer hardcodes a fixed set of module-domain
  strategy families or a keyword router that names them. Turn classification is
  unchanged for the shipped modules.
- The platform MCP bridge tools require an explicit owning module id
  (RFC-05 #30). The tool name and config namespace derive from that id; the
  previous implicit default is removed, so every construction site names the
  module it belongs to and the platform bridge never assumes a specific module.
- Platform-internal modules import the shared contract helpers (utc_now and the
  JSON type aliases) from the public contracts path rather than the private
  submodule (RFC-05 #30).
- Module config reads consolidate onto a single module-scoped
  ModuleConfigReader (RFC-04 #29). The per-module config-helpers indirection is
  gone; each consumer resolves typed config through the shared reader, and
  module-service reads that previously went through the process environment now
  resolve through the config registry with the same defaults, so an operator
  override lands without an environment change.
- The shared investigation message-stream hook gains a query-cache-scope
  option, and the vulnerability-research wrapper gains the auto-reconnect loop
  and catch-up cursor the malware wrapper already had (RFC-04 #29). The public
  hook API stays backward compatible and the sole caller is unchanged.
- The vulnerability-research and malware tool executors no longer diverge on
  their pre-call and access guards (RFC-03 #28). The malware executor gains
  the pre-call hard-block that refuses a bridge call whose identical arguments
  have failed repeatedly (config `tool_executor_hard_block_repeat`), and the
  vulnerability-research executor gains the server allowlist that returns a
  clear not-exposed error for a server the agent may not call. Neither change
  alters a successful call path.
- Investigation pause / resume / re-enqueue handlers now bind the platform
  lifecycle service directly at the api_router call site (RFC-02 #27). The
  per-module lifecycle adapter indirection is gone; each handler passes its
  record models, branch table, ARQ track, and task function to the shared
  `pause_investigation` / `resume_investigation` / `reenqueue_investigation`
  service, and the module still owns its pause-reason vocabulary at that call
  site. Behavior is unchanged; the atomic body keeps a single implementation.
- The RFC-07 ToolRouter now sits on the live MCP tool-dispatch path. The
  agent tool executor routes a bridge call through the router when the
  server resolves to a capability with catalogued instances, so an
  infra-failed call reroutes to another healthy instance and an instance
  is disabled after repeated failures; the happy path is unchanged and a
  single-instance capability passes through directly. Previously the
  router was implemented but never invoked. (RFC-07)
- The RFC-08 self-improvement writers now run on live paths. An
  accept/reject review verdict writes a signed positive/negative pattern
  through the ExperienceWriter on both verdict paths (the emit-state draft
  review and a reviewer's mid-turn vote that flips quorum inline), and the
  CalibrationProposer runs as a schedulable platform automation action
  (`platform.calibration_proposer_sweep`) that aggregates per-outcome_kind
  verdict history into a versioned, reversible threshold proposal.
  Previously both were implemented but never invoked; each new call is
  wrapped so a failure never affects the investigation. (RFC-08)
- The malware and forensics investigation flows now run the RFC-13
  discovery-driven dispatch hub. Malware binds its investigate task to
  `malware.investigate.hub`; the forensics full-analysis path resolves
  through the two-phase dispatcher to `forensics.investigate.hub`, while
  the freeflow and raw_directory modes keep their fixed workflows. The
  vulnerability-research investigate task already ran its hub. Each hub
  reads and writes the shared investigation ledger (migration 102, in the
  linear chain). (RFC-13 #68, #23)
- Malware playbooks execute through an ARQ task that walks the steps and
  writes an execution outcome, replacing the enqueue stub that recorded
  run intent without running anything. The run endpoint returns a queued
  run id.
- Model-family prompt variants and the canary hold gate now operate on
  live turns. A reasoning turn selects the prompt variant for the model
  family it routes to (falling back to the default variant then the file),
  and a canary-cohort turn's drift and cost feed the canary hold gate
  automatically instead of only via a manual admin action. Both are inert
  outside a live prompt rollout. (#33, RFC-10)
- Upload endpoints read request bodies under a hard byte ceiling. Sample,
  investigation, and APK uploads reject a chunked body with no declared
  length and cap the read so an oversized upload cannot exhaust worker
  memory. (#57)
- External intelligence providers (NVD, EPSS, KEV) and the binary-analysis
  collector no longer block the event loop. HTTP calls use an async client
  with async backoff, and subprocess-heavy analysis runs off the loop.
  (#64, #55)
- The web client keeps the access token in memory only, stores the refresh
  token in session storage with a bounded lifetime, and sends a
  double-submit CSRF header on state-changing requests. Finding severity
  uses an explicit vocabulary (Immediate, High, Moderate, Planned).
  (#47, #55)
- Per-model seal drift biases model-routing decisions, and the routing
  learner informs sibling-branch sizing. Prompt resolution keys on model
  family with a database override path. (#31, #32, #33, #34)
- Secret storage rotates on key version and restricts secret files with
  Windows ACLs. (#42)
- LLM cost keys are normalized before aggregation, and a budget can
  reconcile against actual recorded cost. (#38)
- The PoC sandbox fails closed. Each run gets an isolated per-run
  workspace that is torn down after use, governed by an age-and-size
  workspace quota. (#51)
- Scheduled-automation listing is paginated in SQL, the batched
  target-analysis migration no longer loads all rows at once, and the
  cron dependency is required rather than optional. (#56)
- On-demand specialist agents are named panelists instead of capability
  slugs. A panel can pull in an expert branch (reverse engineering,
  mobile, exploit development, variant hunt, crypto) when a case needs
  one; those branches previously rendered as the bare capability slug
  ("re", "mobile", ...) next to the named core spine (Halvar, Maddie,
  Renzo). Each built-in specialist now carries a distinct name so every
  voice on the board reads the same way, with its own label and avatar in
  the branch list and outcome views. Routing is unchanged: dispatch keys
  off the specialist's capability, which is untouched. A migration renames
  the seeded registry rows and any branch already spawned under an old
  name; a specialist a user renamed through the CRUD API keeps its name.
- The apk_static audit (evidence-backed checks with concrete source
  locations) is the primary APK audit on the target detail page; the
  MASVS compliance audit stays available but is presented as the
  secondary path.
- Audit aggregate verdict rows carry the child synthesis scope, headline,
  and key points (merged agreement and named disagreement) rather than
  only a terse agent summary, so the per-control view reports what was
  examined and why, not just the verdict. Rows from older outcomes with
  no panel summary keep the compact layout.
- The APK static summary (package, version, permissions, exported
  components, certificates, SDK levels) is composed in-repo rather than
  by androguard: the manifest fields come from apktool's decoded
  AndroidManifest.xml, certificates and signing scheme from the APK
  signing block, native-library detail from a LIEF pass, and a component
  inventory from Gradle / Maven / native markers. The summary shape is
  unchanged, so the audit dispatchers, PDF report, and target overview
  are unaffected. The native-library and SBOM checks, previously
  roadmap-only, now dispatch as static checks against this data. Both the
  VR and malware modules use the same extractors, which live in a shared
  `aila.platform.apk` package rather than inside a module.
- The per-turn reasoning prompt is assembled by the budget-driven
  RFC-24 ContextAssembler instead of hand-concatenated, and the fixed
  render display caps (former hypothesis / scratchpad / tool-reading
  counts) are removed. A config-resolved token budget
  (reasoning_context_budget_tokens, default 180000) governs the live
  window by tier priority: operator directives, the contract, and kill
  criteria are pinned and never dropped, while lower-priority content is
  trimmed to fit and remains recall-able from durable history. VR and
  malware route through this path; forensics already did and picks up
  the default budget automatically, so no prompt is unbounded.
- The default investigation panel is the 3-role spine -- halvar (researcher,
  primary), maddie (critic), renzo (implementer) -- instead of the former
  fixed 6 personas. Configurable via `vr.core_persona_siblings` (falls back
  to the baseline when unset). Expert diversity now comes from optional
  specialist agents spawned on demand via the oracle, not a hardwired panel.
  This changes the sibling-review quorum denominator (fewer non-proposing
  branches) and cuts baseline per-investigation cost.
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
- The RFC-12 retrieval-intelligence layer is now live on the core
  knowledge-write paths: findings and audit memos, CVE intel memos,
  reusable patterns, and the agent knowledge-store tool all stamp security
  entity tags and write semantic-neighbor `related` edges at write time.
  Retrieval can therefore scope by `source_type` / `metadata_filter` and
  hop the graph route across related knowledge without any per-call opt-in.
  Each write adds one nearest-neighbour query; the entity pass is regex,
  no model cost. No migration.
- Sibling-review quorum approves a draft finding on a MAJORITY of the
  non-proposing branches (`max(2, ceil(N/2))`) instead of near-unanimous
  agreement (`max(2, N-1)`), matching the documented formula. A lone
  abstain or request_edit no longer makes approval mathematically
  unreachable. The threshold is still derived from the static
  non-proposing count, so stale-abandoned siblings cannot shrink it.

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

### Removed

- The three bespoke MCP bridge classes (RFC-11 #35). Their transport and
  server-specific logic collapsed onto the generic client plus one
  middleware plugin per server, preserving every behavior: kwarg
  aliasing, address and encoding coercion, pending-poll with dead-worker
  detection, the per-call dedup cache, prewarm fan-out, the read_function
  not-indexed fallback chain, the virtual line-read and streaming-upload
  actions, APK path recovery, pipeline-only blocking, and per-tool schema
  fetch. Dispatch now builds a bridge on demand from the catalog instead
  of a fixed per-module map.
- The worker's legacy ARQ function shim (`_legacy_arq_functions`) is retired.
  The scheduled-report and network-discovery jobs are now registered through
  the `@platform_task` decorator like every other task, so the ARQ worker
  function list is sourced entirely from the task registry under
  fully-qualified names. The manual scheduled-report trigger also enqueues
  through the shared task queue on the module track rather than a raw bare-name
  enqueue to ARQ's default queue key, so the job reaches a worker.
- The per-module `services/config_helpers.py` files (vulnerability-research,
  malware, forensics, template) are deleted (RFC-04 #29); the shared
  ModuleConfigReader replaces them.
- The vulnerability-research and malware modules no longer carry a
  `workflow/pause_resume.py` lifecycle adapter (RFC-02 #27). Each had become a
  thin binding over the platform lifecycle service; the api_router handlers now
  bind that service inline, so the modules hold no lifecycle wrapper module.
- The vulnerability-research and malware modules no longer carry their own
  `contracts/hypothesis.py`, `contracts/evidence_graph.py`, or
  `contracts/target_stages.py` files (RFC-01 Phase 3). Those three modules
  had become byte-identical re-export shims after the earlier platform
  hoist; they are deleted and every import site now resolves
  `HypothesisProjection`, `HypothesisState`, the `EvidenceGraph` node and
  edge and snapshot contracts, `StageName`, `StageState`, `StageStatus`,
  `TargetAnalysisStages`, and `roll_up_overall_state` directly from
  `aila.platform.contracts.*`. Each module contract barrel keeps
  re-exporting the same names under the same `__all__`, sourced from the
  platform, so the module contract package surface is unchanged. The two
  stale `contracts/target_stages.get` entries in the honesty whitelist are
  dropped. No schema change; behavior-preserving. This closes the last
  open item of RFC-01. (#26)
- androguard and MobSF are no longer part of the APK analysis pipeline.
  The APK static summary is composed in-repo instead (see Changed), and
  MobSF scanning is dropped entirely.
- The MobSF scan stage is removed platform-wide. The shared
  `MOBSF_SCAN` stage identifier and the `mobsf_scan` field on the target
  analysis-stage record are gone, the malware module no longer runs a
  MobSF stage either, and the `mobsf_scan` tool is no longer declared on
  the android-mcp bridge. Existing target rows that persisted a
  `mobsf_scan` stage key load unchanged: the stage record ignores
  unknown keys, so no database migration is required. The target detail
  and report surfaces no longer render a MobSF section.
- androguard is removed platform-wide. The malware module's APK static
  summary is now composed in-repo (apktool manifest, APK signing block,
  a LIEF native-library pass, and a component inventory) exactly like the
  VR module, so no module calls the android-mcp `androguard_summary` tool
  and the bridge no longer declares it. The four in-repo extractors moved
  to a shared `aila.platform.apk` package so both modules compose the
  same static-summary shape without importing each other. The malware APK
  STATIC_SUMMARY stage now runs after APK_DECODE (it reads the decoded
  manifest) instead of alongside it.


- Duplicated agent primitives, support services, and data-model records
  across the vr and malware modules, consolidated onto the platform bases
  above.

---

- Dead `notification_types` and an unreachable unscoped cross-tenant
  cost query. (#41, #57)

---

### Fixed

- Vulnerability scan submission (POST /analyze) is dispatchable again
  (RFC-05 follow-up). The shared scan endpoint selected the first-registered
  module rather than the one that declares a scan track (the resolver matched a
  None-returning protocol default), returning 503; it now selects the module
  that answers with a track. Separately, the platform scan entrypoint was
  registered under its bare callable name while the queue enqueues by the
  fully-qualified name, so the worker rejected the job with "function not
  found" and reaped it as orphan-queued; the worker registry bootstrap now
  imports the platform task entrypoints so they register under the
  fully-qualified name.
- An unevidenced reject vote no longer swings review quorum in the
  vulnerability-research module (RFC-03 #28). The empty-rationale
  reject-to-abstain downgrade now lives in the shared turn runner, so both
  modules apply it uniformly; previously only the malware module downgraded a
  reject cast with no rationale, and a vulnerability-research branch could veto
  a correct outcome with an empty review comment.
- Pausing or re-enqueuing an investigation no longer fails when the task queue
  backend is unreachable (RFC-02 #27). The post-commit queue purge is
  best-effort, but its backend connection error was uncaught, so a pause whose
  database transition had already committed still returned a server error and
  the operator saw a failure for a pause that in fact took effect. The shared
  purge primitive now degrades to a zero-count result and logs a warning when
  the queue backend cannot be reached, so the lifecycle transition reports
  success once its transaction commits.
- Pausing an investigation now cancels its active worker tasks and the running
  loop detects the pause through the cursor (RFC-02). Two mis-keyed predicates
  are corrected. Pause matched `taskrecord` rows by
  `id = ANY([investigation_id, ...branch_ids])`, but a taskrecord id is a fresh
  ARQ uuid, so it cancelled zero rows and a running task held its slot until
  its turn ended; pause now matches on `kwargs_json` (which carries the
  investigation_id), the same key re-enqueue already used. The loop's cursor
  pause-detection looked up `WorkflowStateCursor` by `branch_id` as a primary
  key, but the primary key is `run_id` (the task uuid), so the lookup always
  returned None and the cursor check was dead code; it now queries the
  denormalised `branch_id` column added in migration 101. A paused
  investigation's projections and its worker tasks now move together. (#27)
- The oracle specialist-adjudication toggle read no longer raises when the
  config registry cannot resolve the default (an `int(None)` TypeError in an
  environment where the config schema is not bootstrapped, e.g. a unit test);
  it degrades to skipping adjudication, matching the best-effort contract. (#68)
- A strong-confidence negative conclusion no longer burns as a false positive
  finding. The vulnerability-research outcome-kind mapper routed any submit
  with confidence `strong` or `exact` to `direct_finding` regardless of the
  answer, so a strongly held "no vulnerability found" conclusion was recorded
  in `vr_findings` and the knowledge base as a confirmed vulnerability. The
  mapper now checks answer polarity first: an answer that reads as a negative
  conclusion (no bug, not exploitable, no vulnerability found) maps to
  `audit_memo` (the cleared-region record), never a finding. The negative
  claim detector is also widened to catch the common "no <thing> vulnerability
  found" and "no exploitable <thing> found" phrasings that the fixed prefix
  table missed because the negative noun sits between "no" and the verb.
  (RFC-12 #49)
- Knowledge enrichment silently failed its idempotency and journaling on
  every ingest. The enrichment LLM call derived its idempotency scope as
  `knowledge-enrich:<namespace>`, which overflowed the `varchar(36)`
  `investigation_id` column on the LLM idempotency cache, cost, and seal rows
  for any real namespace; each cache and journal write was rejected and
  dead-lettered, so a re-ingest re-paid the model instead of replaying the
  cached blurb. The scope is now a fixed-width namespace digest
  (`kbenrich-` plus a 26-character digest, 35 characters total), so the cache
  persists and a re-ingest replays it. (RFC-12 #49)
- Knowledge-base writes and reads no longer truncate content. Observations
  burned from tool output were capped at 6000 characters before being stored,
  and prior knowledge retrieved into an investigation prompt was capped at 600
  characters per entry, so long tool results and multi-paragraph findings
  reached the vector store and the agent already clipped. Both caps are
  removed: the full observation is stored and the full retrieved entry is
  returned, matching the finding-burn and backfill paths that already stored
  full content. The prompt render layer still bounds the assembled retrieved
  section, so the model context stays sized while the stored and returned data
  is complete. The retrieval journal also records the full query rather than
  a 2000-character prefix. (RFC-12 #49)
- Knowledge writes silently failing on a database bootstrapped through
  table creation rather than migrations. Such a database could keep the
  embedding column at vector(384) while the provider emits 1024-dim
  vectors, so every knowledge store was rejected at flush time and the
  failure was swallowed by caller-side error handling, leaving the whole
  knowledge, pattern, and memory subsystem quietly non-persisting. A new
  idempotent migration widens the column to vector(1024) only when it is
  narrower, so a drifted database self-heals on the next upgrade and a
  database already at full width is left untouched. (RFC-12 #49, #37)
- The agent knowledge_store tool wrote vectors through a second INSERT
  path that stamped no provenance and reported a stale embedding
  dimension. It now delegates to the knowledge service, so one embedding
  path stamps model_id, content_hash, and source_type on every vector and
  upserts under the advisory-lock dedup instead of a divergent write.
  (RFC-12 #49, #37)
- Investigation message SSE live tail no longer dies on one bad row. The VR
  and malware ``/investigations/{id}/messages/stream`` endpoints projected each
  polled row into a summary with no per-row guard, so a single message that
  failed to serialize (an out-of-enum field, malformed payload) raised inside
  the generator, closed the stream, and the investigation stopped refreshing
  until a full page reload. Each row is now projected defensively: a row that
  fails to serialize is logged and skipped (the cursor advances past it) and
  the live tail keeps delivering the rest.
- Malware Android APK ingestion. Uploading an APK through the malware
  sample-upload endpoint streamed the bytes to ida-headless (the native-binary
  path) and never recorded an ``apk_path``, so the APK_DECODE stage failed with
  "android_apk target requires apk_path in descriptor" and the target sat at
  pending with no stages. APK uploads now stream to the android-mcp uploads
  directory (``ANDROID_MCP_UPLOAD_DIR``, default ``~/.android-mcp/uploads``) and
  record ``apk_path`` in the descriptor, so apktool / jadx decode runs; native
  binaries still go through ida-headless.
- Malware APK decompiled-source indexing on Windows. The unified staging tree
  that feeds the code index linked the jadx and apktool output with directory
  symlinks, which ``os.walk(followlinks=False)`` (used by both the language probe
  and the indexer) does not descend, so indexing failed the target with "No
  supported languages detected". The staging tree now links with NTFS junctions
  (descended by that walk and needing no developer mode), so the decompiled Java
  is indexed and the downstream audit stages run.
- Malware script and document ingestion. Uploading a script or document sample
  streamed the bytes to ida-headless (the native-binary disassembler), which
  cannot load them, so the analysis failed or produced nothing. These kinds now
  save the sample to a per-hash directory and index it through audit-mcp
  (``MALWARE_SAMPLE_DIR``, default ``~/.aila/malware_samples``); scripts get a
  code index the agent can query, and a sample with no source language audit-mcp
  recognizes (a binary document) is kept on disk for line reads instead of
  failing the target. Native binaries still go through ida-headless.
- Malware APK analysis stuck at pending after a resume. Resuming an APK whose
  stages were already complete left the row at pending forever (a permanent
  "analyzing" state in the UI): the android path swallowed the
  already-done signal without re-deriving the overall state, unlike the binary
  path. The android path now re-derives analysis state from per-stage truth on
  resume, so a completed APK returns to ready.
- Malware APK upload directory. APK uploads wrote to a directory that could
  diverge from the one the android-mcp resolver reads for agent tool calls
  (two different environment variables and defaults). Uploads now write to the
  single directory the resolver reads, so an uploaded APK is found by both the
  ingestion path and later agent lookups.
- Malware decompiled-source language detection on non-Windows hosts. The
  language probe over the unified staging tree did not follow directory
  symlinks, so on POSIX (where the staging tree links with symlinks rather than
  Windows junctions) it detected no languages and indexing fell back to
  auto-detection that drops minority languages. The probe now follows symlinks.
- Malware investigations over APK, script, and document targets can now query
  the code index. The investigation agent's tool surface was fixed to
  ida-headless for every kind, so an APK / script / document investigation --
  whose ingestion builds an audit-mcp source index, not an ida-headless binary
  handle -- had no way to read the indexed code and could reason only over the
  static summary. These kinds now receive a read-only audit-mcp tool surface
  (semantic search, read function, call graph, and related query tools);
  mutating and pipeline tools are never exposed. Binary kinds keep ida-headless.
- The forensics investigation hub now executes when selected by the
  two-phase dispatcher. As the inner definition it shares the dispatcher's
  run id, so its cursor has to reset from the dispatcher's terminal state to
  the hub's start state; without that flag the inner run returned no response
  and no phase ran. ``build_dispatch_workflow`` takes an
  ``allow_phase_handoff`` flag and the forensics hub sets it, matching the
  fixed-mode definitions. The hub is registered into the dispatcher's mode
  registry lazily on the first full-analysis route, so a hub-import fault can
  no longer keep the fixed-mode forensics tasks from registering. (RFC-13 #68)
- The startup prompt seeding now covers the malware frontend creation path.
  That frontend rides analysis depth through ``strategy_family`` as a
  ``depth:<value>`` tag; the malware prompt key collapses that tag to the base
  strategy, so a frontend-created malware investigation resolves its prompt
  against the version store instead of falling back to disk. (RFC-09, RFC-10)

- The LLM client publishes its per-call domain event again. The client's
  event-bus reference was never assigned during runtime construction, so the
  guarded publish was dead code; it is now wired to the process-wide bus.
  (#39)
- The global server-sent-events ceiling now bounds the session message
  stream and the forensics readiness stream. Both called the cap check but
  never counted themselves against the gauge, so the ceiling under-counted
  live connections. (#60)
- Promoting an active canary version now applies the minimum-sample gate.
  The promote endpoint called the plain promote path, bypassing the gate
  and the canary cleanup for a canary-stage version. (#34)
- The turn budget's measured cost now tracks the durable cost ledger. The
  reconciler was defined but never called, leaving the budget's measured
  spend at zero for the whole run. (#38)
- The prompt registry falls back to the default-variant version-store row
  when a routed model family has no family-specific override, instead of
  dropping to the file-backed base. (#33)
- The canary promotion gate blocks a candidate flip until a minimum count
  of drift and cost samples has been observed on the active assignment.
  (#34)
- The dev process stack (backend, workers, audit_mcp, ida-headless,
  frontend) survives the terminal or session that launched it closing.
  start.sh spawned each service through PowerShell Start-Process, whose
  children inherit the launching terminal's Windows Job Object
  (kill-on-close), so the whole stack died together when the launching
  session ended while the OS-service dependencies (postgres, redis) kept
  running. start.sh now launches services via WMI Win32_Process.Create,
  which reparents each process out of the terminal job to the WMI provider
  service, and passes the working directory explicitly (the WMI call
  otherwise defaults it to the system directory). Path conversion covers
  git-bash, WSL, and already-Windows cwd forms.
- APK static RESILIENCE audits no longer report a present defensive
  control as a failing one. RESILIENCE checks (integrity verification,
  root / emulator / anti-debug / obfuscation detection) audit whether a
  defense is present: the control being present and reachable is the good
  state, and only its absence, dead code, or trivial bypass is a finding.
  The per-check seed did not state that inverted polarity, so a scout that
  correctly located a working control submitted a direct_finding, which
  the verdict mapper projects to a FINDING and flags the present control
  as a resilience gap. The RESILIENCE seed now states the inverted
  polarity explicitly: a present, reachable control is a cited no_finding,
  and a direct_finding is reserved for an absent, dead, or defeated
  control.
- Call-graph queries resolve interface and dependency-injection dispatch.
  A call through a field whose declared type is an interface (a
  DI-injected collaborator, the common shape in obfuscated Android /
  Kotlin) is left unresolved by the parser, so the resolved call graph
  reported the target method as having zero callers even when it was
  called -- and an agent could wrongly read that as dead code. The
  audit_mcp bridge now requests interface/DI-dispatch resolution on
  callers_of and callees_of by default, so those callers surface (tagged
  as name-matched, inferred confidence). When a query still returns
  nothing, the zero-result hint now names the remaining cause (a call the
  parser dropped entirely, such as a qualified-this receiver in a nested
  or coroutine class) and points at a textual source search instead of
  implying the target is uncalled. The resolution itself ships in the
  audit-mcp graph engine; this change wires the platform bridge to it.
- A specialist request is now recorded once per capability instead of
  once per filing. A panel branch files a request_specialist ledger entry
  when a case needs an expert eye; the same capability was re-filed every
  turn while waiting for a distinct approver, by more than one branch, and
  again by the spawned specialist itself, so the shared ledger filled with
  duplicate request rows. The request write now carries a capability-
  scoped idempotency key, so repeat filings collapse to one row through
  the ledger's uniqueness constraint. Ratification and spawning are
  unchanged (both already deduplicated), and distinct capabilities keep
  distinct rows.
- The audit_mcp index-id auto-correction now fires for APK investigations.
  An android_apk target stores its unified jadx/React index under a
  different handle key than a source-repo target; the tool executor's
  resolver read only the source-repo key, so for APK audits it resolved
  nothing and never injected the correct index id. When the model omitted
  or improvised the opaque index hash -- routine, since it is not
  human-memorable -- the call reached the bridge without a valid index and
  was blocked as missing a required argument, wasting the turn. Every
  audit_mcp call from an APK investigation was affected; source-repo
  investigations were not. The resolver now falls back to the APK index
  handle, so the safety net corrects APK calls the same way it already
  corrected source-repo calls.
- The periodic task reaper no longer cancels a running investigation whose
  arq in-progress lock is present but whose heartbeat is stale.
  `heartbeat_at` is written per workflow state transition, not
  continuously, so a job in one long state (a multi-minute reasoning turn
  or a slow decode) went stale while still running; the reverse-sweep then
  deleted its lock and re-enqueued it, letting arq re-dispatch the same job
  id -- which collided on arq's per-job bookkeeping (`KeyError`) and ran
  the investigation twice. The cron reverse-sweep now trusts a present
  lock and acts only on lock-absent orphans (its stated purpose); a
  genuinely leaked lock still expires at the arq job timeout and is reaped
  by a later sweep. Startup crash-recovery is unchanged.
- The android decode stages (APK decode, jadx decompile, React Native
  extract) run sequentially instead of concurrently. Each spawns a heavy
  JVM subprocess on the single android-mcp host; the previous parallel
  fan-out caused CPU / memory / disk contention that pushed every stage
  past its timeout, and a timed-out android-mcp call leaves a worker
  thread that cannot be killed, so repeated timeouts saturated the pool.
  Running one stage at a time gives each full machine resources and, in
  practice, finishes faster than the contended fan-out.
- Android ingestion stage timeouts raised to 30 minutes for APK decode,
  jadx decompile, and React Native extract. The previous 5-15 minute caps
  pre-empted apktool and jadx on mid-size APKs -- the single-worker
  android-mcp serializes the parallel decode stages, so a stage can wait
  behind its siblings and exceed a tight budget -- leaving the target
  stuck at a failed decode with the static summary never running.
- Application `aila.*` loggers are no longer disabled when a migration
  runs in-process. The Alembic environment called `fileConfig` with the
  default `disable_existing_loggers=True`, which silently disabled every
  logger created before it; any host that migrated before configuring
  logging then dropped subsequent log records. The call now passes
  `disable_existing_loggers=False`, preserving the Alembic and SQLAlchemy
  logger configuration without clobbering the application hierarchy.
- `resolve_domain_profile` adapts a domain id that names a built-in
  reasoning strategy family into a single-family profile instead of the
  blanket generic profile. A domain id that names neither a registered
  profile nor a built-in family still falls back to generic.
- APK ingestion now indexes the decompiled source tree on Windows. The
  unified staging directory linked the jadx output with a directory
  symlink, which the indexer's directory walk skips, so the entire
  decompiled tree was invisible and an audit reported no supported
  languages; staging now uses a directory junction, which the walk
  descends.
- The taint-flow view no longer reports zero paths for reachable sinks.
  The audit_mcp taint_paths_to adapter read the paths from keys that the
  server never returns; the server reports call chains under
  entrypoint_paths with an authoritative path_count plus is_tainted,
  caller_count, direct_callers, and exploitable. The adapter now reads
  those fields, renders each entrypoint-to-sink call chain, and surfaces
  the reachability flags, so a sink with N entrypoint paths shows N
  instead of 0.
- Repeated malformed tool calls now trip the repeat-failure circuit
  breaker instead of retry-storming. The audit_mcp read_lines bridge
  tool previously rejected missing required kwargs, non-integer line
  numbers, inverted or zero-based ranges, and offsets past end-of-file
  with terse messages the contract-error classifier could not
  categorize, so the anti-retry breaker never fired and a branch could
  re-issue the identical malformed call five or more times. read_lines
  now returns a structured error naming the valid params and required
  kwargs (mirroring the existing kwarg validator), and the classifier
  recognizes missing-required and out-of-range value errors as
  breaker-eligible classes, so the branch is redirected after two
  repeats. The audit prompt now states each common tool's exact
  required kwargs (read_lines, read_function, semantic_search and
  find_related top_k, the search_* pattern arg) and points at the
  per-turn tool catalog as the authoritative signature source.
- A reasoning turn whose structured output is not valid JSON is now
  repaired across a bounded number of attempts (each retry shows the
  model the verbatim validation error plus the partial JSON it produced)
  before the turn is given up, instead of consuming the turn on the
  first malformed response.
- An agent that calls a tool name not in the catalog now gets a nearest-
  name suggestion ("Did you mean: ...?") in the error, instead of only a
  generic "re-read the available tools" message.
- The audit_mcp read_lines bridge tool now resolves a file whose basename
  uniquely identifies one file in the indexed tree even when the caller
  passed the wrong directory prefix, instead of returning a not-found
  error. The not-found error's Android/JADX package-rename hint is now
  shown only for actual JADX-decompiled indexes (it was printed for every
  target, misleading callers on Python, C, and Go repositories), and the
  nearest-path suggestions now include a bounded whole-tree basename
  search.
- A vulnerability-research investigation now shows an outcome's polarity
  (finding / no finding / inconclusive) directly in the synthesis section,
  on every outcome row, and in the investigations list. A no-finding
  result (an audit memo whose verdict is no_finding, or a refuted
  finding) is distinguishable at a glance instead of reading like a
  finding; the list no longer labels every primary outcome "has
  finding".
- The LLM retry loop now retries a transient upstream failure (503 and
  other 5xx) raised by a provider SDK that carries only a status_code
  attribute, instead of propagating it raw on the first attempt. A
  non-retryable 4xx still fails fast and cancellation still propagates
  untouched (issue #44).
- Frontend data-layer security hardening: a Content-Security-Policy and
  companion security headers are sent on every response; a 401 logs the user
  out while a 403 no longer force-logs-out; server-sent-event reconnect uses
  jittered back-off; post-login redirects pass a same-origin allowlist; an
  idle timeout clears the session; and the client query cache is bounded so
  sensitive data is not retained indefinitely. Migrating tokens to httpOnly
  cookies remains a scoped follow-up (issue #47).
- LLM-generated proof-of-concept code runs inside an isolation layer (firejail
  or a namespace sandbox with no network, dropped capabilities, and
  no-new-privileges, falling back to resource limits when neither is present)
  and only from within the confined remote working directory, instead of
  running over SSH with resource limits alone; C proof-of-concepts compile
  with sanitizers for reliable crash attribution (issue #51).
- Task-engine correctness: a status flip that means a job is runnable
  (requeue-failed, resume-from-paused) now also enqueues the job to the
  queue instead of leaving it to be reaped; task functions are registered
  and enqueued under a fully-qualified module-scoped name so two modules
  declaring a same-named task can no longer route to the wrong body;
  cancel covers the dead-letter terminal; the conflict-retry backoff uses
  the correct 0-indexed interval; task-list and DAG-validation queries are
  bounded; and dead reaper code was removed (issue #40).
- The workflow-run route, short-memory, and summary JSON columns are stored
  as JSONB instead of text, so they are queryable and shape-checked at the
  database while reads and writes go through native objects uniformly across
  the async and sync database drivers; existing substring matching over the
  route JSON is preserved (issue #45).
- Team isolation is enforced across the investigation engine's database
  access, not just the API surface. The team context is carried in an ambient
  run scope set at each API request and each worker task, so bare UnitOfWork
  usage, the service factory's services, and every database-backed tool filter
  to the caller's team with no per-call-site plumbing; a caller with no team
  (admin) retains global access. Report file paths are confined to the report
  root, and audit-log entries take the actor identity from the authenticated
  context instead of tool input (issue #53). This also closes the reporting
  cache cross-team read: those cache queries now run under the ambient team
  scope, so a team can no longer receive another team's cached report
  (issue #48).
- LLM client resilience: a retry after a tool call has already run no longer
  replays the side-effectful tool, so a transient failure mid-tool-loop cannot
  duplicate messages, observables, or MCP mutations; a cancelled investigation
  aborts before the next tool fires instead of burning credits through the
  remaining retries; and the pooled HTTP client is released on worker and API
  shutdown (issue #44).
- Cancelling a task or investigation is atomic: the task-cancel repository
  helper no longer commits the caller's session mid-operation, so a failure
  while updating the sibling investigation row can no longer leave the task
  cancelled while the investigation stays running; the queue in-progress key
  is dropped after the transaction commits (issue #63).
- Runtime orchestration correctness: a routing failure no longer masks the
  original error during run finalization; each domain error (authentication,
  rate limit, not found, validation, upstream, timeout) now returns its own
  HTTP status instead of a blanket 500, so clients can distinguish and retry
  correctly; the platform timeout error was renamed so it no longer shadows
  the builtin; platform initialization is single and idempotent behind a
  lazily created lock; and the rate limiter bounds wait time instead of
  accumulating unbounded debt under burst. The request orchestrator no longer
  pins a pooled database connection across the multi-second LLM routing call
  and module dispatch (issue #54, issue #63).
- A forensics helper script that exits non-zero is surfaced as an explicit
  failure (an ok flag plus an error marker in stderr) instead of reading as
  empty-output success, and the fuzz-crash scraper rejects symlinks that
  resolve outside the storage root so they cannot leak arbitrary host file
  content into a report (issue #58).
- Single-resource endpoints in the investigation module routers (branch,
  outcome, workspace, target, project, finding, pattern, family, playbook,
  and the message SSE stream) verify the caller's team owns the parent
  investigation or workspace before returning or mutating a row, so a
  cross-team identifier can no longer read or change another team's data;
  admin retains cross-team access (issue #57).
- API multi-tenant and credential-leak residuals in the auth surface are
  closed: shared saved filters are scoped to the caller's team instead of
  every team, auto-provisioned OIDC users receive the role from their
  id_token claims instead of a fixed operator role, and the user refresh
  token is sent in the request body instead of the URL query string where
  it leaked into access logs and browser history (the query-parameter form
  is now rejected) (issue #36).
- Scheduled automations acquire a cross-process occurrence lock and record
  run-history, so two live worker processes no longer double-fire the same
  scheduled run; execution degrades to a database unique constraint when the
  lock backend is unavailable (issue #46).
- Platform contract modules declare `__all__`, and the budget config and state
  contracts reject undeclared fields; the obligation-adjudication contract
  gained direct test coverage and a docstring stating the platform runtime
  does not enforce it (issue #61).
- The test database is bootstrapped through the production create-then-stamp
  path, and a schema-parity test fails when a migration creates a table with
  no model or when the stamped revision drifts from the on-disk head
  (issue #62).
- Confidence-gate consensus retries and the verify second-model call now
  attribute their token spend to the same team as the primary call. The team
  identifier was not threaded into the pipeline context, so those derived
  calls recorded cost rows with no team and escaped per-team budget
  accounting (issue #38).
- Forensics child-table team isolation is enforced through a single documented
  join contract instead of per-endpoint ad-hoc checks, and a completeness test
  fails if a new project-scoped table ships without joining the contract
  (issue #59).
- The Alpine and Arch advisory tools run their blocking HTTP clients on a
  worker thread instead of the event loop, so a slow advisory feed no longer
  stalls concurrent investigation work (issue #64).
- Domain events now carry the ambient investigation correlation id, so the
  audit trail can tie each event to the turn that produced it; events emitted
  outside a correlation scope keep an empty id (issue #39).
- Server-sent events fan out to every live connection for a user, so a second
  browser tab for the same account receives events instead of taking them from
  the first, and closing one tab leaves the other live (issue #60).
- SSH connections reject unknown host keys by default across every connection
  surface instead of auto-adding them on first connect; hosts recorded in
  known_hosts still connect (issue #42).
- Evidence-pack section byte counts are derived from content on every access
  and can no longer be set to understate a section's size and pass the pack's
  total-size budget (issue #52).
- A config value written in one process becomes visible to peer processes
  within about a second through a Redis-backed invalidation counter, instead of
  serving stale config for the full cache TTL; the registry degrades to the
  prior TTL-only cache when Redis is unavailable (issue #56).
- New workflow-run JSON columns are validated by a database check constraint
  that rejects malformed JSON on insert and update while leaving existing rows
  untouched (issue #45).
- Knowledge-base dedup upserts serialize on a Postgres transaction advisory
  lock keyed by (namespace, dedup_key), closing the check-then-insert race
  that could create duplicate entries under concurrent ingestion; retrieval
  paths set hnsw.ef_search for better recall (issue #37).
- The Idempotency-Key middleware namespaces its Redis cache by the caller's
  credential, so a key replayed by a different principal can no longer read
  another tenant's cached response (issue #57).
- Specialist investigation branches (spawned on demand for a capability
  such as variant hunting or cryptography) no longer emit a per-turn
  routing error. The branch `persona_voice` contract is an open string,
  but the persona-to-task-type router still cast every voice through the
  fixed six-persona enum and logged a failure for any specialist voice.
  The router now coerces unknown voices to the default routing without
  raising, so specialist branches route cleanly and the log is quiet.
- An empty-choices response from the LLM gateway now raises a clear,
  retryable provider error instead of an opaque list-index error. The
  chat and tool-loop paths indexed the first completion choice without
  checking that the provider returned any, so a gateway that dropped a
  turn surfaced as an unhelpful IndexError.
- Synthesis now runs on multi-phase investigations, so the consolidated
  verdict addresses the investigation's actual question instead of one
  narrow phase's scoped answer. The dispatch hub finalises an
  investigation through the emit state (hub_stalled with no fresh outcome
  id) before the asynchronous synthesis task runs, and two gates blocked
  it there: the emit synthesis trigger fired only when a fresh outcome id
  was present, and the synthesis runner refused any non-live
  investigation. Both are fixed -- the emit trigger also fires on terminal
  completion, and COMPLETED is now a synthesizable status (PAUSED /
  FAILED / ABANDONED stay excluded so a pause or abandon mid-run still
  aborts the write). Without this, a source-repo investigation that walked
  several audit phases surfaced the last phase's answer (for example a
  crypto-audit negative) as the headline instead of the consolidated panel
  verdict.
- Draft-outcome reviewers are now shown the finding they vote on. The
  submit-block review directive listed each pending draft by id, kind,
  and confidence only, and the emit-time review notice showed the first
  400 characters of the raw payload JSON (brace and key plumbing, the
  finding cut mid-token), so a sibling could not judge the draft and
  abstained. A shared `summarize_outcome_for_review` helper now extracts
  the finding text (`answer` for vr, `headline_verdict` for malware) plus
  a few high-signal fields, sanitises it against prompt injection, and
  both the review directive and the review notice render that excerpt.
- Sibling `request_edit` review suggestions now reach the outcome. A
  `request_edit` vote's `suggested_edits` and the reviewer comment were
  written to the review row and never read back: the synthesis agent,
  documented as the sole consumer, had no step that loaded them, so every
  requested correction was silently dropped. The synthesis runner now
  loads every review on the canonical outcome and both module renderers
  surface the vote, comment, and suggested_edits to the synthesiser, so
  the consolidated verdict honors a requested confidence change, corrects
  a claim a reviewer flagged as wrong, and names a dissent instead of
  dropping it.
- Dispatch-hub audit phases activate on the target's kind instead of
  waiting for a shared-ledger discovery. Gating source_audit, variant_hunt,
  binary_audit, and mobile_audit on discoveries alone stalled the hub when
  recon posted none, and let a source-repo investigation walk into
  binary_audit or mobile_audit, whose server allowlist blocks the source
  path. Each audit phase is now scoped to the target payloads it can
  operate on (source_audit to source repositories; variant_hunt to source
  and binary; binary_audit to native binaries, archives, and images;
  mobile_audit to Android and iOS packages); poc_development stays gated on
  a quorum-confirmed finding.
- `read_function` returns real source instead of looping when a function is
  absent from the index. After the class-rewrite and bare-name retries miss
  (the function simply was not captured by the indexer), the bridge now
  auto-falls back: with a `file_path` it reads that file's first 400 lines
  from disk (bypassing the indexer); otherwise it runs `semantic_search` on
  the name and returns the top match. Previously the only output was a
  suggestion-only error the agent ignored, repeating the call until the
  3-strike hard-block.
- `read_function` auto-retries with the bare method name when a
  class-qualified name is not indexed. Agents over-qualify (a class-scoped
  method name) but trailmark keys the function index on the bare name; the
  bridge previously only appended nearest-name suggestions, and the agent
  repeated the qualified name until the 3-strike hard-block. It now retries
  once with the tail after the last separator and returns the body if it
  resolves, saving the wasted turns.
- The discovery-driven dispatch hub no longer stalls at recon. Recon
  agents route their target characterization into `hypotheses` (and a
  terminal scoping outcome), not ledger notes, so the audit phases -- which
  gate on `make_discovery_condition('discovery')` -- never activated: the
  hub raised a `no activatable phase` replan, nobody ratified it, and the
  branch short-circuited to a draft. Two fixes: (1) recon hypotheses are
  coerced into ledger discoveries (idempotent per hypothesis id), the feeder
  that unlocks `source_audit`/`variant_hunt`; (2) the hub gets its own recon
  directive that tells the agent to surface discoveries and NOT submit a
  terminal finding during recon (the V2 kind-router directive told it to
  submit, which ends the branch under the hub). Verified: a fresh run posts
  9 discoveries with zero replan requests.
- audit_mcp tool calls now always use the investigation's one resolved
  index. The executor previously rewrote only a hardcoded blocklist of
  placeholder `index_id` values (`main`, `primary`, `head`, ...); a model
  that invented any other value (`code_graph`, etc.) had it passed through
  unchanged, producing `Unknown index` / `not indexed` errors and wasted
  turns. A VR investigation is bound to exactly one audit_mcp index, so the
  executor now forces that resolved index on every audit_mcp call and
  ignores the model-supplied value entirely, eliminating the whole class of
  wrong-index tool failures.
- The investigation branch list (`/vr/investigations/{id}/branches`) and the
  branch SSE event no longer 500 when an investigation contains an on-demand
  specialist branch. `VRBranchSummary.persona_voice` was typed as the
  `PersonaVoice` enum, which rejected specialist voice identifiers (`re`,
  `exploit-dev`, etc.); it is now a plain string, since specialists are
  user-extensible. Without this the entire detail page lost its branch and
  agent-name display for any investigation that spawned a specialist.
- Per-phase prompt selection now works: a dispatch phase's `strategy_family`
  overrides the investigation-level prompt family (threaded loop ->
  `_directive.phase_strategy_family` observable -> turn runner), falling back
  to the investigation family when a phase sets none. The field was
  previously declared but ignored.
- The dispatch hub's overall-turn budget guard is now fed: a phase loop that
  exits on its turn cap sets `_budget_exhausted` once the branch's cumulative
  turns reach the overall cap, so the hub stops the walk within a single task
  instead of relying only on the re-enqueue cap.
- Quorum-approved findings now confirm the proposing branch's discoveries on
  the shared ledger (RFC-13 Phase 4). Previously nothing wrote ledger
  decision entries, so no discovery was ever confirmed: the confirmed-trust
  dispatch phases (poc_development) could never activate and replan requests
  could never ratify. The outcome-review quorum and the ledger oracle were
  disconnected; approving a finding now bridges them.
- A multi-branch finding whose siblings all go idle before reaching quorum is
  held as a draft for operator review instead of auto-approving with no
  corroboration. The single-branch no-siblings case still auto-approves
  (there is genuinely no one to vote).
- Sibling deliberation cycled until the auto-continue cap on any finding
  that drew a split vote. Under near-unanimous quorum a single abstain or
  request_edit made approval unreachable, so the outcome stayed draft and
  auto-deliberation resurrected already-voted completed siblings on every
  setup re-entry (turn count reset, prior messages deleted), producing no
  new votes and no convergence. Auto-deliberation now leaves a completed
  sibling completed when it has no unvoted pending draft, so a fully-
  deliberated finding settles: the panel goes quiet, the investigation
  completes, and an unapproved draft is held for operator review instead
  of churning.
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
- A non-retryable provider `LLMError` raised during a reasoning turn
  escaped the turn runner uncaught (it is a direct `Exception` subclass,
  absent from the builtin-error except tuple that wraps engine failures as
  the module researcher error). It crashed the phase state, failed the
  task, and flipped the whole investigation to FAILED, which then starved
  every sibling branch at the setup status-lock and left the dispatch hub
  completing with zero turns. Such errors are now wrapped as the module
  researcher error, so the investigation stays RUNNING, other branches
  continue, and auto_continue re-enqueues the affected branch.
- Reasoning turns sent a strict `json_schema` response format built from
  `ReasoningTurnDecision`, whose free-form dict fields (observables,
  payload, edit_patches) cannot be expressed in strict structured-output
  mode. Strict OpenAI-compatible providers rejected the schema outright,
  so every reasoning turn failed on those providers. `chat_json` now
  retries the same call in `json_object` mode with the schema appended to
  the prompt when a provider rejects the strict schema, so reasoning turns
  run across both strict and lenient providers.
- Dispatch-hub investigations advanced every branch to zero turns and then
  spun into a task runaway. The hub forwarded the last phase loop's stale
  `max_turns` exit reason to the emit state, so auto_continue re-enqueued
  the branch on every hub completion; each re-enqueue started a fresh
  workflow run at setup, and the setup reactivation path reset an
  abandoned branch's turn count and deleted its messages, while a dedup
  hash mismatch let duplicate per-branch tasks accumulate (observed: 563
  tasks for one investigation). The hub now stamps an explicit terminal
  exit reason (`hub_complete` / `hub_stalled` / `hub_budget_exhausted`) on
  its emit transitions, auto_continue skips those reasons and is bounded
  by a per-branch cycle ceiling, the dispatch walk and cycle counter
  persist across re-enqueues, and a branch-scoped dedup suppresses
  duplicate per-branch tasks.
- Recon-phase findings were written to the shared ledger as `note`
  entries, but the discovery-driven audit phases (source_audit,
  variant_hunt, binary_audit, mobile_audit, poc_development) activate only
  on `discovery` entries, so the phase graph never advanced past recon.
  Recon `note` writes are now recorded as `discovery` so the audit phases
  can activate.
- A branch that reissued an identical blocked tool call burned turns
  without limit; after three consecutive hard-blocked calls the branch
  loop now exits cleanly.
- The pre-submit draft-pending gate could reject a branch's terminal
  submit indefinitely; it now forces the submit through after a
  configurable rejection cap (`draft_pending_reject_cap`), matching the
  variant-hunt and unresolved-hypothesis submit gates.

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
