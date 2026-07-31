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

### Changed

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

### Removed

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

### Fixed

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
