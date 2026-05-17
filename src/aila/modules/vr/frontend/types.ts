/**
 * TypeScript shapes for the VR module's HTTP contract. Mirrors the Pydantic
 * models in `src/aila/modules/vr/contracts/`. When the Python contract changes
 * the values here MUST be updated to match.
 */

export type InputSource = "upload" | "git_repo" | "http_url";

export type TargetFormat =
  | "elf"
  | "pe_exe"
  | "pe_dll"
  | "pe_sys"
  | "macho"
  | "apk"
  | "ipa"
  | "jar"
  | "war"
  | "aar"
  | "dotnet"
  | "source_archive"
  | "source_tree"
  | "git_repo"
  | "raw_binary";

export type TargetClass =
  | "native"
  | "kernel"
  | "hypervisor"
  | "jvm"
  | "python"
  | "javascript"
  | "php"
  | "go"
  | "rust"
  | "android"
  | "ios"
  | "dotnet";

export type VRProjectStatus =
  | "created"
  | "analyzing"
  | "completed"
  | "failed"
  | "stalled";

export type CrashType =
  | "overflow_stack"
  | "overflow_heap"
  | "uaf"
  | "double_free"
  | "type_confusion"
  | "format_string"
  | "integer_overflow"
  | "null_deref"
  | "oob_read"
  | "oob_write"
  | "arw"
  | "aar"
  | "aaw"
  | "rip_control"
  | "leak_stack"
  | "leak_heap"
  | "leak_libc"
  | "leak_pie"
  | "info_disclosure"
  | "cmd_injection"
  | "deser_gadget"
  | "ssti"
  | "sqli"
  | "ssrf";

export type DisclosureStatus =
  | "undisclosed"
  | "reported"
  | "acknowledged"
  | "patch_pending"
  | "patched"
  | "public";

/**
 * Ingestion request shape — describes HOW a binary reaches AILA. The
 * api_router materializes this into a persistent vr_targets row before
 * creating the project. Renamed from VRTarget in the M3.T-1 Stage 2
 * refactor (D-53) to disambiguate from the persistent VRTargetSummary.
 */
export interface TargetIngestionSpec {
  input_source: InputSource;
  target_format?: TargetFormat | null;
  target_class: TargetClass;
  source_available: boolean;
  upload_filename?: string | null;
  upload_sha256?: string | null;
  repo_url?: string | null;
  vulnerable_ref?: string | null;
  patched_ref?: string | null;
  build_command?: string | null;
  build_artifact?: string | null;
  download_url?: string | null;
  binary_id?: string | null;
}

/** Workspace = thematic project per D-49. */
export type WorkspaceTheme =
  | "browser_engines"
  | "linux_kernel"
  | "container_runtimes"
  | "industrial_scada"
  | "mobile_baseband"
  | "custom";

export type WorkspaceStatus = "active" | "archived";

export interface VRWorkspaceCreate {
  name: string;
  slug: string;
  description?: string;
  theme?: WorkspaceTheme;
}

export interface VRWorkspaceSummary {
  id: string;
  name: string;
  slug: string;
  description: string;
  theme: WorkspaceTheme;
  status: WorkspaceStatus;
  target_count: number;
  active_investigation_count: number;
  created_at?: string | null;
  updated_at?: string | null;
}

/** Persistent target identity per D-49/D-50. */
export type TargetKind =
  | "native_binary"
  | "source_repo"
  | "cve"
  | "protocol_capture"
  | "crash_input"
  | "patch_diff"
  | "apk"
  | "ipa"
  | "jar"
  | "dotnet_assembly"
  | "kernel_image"
  | "kernel_module"
  | "hypervisor_image";

export type TargetStatus = "active" | "archived" | "quarantined";

export type AnalysisState = "pending" | "ingesting" | "ready" | "failed";

export type TargetTagSource = "operator" | "system" | "pattern";

export interface TargetTag {
  tag: string;
  source: TargetTagSource;
}

export interface VRTargetCreate {
  workspace_id: string;
  display_name: string;
  kind: TargetKind;
  descriptor?: Record<string, unknown>;
  primary_language?: string | null;
  secondary_languages?: string[];
  tags?: string[];
}

export interface VRTargetSummary {
  id: string;
  workspace_id: string;
  display_name: string;
  kind: TargetKind;
  descriptor: Record<string, unknown>;
  uploaded_filename?: string | null;
  primary_language?: string | null;
  secondary_languages: string[];
  status: TargetStatus;
  analysis_state: AnalysisState;
  analysis_state_message?: string | null;
  analysis_started_at?: string | null;
  analysis_completed_at?: string | null;
  tags: TargetTag[];
  created_at?: string | null;
  updated_at?: string | null;
}

export interface VRProjectCreate {
  name: string;
  workspace_id: string;
  cve_id?: string | null;
  target: TargetIngestionSpec;
  patched_target?: TargetIngestionSpec | null;
  context_notes: string;
  analysis_system_id: number;
  poc_system_id?: number | null;
}

export interface VRProjectSummary {
  id: string;
  name: string;
  cve_id?: string | null;
  status: VRProjectStatus;
  workspace_id?: string | null;
  target_id?: string | null;
  patched_target_id?: string | null;
  finding_count: number;
  created_at?: string | null;
  operator_id?: string | null;
  latest_disclosure_status?: string | null;
  disclosure_submission_count?: number;
  analysis_system_id?: number | null;
  poc_system_id?: number | null;
}

export interface CrashSignature {
  crash_type: CrashType;
  frames: string[];
  signature_hash: string;
}

export interface PoCResult {
  code: string;
  language: string;
  crashes_vulnerable: number;
  crashes_patched: number;
  asan_report: string;
  exit_code?: number | null;
}

export interface VRFinding {
  id?: string | null;
  project_id: string;
  crash_type?: CrashType | null;
  crash_signature?: CrashSignature | null;
  root_cause: string;
  vulnerable_function: string;
  poc?: PoCResult | null;
  advisory_id?: string | null;
  disclosure_status: DisclosureStatus;
  vendor_contact?: string | null;
  reported_at?: string | null;
  embargo_until?: string | null;
  assigned_cve_id?: string | null;
  patch_version?: string | null;
}

export interface DisclosureUpdate {
  disclosure_status: DisclosureStatus;
  vendor_contact?: string | null;
  assigned_cve_id?: string | null;
  patch_version?: string | null;
}

/** Standard envelope shape returned by every VR endpoint (DataEnvelope[T]). */
export interface Envelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

/** Pagination metadata embedded in `Envelope.meta` for list endpoints. */
export interface PaginatedMeta {
  total: number;
  offset: number;
  limit: number;
}

/** Subset of ManagedSystem fields surfaced by GET /systems. */
export interface RegisteredSystem {
  id: number;
  name: string;
  host: string;
  username: string;
  port: number;
}

/** Investigation kinds matching M3.R-1 InvestigationKind enum. */
export type InvestigationKind =
  | "discovery"
  | "variant_hunt"
  | "triage"
  | "n_day"
  | "audit";

/** Investigation lifecycle states. */
export type InvestigationStatus =
  | "created"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "abandoned";

export type InvestigationPauseReason =
  | "operator"
  | "low_confidence"
  | "cost_budget"
  | "awaiting_campaign"
  | "awaiting_mcp";

export type BranchStatus =
  | "active"
  | "paused"
  | "merged"
  | "promoted"
  | "abandoned";

export type PersonaVoice =
  | "halvar" | "maddie" | "yuki" | "renzo" | "noor" | "wei";

export type SenderKind = "engine" | "operator";

export type PayloadKind =
  | "text"
  | "tool_call"
  | "code_pointer"
  | "graph_view"
  | "taint_flow"
  | "xref_view"
  | "patch_diff"
  | "decompiled_function"
  | "hypothesis_update"
  | "outcome_pending";

export type OperatorIntent =
  | "steering" | "question" | "correction"
  | "dismissal" | "outcome_selection"
  | "branch_command" | "unclassified";

export type OutcomeKind =
  | "assessment_report" | "strategy_descriptor" | "profile_spec_draft"
  | "config_delta" | "variant_hunt_order" | "patch_assessment_report"
  | "audit_memo" | "direct_finding" | "crash_triage_report"
  | "campaign_launch" | "sub_investigation";

export type OutcomeConfidence =
  | "exact" | "strong" | "medium" | "caveated" | "unknown";

export type OutcomeDispatchStatus =
  | "pending" | "dispatched" | "failed" | "skipped";

export interface VRInvestigationSummary {
  id: string;
  title: string;
  target_id: string;
  workspace_id?: string | null;
  parent_investigation_id?: string | null;
  kind: InvestigationKind;
  status: InvestigationStatus;
  pause_reason?: InvestigationPauseReason | null;
  auto_pilot: boolean;
  strategy_family: string;
  cost_budget_usd: number;
  cost_actual_usd: number;
  llm_tokens_cost_usd: number;
  mcp_calls_cost_usd: number;
  fuzz_infra_cost_usd: number;
  branch_count: number;
  message_count: number;
  outcome_count: number;
  primary_outcome_id?: string | null;
  linked_campaign_ids: string[];
  linked_finding_ids: string[];
  started_at?: string | null;
  stopped_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface VRBranchSummary {
  id: string;
  investigation_id: string;
  parent_branch_id?: string | null;
  status: BranchStatus;
  persona_voice?: PersonaVoice | null;
  fork_reason: string;
  fork_at_turn?: number | null;
  turn_count: number;
  branch_cost_usd: number;
  closed_reason: string;
  merged_into_branch_id?: string | null;
  promoted: boolean;
  closed_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  strategy_family?: string | null;
}

export interface VRMessageSummary {
  id: string;
  investigation_id: string;
  branch_id: string;
  sender_kind: SenderKind;
  sender_id?: string | null;
  payload_kind: PayloadKind;
  payload: Record<string, unknown>;
  operator_intent?: OperatorIntent | null;
  at_turn?: number | null;
  evidence_refs: string[];
  created_at?: string | null;
}

export interface VROutcomeSummary {
  id: string;
  investigation_id: string;
  branch_id: string;
  outcome_kind: OutcomeKind;
  payload: Record<string, unknown>;
  confidence: OutcomeConfidence;
  evidence_refs: string[];
  accepted_by_operator: boolean;
  accepted_at?: string | null;
  dispatch_status: OutcomeDispatchStatus;
  dispatch_target?: string | null;
  created_at?: string | null;
}

// ─── Pattern catalog (Knowledge Transfer plan) ─────────────────────────────

export type PatternKind =
  | "exploitation_technique"
  | "fuzzing_strategy"
  | "search_heuristic"
  | "tool_recipe"
  | "triage_rule";

export type PatternStatus = "draft" | "active" | "archived";
export type PatternScope = "local" | "workspace" | "team" | "global";
export type PatternConfidence =
  | "exact"
  | "strong"
  | "medium"
  | "caveated"
  | "unknown";

export interface VRPatternSummary {
  id: string;
  workspace_id: string;
  investigation_id?: string | null;
  kind: PatternKind;
  summary: string;
  body: string;
  applicability: Record<string, unknown>;
  confidence: PatternConfidence;
  evidence_refs: string[];
  status: PatternStatus;
  scope: PatternScope;
  superseded_by?: string | null;
  knowledge_entry_id?: number | null;
  times_retrieved: number;
  last_used_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

// ─── Disclosure lifecycle (Disclosure Lifecycle plan) ──────────────────────

export type DisclosureKind =
  | "bounty"
  | "broker"
  | "coordination"
  | "vendor_direct"
  | "cna"
  | "public"
  | "academic";

export type DisclosureSubmissionStatus =
  | "drafted"
  | "submitted"
  | "acknowledged"
  | "triaging"
  | "accepted"
  | "rejected"
  | "patched"
  | "published"
  | "closed"
  | "withdrawn";

export type ArtifactTier = "working_poc" | "sanitized_poc" | "no_poc";

export interface DisclosureTrackInfo {
  track_id: string;
  kind: DisclosureKind;
  display_name: string;
  program_url?: string | null;
  required_artifacts: string[];
  accepted_poc_tiers: ArtifactTier[];
  embargo_default_days?: number | null;
  severity_schema: string;
  notes: string;
}

export interface VRDisclosureSubmissionSummary {
  id: string;
  finding_id: string;
  track_id: string;
  workspace_id: string;
  kind: DisclosureKind;
  status: DisclosureSubmissionStatus;
  poc_tier: ArtifactTier;
  severity_rating?: string | null;
  embargo_until?: string | null;
  embargo_days_used?: number | null;
  vendor_reference?: string | null;
  bounty_awarded_usd?: number | null;
  rendered_submission_path?: string | null;
  notes: string;
  validation_errors: string[];
  track_info?: DisclosureTrackInfo | null;
  created_at?: string | null;
  updated_at?: string | null;
  sections?: Record<string, string>;
  regenerated_from_finding_at?: string | null;
}

export interface RenderedSubmission {
  submission_id: string;
  track_id: string;
  finding_id: string;
  rendered_at: string;
  body: string;
  body_format: string;
  metadata: Record<string, unknown>;
  validation_errors: string[];
}

// ─── Fuzzing (Fuzzing plan) ────────────────────────────────────────────────

export type FuzzEngineId =
  | "afl++"
  | "afl++_qemu"
  | "libfuzzer"
  | "honggfuzz"
  | "fuzzilli_v8"
  | "v8_d8_sbx"
  | "jazzer"
  | "cargo-fuzz"
  | "go-fuzz"
  | "atheris";

export type FuzzStrategyId =
  | "mutational"
  | "coverage_guided"
  | "differential"
  | "generative"
  | "grammar";

export type CampaignStatus =
  | "created"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "aborted";

export type CrashTriageVerdict =
  | "untriaged"
  | "security_relevant"
  | "likely_harmless"
  | "duplicate"
  | "needs_manual_review";

export type CrashSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational"
  | "unknown";

export interface VRFuzzCampaignSummary {
  id: string;
  target_id: string;
  workspace_id: string;
  name: string;
  engine_id: FuzzEngineId;
  strategy_id: FuzzStrategyId;
  engine_config: Record<string, unknown>;
  strategy_config: Record<string, unknown>;
  status: CampaignStatus;
  duration_hours?: number | null;
  analysis_system_id?: number | null;
  remote_pid?: number | null;
  remote_corpus_dir?: string | null;
  remote_crashes_dir?: string | null;
  launched_at?: string | null;
  launch_log?: string | null;
  execs_per_sec?: number | null;
  total_execs: number;
  corpus_size: number;
  coverage_pct?: number | null;
  crashes_found: number;
  started_at?: string | null;
  stopped_at?: string | null;
  last_progress_at?: string | null;
  notes: string;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface VRFuzzCrashSummary {
  id: string;
  campaign_id: string;
  stack_hash: string;
  crash_type?: string | null;
  crash_signature?: string | null;
  severity: CrashSeverity;
  triage_verdict: CrashTriageVerdict;
  triage_reason?: string | null;
  duplicate_of_crash_id?: string | null;
  promoted_to_finding_id?: string | null;
  reproducer_path?: string | null;
  reproducer_size_bytes?: number | null;
  stack_trace?: string | null;
  extra: Record<string, unknown>;
  discovered_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

// ─── MCP server registry projection (operator-visible) ─────────────────

export type McpServerStatus = "reachable" | "unreachable";
export type McpServerUrlSource = "env" | "config" | "default";

export interface McpServerSummary {
  id: string;                          // 'audit_mcp' | 'ida_headless'
  name: string;                        // human display name
  description: string;                 // what this MCP owns
  base_url: string;                    // currently resolved URL
  base_url_source: McpServerUrlSource; // where the URL came from
  default_url: string;                 // built-in default
  env_var: string;                     // env var name (op reference only)
  config_key: string;                  // vr.<key> for PATCH
  status: McpServerStatus;             // reachability verdict
  latency_ms: number | null;           // probe round-trip
  tool_count: number;                  // distinct /tools/* endpoints
  tools: string[];                     // sorted tool names
  last_probed_at: string;              // ISO 8601
  error: string | null;                // when status='unreachable'
}

// ─── MCP call log (operator audit trail) ───────────────────────────────

export interface McpCallLogEntry {
  id: string;
  server_id: string;          // 'audit_mcp' | 'ida_headless'
  base_url: string;           // resolved URL at call time
  action: string;             // MCP tool name
  status: string;             // 'ready' | 'pending' | 'error'
  http_status: number | null;
  latency_ms: number | null;
  error_excerpt: string | null;
  called_at: string;          // ISO 8601
}
