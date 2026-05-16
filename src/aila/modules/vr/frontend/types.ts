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
  | "dotnet_assembly";

export type TargetStatus = "active" | "archived" | "quarantined";

export type EnrichmentStatus = "unenriched" | "running" | "complete" | "failed";

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
  primary_language?: string | null;
  secondary_languages: string[];
  status: TargetStatus;
  enrichment_status: EnrichmentStatus;
  last_enriched_at?: string | null;
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
