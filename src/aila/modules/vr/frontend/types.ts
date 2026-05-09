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

export interface VRTarget {
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

export interface VRProjectCreate {
  name: string;
  cve_id?: string | null;
  target: VRTarget;
  patched_target?: VRTarget | null;
  context_notes: string;
  analysis_system_id: number;
  poc_system_id?: number | null;
}

export interface VRProjectSummary {
  id: string;
  name: string;
  cve_id?: string | null;
  status: VRProjectStatus;
  target_class: TargetClass;
  input_source?: string | null;
  target_format?: string | null;
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
