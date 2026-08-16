/**
 * React-query hooks for creating VR / malware targets and investigations, plus
 * a couple of thin list queries the intake and upload wizards need to render
 * their pickers.
 *
 * All list GETs go through the platform DataEnvelope: `apiFetch` unwraps the
 * `{data}` layer so a `list_targets` response returns `Target[]` directly.
 * Every mutation invalidates the DataPage cache key its list page reads from
 * (`["datapage", "/<module>/<resource>"]`) plus the LeftRail cache key for
 * investigations (`["vr", "investigations"]`), so the console refreshes as
 * soon as the operator finishes a create flow.
 *
 * FormData bodies here rely on the FormData guard in `client.ts`: the wrapper
 * skips its default `Content-Type: application/json` stamp when the body is a
 * `FormData` instance so the browser writes the multipart boundary itself.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/* ============================================================================
 * Shared list queries used by the wizards
 * ==========================================================================*/

export interface WorkspaceRow {
  id: string;
  name: string;
  slug?: string;
  status?: string;
}

/** GET /{module}/workspaces -- backing the workspace select in every wizard. */
export function useWorkspaces(
  module: "vr" | "malware",
): UseQueryResult<WorkspaceRow[]> {
  return useQuery({
    queryKey: ["intake", module, "workspaces"],
    queryFn: () => apiFetch<WorkspaceRow[]>(`/${module}/workspaces?limit=200`),
    staleTime: 30_000,
  });
}

export interface TargetRow {
  id: string;
  display_name: string;
  kind: string;
  workspace_id?: string;
  workspace_name?: string | null;
  status?: string;
  analysis_state?: string;
  created_at?: string | null;
}

/** GET /{module}/targets -- backing the target picker in IntakeWizard.
 * Pass `enabled: false` to keep the hook mounted for React's Rules of Hooks
 * while the wizard is on a module (vulnerability / forensics) that doesn't
 * consume this list. */
export function useTargets(
  module: "vr" | "malware",
  opts?: { workspaceId?: string | null; enabled?: boolean },
): UseQueryResult<TargetRow[]> {
  const wsId = opts?.workspaceId ?? null;
  const path = wsId
    ? `/${module}/targets?limit=200&workspace_id=${encodeURIComponent(wsId)}`
    : `/${module}/targets?limit=200`;
  return useQuery({
    queryKey: ["intake", module, "targets", wsId ?? ""],
    queryFn: () => apiFetch<TargetRow[]>(path),
    staleTime: 15_000,
    enabled: opts?.enabled ?? true,
  });
}

/* ============================================================================
 * VR target creation
 * ==========================================================================*/

export type VRTargetKind =
  | "native_binary"
  | "source_repo"
  | "cve"
  | "protocol_capture"
  | "crash_input"
  | "patch_diff"
  | "android_apk"
  | "ipa"
  | "jar"
  | "dotnet_assembly"
  | "kernel_image"
  | "kernel_module"
  | "hypervisor_image";

export interface VRTargetCreatePayload {
  workspace_id: string;
  display_name: string;
  kind: VRTargetKind;
  descriptor?: Record<string, unknown>;
  primary_language?: string | null;
  secondary_languages?: string[];
  tags?: string[];
}

export interface CreatedVRTarget {
  id: string;
  display_name: string;
  kind: string;
  workspace_id?: string;
  status?: string;
  analysis_state?: string;
  uploaded_filename?: string | null;
}

/** POST /vr/targets -- descriptor-only create for kinds that don't take a
 * binary upload (source_repo, cve, patch_diff, protocol_capture, crash_input).
 * The upload path uses `useUploadVrBinary` after this returns.
 */
export function useCreateVrTarget(): UseMutationResult<
  CreatedVRTarget,
  Error,
  VRTargetCreatePayload
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body) =>
      apiFetch<CreatedVRTarget>("/vr/targets", {
        method: "POST",
        body: JSON.stringify({
          descriptor: {},
          secondary_languages: [],
          tags: [],
          ...body,
        }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datapage", "/vr/targets"] });
      void qc.invalidateQueries({ queryKey: ["intake", "vr", "targets"] });
    },
  });
}

export interface VRUploadResult {
  task_id?: string;
  target_id: string;
  uploaded_filename: string;
}

/** POST /vr/targets/{id}/upload -- attach a binary to an existing target row
 * (native_binary, kernel_image, kernel_module, hypervisor_image, ipa, jar,
 * dotnet_assembly). The APK path is a single-shot endpoint, `useUploadApkTarget`.
 */
export function useUploadVrBinary(): UseMutationResult<
  VRUploadResult,
  Error,
  { target_id: string; file: File }
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (arg) => {
      const fd = new FormData();
      fd.append("file", arg.file, arg.file.name);
      return apiFetch<VRUploadResult>(
        `/vr/targets/${encodeURIComponent(arg.target_id)}/upload`,
        { method: "POST", body: fd },
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datapage", "/vr/targets"] });
      void qc.invalidateQueries({ queryKey: ["intake", "vr", "targets"] });
    },
  });
}

export interface VRApkUploadResult {
  target_id: string;
  uploaded_filename: string;
  uploaded_sha256: string;
  apk_path: string;
  bytes_written: number;
  enqueue_error: string | null;
}

/** POST /vr/targets/upload-apk -- single-shot create+upload for android_apk.
 * Server side runs APK_DECODE -> JADX_DECOMPILE -> INDEX_DECOMPILED ->
 * STATIC_SUMMARY automatically.
 */
export function useUploadApkTarget(): UseMutationResult<
  VRApkUploadResult,
  Error,
  { workspace_id: string; display_name: string; file: File }
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (arg) => {
      const fd = new FormData();
      fd.append("workspace_id", arg.workspace_id);
      fd.append("display_name", arg.display_name);
      fd.append("file", arg.file, arg.file.name);
      return apiFetch<VRApkUploadResult>("/vr/targets/upload-apk", {
        method: "POST",
        body: fd,
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datapage", "/vr/targets"] });
      void qc.invalidateQueries({ queryKey: ["intake", "vr", "targets"] });
    },
  });
}

/* ============================================================================
 * Malware target creation
 * ==========================================================================*/

export type MalwareTargetKind =
  | "pe_sample"
  | "elf_sample"
  | "mach_o_sample"
  | "shellcode"
  | "android_apk"
  | "dotnet_assembly"
  | "script_sample"
  | "document_sample";

export interface CreatedMalwareTarget {
  id: string;
  display_name: string;
  kind: string;
  workspace_id?: string;
  status?: string;
  analysis_state?: string;
  uploaded_filename?: string | null;
  descriptor?: Record<string, unknown>;
}

/** POST /malware/targets/upload -- single-shot create+upload for every one of
 * the eight malware target kinds. `tags` is JSON-serialized because the router
 * declares it as a `Form(str)` field with a JSON default.
 */
export function useUploadMalwareTarget(): UseMutationResult<
  CreatedMalwareTarget,
  Error,
  {
    workspace_id: string;
    display_name: string;
    kind: MalwareTargetKind;
    sample: File;
    tags?: string[];
  }
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (arg) => {
      const fd = new FormData();
      fd.append("workspace_id", arg.workspace_id);
      fd.append("display_name", arg.display_name);
      fd.append("kind", arg.kind);
      fd.append("sample", arg.sample, arg.sample.name);
      fd.append("tags", JSON.stringify(arg.tags ?? []));
      return apiFetch<CreatedMalwareTarget>("/malware/targets/upload", {
        method: "POST",
        body: fd,
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ["datapage", "/malware/targets"],
      });
      void qc.invalidateQueries({ queryKey: ["intake", "malware", "targets"] });
    },
  });
}

export interface MalwareTargetCreatePayload {
  workspace_id: string;
  display_name: string;
  kind: MalwareTargetKind;
  descriptor?: Record<string, unknown>;
  primary_language?: string | null;
  secondary_languages?: string[];
  tags?: string[];
}

/** POST /malware/targets -- descriptor-only path (URL download spec, on-disk
 * sample_path). Included for parity with VR's descriptor create; the upload
 * wizard's primary flow is `useUploadMalwareTarget`.
 */
export function useCreateMalwareTarget(): UseMutationResult<
  CreatedMalwareTarget,
  Error,
  MalwareTargetCreatePayload
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body) =>
      apiFetch<CreatedMalwareTarget>("/malware/targets", {
        method: "POST",
        body: JSON.stringify({
          descriptor: {},
          secondary_languages: [],
          tags: [],
          ...body,
        }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ["datapage", "/malware/targets"],
      });
      void qc.invalidateQueries({ queryKey: ["intake", "malware", "targets"] });
    },
  });
}

/* ============================================================================
 * Investigation creation
 * ==========================================================================*/

export type VRInvestigationKind =
  | "discovery"
  | "variant_hunt"
  | "triage"
  | "n_day"
  | "audit"
  | "masvs_audit"
  | "apk_static_audit";

export interface VRInvestigationPayload {
  title: string;
  initial_question: string;
  target_id: string;
  kind?: VRInvestigationKind;
  secondary_target_ids?: string[];
  parent_investigation_id?: string | null;
  strategy_family?: string | null;
  auto_pilot?: boolean;
  cost_budget_usd?: number;
}

export interface CreatedInvestigation {
  id: string;
  title: string;
  kind?: string;
  target_id?: string;
  status?: string;
}

/** POST /vr/investigations -- consumes VRInvestigationCreate. `title` and
 * `initial_question` are the only truly required fields alongside `target_id`;
 * `kind` / `auto_pilot` / `cost_budget_usd` default sensibly server-side, but
 * we still pass them so the operator's choices are honoured on the row.
 */
export function useCreateVrInvestigation(): UseMutationResult<
  CreatedInvestigation,
  Error,
  VRInvestigationPayload
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body) =>
      apiFetch<CreatedInvestigation>("/vr/investigations", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["vr", "investigations"] });
      void qc.invalidateQueries({
        queryKey: ["datapage", "/vr/investigations"],
      });
    },
  });
}

export type MalwareInvestigationKind =
  | "full_analysis"
  | "triage"
  | "unpack_only"
  | "config_extract"
  | "yara_generate"
  | "family_attribute";

export type AnalysisDepth = "low" | "medium" | "high" | "ultimate";

export interface MalwareInvestigationPayload {
  title: string;
  initial_question: string;
  target_id: string;
  kind?: MalwareInvestigationKind;
  secondary_target_ids?: string[];
  parent_investigation_id?: string | null;
  strategy_family?: string | null;
  auto_pilot?: boolean;
  analysis_depth?: AnalysisDepth;
  cost_budget_usd?: number;
}

/** POST /malware/investigations -- consumes MalwareInvestigationCreate.
 * `analysis_depth` is immutable after create (locked decision #8), which is
 * why the wizard surfaces it at review time.
 */
export function useCreateMalwareInvestigation(): UseMutationResult<
  CreatedInvestigation,
  Error,
  MalwareInvestigationPayload
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body) =>
      apiFetch<CreatedInvestigation>("/malware/investigations", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ["datapage", "/malware/investigations"],
      });
    },
  });
}
