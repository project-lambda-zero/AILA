import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import { toast } from "@/components/ui/sonner";

import type {
  ArtifactTier,
  DisclosureSubmissionStatus,
  DisclosureUpdate,
  Envelope,
  InvestigationKind,
  OperatorIntent,
  PatternConfidence,
  PatternKind,
  PatternScope,
  PatternStatus,
  RenderedSubmission,
  TargetKind,
  VRDisclosureSubmissionSummary,
  VRFinding,
  VRFuzzCampaignSummary,
  VRFuzzCrashSummary,
  VRInvestigationSummary,
  VRMessageSummary,
  VRPatternSummary,
  VRProjectCreate,
  VRProjectSummary,
  VRTargetSummary,
  VRWorkspaceSummary,
  WorkspaceTheme,
} from "./types";

export function useCreateVRProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: VRProjectCreate) =>
      authorizedRequestJson<Envelope<VRProjectSummary>>("/vr/projects", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "projects"] });
      toast.success(`VR project "${result.data.name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Failed to create VR project: ${err.message}`);
    },
  });
}

export function useUpdateDisclosure(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      findingId,
      body,
    }: {
      findingId: string;
      body: DisclosureUpdate;
    }) =>
      authorizedRequestJson<Envelope<VRFinding>>(
        `/vr/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/disclosure`,
        {
          method: "PATCH",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: (_result, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["vr", "findings", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["vr", "finding", projectId, variables.findingId],
      });
      toast.success("Disclosure status updated");
    },
    onError: (err: Error) => {
      toast.error(`Failed to update disclosure: ${err.message}`);
    },
  });
}

export function usePauseInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/pause`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success("Investigation paused");
    },
    onError: (err: Error) => {
      toast.error(`Pause failed: ${err.message}`);
    },
  });
}

/**
 * Resume a paused investigation.
 *
 * Returns the standard useMutation result PLUS an `isResuming` boolean
 * that stays true during the API call AND for 2s after success. Callers
 * (resume button label, disabled-state) read `isResuming` instead of
 * `isPending` so the UI does not flicker from 'paused' → 'running' in
 * one frame.
 *
 * fix §54 — frontend status display when an investigation is freshly
 * RESUMED. The previous hook invalidated the investigation cache
 * immediately on success, so the refetch returned `status='running'`
 * a few hundred ms after the click — visually the stepper jumped
 * from 'paused' to 'investigation_loop' instantly, even though the
 * worker had not yet picked the task up. The 2s hold gives the
 * operator visual confirmation that resume actually fired AND lines
 * up with the wall-clock worker pickup latency observed in production
 * (typically <1s; 2s is generous headroom).
 *
 * TODO: once the API exposes
 * workflow_state_cursor.current_state, replace the hard-coded 2s
 * with a subscription that resolves when the cursor leaves
 * '__paused__'. That is the real SSOT for "worker has picked up
 * the task". Hard-coded 2s is the best the frontend can do without
 * cursor exposure.
 */
export function useResumeInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  const [postSuccessHold, setPostSuccessHold] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clear any pending timer when the consumer unmounts so the
  // setPostSuccessHold(false) below does not run on a torn-down
  // component. invalidateQueries is fine to call post-unmount —
  // queryClient outlives the component.
  useEffect(
    () => () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    },
    [],
  );

  const mutation = useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/resume`,
        { method: "POST" },
      ),
    onSuccess: () => {
      setPostSuccessHold(true);
      if (timerRef.current !== null) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        setPostSuccessHold(false);
        timerRef.current = null;
        // After the hold elapses, fetch the real state. By this point
        // the worker has typically advanced the cursor out of
        // __paused__ and the stepper renders the correct stage.
        queryClient.invalidateQueries({
          queryKey: ["vr", "investigation", investigationId],
        });
        queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      }, 2000);
      toast.success("Investigation resuming…");
    },
    onError: (err: Error) => {
      toast.error(`Resume failed: ${err.message}`);
    },
  });

  return {
    ...mutation,
    isResuming: mutation.isPending || postSuccessHold,
  };
}

export function useResetInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/reset`,
        { method: "POST" },
      ),
    onSuccess: () => {
      // Wipe every cache touching this investigation — messages,
      // branches, outcomes — so the page re-fetches the empty state.
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "messages", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "branches", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "outcomes", investigationId] });
      toast.success("Investigation reset to start — re-enqueue to run again");
    },
    onError: (err: Error) => {
      toast.error(`Reset failed: ${err.message}`);
    },
  });
}

/** Reopen a terminal investigation (COMPLETED / FAILED / ABANDONED).
 *  Non-destructive: existing branches + messages + outcomes preserved.
 *  Spawns ONE fresh primary branch with fork_reason='operator_reopen:
 *  <user>', flips investigation back to RUNNING, enqueues
 *  run_vr_investigate for the new branch. Server-side wired at
 *  vr/api_router.py::reopen_investigation. */
export function useReopenInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/reopen`,
        { method: "POST" },
      ),
    onSuccess: () => {
      // Invalidate everything that renders investigation state — the
      // status flip + new branch + new task all need fresh fetches.
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "branches", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "messages", investigationId] });
      toast.success("Investigation reopened — new branch dispatched");
    },
    onError: (err: Error) => {
      toast.error(`Reopen failed: ${err.message}`);
    },
  });
}

export type InvestigationKindOverride =
  | "discovery"
  | "variant_hunt"
  | "triage"
  | "n_day"
  | "audit";

export interface ReenqueueBody {
  /** Optional kind override — backend updates inv.kind +
   *  strategy_family before submitting the new task. Omit to keep
   *  the existing kind.
   */
  kind?: InvestigationKindOverride;
}

export function useReenqueueInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body?: ReenqueueBody) =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/re-enqueue`,
        { method: "POST", body: JSON.stringify(body ?? {}) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation-messages", investigationId] });
      toast.success("Investigation re-enqueued — agent resumes from current case state");
    },
    onError: (err: Error) => {
      toast.error(`Re-enqueue failed: ${err.message}`);
    },
  });
}

export interface SendOperatorMessageBody {
  text: string;
  branch_id?: string;
  explicit_intent?: OperatorIntent;
}

export function useSendOperatorMessage(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: SendOperatorMessageBody) =>
      authorizedRequestJson<Envelope<VRMessageSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/messages`,
        {
          method: "POST",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["vr", "investigation-messages", investigationId],
      });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      toast.success("Message sent — engine will see it next turn");
    },
    onError: (err: Error) => {
      toast.error(`Send failed: ${err.message}`);
    },
  });
}

export interface CreateInvestigationBody {
  title: string;
  initial_question: string;
  target_id: string;
  kind?: InvestigationKind;
  secondary_target_ids?: string[];
  parent_investigation_id?: string;
  strategy_family?: string;
  auto_pilot?: boolean;
  cost_budget_usd?: number;
}

export function useCreateInvestigation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateInvestigationBody) =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        "/vr/investigations",
        {
          method: "POST",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success(
        `Investigation "${result.data.title}" started — workflow firing`,
      );
    },
    onError: (err: Error) => {
      toast.error(`Create failed: ${err.message}`);
    },
  });
}

export function useToggleInvestigationFavorite() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (investigationId: string) =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/favorite`,
        { method: "PATCH" },
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success(
        result.data.is_favorite ? "Added to favorites" : "Removed from favorites",
      );
    },
    onError: (err: Error) => {
      toast.error(`Favorite toggle failed: ${err.message}`);
    },
  });
}


export function useReverifyInvestigation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (investigationId: string) =>
      authorizedRequestJson<{ task_id: string; cleared_prior_report: boolean }>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/verify`,
        { method: "POST" },
      ),
    onSuccess: (result, investigationId) => {
      // poll outcomes more aggressively for ~60s; the new verifier_report
      // lands ~30-60s after task submit
      queryClient.invalidateQueries({ queryKey: ["vr", "outcomes", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success(
        result.cleared_prior_report
          ? "Re-verify started (prior report cleared) — verdict in ~30s"
          : "Verifier started — verdict in ~30s",
      );
    },
    onError: (err: Error) => {
      toast.error(`Re-verify failed: ${err.message}`);
    },
  });
}

export function usePromoteOutcomeToFinding(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ outcomeId, reason }: { outcomeId: string; reason?: string }) =>
      authorizedRequestJson<Envelope<{
        outcome_id: string;
        promoted_to: string;
        dispatch_status: string;
        dispatch_target: string | null;
        reason: string;
      }>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/outcomes/${encodeURIComponent(outcomeId)}/promote-to-finding`,
        {
          method: "POST",
          body: JSON.stringify({ reason: reason ?? "" }),
        },
      ),
    onSuccess: (envelope) => {
      const result = envelope.data;
      queryClient.invalidateQueries({ queryKey: ["vr", "outcomes", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "findings"] });
      if (result.dispatch_status === "dispatched") {
        toast.success(
          result.dispatch_target
            ? `Promoted → direct_finding (${result.dispatch_target})`
            : "Promoted → direct_finding (dispatched)",
        );
      } else {
        toast.error(
          `Promoted but dispatch ${result.dispatch_status}: ${result.reason}`,
        );
      }
    },
    onError: (err: Error) => {
      toast.error(`Promote failed: ${err.message}`);
    },
  });
}

export interface CreateWorkspaceBody {
  name: string;
  slug: string;
  description?: string;
  theme?: WorkspaceTheme;
}

export function useCreateWorkspace() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateWorkspaceBody) =>
      authorizedRequestJson<Envelope<VRWorkspaceSummary>>("/vr/workspaces", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "workspaces"] });
      toast.success(`Workspace "${result.data.name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Create workspace failed: ${err.message}`);
    },
  });
}

export interface CreateTargetBody {
  workspace_id: string;
  display_name: string;
  kind: TargetKind;
  descriptor?: Record<string, unknown>;
  primary_language?: string;
  secondary_languages?: string[];
  tags?: string[];
}

export function useCreateTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateTargetBody) =>
      authorizedRequestJson<Envelope<VRTargetSummary>>("/vr/targets", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "targets"] });
      toast.success(`Target "${result.data.display_name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Create target failed: ${err.message}`);
    },
  });
}

/** Multipart POST to /vr/targets/upload-apk — creates a new
 * `android_apk` target with the uploaded .apk file. Backend:
 *  1. validates workspace ownership
 *  2. content-addresses the bytes (SHA-256) to
 *     `~/.android-mcp/uploads/<team>/<sha>.apk`
 *  3. creates a VRTargetRecord with kind=android_apk
 *  4. auto-enqueues the five-stage ingestion
 *     (APK_DECODE -> JADX_DECOMPILE -> INDEX_DECOMPILED ->
 *      STATIC_SUMMARY -> MOBSF_SCAN). */
export function useUploadApkTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (args: {
      workspace_id: string;
      display_name: string;
      file: File;
    }) => {
      const fd = new FormData();
      fd.append("workspace_id", args.workspace_id);
      fd.append("display_name", args.display_name);
      fd.append("file", args.file, args.file.name);
      return await authorizedRequestJson<Envelope<VRTargetSummary>>(
        "/vr/targets/upload-apk",
        { method: "POST", body: fd },
      );
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "targets"] });
      toast.success(
        `APK upload accepted: ${result.data.display_name}. Ingestion (5 stages) running in background.`,
      );
    },
    onError: (err: Error) => {
      toast.error(`APK upload failed: ${err.message}`);
    },
  });
}

/** Multipart POST to /vr/targets/{id}/upload — uploads a binary file
 * to an existing target (native_binary / kernel_image / kernel_module /
 * hypervisor_image / ipa / jar / dotnet_assembly). For android_apk use
 * `useUploadApkTarget` instead (different endpoint, different lifecycle).
 * Backend streams the bytes through to IDA-MCP and stores the returned
 * binary handle in the target. Re-triggers analysis. */
export function useUploadArtifactByTargetId() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (args: { target_id: string; file: File }) => {
      const fd = new FormData();
      fd.append("file", args.file, args.file.name);
      return await authorizedRequestJson<Envelope<Record<string, unknown>>>(
        `/vr/targets/${encodeURIComponent(args.target_id)}/upload`,
        { method: "POST", body: fd },
      );
    },
    onSuccess: (_result, vars) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "targets"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "target", vars.target_id] });
    },
    onError: (err: Error) => {
      toast.error(`Upload failed: ${err.message}`);
    },
  });
}

export function useRankTarget(targetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<{ task_id: string; target_id: string }>>(
        `/vr/targets/${encodeURIComponent(targetId)}/rank`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "target", targetId] });
      toast.success("Function ranking enqueued — refresh in 30-60s");
    },
    onError: (err: Error) => {
      toast.error(`Rank failed: ${err.message}`);
    },
  });
}

export function useAnalyzeTarget(targetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<{ task_id: string; target_id: string }>>(
        `/vr/targets/${encodeURIComponent(targetId)}/analyze`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "target", targetId] });
      toast.success("Re-analysis enqueued");
    },
    onError: (err: Error) => {
      toast.error(`Analyze failed: ${err.message}`);
    },
  });
}

export interface RefreshSourceResult {
  target_id: string;
  display_name: string;
  /** `current` (no upstream change), `refreshing` (audit-mcp rebuild
   *  started), `rebuilding` (android_apk staged-analysis re-enqueued),
   *  `error` (an MCP surfaced an error). */
  status: "current" | "refreshing" | "rebuilding" | "error" | string;
  old_sha: string | null;
  new_sha: string | null;
  index_id: string;
  forced: boolean;
  root_path: string | null;
  /** Only set on android_apk refreshes: count of stages reset back to
   *  PENDING by the backend before re-enqueueing run_target_analysis. */
  stages_reset?: number;
  /** Only set on android_apk refreshes: the new run_target_analysis
   *  task id enqueued on the vr worker queue. */
  task_id?: string;
}

/** Re-run a target's ingestion. Git-backed kinds hit audit-mcp's
 * refresh_index (idempotent when upstream did not move, returns
 * status=current). android_apk kinds reset the staged-analysis
 * checkpoints and re-enqueue the worker (returns status=rebuilding).
 */
export function useRefreshTargetSource(targetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (opts: { force?: boolean } = {}) =>
      authorizedRequestJson<Envelope<RefreshSourceResult>>(
        `/vr/targets/${encodeURIComponent(targetId)}/refresh-source${
          opts.force ? "?force=true" : ""
        }`,
        { method: "POST" },
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "target", targetId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "targets"] });
      const r = result.data;
      if (r.status === "current") {
        toast.success(
          `Source current (${(r.new_sha ?? "?").slice(0, 8)})`,
        );
      } else if (r.status === "refreshing") {
        const oldS = (r.old_sha ?? "—").slice(0, 8);
        const newS = (r.new_sha ?? "?").slice(0, 8);
        toast.success(
          `Refreshing ${r.display_name}: ${oldS} → ${newS}`,
        );
      } else if (r.status === "rebuilding") {
        const n = r.stages_reset ?? 0;
        toast.success(
          n > 0
            ? `Re-running ${r.display_name}: ${n} stage${n === 1 ? "" : "s"} reset`
            : `Re-running ${r.display_name}: staged analysis re-enqueued`,
        );
      } else {
        toast.success(`Refresh status: ${r.status}`);
      }
    },
    onError: (err: Error) => {
      toast.error(`Refresh failed: ${err.message}`);
    },
  });
}

// ─── Patterns ───────────────────────────────────────────────────────────────

export interface PatternPatchBody {
  summary?: string;
  body?: string;
  applicability?: Record<string, unknown>;
  confidence?: PatternConfidence;
  status?: PatternStatus;
  scope?: PatternScope;
  superseded_by?: string;
}

export interface PatternCreateBody {
  workspace_id: string;
  investigation_id?: string;
  kind: PatternKind;
  summary: string;
  body: string;
  applicability?: Record<string, unknown>;
  confidence?: PatternConfidence;
  evidence_refs?: string[];
  scope?: PatternScope;
}

export function useCreatePattern() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: PatternCreateBody) =>
      authorizedRequestJson<Envelope<VRPatternSummary>>("/vr/patterns", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "patterns"] });
      toast.success(`Pattern "${result.data.summary}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Failed to create pattern: ${err.message}`);
    },
  });
}

export function usePatchPattern(patternId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: PatternPatchBody) =>
      authorizedRequestJson<Envelope<VRPatternSummary>>(
        `/vr/patterns/${encodeURIComponent(patternId)}`,
        { method: "PATCH", body: JSON.stringify(body) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "patterns"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "pattern", patternId] });
      toast.success("Pattern updated");
    },
    onError: (err: Error) => {
      toast.error(`Failed to update pattern: ${err.message}`);
    },
  });
}

// ─── Disclosures ────────────────────────────────────────────────────────────

export interface DisclosureCreateBody {
  /** Exactly one of finding_id or investigation_id MUST be set. */
  finding_id?: string;
  /** Investigation anchor: the service resolves the investigation's
   *  single linked finding, OR auto-creates a stub if none exists. */
  investigation_id?: string;
  track_id: string;
  workspace_id: string;
  poc_tier?: ArtifactTier;
  severity_rating?: string;
  embargo_days_override?: number;
  notes?: string;
}

export interface DisclosurePatchBody {
  status?: DisclosureSubmissionStatus;
  poc_tier?: ArtifactTier;
  severity_rating?: string;
  embargo_days_override?: number;
  vendor_reference?: string;
  bounty_awarded_usd?: number;
  notes?: string;
}

export function useCreateDisclosure() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: DisclosureCreateBody) =>
      authorizedRequestJson<Envelope<VRDisclosureSubmissionSummary>>(
        "/vr/disclosures",
        { method: "POST", body: JSON.stringify(body) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "disclosures"] });
      toast.success("Disclosure submission created");
    },
    onError: (err: Error) => {
      toast.error(`Failed to create disclosure: ${err.message}`);
    },
  });
}

export function usePatchDisclosure(submissionId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: DisclosurePatchBody) =>
      authorizedRequestJson<Envelope<VRDisclosureSubmissionSummary>>(
        `/vr/disclosures/${encodeURIComponent(submissionId)}`,
        { method: "PATCH", body: JSON.stringify(body) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "disclosures"] });
      queryClient.invalidateQueries({
        queryKey: ["vr", "disclosure", submissionId],
      });
      toast.success("Disclosure updated");
    },
    onError: (err: Error) => {
      toast.error(`Failed to update disclosure: ${err.message}`);
    },
  });
}

export function useRenderDisclosure(submissionId: string) {
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<RenderedSubmission>>(
        `/vr/disclosures/${encodeURIComponent(submissionId)}/render`,
        { method: "POST" },
      ),
    onError: (err: Error) => {
      toast.error(`Re-render failed: ${err.message}`);
    },
  });
}

export function usePatchDisclosureSections(submissionId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (sections: Record<string, string>) =>
      authorizedRequestJson<Envelope<VRDisclosureSubmissionSummary>>(
        `/vr/disclosures/${encodeURIComponent(submissionId)}/sections`,
        { method: "PATCH", body: JSON.stringify({ sections }) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "disclosures"] });
      queryClient.invalidateQueries({
        queryKey: ["vr", "disclosure", submissionId],
      });
      toast.success("Sections saved");
    },
    onError: (err: Error) => {
      toast.error(`Failed to save sections: ${err.message}`);
    },
  });
}

export function useRegenerateDisclosureSections(submissionId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRDisclosureSubmissionSummary>>(
        `/vr/disclosures/${encodeURIComponent(submissionId)}/regenerate`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["vr", "disclosure", submissionId],
      });
      toast.success("Sections regenerated from finding");
    },
    onError: (err: Error) => {
      toast.error(`Regenerate failed: ${err.message}`);
    },
  });
}

// ─── Fuzz campaigns ─────────────────────────────────────────────────────────

export interface FuzzCampaignCreateBody {
  target_id: string;
  workspace_id: string;
  name: string;
  engine_id: string;
  strategy_id: string;
  engine_config?: Record<string, unknown>;
  strategy_config?: Record<string, unknown>;
  duration_hours?: number;
  analysis_system_id?: number | null;
  notes?: string;
}

export interface FuzzCampaignPatchBody {
  status?: string;
  notes?: string;
  duration_hours?: number;
  execs_per_sec?: number;
  total_execs?: number;
  corpus_size?: number;
  coverage_pct?: number;
  crashes_found?: number;
}

export function useCreateFuzzCampaign() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: FuzzCampaignCreateBody) =>
      authorizedRequestJson<Envelope<VRFuzzCampaignSummary>>(
        "/vr/fuzz/campaigns",
        { method: "POST", body: JSON.stringify(body) },
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "fuzz-campaigns"] });
      toast.success(`Fuzz campaign "${result.data.name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Failed to create fuzz campaign: ${err.message}`);
    },
  });
}

export function usePatchFuzzCampaign(campaignId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: FuzzCampaignPatchBody) =>
      authorizedRequestJson<Envelope<VRFuzzCampaignSummary>>(
        `/vr/fuzz/campaigns/${encodeURIComponent(campaignId)}`,
        { method: "PATCH", body: JSON.stringify(body) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "fuzz-campaigns"] });
      queryClient.invalidateQueries({
        queryKey: ["vr", "fuzz-campaign", campaignId],
      });
      toast.success("Fuzz campaign updated");
    },
    onError: (err: Error) => {
      toast.error(`Failed to update fuzz campaign: ${err.message}`);
    },
  });
}

export interface LaunchFuzzCampaignResponse {
  campaign_id: string;
  status: string;
  remote_pid?: number | null;
  remote_corpus_dir?: string | null;
  remote_crashes_dir?: string | null;
  description?: string | null;
  task_id?: string | null;
}

export function useLaunchFuzzCampaign(campaignId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ synchronous = false }: { synchronous?: boolean } = {}) =>
      authorizedRequestJson<Envelope<LaunchFuzzCampaignResponse>>(
        `/vr/fuzz/campaigns/${encodeURIComponent(campaignId)}/launch?synchronous=${synchronous}`,
        { method: "POST" },
      ),
    onSuccess: (res) => {
      queryClient.invalidateQueries({
        queryKey: ["vr", "fuzz-campaign", campaignId],
      });
      queryClient.invalidateQueries({ queryKey: ["vr", "fuzz-campaigns"] });
      const r = res?.data;
      if (r?.status === "queued") {
        toast.success(`Launch queued (task ${r.task_id?.slice(0, 8) ?? "?"})`);
      } else if (r?.status === "launched") {
        toast.success(`Fuzzer launched · remote PID ${r.remote_pid ?? "?"}`);
      } else if (r?.status === "already-running") {
        toast.info(`Already running · PID ${r.remote_pid ?? "?"}`);
      } else {
        toast.success("Launch request accepted");
      }
    },
    onError: (err: Error) => {
      toast.error(`Launch failed: ${err.message}`);
    },
  });
}

// ─── MCP server retarget ───────────────────────────────────────────────

export function useUpdateMcpServer() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      serverId,
      baseUrl,
    }: {
      serverId: string;
      baseUrl: string;
    }) =>
      await authorizedRequestJson<Envelope<unknown>>(
        `/vr/mcp/servers/${encodeURIComponent(serverId)}`,
        { method: "PATCH", body: { base_url: baseUrl } },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "mcp-servers"] });
      toast.success("MCP server updated");
    },
    onError: (err: Error) => {
      toast.error(`Failed to update MCP server: ${err.message}`);
    },
  });
}

// ─── Binary upload (multipart) ─────────────────────────────────────────
// Streams a binary through AILA → IDA MCP /upload, persists the returned
// handle on the target, then re-triggers analysis. Available for the
// upload-capable kinds: native_binary, kernel_image, kernel_module,
// hypervisor_image, apk, ipa, jar, dotnet_assembly.

export function useUploadTargetArtifact(targetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (file: File) => {
      const fd = new FormData();
      fd.append("file", file, file.name);
      // authorizedRequestJson normalizes FormData → leaves headers alone
      // so the browser sets the multipart boundary itself.
      return await authorizedRequestJson<
        Envelope<{ task_id: string; target_id: string; uploaded_filename: string }>
      >(`/vr/targets/${encodeURIComponent(targetId)}/upload`, {
        method: "POST",
        body: fd,
      });
    },
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "target", targetId] });
      toast.success(`Uploaded ${resp.data.uploaded_filename} — re-analyzing`);
    },
    onError: (err: Error) => {
      toast.error(`Upload failed: ${err.message}`);
    },
  });
}

// ─── Destructive deletes ───────────────────────────────────────────────
// All seven hit a 204 endpoint. Each invalidates list + detail query
// keys for its kind so the UI refreshes without a hard navigate. The
// caller is responsible for confirm UX + post-delete navigation.

type DeleteVariables = { id: string };

function makeDeleter(
  pathPrefix: string,
  invalidateKeys: readonly string[],
  noun: string,
) {
  return function useDeleteHook() {
    const queryClient = useQueryClient();
    return useMutation({
      mutationFn: ({ id }: DeleteVariables) =>
        authorizedRequestJson<void>(
          `${pathPrefix}/${encodeURIComponent(id)}`,
          { method: "DELETE" },
        ),
      onSuccess: () => {
        for (const key of invalidateKeys) {
          queryClient.invalidateQueries({ queryKey: ["vr", key] });
        }
        toast.success(`${noun} deleted`);
      },
      onError: (err: Error) => {
        // Most likely a 409 conflict: "has N investigation(s)" etc.
        toast.error(`Failed to delete ${noun.toLowerCase()}: ${err.message}`);
      },
    });
  };
}

export const useDeleteWorkspace = makeDeleter(
  "/vr/workspaces",
  ["workspaces", "targets", "investigations"],
  "Workspace",
);
export const useDeleteTarget = makeDeleter(
  "/vr/targets",
  ["targets", "workspaces"],
  "Target",
);
export const useDeleteInvestigation = makeDeleter(
  "/vr/investigations",
  ["investigations", "patterns"],
  "Investigation",
);
export const useDeleteProject = makeDeleter(
  "/vr/projects",
  ["projects", "findings"],
  "Project",
);
export const useDeletePattern = makeDeleter(
  "/vr/patterns",
  ["patterns"],
  "Pattern",
);
export const useDeleteDisclosure = makeDeleter(
  "/vr/disclosures",
  ["disclosures"],
  "Disclosure",
);
export const useDeleteFuzzCampaign = makeDeleter(
  "/vr/fuzz/campaigns",
  ["fuzz-campaigns", "fuzz-crashes"],
  "Fuzz campaign",
);

// ── Fuzz proposals (operator-in-the-loop) ──────────────────────────

export interface AcceptFuzzProposalBody {
  name?: string | null;
  engine_id?: string | null;
  strategy_id?: string | null;
  engine_config?: Record<string, unknown> | null;
  strategy_config?: Record<string, unknown> | null;
  duration_hours?: number | null;
  analysis_system_id?: number | null;
  auto_launch?: boolean;
  skip_prepare?: boolean;
  decision_reason?: string | null;
}

export interface AcceptFuzzProposalResponse {
  proposal_id: string;
  campaign_id: string;
  workdir: string;
  harness_path: string | null;
  seeds_written: number;
  dictionary_written: boolean;
  auto_launched: boolean;
  build_log: string;
}

export function useAcceptFuzzProposal(proposalId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: AcceptFuzzProposalBody) =>
      authorizedRequestJson<Envelope<AcceptFuzzProposalResponse>>(
        `/vr/fuzz/proposals/${encodeURIComponent(proposalId)}/accept`,
        { method: "POST", body: JSON.stringify(body) },
      ),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "fuzz-proposals"] });
      queryClient.invalidateQueries({ queryKey: ["vr", "fuzz-campaigns"] });
      const r = res?.data;
      if (r?.auto_launched) {
        toast.success(
          `Proposal accepted · campaign ${r.campaign_id.slice(0, 8)} launched`,
        );
      } else {
        toast.success(
          `Proposal accepted · campaign ${r?.campaign_id.slice(0, 8) ?? "?"} created`,
        );
      }
    },
    onError: (err: Error) => {
      toast.error(`Failed to accept proposal: ${err.message}`);
    },
  });
}

export function useRejectFuzzProposal(proposalId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { decision_reason: string }) =>
      authorizedRequestJson<Envelope<unknown>>(
        `/vr/fuzz/proposals/${encodeURIComponent(proposalId)}/reject`,
        { method: "POST", body: JSON.stringify(body) },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "fuzz-proposals"] });
      toast.success("Proposal rejected");
    },
    onError: (err: Error) => {
      toast.error(`Failed to reject proposal: ${err.message}`);
    },
  });
}

// ─── MASVS audit ────────────────────────────────────────────────────────────
// POST /vr/targets/{id}/masvs-audit fans one batch into one parent
// VRInvestigation (kind=masvs_audit) plus one child per OWASP MASVS L1
// control (kind=audit, parent_investigation_id pointing at the parent).
// The dispatcher is idempotent: same target + same catalog version with
// an active parent returns HTTP 200 + idempotent_reuse=true and reuses
// the prior ids verbatim. Fresh dispatches return HTTP 201. Per-child
// ARQ submit failures land in `enqueue_errors` keyed by child
// investigation id — the row exists, the operator retries via
// POST /vr/investigations/{id}/re-enqueue.

/** Frontend-side estimate for the pre-confirm "expected spend" UI.
 *  The backend is authoritative — `cost_budget_total_usd` in the
 *  dispatch response carries the real total, computed from the live
 *  catalog. These constants exist only so the operator sees a
 *  reasonable number BEFORE clicking, without forcing a round-trip.
 *  Keep them in sync with `child_budget_usd` in
 *  `vr/api_router.py::dispatch_masvs_audit` and the L1 row count in
 *  `vr/masvs/catalog.py`. */
export const MASVS_DEFAULT_CHILD_BUDGET_USD = 50;
export const MASVS_L1_CONTROL_COUNT_ESTIMATE = 53;

export interface MasvsAuditDispatchResult {
  parent_investigation_id: string;
  /** One id per dispatched child investigation, in MASVS catalog order.
   *  `child_investigation_ids.length === total_controls` always. */
  child_investigation_ids: string[];
  total_controls: number;
  /** Catalog snapshot pinned on the parent (e.g. "1.4.2-aila"). */
  masvs_spec_version: string;
  /** Sum of every child investigation's cost_budget_usd. */
  cost_budget_total_usd: number;
  /** Per-child submit failures keyed by child id. Empty on the happy
   *  path and always empty on an idempotent reuse. */
  enqueue_errors: Record<string, string>;
  /** True when the dispatcher matched an existing active parent (same
   *  target, same catalog version, status not terminal) and returned
   *  that parent's ids without fanning a fresh batch. */
  idempotent_reuse: boolean;
}

export function useMasvsAudit(targetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<MasvsAuditDispatchResult>>(
        `/vr/targets/${encodeURIComponent(targetId)}/masvs-audit`,
        { method: "POST" },
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["vr", "target", targetId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      queryClient.invalidateQueries({
        queryKey: ["vr", "investigations-for-target", targetId],
      });
      const r = result.data;
      const parentShort = r.parent_investigation_id.slice(0, 8);
      const failedCount = Object.keys(r.enqueue_errors).length;
      if (r.idempotent_reuse) {
        toast.info(
          `MASVS audit already in progress: ${r.total_controls} controls, parent ${parentShort}`,
        );
      } else if (failedCount > 0) {
        toast.warning(
          `MASVS audit dispatched (${r.total_controls} controls) — ${failedCount} child${
            failedCount === 1 ? "" : "ren"
          } failed to enqueue, retry via /re-enqueue`,
        );
      } else {
        toast.success(
          `MASVS audit dispatched: ${r.total_controls} controls (catalog ${r.masvs_spec_version}, ~$${r.cost_budget_total_usd.toFixed(0)} budget)`,
        );
      }
    },
    onError: (err: Error) => {
      toast.error(`MASVS audit failed: ${err.message}`);
    },
  });
}
