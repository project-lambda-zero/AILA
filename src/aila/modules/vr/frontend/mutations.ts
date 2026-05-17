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

export function useResumeInvestigation(investigationId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<Envelope<VRInvestigationSummary>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/resume`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vr", "investigation", investigationId] });
      queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
      toast.success("Investigation resumed");
    },
    onError: (err: Error) => {
      toast.error(`Resume failed: ${err.message}`);
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
  finding_id: string;
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
