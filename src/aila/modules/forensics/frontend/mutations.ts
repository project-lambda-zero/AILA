import { useMutation, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson, requestBlob } from "@platform/api/http";
import { saveBlobResponse } from "@platform/api/download";
import { toast } from "@/components/ui/sonner";

import type {
  AnalystDirective,
  AnalystDirectiveCreate,
  CancelInvestigationResult,
  FetchRawRequest,
  FindingSuppression,
  FindingSuppressionRequest,
  InvestigationSummary,
  ProjectCreate,
  ProjectSummary,
  MachineReadinessResult,
  RetrieveFileRequest,
  SolidEvidence,
  TagInvestigationRequest,
} from "./types";

import type { BlobResponsePayload } from "@platform/api/http";

/** Authed blob request -- mirrors authorizedRequestJson but returns a blob payload. */
async function authorizedRequestBlob(
  pathname: string,
  body: unknown,
): Promise<BlobResponsePayload> {
  const { getAuthTokenStandalone } = await import("@platform/auth/useAuthStore");
  const token = await getAuthTokenStandalone();
  return requestBlob(pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    token,
  });
}

interface Envelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

export function useCreateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: ProjectCreate) =>
      authorizedRequestJson<Envelope<ProjectSummary>>("/forensics/projects", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["forensics", "projects"] });
      toast.success(`Project "${result.data.name}" created`);
    },
    onError: (err: Error) => {
      toast.error(`Failed to create project: ${err.message}`);
    },
  });
}

export function useCheckReadiness() {
  return useMutation({
    mutationFn: (projectId: string) =>
      authorizedRequestJson<Envelope<MachineReadinessResult>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/readiness-check`,
        { method: "POST" }
      ),
    onError: (err: Error) => {
      toast.error(`Readiness check failed: ${err.message}`);
    },
  });
}

export function useTriggerFullAnalysis() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) =>
      authorizedRequestJson<Envelope<{ task_id: string; status: string }>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/full-analysis`,
        { method: "POST" }
      ),
    onSuccess: (data) => {
      toast.success(`Full-analysis task queued (id=${data.data.task_id.slice(0, 8)})`);
      queryClient.invalidateQueries({ queryKey: ["forensics", "artifacts"] });
    },
    onError: (err: Error) => {
      toast.error(`Failed to queue full analysis: ${err.message}`);
    },
  });
}

export function useDeleteProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) =>
      authorizedRequestJson<void>(
        `/forensics/projects/${encodeURIComponent(projectId)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["forensics", "projects"] });
      toast.success("Project deleted");
    },
    onError: (err: Error) => {
      toast.error(`Failed to delete project: ${err.message}`);
    },
  });
}

export function useCreateDirective(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: AnalystDirectiveCreate) =>
      authorizedRequestJson<Envelope<AnalystDirective>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/directives`,
        {
          method: "POST",
          body: JSON.stringify(body),
        }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "directives", projectId],
      });
      toast.success("Directive added -- AILA will read it on next turn.");
    },
    onError: (err: Error) => {
      toast.error(`Failed to add directive: ${err.message}`);
    },
  });
}

export function useDeleteDirective(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (directiveId: string) =>
      authorizedRequestJson<void>(
        `/forensics/projects/${encodeURIComponent(projectId)}/directives/${encodeURIComponent(directiveId)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "directives", projectId],
      });
      toast.success("Directive removed.");
    },
    onError: (err: Error) => {
      toast.error(`Failed to remove directive: ${err.message}`);
    },
  });
}

export function useStartInvestigation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      projectId,
      question,
      maxAttempts,
    }: {
      projectId: string;
      question: string;
      maxAttempts: number;
    }) =>
      authorizedRequestJson<Envelope<InvestigationSummary>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/investigate`,
        {
          method: "POST",
          body: JSON.stringify({
            question,
            max_attempts: maxAttempts,
          }),
        }
      ),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "investigations", variables.projectId],
      });
      toast.success("Investigation started");
    },
    onError: (err: Error) => {
      toast.error(`Failed to start investigation: ${err.message}`);
    },
  });
}

export function useRerunInvestigation(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      investigationId,
      maxAttempts,
      questionOverride,
    }: {
      investigationId: string;
      maxAttempts?: number;
      questionOverride?: string | null;
    }) =>
      authorizedRequestJson<Envelope<InvestigationSummary>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/rerun`,
        {
          method: "POST",
          body: JSON.stringify({
            max_attempts: maxAttempts ?? null,
            question_override: questionOverride ?? null,
          }),
        }
      ),
    onSuccess: (envelope) => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "investigations", projectId],
      });
      const newId = envelope.data?.id ?? "";
      toast.success(
        newId
          ? `Rerun started -- new investigation ${newId.slice(0, 8)}`
          : "Rerun started"
      );
    },
    onError: (err: Error) => {
      toast.error(`Failed to rerun investigation: ${err.message}`);
    },
  });
}

export function useCancelInvestigation(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (investigationId: string) =>
      authorizedRequestJson<Envelope<CancelInvestigationResult>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/cancel`,
        { method: "POST" }
      ),
    onSuccess: (result, investigationId) => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "investigations", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "investigation", projectId, investigationId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "investigation-poll", projectId, investigationId],
      });
      if (result.data.already_terminal) {
        toast.info("Investigation already finished -- nothing to cancel.");
      } else {
        toast.success("Investigation stopped.");
      }
    },
    onError: (err: Error) => {
      toast.error(`Failed to cancel investigation: ${err.message}`);
    },
  });
}

export function useTagInvestigation(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      investigationId,
      body,
    }: {
      investigationId: string;
      body: TagInvestigationRequest;
    }) =>
      authorizedRequestJson<Envelope<SolidEvidence>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/tag`,
        {
          method: "POST",
          body: JSON.stringify(body),
        }
      ),
    onSuccess: (_result, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "solid-evidence", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "directives", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: [
          "forensics",
          "directives",
          projectId,
          variables.investigationId,
        ],
      });
      if (variables.body.verdict === "true") {
        toast.success(
          "Tagged as TRUE finding -- future runs will treat it as ground truth."
        );
      } else {
        toast.success(
          "Tagged as FALSE finding -- future runs will skip this hypothesis."
        );
      }
    },
    onError: (err: Error) => {
      toast.error(`Failed to tag investigation: ${err.message}`);
    },
  });
}

export function useSuppressFinding(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: FindingSuppressionRequest) =>
      authorizedRequestJson<Envelope<FindingSuppression>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/findings/suppress`,
        {
          method: "POST",
          body: JSON.stringify(body),
        }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "findings", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "finding-suppressions", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "directives", projectId],
      });
      toast.success(
        "Marked as false positive -- hidden from findings, future runs will treat as benign."
      );
    },
    onError: (err: Error) => {
      toast.error(`Failed to mark false positive: ${err.message}`);
    },
  });
}

export function useUnsuppressFinding(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (suppressionId: string) =>
      authorizedRequestJson<void>(
        `/forensics/projects/${encodeURIComponent(projectId)}/findings/suppressions/${encodeURIComponent(suppressionId)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "findings", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "finding-suppressions", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "directives", projectId],
      });
      toast.success("Unsuppressed -- the finding will re-appear.");
    },
    onError: (err: Error) => {
      toast.error(`Failed to unsuppress: ${err.message}`);
    },
  });
}

export function useUntagSolidEvidence(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (evidenceId: string) =>
      authorizedRequestJson<void>(
        `/forensics/projects/${encodeURIComponent(projectId)}/solid-evidence/${encodeURIComponent(evidenceId)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "solid-evidence", projectId],
      });
      queryClient.invalidateQueries({
        queryKey: ["forensics", "directives", projectId],
      });
      toast.success("Removed from Solid Evidence.");
    },
    onError: (err: Error) => {
      toast.error(`Failed to remove: ${err.message}`);
    },
  });
}

export function useRetrieveFile(projectId: string) {
  return useMutation({
    mutationFn: async (body: RetrieveFileRequest) => {
      const payload = await authorizedRequestBlob(
        `/forensics/projects/${encodeURIComponent(projectId)}/retrieve-file`,
        body,
      );
      const trimmed = body.virtual_path.replace(/[\\/]+$/, "");
      const leaf = (trimmed.split(/[\\/]/).pop() || "retrieved").trim();
      const isZip = (payload.contentType ?? "").toLowerCase().includes("zip");
      const fallback = isZip && !leaf.toLowerCase().endsWith(".zip")
        ? `${leaf}.zip`
        : leaf || "retrieved.bin";
      saveBlobResponse(payload, fallback);
      return {
        fileName: payload.fileName ?? fallback,
        size: payload.blob.size,
      };
    },
    onSuccess: (result) => {
      toast.success(
        `Retrieved ${result.fileName} (${formatBytes(result.size)})`,
      );
    },
    onError: (err: Error) => {
      toast.error(`Retrieve failed: ${err.message}`);
    },
  });
}

export function useFetchRaw(projectId: string) {
  return useMutation({
    mutationFn: async (body: FetchRawRequest) => {
      const payload = await authorizedRequestBlob(
        `/forensics/projects/${encodeURIComponent(projectId)}/fetch-raw`,
        body,
      );
      const isZip = (payload.contentType ?? "").toLowerCase().includes("zip");
      const fallback = isZip ? "retrieved.zip" : "retrieved.bin";
      saveBlobResponse(payload, fallback);
      return {
        fileName: payload.fileName ?? fallback,
        size: payload.blob.size,
      };
    },
    onSuccess: (result) => {
      toast.success(
        `Fetched ${result.fileName} (${formatBytes(result.size)})`,
      );
    },
    onError: (err: Error) => {
      toast.error(`Fetch failed: ${err.message}`);
    },
  });
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Authed GET that streams a file back and saves via saveBlobResponse. */
async function downloadAuthed(pathname: string, fallback: string): Promise<void> {
  const { getAuthTokenStandalone } = await import("@platform/auth/useAuthStore");
  const token = await getAuthTokenStandalone();
  const payload = await requestBlob(pathname, { method: "GET", token });
  saveBlobResponse(payload, payload.fileName ?? fallback);
}

export function useDownloadWriteup(projectId: string) {
  return useMutation({
    mutationFn: async ({
      writeupId,
      titleSlug,
    }: {
      writeupId: string;
      titleSlug: string;
    }) => {
      await downloadAuthed(
        `/forensics/projects/${encodeURIComponent(projectId)}/writeups/${encodeURIComponent(writeupId)}.md`,
        `${titleSlug}.md`,
      );
    },
    onError: (err: Error) => {
      toast.error(`Download failed: ${err.message}`);
    },
  });
}

export function useDeleteWriteup(projectId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (writeupId: string) =>
      authorizedRequestJson<void>(
        `/forensics/projects/${encodeURIComponent(projectId)}/writeups/${encodeURIComponent(writeupId)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["forensics", "writeups", projectId],
      });
      toast.success("Write-up deleted");
    },
    onError: (err: Error) => {
      toast.error(`Delete failed: ${err.message}`);
    },
  });
}

export function useDownloadCarvedFile(projectId: string) {
  return useMutation({
    mutationFn: async ({
      sha256,
      filename,
    }: {
      sha256: string;
      filename: string;
    }) => {
      await downloadAuthed(
        `/forensics/projects/${encodeURIComponent(projectId)}/pcap/carved/${encodeURIComponent(sha256)}`,
        filename,
      );
    },
    onError: (err: Error) => {
      toast.error(`Download failed: ${err.message}`);
    },
  });
}

export function useDownloadWriteupsBundle(projectId: string) {
  return useMutation({
    mutationFn: async () => {
      await downloadAuthed(
        `/forensics/projects/${encodeURIComponent(projectId)}/writeups.md`,
        "writeups.md",
      );
    },
    onSuccess: () => {
      toast.success("Write-ups bundle downloaded");
    },
    onError: (err: Error) => {
      toast.error(`Download failed: ${err.message}`);
    },
  });
}

export function useDownloadDirectives(projectId: string) {
  return useMutation({
    mutationFn: async (opts?: {
      investigationId?: string | null;
      includeInactive?: boolean;
    }) => {
      const params = new URLSearchParams();
      if (opts?.investigationId) params.set("investigation_id", opts.investigationId);
      if (opts?.includeInactive) params.set("include_inactive", "true");
      const qs = params.toString();
      await downloadAuthed(
        `/forensics/projects/${encodeURIComponent(projectId)}/directives.md${qs ? `?${qs}` : ""}`,
        "directives.md",
      );
    },
    onSuccess: () => {
      toast.success("Directives exported");
    },
    onError: (err: Error) => {
      toast.error(`Export failed: ${err.message}`);
    },
  });
}
