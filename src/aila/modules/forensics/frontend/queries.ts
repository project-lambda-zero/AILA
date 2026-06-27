import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { ApiHttpError, authorizedRequestJson } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { streamJsonEvents } from "@platform/api/sse";

import type {
  AnalystDirective,
  AnswerCandidate,
  EvidenceItem,
  FindingSuppression,
  InvestigationDetail,
  InvestigationSummary,
  MachineReadinessResult,
  NetworkAnalysis,
  NormalizedArtifact,
  Occurrence,
  PaginatedResponse,
  ProjectSummary,
  PromotedLead,
  RegisteredSystem,
  RegistryAnalysis,
  SolidEvidence,
  TimelineEntry,
  WriteUpItem,
} from "./types";

interface Envelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

export function useForensicsProjects(page = 1, pageSize = 20) {
  return useQuery({
    queryKey: ["forensics", "projects", page, pageSize],
    queryFn: async () =>
      (
        await authorizedRequestJson<
          Envelope<PaginatedResponse<ProjectSummary>>
        >(`/forensics/projects?page=${page}&page_size=${pageSize}`)
      ).data,
  });
}

export function useForensicsProject(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "project", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<ProjectSummary>>(
          `/forensics/projects/${encodeURIComponent(projectId)}`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useProjectEvidence(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "evidence", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<EvidenceItem[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/evidence`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useProjectArtifacts(
  projectId: string,
  opts: {
    family?: string;
    type?: string;
    source?: "investigations" | "collectors";
    investigationId?: string;
    page?: number;
    pageSize?: number;
  } = {}
) {
  const params = new URLSearchParams();
  if (opts.family) params.set("artifact_family", opts.family);
  if (opts.type) params.set("artifact_type", opts.type);
  if (opts.source) params.set("source", opts.source);
  if (opts.investigationId) params.set("investigation_id", opts.investigationId);
  params.set("page", String(opts.page ?? 1));
  params.set("page_size", String(opts.pageSize ?? 50));

  return useQuery({
    queryKey: ["forensics", "artifacts", projectId, opts],
    queryFn: async () =>
      (
        await authorizedRequestJson<
          Envelope<PaginatedResponse<NormalizedArtifact>>
        >(
          `/forensics/projects/${encodeURIComponent(projectId)}/artifacts?${params}`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useProjectLeads(projectId: string, limit = 20) {
  return useQuery({
    queryKey: ["forensics", "leads", projectId, limit],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<PromotedLead[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/leads?limit=${limit}`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useProjectInvestigations(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "investigations", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<InvestigationSummary[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/investigations`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useInvestigationDetail(
  projectId: string,
  investigationId: string
) {
  return useQuery({
    queryKey: ["forensics", "investigation", projectId, investigationId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<InvestigationDetail>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}`
        )
      ).data,
    enabled: !!projectId && !!investigationId,
  });
}

const TERMINAL_STATUSES = new Set(["completed", "failed", "exhausted", "cancelled"]);

/** Poll investigation detail every 2 s until status reaches a terminal state. */
export function useInvestigationPolling(
  projectId: string,
  investigationId: string
) {
  return useQuery({
    queryKey: ["forensics", "investigation-poll", projectId, investigationId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<InvestigationDetail>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}`
        )
      ).data,
    enabled: !!projectId && !!investigationId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && TERMINAL_STATUSES.has(status) ? false : 2000;
    },
  });
}

export function useProjectAnswers(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "answers", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<AnswerCandidate[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/answers`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useInvestigationAnswers(projectId: string, investigationId: string) {
  const query = useProjectAnswers(projectId);
  return {
    ...query,
    data: query.data?.filter((a) => a.investigation_id === investigationId),
  };
}

export function useProjectWriteups(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "writeups", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<WriteUpItem[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/writeups`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useNetworkAnalysis(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "network-analysis", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<NetworkAnalysis>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/network-analysis`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useRegisteredSystems() {
  return useQuery({
    queryKey: ["platform", "systems"],
    queryFn: async () => {
      const res = await authorizedRequestJson<{ items: RegisteredSystem[] }>(
        "/systems"
      );
      return res?.items ?? [];
    },
  });
}

export function useRegistryAnalysis(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "registry-analysis", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<RegistryAnalysis>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/registry-analysis`
        )
      ).data,
    enabled: !!projectId,
  });
}

/**
 * List analyst directives for a project, optionally including
 * directives scoped to a specific investigation. Refetches every 4 s
 * so the panel reflects mid-investigation additions made by teammates.
 */
export function useDirectives(
  projectId: string,
  investigationId?: string | null
) {
  const params = new URLSearchParams();
  if (investigationId) params.set("investigation_id", investigationId);
  const qs = params.toString() ? `?${params}` : "";
  return useQuery({
    queryKey: ["forensics", "directives", projectId, investigationId ?? null],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<AnalystDirective[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/directives${qs}`
        )
      ).data,
    enabled: !!projectId,
    refetchInterval: 4000,
  });
}

export function useTimeline(
  projectId: string,
  opts: { limit?: number; minConfidence?: "low" | "medium" | "high" } = {}
) {
  const limit = opts.limit ?? 2000;
  const minConfidence = opts.minConfidence ?? "medium";
  return useQuery({
    queryKey: ["forensics", "timeline", projectId, limit, minConfidence],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<TimelineEntry[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/timeline?limit=${limit}&min_confidence=${minConfidence}`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useOccurrences(
  projectId: string,
  opts: { limit?: number; minConfidence?: "low" | "medium" | "high" } = {}
) {
  const limit = opts.limit ?? 2000;
  const minConfidence = opts.minConfidence ?? "medium";
  return useQuery({
    queryKey: ["forensics", "occurrences", projectId, limit, minConfidence],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<Occurrence[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/occurrences?limit=${limit}&min_confidence=${minConfidence}`
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useMachineReadiness(projectId: string, enabled = false) {
  return useQuery({
    queryKey: ["forensics", "readiness", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<MachineReadinessResult>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/readiness-check`,
          { method: "POST" }
        )
      ).data,
    enabled: enabled && !!projectId,
  });
}

export interface Finding {
  artifact_type: string;
  artifact_family: string;
  source_tool?: string | null;
  suspicious_reasons: string[];
  executable?: string | null;
  path?: string | null;
  name?: string | null;
  last_run?: string | null;
  run_count?: number | null;
  user?: string | null;
  /** Number of identical-key duplicates collapsed into this finding (1 = unique). */
  occurrences?: number;
  raw_record?: Record<string, unknown>;
  /** Stable sha256 hash of (artifact_type, executable, path, name, user). */
  fingerprint?: string;
}

/**
 * List analyst-tagged solid-evidence rows for a project. Covers both
 * TRUE (confirmed) and FALSE (disproved) findings. Refetches every 10 s
 * so a fresh tag from a teammate surfaces without a full reload.
 */
export function useSolidEvidence(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "solid-evidence", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<SolidEvidence[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/solid-evidence`
        )
      ).data,
    enabled: !!projectId,
    refetchInterval: 10000,
  });
}

export function useProjectFindings(projectId: string) {
  return useQuery<Envelope<Finding[]>>({
    queryKey: ["forensics", "findings", projectId],
    queryFn: () =>
      authorizedRequestJson<Envelope<Finding[]>>(
        `/forensics/projects/${encodeURIComponent(projectId)}/findings`
      ),
    enabled: !!projectId,
    refetchInterval: 10000,
  });
}

export function useFindingSuppressions(projectId: string) {
  return useQuery({
    queryKey: ["forensics", "finding-suppressions", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<FindingSuppression[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/findings/suppressions`
        )
      ).data,
    enabled: !!projectId,
  });
}

export interface InvestigationEvent {
  stage?: string | null;
  message?: string | null;
  percent?: number | null;
  timestamp?: string | null;
  /** JSON-encoded structured payload (lane, path, error, etc.) -- see ForensicsWorkflowEmitter. */
  data_json?: string | null;
}

/**
 * Stream live investigation progress via SSE.
 * Follows the same pattern as `useScanEventFeed` in platform/features/scans/api.ts.
 * Pass an empty string to disable (status stays "idle").
 */
export function useInvestigationEventFeed(projectId: string, investigationId: string) {
  const [events, setEvents] = useState<InvestigationEvent[]>([]);
  const [feedStatus, setFeedStatus] = useState<
    "idle" | "connecting" | "live" | "unavailable" | "closed" | "error"
  >("idle");
  const [feedError, setFeedError] = useState<string | null>(null);

  useEffect(() => {
    if (!projectId || !investigationId) {
      setEvents([]);
      setFeedStatus("idle");
      setFeedError(null);
      return;
    }

    const controller = new AbortController();
    let closedByAbort = false;
    setEvents([]);
    setFeedStatus("connecting");
    setFeedError(null);

    const url = `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/events`;

    void getAuthTokenStandalone()
      .then((token) =>
        streamJsonEvents<InvestigationEvent>(url, {
          token,
          signal: controller.signal,
          onEvent: (event) => {
            const message = event.data?.message ?? "";
            if (message.startsWith("No progress stream available")) {
              setFeedStatus("unavailable");
            } else {
              setFeedStatus("live");
            }
            setEvents((current) => [...current, event.data]);
          },
        })
      )
      .then(() => {
        if (!closedByAbort) {
          setFeedStatus((current) => (current === "idle" ? current : "closed"));
        }
      })
      .catch((err: unknown) => {
        if (closedByAbort || controller.signal.aborted) return;
        const message =
          err instanceof ApiHttpError || err instanceof Error
            ? err.message
            : "Investigation event streaming failed.";
        setFeedStatus("error");
        setFeedError(message);
      });

    return () => {
      closedByAbort = true;
      controller.abort();
    };
  }, [projectId, investigationId]);

  return { events, feedStatus, feedError };
}
