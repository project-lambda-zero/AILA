import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson, buildApiUrl } from "@platform/api/http";
import { useSSEStream } from "@platform/hooks/useSSEStream";

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
  ReasoningGraphDiffResult,
  ReasoningGraphSnapshot,
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

export type InvestigationFeedStatus =
  | "idle"
  | "connecting"
  | "live"
  | "unavailable"
  | "closed"
  | "error";

/**
 * Stream live investigation progress via SSE.
 *
 * Delegates transport (auth, fetch, line splitting, AbortController,
 * reconnect+backoff) to the platform `useSSEStream` hook so a backend
 * or worker restart mid-investigation resumes automatically with
 * exponential backoff (1s -> 2s -> 4s -> 8s -> 16s capped at 30s;
 * reset on every successful connect). Prior to #111/#145 this was a
 * hand-rolled `streamJsonEvents` call that silently died on the first
 * drop and left the "Live" tab stuck on the last event it saw.
 *
 * Status mapping onto the caller's contract:
 *  - platform `reconnecting` before first byte -> "connecting"
 *  - platform `connected` -> "live" (or "unavailable" when the first
 *    payload is the backend's `No progress stream available` marker)
 *  - platform `reconnecting` after a drop -> "connecting" (the amber
 *    dot in InvestigationDetailPage keeps blinking through the
 *    backoff instead of settling to closed)
 *  - platform `disconnected` (buildUrl returned null: both ids empty
 *    or the caller flipped isRunning to false) -> "idle"
 *
 * Pass an empty string for either id to disable (status stays "idle").
 */
export function useInvestigationEventFeed(projectId: string, investigationId: string) {
  const [events, setEvents] = useState<InvestigationEvent[]>([]);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    // Reset accumulated state whenever the target investigation changes
    // (or is cleared). Without this, switching between investigations
    // would append the new stream onto the previous investigation's
    // events, and a stale "unavailable" flag would suppress the "live"
    // status for a fresh investigation whose backend does have events.
    setEvents([]);
    setUnavailable(false);
  }, [projectId, investigationId]);

  const { status: streamStatus } = useSSEStream<InvestigationEvent>({
    buildUrl: () => {
      if (!projectId || !investigationId) return null;
      return buildApiUrl(
        `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/events`,
      );
    },
    parseEvent: (raw) => {
      try {
        return JSON.parse(raw) as InvestigationEvent;
      } catch {
        return null;
      }
    },
    onMessage: (event) => {
      const message = event?.message ?? "";
      if (message.startsWith("No progress stream available")) {
        setUnavailable(true);
      }
      setEvents((current) => [...current, event]);
    },
    reconnect: true,
    deps: [],
    queryKeyPrefix: ["forensics", "investigation-events", projectId, investigationId],
  });

  let feedStatus: InvestigationFeedStatus;
  if (!projectId || !investigationId) {
    feedStatus = "idle";
  } else if (streamStatus === "connected") {
    feedStatus = unavailable ? "unavailable" : "live";
  } else {
    // Both "reconnecting" (initial connect + between-attempts backoff)
    // and "disconnected" (buildUrl returned null after ids cleared)
    // map to "connecting" while the ids are set -- the reconnect loop
    // is still trying.
    feedStatus = "connecting";
  }

  // feedError is retained in the return shape for the callsite's
  // structural compat but is no longer surfaced by the platform hook;
  // transport errors trigger a reconnect rather than a terminal error.
  return { events, feedStatus, feedError: null as string | null };
}

/**
 * List durable reasoning-graph snapshots for one investigation, one row per
 * reasoning turn. Snapshots are ordered by ``step_number`` on the server;
 * the replay UI walks them in that order.
 */
export function useReasoningGraphs(projectId: string, investigationId: string) {
  return useQuery({
    queryKey: ["forensics", "reasoning-graphs", projectId, investigationId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<ReasoningGraphSnapshot[]>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/reasoning-graphs`,
        )
      ).data,
    enabled: !!projectId && !!investigationId,
  });
}

/**
 * Fetch the diff between two reasoning-graph snapshots (by ``step_number``).
 * Backend validates ``from_step``/``to_step`` >= 1; hook stays disabled until
 * both are truthy so the initial render does not blow up on 422.
 */
export function useReasoningGraphDiff(
  projectId: string,
  investigationId: string,
  fromStep: number | null,
  toStep: number | null,
) {
  return useQuery({
    queryKey: [
      "forensics",
      "reasoning-graph-diff",
      projectId,
      investigationId,
      fromStep,
      toStep,
    ],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<ReasoningGraphDiffResult>>(
          `/forensics/projects/${encodeURIComponent(projectId)}/investigations/${encodeURIComponent(investigationId)}/reasoning-graphs/diff?from_step=${fromStep}&to_step=${toStep}`,
        )
      ).data,
    enabled:
      !!projectId &&
      !!investigationId &&
      typeof fromStep === "number" &&
      fromStep >= 1 &&
      typeof toStep === "number" &&
      toStep >= 1,
  });
}
