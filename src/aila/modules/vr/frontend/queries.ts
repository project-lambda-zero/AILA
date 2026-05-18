import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import type {
  DisclosureTrackInfo,
  Envelope,
  McpServerSummary,
  McpCallLogEntry,
  RegisteredSystem,
  VRBranchSummary,
  VRDisclosureSubmissionSummary,
  VRFinding,
  VRFuzzCampaignSummary,
  VRFuzzCrashSummary,
  VRInvestigationSummary,
  VRMessageSummary,
  VROutcomeSummary,
  VRPatternSummary,
  VRProjectSummary,
  VRTargetSummary,
  VRWorkspaceSummary,
} from "./types";

export function useVRProjects(offset = 0, limit = 20) {
  return useQuery({
    queryKey: ["vr", "projects", offset, limit],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<VRProjectSummary[]>>(
        `/vr/projects?offset=${offset}&limit=${limit}`,
      ),
  });
}

export function useVRProject(projectId: string) {
  return useQuery({
    queryKey: ["vr", "project", projectId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRProjectSummary>>(
          `/vr/projects/${encodeURIComponent(projectId)}`,
        )
      ).data,
    enabled: !!projectId,
  });
}

export function useVRFindings(projectId: string, offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["vr", "findings", projectId, offset, limit],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<VRFinding[]>>(
        `/vr/projects/${encodeURIComponent(projectId)}/findings?offset=${offset}&limit=${limit}`,
      ),
    enabled: !!projectId,
  });
}

export function useVRFinding(projectId: string, findingId: string) {
  return useQuery({
    queryKey: ["vr", "finding", projectId, findingId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRFinding>>(
          `/vr/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`,
        )
      ).data,
    enabled: !!projectId && !!findingId,
  });
}

export function useRegisteredSystems() {
  return useQuery({
    queryKey: ["platform", "systems"],
    queryFn: async () => {
      const res = await authorizedRequestJson<{ items: RegisteredSystem[] }>(
        "/systems",
      );
      return res?.items ?? [];
    },
  });
}

/** id → RegisteredSystem map. Use to render a campaign's
 *  analysis_system_id as a human-readable host instead of an int. */
export function useSystemMap() {
  const { data } = useRegisteredSystems();
  const list: RegisteredSystem[] = data ?? [];
  const map = new Map<number, RegisteredSystem>();
  for (const s of list) map.set(s.id, s);
  return map;
}

export interface SystemHeartbeat {
  system_id: number;
  reachable: boolean;
  latency_ms: number | null;
  checked_at: string;
  error: string | null;
}

/** Polls /systems/:id/heartbeat (cached 30s server-side). Returns the
 *  freshest reachable + latency reading; consumers render a LiveDot. */
export function useSystemHeartbeat(systemId: number | null | undefined) {
  return useQuery({
    queryKey: ["platform", "system-heartbeat", systemId],
    queryFn: async () => {
      const res = await authorizedRequestJson<{ data: SystemHeartbeat }>(
        `/systems/${systemId}/heartbeat`,
      );
      return res?.data;
    },
    enabled: !!systemId,
    refetchInterval: 30000,
  });
}

export function useInvestigations(offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["vr", "investigations", offset, limit],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<VRInvestigationSummary[]>>(
        `/vr/investigations?offset=${offset}&limit=${limit}`,
      ),
    refetchInterval: 5000, // poll while a frontend SSE stream isn't wired
  });
}

/**
 * Convenience hook — returns all investigations across the workspace
 * filtered to those rooted on a given target_id. The backend list
 * endpoint doesn't yet accept a target_id filter, so we filter
 * client-side; the data set is small enough (per-workspace) that
 * this is fine for v0.5 (08_FRONTEND_UX.md §1.4 hypothesis tab).
 */
export function useInvestigationsForTarget(targetId: string) {
  return useQuery({
    queryKey: ["vr", "investigations-for-target", targetId],
    queryFn: async () => {
      const res = await authorizedRequestJson<
        Envelope<VRInvestigationSummary[]>
      >(`/vr/investigations?offset=0&limit=200`);
      return {
        ...res,
        data: res.data.filter((i) => i.target_id === targetId),
      };
    },
    enabled: !!targetId,
    refetchInterval: 8000,
  });
}

export interface EvidenceGraphNodeWire {
  id: string;
  kind: string;
  label: string;
  state: string;
  x: number;
  y: number;
  attributes: Record<string, unknown>;
}

export interface EvidenceGraphEdgeWire {
  source: string;
  target: string;
  kind: string;
  attributes: Record<string, unknown>;
}

export interface EvidenceGraphSnapshot {
  investigation_id: string;
  layout: "concentric" | "radial" | "grid";
  nodes: EvidenceGraphNodeWire[];
  edges: EvidenceGraphEdgeWire[];
}

export function useEvidenceGraph(
  investigationId: string,
  layout: "concentric" | "radial" | "grid" = "concentric",
) {
  return useQuery({
    queryKey: ["vr", "evidence-graph", investigationId, layout],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<EvidenceGraphSnapshot>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/evidence-graph?layout=${layout}`,
      ),
    enabled: !!investigationId,
    refetchInterval: 10000,
  });
}

export function useInvestigation(investigationId: string) {
  return useQuery({
    queryKey: ["vr", "investigation", investigationId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRInvestigationSummary>>(
          `/vr/investigations/${encodeURIComponent(investigationId)}`,
        )
      ).data,
    enabled: !!investigationId,
    refetchInterval: 3000,
  });
}

export function useInvestigationMessages(
  investigationId: string,
  branchId?: string,
  offset = 0,
  limit = 500,
) {
  return useQuery({
    queryKey: ["vr", "investigation-messages", investigationId, branchId, offset, limit],
    queryFn: async () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(limit),
      });
      if (branchId) params.set("branch_id", branchId);
      return await authorizedRequestJson<Envelope<VRMessageSummary[]>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/messages?${params.toString()}`,
      );
    },
    enabled: !!investigationId,
    refetchInterval: 3000,
  });
}

export function useInvestigationBranches(investigationId: string) {
  return useQuery({
    queryKey: ["vr", "investigation-branches", investigationId],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<VRBranchSummary[]>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/branches`,
      ),
    enabled: !!investigationId,
    refetchInterval: 5000,
  });
}

export function useInvestigationOutcomes(investigationId: string) {
  return useQuery({
    queryKey: ["vr", "investigation-outcomes", investigationId],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<VROutcomeSummary[]>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/outcomes`,
      ),
    enabled: !!investigationId,
    refetchInterval: 5000,
  });
}

export interface HypothesisProjection {
  id: string;
  claim: string;
  why_plausible: string;
  kill_criterion: string;
  state: "live" | "rejected" | "mixed";
  rejection_reason: string | null;
  live_in_branches: string[];
  rejected_in_branches: string[];
}

export function useInvestigationHypotheses(investigationId: string) {
  return useQuery({
    queryKey: ["vr", "investigation-hypotheses", investigationId],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<HypothesisProjection[]>>(
        `/vr/investigations/${encodeURIComponent(investigationId)}/hypotheses`,
      ),
    enabled: !!investigationId,
    refetchInterval: 8000,
  });
}

export function useWorkspaces(offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["vr", "workspaces", offset, limit],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<VRWorkspaceSummary[]>>(
        `/vr/workspaces?offset=${offset}&limit=${limit}`,
      ),
  });
}

export interface VRTargetDetail extends VRTargetSummary {
  capability_profile: Record<string, unknown>;
  descriptor: Record<string, unknown>;
}

export function useTargets(opts?: {
  workspaceId?: string;
  kind?: string;
  status?: string;
  offset?: number;
  limit?: number;
}) {
  const { workspaceId, kind, status, offset = 0, limit = 50 } = opts ?? {};
  return useQuery({
    queryKey: ["vr", "targets", workspaceId, kind, status, offset, limit],
    queryFn: async () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(limit),
      });
      if (workspaceId) params.set("workspace_id", workspaceId);
      if (kind) params.set("kind", kind);
      if (status) params.set("status", status);
      return await authorizedRequestJson<Envelope<VRTargetSummary[]>>(
        `/vr/targets?${params.toString()}`,
      );
    },
  });
}

export function useTarget(targetId: string) {
  return useQuery({
    queryKey: ["vr", "target", targetId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRTargetDetail>>(
          `/vr/targets/${encodeURIComponent(targetId)}`,
        )
      ).data,
    enabled: !!targetId,
    refetchInterval: 5000,
  });
}

// ─── Patterns ───────────────────────────────────────────────────────────────

export function usePatterns(opts?: {
  workspaceId?: string;
  kind?: string;
  status?: string;
  scope?: string;
  offset?: number;
  limit?: number;
}) {
  const {
    workspaceId, kind, status, scope, offset = 0, limit = 50,
  } = opts ?? {};
  return useQuery({
    queryKey: [
      "vr", "patterns", workspaceId, kind, status, scope, offset, limit,
    ],
    queryFn: async () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(limit),
      });
      if (workspaceId) params.set("workspace_id", workspaceId);
      if (kind) params.set("kind", kind);
      if (status) params.set("status", status);
      if (scope) params.set("scope", scope);
      return await authorizedRequestJson<Envelope<VRPatternSummary[]>>(
        `/vr/patterns?${params.toString()}`,
      );
    },
  });
}

export function usePattern(patternId: string) {
  return useQuery({
    queryKey: ["vr", "pattern", patternId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRPatternSummary>>(
          `/vr/patterns/${encodeURIComponent(patternId)}`,
        )
      ).data,
    enabled: !!patternId,
  });
}

// ─── Disclosures ────────────────────────────────────────────────────────────

export function useDisclosureTracks() {
  return useQuery({
    queryKey: ["vr", "disclosure-tracks"],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<DisclosureTrackInfo[]>>(
          "/vr/disclosure-tracks",
        )
      ).data,
  });
}

export function useDisclosures(opts?: {
  findingId?: string;
  workspaceId?: string;
  trackId?: string;
  status?: string;
  offset?: number;
  limit?: number;
}) {
  const {
    findingId, workspaceId, trackId, status, offset = 0, limit = 50,
  } = opts ?? {};
  return useQuery({
    queryKey: [
      "vr", "disclosures",
      findingId, workspaceId, trackId, status, offset, limit,
    ],
    queryFn: async () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(limit),
      });
      if (findingId) params.set("finding_id", findingId);
      if (workspaceId) params.set("workspace_id", workspaceId);
      if (trackId) params.set("track_id", trackId);
      if (status) params.set("status", status);
      return await authorizedRequestJson<
        Envelope<VRDisclosureSubmissionSummary[]>
      >(`/vr/disclosures?${params.toString()}`);
    },
  });
}

export function useDisclosure(submissionId: string) {
  return useQuery({
    queryKey: ["vr", "disclosure", submissionId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRDisclosureSubmissionSummary>>(
          `/vr/disclosures/${encodeURIComponent(submissionId)}`,
        )
      ).data,
    enabled: !!submissionId,
  });
}

// ─── Fuzz campaigns + crashes ───────────────────────────────────────────────

export function useFuzzCampaigns(opts?: {
  targetId?: string;
  workspaceId?: string;
  status?: string;
  offset?: number;
  limit?: number;
}) {
  const {
    targetId, workspaceId, status, offset = 0, limit = 50,
  } = opts ?? {};
  return useQuery({
    queryKey: [
      "vr", "fuzz-campaigns",
      targetId, workspaceId, status, offset, limit,
    ],
    queryFn: async () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(limit),
      });
      if (targetId) params.set("target_id", targetId);
      if (workspaceId) params.set("workspace_id", workspaceId);
      if (status) params.set("status", status);
      return await authorizedRequestJson<Envelope<VRFuzzCampaignSummary[]>>(
        `/vr/fuzz/campaigns?${params.toString()}`,
      );
    },
    refetchInterval: 5000,  // progress updates
  });
}

export function useFuzzCampaign(campaignId: string) {
  return useQuery({
    queryKey: ["vr", "fuzz-campaign", campaignId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRFuzzCampaignSummary>>(
          `/vr/fuzz/campaigns/${encodeURIComponent(campaignId)}`,
        )
      ).data,
    enabled: !!campaignId,
    refetchInterval: 3000,
  });
}

export interface FuzzTelemetryPoint {
  id: string;
  campaign_id: string;
  measured_at: string;
  execs_per_sec: number | null;
  total_execs: number | null;
  corpus_size: number | null;
  coverage_pct: number | null;
  crashes_found: number | null;
}

export function useCampaignTelemetry(campaignId: string) {
  return useQuery({
    queryKey: ["vr", "campaign-telemetry", campaignId],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<FuzzTelemetryPoint[]>>(
        `/vr/fuzz/campaigns/${encodeURIComponent(campaignId)}/telemetry?offset=0&limit=500`,
      ),
    enabled: !!campaignId,
    refetchInterval: 10000,
  });
}

export function useFuzzCrashes(opts?: {
  campaignId?: string;
  verdict?: string;
  severity?: string;
  offset?: number;
  limit?: number;
}) {
  const {
    campaignId, verdict, severity, offset = 0, limit = 100,
  } = opts ?? {};
  return useQuery({
    queryKey: [
      "vr", "fuzz-crashes", campaignId, verdict, severity, offset, limit,
    ],
    queryFn: async () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(limit),
      });
      if (campaignId) params.set("campaign_id", campaignId);
      if (verdict) params.set("verdict", verdict);
      if (severity) params.set("severity", severity);
      return await authorizedRequestJson<Envelope<VRFuzzCrashSummary[]>>(
        `/vr/fuzz/crashes?${params.toString()}`,
      );
    },
    refetchInterval: 5000,
  });
}

export function useFuzzCrash(crashId: string) {
  return useQuery({
    queryKey: ["vr", "fuzz-crash", crashId],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<VRFuzzCrashSummary>>(
          `/vr/fuzz/crashes/${encodeURIComponent(crashId)}`,
        )
      ).data,
    enabled: !!crashId,
  });
}

// ─── MCP servers ────────────────────────────────────────────────────────
// Lists registered MCP servers (audit-mcp, ida-headless) with live health
// probes. Refetches every 5s while page is open so the operator sees
// breakage immediately. Use mutations.useUpdateMcpServer to retarget.

export function useMcpServers() {
  return useQuery({
    queryKey: ["vr", "mcp-servers"],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<McpServerSummary[]>>(
        "/vr/mcp/servers",
      ),
    refetchInterval: 5000,
  });
}

export function useMcpCalls(opts?: { serverId?: string; status?: string }) {
  const params = new URLSearchParams();
  if (opts?.serverId) params.set("server_id", opts.serverId);
  if (opts?.status) params.set("status", opts.status);
  const qs = params.toString();
  return useQuery({
    queryKey: ["vr", "mcp-calls", opts?.serverId ?? "", opts?.status ?? ""],
    queryFn: async () =>
      await authorizedRequestJson<Envelope<McpCallLogEntry[]>>(
        `/vr/mcp/calls${qs ? `?${qs}` : ""}`,
      ),
    refetchInterval: 3000,  // operator wants near-live tail
  });
}

// ─── Tiny ID resolvers ─────────────────────────────────────────────────
// Pages need human names instead of raw UUIDs. These hooks reuse the
// existing list cache (no extra fetch when the list is already loaded)
// and surface a stable fallback when the entity hasn't loaded yet.
//
// Two flavors:
//  - useXName(id) for one-off lookups (page header, breadcrumb, etc.)
//  - useXMap() returns an `id -> entity` Map for use inside .map() loops
//    where calling a hook per row would violate the Rules of Hooks.

export function useTargetMap(): Map<string, VRTargetSummary> {
  const { data } = useTargets();
  return new Map((data?.data ?? []).map((t) => [t.id, t]));
}

export function useTargetName(targetId: string | null | undefined): string {
  const map = useTargetMap();
  if (!targetId) return "—";
  return map.get(targetId)?.display_name ?? "loading…";
}

export function useWorkspaceMap(): Map<string, VRWorkspaceSummary> {
  const { data } = useWorkspaces();
  return new Map((data?.data ?? []).map((w) => [w.id, w]));
}

export function useWorkspaceName(workspaceId: string | null | undefined): string {
  const map = useWorkspaceMap();
  if (!workspaceId) return "—";
  return map.get(workspaceId)?.name ?? "loading…";
}

export function useBranchLabel(
  branches: VRBranchSummary[] | undefined,
  branchId: string | null | undefined,
): string {
  if (!branchId || !branches) return "—";
  const hit = branches.find((b) => b.id === branchId);
  if (!hit) return "branch";
  const persona = hit.persona_voice ? `${hit.persona_voice}` : "branch";
  // fork_at_turn disambiguates siblings spawned by the same persona
  return hit.fork_at_turn != null ? `${persona} @t${hit.fork_at_turn}` : persona;
}

/** ── Fuzz campaign proposals (operator-in-the-loop) ────────────── */

export type FuzzProposalStatus =
  | "pending"
  | "accepted"
  | "rejected"
  | "superseded";

export interface SeedCorpusEntry {
  filename: string;
  content_base64: string;
  notes: string;
}

export interface VRFuzzCampaignProposalSummary {
  id: string;
  investigation_id: string;
  outcome_id: string;
  target_id: string;
  workspace_id: string;
  profile: string;
  rationale: string;
  confidence: string;
  target_descriptor: Record<string, unknown>;
  suggested_engine_id: string | null;
  suggested_engine_config: Record<string, unknown>;
  suggested_strategy_id: string | null;
  suggested_duration_hours: number | null;
  harness_source: string | null;
  harness_language: string | null;
  harness_build_command: string | null;
  harness_target_path: string | null;
  seed_corpus: SeedCorpusEntry[];
  dictionary_content: string | null;
  status: FuzzProposalStatus;
  accepted_campaign_id: string | null;
  decided_at: string | null;
  decided_by: string | null;
  decision_reason: string | null;
  prepare_log: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export function useFuzzProposals(opts?: {
  investigationId?: string;
  targetId?: string;
  status?: FuzzProposalStatus;
}) {
  const { investigationId, targetId, status } = opts ?? {};
  return useQuery({
    queryKey: [
      "vr",
      "fuzz-proposals",
      investigationId ?? null,
      targetId ?? null,
      status ?? null,
    ],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (investigationId) params.set("investigation_id", investigationId);
      if (targetId) params.set("target_id", targetId);
      if (status) params.set("status", status);
      const qs = params.toString();
      return await authorizedRequestJson<
        Envelope<VRFuzzCampaignProposalSummary[]>
      >(`/vr/fuzz/proposals${qs ? `?${qs}` : ""}`);
    },
    refetchInterval: 8000,
  });
}
