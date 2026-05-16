import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import type {
  Envelope,
  RegisteredSystem,
  VRBranchSummary,
  VRFinding,
  VRInvestigationSummary,
  VRMessageSummary,
  VROutcomeSummary,
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
  limit = 100,
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
