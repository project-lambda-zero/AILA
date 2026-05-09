import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import type {
  Envelope,
  RegisteredSystem,
  VRFinding,
  VRProjectSummary,
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
